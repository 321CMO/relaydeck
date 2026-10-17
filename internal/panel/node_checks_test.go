package panel

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/321CMO/relaydeck/internal/nodecheck"
)

func TestNodeCheckAuthenticatedRoundTripAndIsolation(t *testing.T) {
	store := testStore(t)
	f := fixture()
	f.Servers[0].MachineID = "a"
	f.Servers[0].LastSeen = time.Now()
	if e := store.Update(func(s *State) error { *s = f; return nil }); e != nil {
		t.Fatal(e)
	}
	a := New(store, "http://127.0.0.1:8787", store.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	input := map[string]string{"serverId": "srv_a", "target": "www.microsoft.com:443", "sni": "www.microsoft.com"}
	if w := request(t, a, "POST", "/api/nodes/checks", input, nil, "", ""); w.Code != 401 {
		t.Fatal("unauthenticated check allowed")
	}
	w := request(t, a, "POST", "/api/nodes/checks", input, cookie, csrf, "")
	if w.Code != 202 {
		t.Fatal(w.Body.String())
	}
	var job nodeCheckJob
	json.Unmarshal(w.Body.Bytes(), &job)
	if w = request(t, a, "POST", "/api/nodes/checks", input, cookie, csrf, ""); w.Code != 409 {
		t.Fatal("unbounded per-server jobs")
	}
	report := func(server, token string, results []nodecheck.Result) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{"serverId": server, "epoch": f.Epoch, "applied": 3, "nodeCheckResults": results})
		r := httptest.NewRequest("POST", "/api/agent/sync", strings.NewReader(string(raw)))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		return w
	}
	r := nodecheck.Result{ID: job.ID, Success: true, Stage: "complete", Message: "checked"}
	if w = report("srv_a", "wrong", []nodecheck.Result{r}); w.Code != 403 {
		t.Fatal("unauthenticated report accepted")
	}
	if w = report("srv_b", f.Servers[1].AgentToken, []nodecheck.Result{r}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = request(t, a, "GET", "/api/nodes/checks/"+job.ID, nil, cookie, "", "")
	json.Unmarshal(w.Body.Bytes(), &job)
	if job.Status != "pending" {
		t.Fatal("cross-server result accepted")
	}
	w = report("srv_a", f.Servers[0].AgentToken, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), job.ID) {
		t.Fatal("request not dispatched to bound Agent")
	}
	w = report("srv_a", f.Servers[0].AgentToken, []nodecheck.Result{r})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = request(t, a, "GET", "/api/nodes/checks/"+job.ID, nil, cookie, "", "")
	json.Unmarshal(w.Body.Bytes(), &job)
	if job.Status != "passed" || job.Result == nil {
		t.Fatal("result not available")
	}
	a.nodeChecks.mu.Lock()
	a.nodeChecks.jobs[job.ID].Created = time.Now().Add(-11 * time.Minute)
	a.nodeChecks.mu.Unlock()
	if w = request(t, a, "GET", "/api/nodes/checks/"+job.ID, nil, cookie, "", ""); w.Code != 404 {
		t.Fatal("expired result retained")
	}
	input["serverId"] = "srv_b"
	if w = request(t, a, "POST", "/api/nodes/checks", input, cookie, csrf, ""); w.Code != 422 {
		t.Fatal("offline Agent accepted")
	}
}
func TestCredentialGeneratorsAndRealityRotation(t *testing.T) {
	store := testStore(t)
	f := fixture()
	store.Update(func(s *State) error { *s = f; return nil })
	a := New(store, "http://127.0.0.1:8787", store.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	for _, kind := range []string{"reality", "short-id", "hy2", "ss2022"} {
		w := request(t, a, "POST", "/api/nodes/generate-keys", map[string]string{"type": kind, "method": "2022-blake3-aes-256-gcm"}, cookie, csrf, "")
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		var v map[string]json.RawMessage
		json.Unmarshal(w.Body.Bytes(), &v)
		var value string
		switch kind {
		case "reality", "short-id":
			json.Unmarshal(v["shortId"], &value)
			b, e := hex.DecodeString(value)
			if e != nil || len(b) != 8 {
				t.Fatal("weak Short ID")
			}
			if kind == "reality" {
				var ids []string
				json.Unmarshal(v["shortIds"], &ids)
				if len(ids) != 1 || ids[0] != value {
					t.Fatal("new Short ID not synchronized with list")
				}
			}
		case "hy2":
			json.Unmarshal(v["obfsPassword"], &value)
			b, e := base64.RawURLEncoding.DecodeString(value)
			if e != nil || len(b) != 32 {
				t.Fatal("wrong obfuscation entropy")
			}
		case "ss2022":
			json.Unmarshal(v["serverKey"], &value)
			if !validSSKeys(value, "2022-blake3-aes-256-gcm", false) {
				t.Fatal("wrong SS key length")
			}
		}
	}
	old := f.Nodes[0]
	old.ShortIDs = []string{"aabbccdd", "01234567"}
	n := old
	n.PrivateKey = ""
	n.ShortIDs = nil
	n.ShortID = ""
	if e := prepareNodeOptions(&f, &n, &old); e != nil || len(n.ShortIDs) != 2 {
		t.Fatal("blank edit removed accepted Short IDs", e)
	}
	n.PrivateKey, _, _ = realityKeys()
	if e := prepareNodeOptions(&f, &n, &old); e == nil {
		t.Fatal("Reality rotation lacks acknowledgement")
	}
	n.RotateCredentials = true
	if e := prepareNodeOptions(&f, &n, &old); e != nil {
		t.Fatal(e)
	}
}
func TestNodeTransportAndHopSafety(t *testing.T) {
	s := fixture()
	n := s.Nodes[1]
	n.ServerID = "srv_a"
	n.Port = s.Nodes[0].Port
	n.Network = "udp"
	s.Settings.HTTPS.AdminPort = n.Port
	if e := validateNode(&s, n); e != nil {
		t.Fatal("independent TCP / UDP sockets falsely conflict", e)
	}
	n.Network = "tcp"
	if e := validateNode(&s, n); e == nil {
		t.Fatal("TCP conflict accepted")
	}
	n.Port = 20838
	n.Network = ""
	for _, p := range []int{2019, 8787, 10085, 18999} {
		n.Port = p
		if e := validateNode(&s, n); e == nil {
			t.Fatalf("reserved %d accepted", p)
		}
	}
	crt, key := cert(t, "hy.example.com")
	n = Node{ID: "hy", Name: "HY", ServerID: "srv_a", Address: "entry.example.com", Port: 443, Protocol: "hy2", Enabled: true, SNI: "hy.example.com", TLSMode: "import", Certificate: crt, Key: key, HopStart: 20000, HopEnd: 20010, HopInterval: 30}
	if e := validateNode(&s, n); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Node){func(n *Node) { n.HopStart = 0 }, func(n *Node) { n.HopInterval = 3601 }, func(n *Node) { n.HopEnd = 30000 }, func(n *Node) { n.HopStart = 18998; n.HopEnd = 19000 }, func(n *Node) { n.PublicPort = 8443 }} {
		bad := n
		mutate(&bad)
		if e := validateNode(&s, bad); e == nil {
			t.Fatalf("invalid hopping configuration accepted: %+v", bad)
		}
	}
}
func TestInboundALPNActuallyCompiled(t *testing.T) {
	s := fixture()
	s.Nodes[0].ALPN = []string{"h2"}
	d, e := Compile(s, "srv_a", t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	var cfg struct {
		Inbounds []struct {
			Tag string `json:"tag"`
			TLS struct {
				ALPN []string `json:"alpn"`
			} `json:"tls"`
		} `json:"inbounds"`
	}
	json.Unmarshal(d.Config, &cfg)
	for _, in := range cfg.Inbounds {
		if in.Tag == inboundTag(s.Nodes[0]) && len(in.TLS.ALPN) == 1 && in.TLS.ALPN[0] == "h2" {
			return
		}
	}
	t.Fatal("ALPN lost from actual inbound")
}
