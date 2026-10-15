package panel

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestShareImportPreservesParameters(t *testing.T) {
	s := fixture()
	_, pub, _ := realityKeys()
	flow := ""
	cases := []Outbound{
		{ProtocolOptions: ProtocolOptions{Flow: &flow, Fingerprint: "firefox", ALPN: []string{"h2"}}, Type: "reality", Name: "出口 日本", Address: "2001:db8::1", Port: 24443, UUID: uuid(), PublicKey: pub, ShortID: "01234567", SNI: "www.microsoft.com"},
		{ProtocolOptions: ProtocolOptions{Obfs: "salamander", ObfsPassword: "secret:mask@#", ALPN: []string{"h3"}, Insecure: true, UpMbps: 80, DownMbps: 120}, Type: "hy2", Name: "跳跃", Address: "hy.example.com", Port: 8443, Password: "auth:secret@#?", SNI: "hy.example.com", HopPorts: "20000-20010,21000", HopInterval: 5},
		{ProtocolOptions: ProtocolOptions{Method: "2022-blake3-aes-256-gcm", Network: "tcp"}, Type: "ss2022", Name: "SS", Address: "ss.example.com", Port: 20838, Password: ssKeyFor("2022-blake3-aes-256-gcm") + ":" + ssKeyFor("2022-blake3-aes-256-gcm")},
		{Type: "socks", Name: "SOCKS", Address: "proxy.example.com", Port: 11080, Username: "user@abc", Password: "pass:#?"},
		{ProtocolOptions: ProtocolOptions{ALPN: []string{"h2"}, Insecure: true}, Type: "http", TLS: true, Name: "HTTPS", Address: "proxy.example.com", Port: 9443, Username: "user", Password: "pass+word", SNI: "tls.example.com"},
	}
	for _, o := range cases {
		t.Run(o.Type, func(t *testing.T) {
			o.ID = "source"
			o.ServerID = "srv_a"
			o.Tag = "source"
			o.Enabled = true
			link := outboundShare(o)
			got, e := parseOutboundShare(link)
			if e != nil {
				t.Fatal(e)
			}
			got.ServerID = "srv_a"
			got.ID = "imported"
			if e := validateOutbound(s, got); e != nil {
				t.Fatal(e)
			}
			if connectionIdentity(s, o) == "" || got.Port != o.Port || got.Name != o.Name || connectionIdentity(s, got) != connectionIdentity(s, o) {
				t.Fatal("share round trip changed effective connection parameters")
			}
		})
	}
	for _, link := range []string{"hysteria2://pw@host.example:0/", "hysteria2://pw@host.example:443/?unknown-secret=VALUE", "vless://id@host.example:443?security=reality&type=xhttp", "socks5://host.example:1080?insecure=1"} {
		rows, e := parseOutboundBatch(s, "srv_a", link)
		if e == nil && len(rows) > 0 && rows[0].item.Error == "" {
			t.Fatal("unsupported or invalid link silently imported")
		}
	}
	encoded := base64.RawURLEncoding.EncodeToString([]byte(outboundShare(cases[1]) + "\n" + outboundShare(cases[3])))
	rows, e := parseOutboundBatch(s, "srv_a", encoded)
	if e != nil || len(rows) != 2 || rows[0].item.Error != "" {
		t.Fatal("Base64 multi-import failed", e)
	}
	legacy := base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:" + ssKey() + "@[2001:db8::2]:12345"))
	o, e := parseOutboundShare("ss://" + legacy + "#legacy")
	if e != nil || o.Port != 12345 || o.Address != "2001:db8::2" {
		t.Fatal("legacy SS authority failed", e)
	}
}

func TestOutboundImportAtomicSecretsAndReferences(t *testing.T) {
	store := testStore(t)
	store.Update(func(s *State) error { *s = fixture(); return nil })
	a := New(store, "http://127.0.0.1:8787", store.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	text := "hysteria2://sensitive-auth@hy.example.com:8443/?sni=hy.example.com&obfs=salamander&obfs-password=sensitive-mask&mport=20000-20010&hop-interval=5#Imported\ninvalid://host\n"
	preview := request(t, a, "POST", "/api/outbounds/import", map[string]any{"serverId": "srv_a", "text": text, "preview": true}, cookie, csrf, "")
	if preview.Code != 200 || strings.Contains(preview.Body.String(), "sensitive-auth") || strings.Contains(preview.Body.String(), "sensitive-mask") {
		t.Fatal("preview failed or leaked credentials")
	}
	var p struct {
		Items    []importItem `json:"items"`
		Snapshot string       `json:"snapshot"`
	}
	json.Unmarshal(preview.Body.Bytes(), &p)
	if len(p.Items) != 2 || p.Items[0].Error != "" || p.Items[1].Error == "" {
		t.Fatal("per-line import diagnostics missing")
	}
	commit := func(indices []int, mode string, snapshot string) *httptest.ResponseRecorder {
		return request(t, a, "POST", "/api/outbounds/import", map[string]any{"serverId": "srv_a", "text": text, "indices": indices, "mode": mode, "snapshot": snapshot}, cookie, csrf, "")
	}
	if w := commit([]int{1, 2}, "new", p.Snapshot); w.Code != 422 || len(store.Read().Outbounds) != 0 {
		t.Fatal("invalid batch partly committed")
	}
	if w := commit([]int{1}, "new", p.Snapshot); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	o := store.Read().Outbounds[0]
	id := o.ID
	tag := o.Tag
	if w := commit([]int{1}, "new", p.Snapshot); w.Code != 422 {
		t.Fatal("stale preview accepted")
	}
	store.Update(func(s *State) error {
		s.Routes = append(s.Routes, Route{ID: "route", Scope: "server", ServerID: "srv_a", Action: "outbound", OutboundID: id, Domains: "full:example.com"})
		return nil
	})
	// Reimport with a changed password and the same source name retains the stable ID and route.
	text = strings.Replace(text, "sensitive-auth", "updated-auth", 1)
	if w := commit([]int{1}, "replace", importSnapshot(store.Read(), "srv_a")); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	got := store.Read()
	if len(got.Outbounds) != 1 || got.Outbounds[0].ID != id || got.Outbounds[0].Tag != tag || got.Outbounds[0].Password != "updated-auth" || got.Routes[0].OutboundID != id || got.Schema != 5 {
		t.Fatal("overwrite lost stable references or protocol data")
	}
	w := request(t, a, "GET", "/api/state", nil, cookie, "", "")
	if strings.Contains(w.Body.String(), "sensitive-mask") || strings.Contains(w.Body.String(), "updated-auth") {
		t.Fatal("state leaked credentials")
	}
	w = request(t, a, "GET", "/api/outbounds/"+id+"/share", nil, cookie, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "updated-auth") {
		t.Fatal("explicit authenticated share did not export saved credentials")
	}
	w = request(t, a, "GET", "/api/outbounds/"+id+"/share", nil, nil, "", "")
	if w.Code != 401 {
		t.Fatal("share export lacks authentication")
	}
	backup, e := store.Export("strong-test-backup-pass")
	if e != nil {
		t.Fatal(e)
	}
	next := testStore(t)
	if e := next.Import(backup, "strong-test-backup-pass"); e != nil {
		t.Fatal(e)
	}
	if next.Read().Schema != 5 || next.Read().Outbounds[0].ObfsPassword != "sensitive-mask" {
		t.Fatal("schema 5 backup lost options")
	}
}

func TestNodeOptionsRotationAndNativeTags(t *testing.T) {
	store := testStore(t)
	f := fixture()
	store.Update(func(s *State) error { *s = f; return nil })
	a := New(store, "http://127.0.0.1:8787", store.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	n := f.Nodes[1]
	before := f.Users[0].Credentials[n.ID]
	n.Method = "2022-blake3-aes-256-gcm"
	n.ServerKey = ""
	w := request(t, a, "POST", "/api/nodes/"+n.ID, n, cookie, csrf, "")
	if w.Code != 422 || store.Read().Users[0].Credentials[n.ID] != before {
		t.Fatal("algorithm changed credentials without explicit rotation")
	}
	n.RotateCredentials = true
	n.Tag = "custom-ss-in"
	n.Listen = "127.0.0.1"
	n.PublicPort = 24444
	w = request(t, a, "POST", "/api/nodes/"+n.ID, n, cookie, csrf, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	s := store.Read()
	updated := s.Nodes[1]
	if !validSSKeys(updated.ServerKey, n.Method, false) || !validSSKeys(s.Users[0].Credentials[n.ID], n.Method, false) || s.Users[0].Credentials[n.ID] == before {
		t.Fatal("AES-256 rotation generated wrong key length")
	}
	if clientPort(updated) != 24444 || !strings.Contains(uri(updated, s.Users[0]), ":24444") {
		t.Fatal("advertised port lost")
	}
	s.Routes = []Route{{ID: "r", Scope: "server", ServerID: n.ServerID, NodeIDs: []string{n.ID}, Action: "reject"}}
	d, e := Compile(s, n.ServerID, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(d.Config), `"custom-ss-in"`) || !strings.Contains(string(d.Config), `"2022-blake3-aes-256-gcm"`) {
		t.Fatal("native tag or method was ignored")
	}
	secret := updated.ServerKey
	w = request(t, a, "GET", "/api/state", nil, cookie, "", "")
	if strings.Contains(w.Body.String(), secret) {
		t.Fatal("node main key leaked")
	}
}

func TestOfficialImportedProtocolTCPUDP(t *testing.T) {
	core := networkCore(t)
	for _, kind := range []string{"reality", "hy2", "ss128", "ss256"} {
		t.Run(kind, func(t *testing.T) {
			s := fixture()
			n := s.Nodes[0]
			n.Port = freePort(t)
			n.Tag = "imported-test-in"
			n.Listen = "127.0.0.1"
			n.Protocol = kind
			n.ExitID = ""
			n.SNI = "imported.example.com"
			n.Certificate, n.Key = cert(t, n.SNI)
			n.TLSMode = "import"
			if strings.HasPrefix(kind, "ss") {
				n.Protocol = "ss2022"
				n.Method = "2022-blake3-aes-128-gcm"
				if kind == "ss256" {
					n.Method = "2022-blake3-aes-256-gcm"
				}
				n.ServerKey = ssKeyFor(n.Method)
			}
			if kind == "hy2" {
				n.Obfs = "salamander"
				n.ObfsPassword = "temporary-obfs-password"
				n.UpMbps = 100
				n.DownMbps = 100
			}
			if kind == "reality" {
				flow := ""
				n.Flow = &flow
				n.Fingerprint = "firefox"
				n.ShortIDs = []string{n.ShortID, "abcdef12"}
				n.MaxTimeDifference = "1m"
				pair, e := tls.X509KeyPair([]byte(n.Certificate), []byte(n.Key))
				if e != nil {
					t.Fatal(e)
				}
				target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
				target.Config.ErrorLog = log.New(io.Discard, "", 0)
				target.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
				target.StartTLS()
				t.Cleanup(target.Close)
				n.Target = target.Listener.Addr().String()
			}
			n.Address = "127.0.0.1"
			s.Nodes = []Node{n}
			u := s.Users[0]
			u.NodeIDs = []string{n.ID}
			u.Credentials = map[string]string{n.ID: credential(n.Protocol)}
			if n.Protocol == "ss2022" {
				u.Credentials[n.ID] = ssKeyFor(n.Method)
			}
			s.Users = []User{u}
			ready := n.Port
			if n.Protocol == "hy2" {
				ready = 0
			}
			coreProcess(t, core, localCompile(t, s, "srv_a"), ready)
			link := uri(n, u)
			if n.Protocol == "hy2" {
				link = strings.Replace(link, "/?", "/?insecure=1&", 1)
			}
			o, e := parseOutboundShare(link)
			if e != nil {
				t.Fatal(e)
			}
			o.ServerID = "srv_a"
			o.ID = "imported"
			m, e := compileOutbound(s, o)
			if e != nil {
				t.Fatal(e)
			}
			client, socks := proxyClient(t, core, m)
			target, udp, _, _ := echoTargets(t)
			if e := getThrough(t, client, target); e != nil {
				t.Fatal("imported TCP failed", e)
			}
			if reply, e := udpThrough(socks, udp); e != nil || reply != "managed-udp" {
				t.Fatal("imported UDP failed", e)
			}
		})
	}
}
