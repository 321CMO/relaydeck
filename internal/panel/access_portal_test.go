package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestProtectedAdminEntry(t *testing.T) {
	s := testStore(t)
	h := HTTPS{Domain: "panel.example.com", Mode: "auto", AdminPort: 38443, AdminPath: randomToken(24)}
	s.Update(func(s *State) error { s.Settings.HTTPS = h; return nil })
	a := New(s, "https://panel.example.com", s.dir, false, fstest.MapFS{"index.html": {Data: []byte("panel-ui")}})
	entry := a.AdminURL(h)
	for _, url := range []string{"https://panel.example.com/", "https://panel.example.com/api/session", "https://panel.example.com:38443/", "https://panel.example.com:38443/api/session", "https://panel.example.com/" + h.AdminPath + "/api/session", "https://panel.example.com:38443/wrong/api/session", "https://panel.example.com:38443/" + h.AdminPath + "//api/session", "https://panel.example.com:38443/" + h.AdminPath + "/%2fapi/session"} {
		if w := request(t, a, "GET", url, nil, nil, "", ""); w.Code != 404 {
			t.Fatalf("unprotected request returned %d", w.Code)
		}
	}
	w := request(t, a, "POST", entry+"api/setup", map[string]string{"token": s.Read().SetupToken, "username": "admin", "password": "correct-test-password"}, nil, "", "https://panel.example.com:38443")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if cookie.Path != "/"+h.AdminPath+"/" || !cookie.Secure || !cookie.HttpOnly {
		t.Fatal("admin cookie scope")
	}
	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	if w = request(t, a, "GET", entry+"api/state", nil, cookie, "", ""); w.Code != 200 {
		t.Fatal("correct entry rejected")
	}
	if w = request(t, a, "POST", entry+"api/logout", nil, cookie, result["csrf"], "https://panel.example.com"); w.Code != 403 {
		t.Fatal("public origin accepted admin mutation")
	}
	if w = request(t, a, "POST", entry+"api/logout", nil, cookie, result["csrf"], "https://panel.example.com:38443"); w.Code != 200 {
		t.Fatal("protected admin origin rejected")
	}
}

func TestAccessBootstrapStableAndPendingHTTPSPreserved(t *testing.T) {
	s := testStore(t)
	a := New(s, "https://panel.example.com", s.dir, false, nil)
	if e := a.BootstrapHTTPS(); e != nil {
		t.Fatal(e)
	}
	if e := a.ConfigureAccess(0, false); e != nil {
		t.Fatal(e)
	}
	first := s.Read().Settings.HTTPS
	b, _ := os.ReadFile(filepath.Join(s.dir, "Caddyfile"))
	s.Update(func(s *State) error { s.Settings.HTTPS.Email = "saved-but-not-loaded@example.com"; return nil })
	if e := a.ConfigureAccess(0, false); e != nil {
		t.Fatal(e)
	}
	second := s.Read().Settings.HTTPS
	after, _ := os.ReadFile(filepath.Join(s.dir, "Caddyfile"))
	if first.AdminPort != second.AdminPort || first.AdminPath != second.AdminPath || !bytes.Equal(b, after) {
		t.Fatal("restart changed entry or applied pending HTTPS settings")
	}
	info, _ := os.Stat(filepath.Join(s.dir, "admin-entry.txt"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("entry file is not private")
	}
}

func TestTrafficReportsAreIdempotentAndSurviveCenterRestore(t *testing.T) {
	s := fixture()
	now := time.Now().UTC()
	r := &TrafficReport{Stream: randomToken(24), Since: now.Add(-time.Hour), Observed: now, Users: map[string]TrafficCounter{"user_alice": {Upload: 100, Download: 200}}}
	v := &s.Servers[0]
	for i := 0; i < 3; i++ {
		if e := ingestTraffic(&s, v, r); e != nil {
			t.Fatal(e)
		}
	}
	if s.Users[0].Used != 300 || s.Users[1].Used != 0 {
		t.Fatal("duplicate report or cross-user usage")
	}
	backup := cloneState(s)
	r.Users["user_alice"] = TrafficCounter{Upload: 150, Download: 250}
	if e := ingestTraffic(&s, v, r); e != nil {
		t.Fatal(e)
	}
	if e := ingestTraffic(&backup, &backup.Servers[0], r); e != nil {
		t.Fatal(e)
	}
	if backup.Users[0].Used != 400 || s.Users[0].Used != 400 {
		t.Fatal("restored center did not catch up by delta")
	}
	r.Users["user_alice"] = TrafficCounter{Upload: 10, Download: 20}
	ingestTraffic(&s, v, r)
	if s.Users[0].Used != 400 {
		t.Fatal("older report reduced or repeated usage")
	}
	r.Stream = randomToken(24)
	ingestTraffic(&s, v, r)
	if s.Users[0].Used != 430 {
		t.Fatal("new agent ledger did not add its own deltas")
	}
	r.Users["user_alice"] = TrafficCounter{Upload: -1}
	if ingestTraffic(&s, v, r) == nil {
		t.Fatal("negative bytes accepted")
	}
}

func TestPersonalPortalIsolationAndClientNegotiation(t *testing.T) {
	s := testStore(t)
	f := fixture()
	f.Users[0].Name = "<script>alert(1)</script>"
	s.Update(func(s *State) error { *s = f; return nil })
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	url := "/s/" + f.Users[0].Token
	w := request(t, a, "GET", url, nil, nil, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "暂无数据") || strings.Contains(w.Body.String(), "<script>alert") || strings.Contains(w.Body.String(), f.Users[1].Name) || strings.Contains(w.Body.String(), f.Users[1].Token) {
		t.Fatal("portal missing unknown state or leaks another user")
	}
	for _, secret := range []string{f.Nodes[0].PrivateKey, f.Nodes[1].ServerKey, f.Users[0].Credentials[f.Nodes[0].ID], f.Servers[0].AgentToken} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("portal exposed node or administrator credentials")
		}
	}
	s.Update(func(s *State) error {
		u := &s.Users[0]
		u.Upload = 1024
		u.Download = 2048
		u.Used = 3072
		u.UsageSince = time.Now().Add(-time.Hour)
		u.UsageUpdated = time.Now()
		return nil
	})
	w = request(t, a, "GET", url+"?format=clash", nil, nil, "", "")
	if w.Code != 200 || w.Header().Get("Subscription-Userinfo") != "upload=1024; download=2048; total=0" || !strings.Contains(w.Body.String(), "reality-opts") {
		t.Fatal("client subscription or verified usage header missing")
	}
	s.Update(func(s *State) error { s.Users[0].Enabled = false; return nil })
	w = request(t, a, "GET", url, nil, nil, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "已停用") || !strings.Contains(w.Body.String(), "3.00 KiB") || strings.Contains(w.Body.String(), ">下载 Clash") {
		t.Fatal("disabled friend cannot inspect own usage or can import")
	}
	if w = request(t, a, "GET", url+"?format=clash", nil, nil, "", ""); w.Code != 403 {
		t.Fatal("disabled subscription exported")
	}
	if w = request(t, a, "GET", "/s/"+randomToken(32), nil, nil, "", ""); w.Code != http.StatusNotFound {
		t.Fatal("unknown token accepted")
	}
}
