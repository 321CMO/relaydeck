package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func mutationRequest(t *testing.T, a *App, path, key string, input any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(input)
	r := httptest.NewRequest("POST", path, bytes.NewReader(b))
	r.AddCookie(cookie)
	r.Header.Set("Origin", "http://127.0.0.1:8787")
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}

func TestCreationReceiptsDurableAtomicAndPrivate(t *testing.T) {
	s := testStore(t)
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	in := map[string]string{"name": "create-once", "address": "entry.example.com"}
	key := "same-browser-operation-2026"
	first := mutationRequest(t, a, "/api/servers", key, in, cookie, csrf)
	if first.Code != 200 {
		t.Fatal(first.Body.String())
	}
	var result map[string]any
	json.Unmarshal(first.Body.Bytes(), &result)
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			w := mutationRequest(t, a, "/api/servers", key, in, cookie, csrf)
			if w.Code != 200 || w.Body.String() != first.Body.String() {
				t.Error("concurrent replay changed response")
			}
		})
	}
	wg.Wait()
	if len(s.Read().Servers) != 1 || len(s.Read().Mutations) != 1 || s.Read().Schema != 6 {
		t.Fatal("create was duplicated or receipt not persisted")
	}
	in["name"] = "different"
	if mutationRequest(t, a, "/api/servers", key, in, cookie, csrf).Code != 422 {
		t.Fatal("same key accepted different contents")
	}
	in["name"] = "create-once"
	w := request(t, a, "GET", "/api/state", nil, cookie, "", "")
	if strings.Contains(w.Body.String(), result["registrationCode"].(string)) || strings.Contains(w.Body.String(), "mutations") {
		t.Fatal("receipt secrets leaked")
	}
	dir := s.dir
	s.Close()
	next, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	a = New(next, "http://127.0.0.1:8787", dir, true, nil)
	w = request(t, a, "POST", "/api/login", map[string]string{"username": "admin", "password": "correct-test-password"}, nil, "", "http://127.0.0.1:8787")
	var login map[string]string
	json.Unmarshal(w.Body.Bytes(), &login)
	cookie = w.Result().Cookies()[0]
	w = mutationRequest(t, a, "/api/servers", key, in, cookie, login["csrf"])
	if w.Code != 200 || w.Body.String() != first.Body.String() || len(next.Read().Servers) != 1 {
		t.Fatal("restart lost durable replay")
	}
	backup, err := next.Export("backup-test-password")
	if err != nil {
		t.Fatal(err)
	}
	restored := testStore(t)
	if err := restored.Import(backup, "backup-test-password"); err != nil || restored.Read().Schema != 6 {
		t.Fatal("schema 6 backup not preserved", err)
	}
}

func TestSettingsSectionConflictsAndIndependentFields(t *testing.T) {
	s := testStore(t)
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	versions := settingsVersions(s.Read().Settings)
	post := func(section, version string, value any) *httptest.ResponseRecorder {
		return request(t, a, "POST", "/api/settings/section", map[string]any{"section": section, "version": version, "value": value}, cookie, csrf, "")
	}
	if w := post("routing", versions["routing"], map[string]string{"routingPreset": "proxy-all"}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	h := s.Read().Settings.HTTPS
	h.Email = "admin@example.com"
	if w := post("https", versions["https"], h); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if s.Read().Settings.RoutingPreset != "proxy-all" {
		t.Fatal("unrelated setting overwritten")
	}
	h.Email = "stale@example.com"
	if w := post("https", versions["https"], h); w.Code != 409 || s.Read().Settings.HTTPS.Email != "admin@example.com" {
		t.Fatal("stale update accepted")
	}
	v := settingsVersion(s.Read().Settings, "https")
	s.Update(func(s *State) error {
		s.Settings.HTTPS.Status = "failed"
		s.Settings.HTTPS.Expires = "2030-01-01"
		return nil
	})
	if settingsVersion(s.Read().Settings, "https") != v {
		t.Fatal("operational status produced false edit conflict")
	}
	crt, key := cert(t, "panel.example.com")
	_, wrong := cert(t, "panel.example.com")
	s.Update(func(s *State) error {
		s.Settings.HTTPS = HTTPS{Domain: "panel.example.com", Mode: "import", Certificate: crt, Key: key}
		return nil
	})
	h = s.Read().Settings.HTTPS
	h.Certificate = ""
	h.Key = wrong
	if w := post("https", settingsVersion(s.Read().Settings, "https"), h); w.Code != 422 || s.Read().Settings.HTTPS.Key != key {
		t.Fatal("private-key-only input silently ignored")
	}
}

func TestImportPreviewBoundToContentsAndTarget(t *testing.T) {
	s := testStore(t)
	s.Update(func(s *State) error { *s = fixture(); return nil })
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	text := "socks5://127.0.0.1:11080#Previewed"
	w := request(t, a, "POST", "/api/outbounds/import", map[string]any{"serverId": "srv_a", "text": text, "preview": true}, cookie, csrf, "")
	var p map[string]any
	json.Unmarshal(w.Body.Bytes(), &p)
	for _, input := range []map[string]any{{"serverId": "srv_b", "text": text}, {"serverId": "srv_a", "text": "socks5://127.0.0.1:11081#NotPreviewed"}} {
		input["snapshot"] = p["snapshot"]
		input["indices"] = []int{1}
		input["mode"] = "new"
		w = request(t, a, "POST", "/api/outbounds/import", input, cookie, csrf, "")
		if w.Code != 422 || len(s.Read().Outbounds) != 0 {
			t.Fatal("unpreviewed source or target was committed")
		}
	}
}

func TestDiagnosticsAndDeliveryReadiness(t *testing.T) {
	s := fixture()
	s.Tasks = []Task{{ID: "failed", Error: "token=" + s.Servers[0].AgentToken + " private_key=" + s.Nodes[0].PrivateKey + " uuid=" + s.Users[0].Credentials[s.Nodes[0].ID]}}
	public := publicState(cloneState(s))
	b, _ := json.Marshal(public)
	for _, secret := range []string{s.Servers[0].AgentToken, s.Nodes[0].PrivateKey, s.Users[0].Credentials[s.Nodes[0].ID]} {
		if strings.Contains(string(b), secret) {
			t.Fatal("diagnostics leaked secret")
		}
	}
	if deliveryReadiness(s, s.Users[0])["ready"].(int) != 2 {
		t.Fatal("ready count incorrect")
	}
	s.Nodes[0].Enabled = false
	if deliveryReadiness(s, s.Users[0])["ready"].(int) != 1 {
		t.Fatal("disabled node counted ready")
	}
	s.Users[0].Enabled = false
	if deliveryReadiness(s, s.Users[0])["ready"].(int) != 0 {
		t.Fatal("disabled user counted ready")
	}
	s = fixture()
	s.Nodes[1].Network = "tcp"
	yaml, err := clashConfig(s, s.Users[0], s.Nodes)
	if err != nil || !bytes.Contains(yaml, []byte("udp: false")) {
		t.Fatal("TCP-only SS advertised UDP")
	}
}

func TestEightCharacterPasswordSetupChangeAndReset(t *testing.T) {
	s := testStore(t)
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	w := request(t, a, "POST", "/api/setup", map[string]string{"token": s.Read().SetupToken, "username": "admin", "password": "12345678"}, nil, "", "http://127.0.0.1:8787")
	if w.Code != 200 {
		t.Fatal("8-character setup rejected", w.Body.String())
	}
	var auth map[string]string
	json.Unmarshal(w.Body.Bytes(), &auth)
	cookie := w.Result().Cookies()[0]
	for _, tc := range []struct {
		password string
		want     int
	}{{"1234567", 422}, {"abcdefgh", 200}} {
		password, want := tc.password, tc.want
		w = request(t, a, "POST", "/api/account/password", map[string]string{"currentPassword": "12345678", "newPassword": password, "confirmPassword": password}, cookie, auth["csrf"], "http://127.0.0.1:8787")
		if w.Code != want {
			t.Fatalf("password length validation: %d", w.Code)
		}
	}
	if err := a.ResetPassword("1234567"); err == nil {
		t.Fatal("short CLI reset accepted")
	}
	if err := a.ResetPassword("87654321"); err != nil {
		t.Fatal("8-character CLI reset rejected", err)
	}
	w = request(t, a, "POST", "/api/login", map[string]string{"username": "admin", "password": "87654321"}, nil, "", "http://127.0.0.1:8787")
	if w.Code != 200 {
		t.Fatal("8-character password login failed")
	}
}
