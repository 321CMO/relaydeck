package panel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, e := OpenStore(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func fixture() State {
	s := initial()
	s.Servers = []Server{{ID: "srv_a", Name: "入口", Address: "entry.example.com", PrivateIP: "10.0.0.1", BackhaulKey: ssKey(), AgentToken: randomToken(32), Desired: 3, Applied: 3}, {ID: "srv_b", Name: "落地", Address: "exit.example.com", PrivateIP: "10.0.0.2", BackhaulKey: ssKey(), AgentToken: randomToken(32), Desired: 3, Applied: 3}}
	private, public, _ := realityKeys()
	s.Nodes = []Node{{ID: "node_reality123", Name: "Reality", ServerID: "srv_a", Address: "entry.example.com", Port: 443, Protocol: "reality", Enabled: true, SNI: "www.microsoft.com", Target: "www.microsoft.com:443", PrivateKey: private, PublicKey: public, ShortID: "01234567", RequiredRevision: 3}, {ID: "node_ss2022123", Name: "SS", ServerID: "srv_b", Address: "exit.example.com", Port: 20838, Protocol: "ss2022", Enabled: true, ServerKey: ssKey(), RequiredRevision: 3}}
	s.Users = []User{{ID: "user_alice", Name: "Alice", Enabled: true, Token: randomToken(32), NodeIDs: []string{s.Nodes[0].ID, s.Nodes[1].ID}, Credentials: map[string]string{s.Nodes[0].ID: uuid(), s.Nodes[1].ID: ssKey()}, Required: map[string]int64{"srv_a": 3, "srv_b": 3}}, {ID: "user_bob", Name: "Bob", Enabled: true, Token: randomToken(32), NodeIDs: []string{s.Nodes[1].ID}, Credentials: map[string]string{s.Nodes[1].ID: ssKey()}, Required: map[string]int64{"srv_b": 3}}}
	return s
}
func cert(t *testing.T, domain string) (string, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	key, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
}
func request(t *testing.T, a *App, method, path string, input any, cookie *http.Cookie, csrf, origin string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(input)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	if cookie != nil {
		r.AddCookie(cookie)
	}
	r.Header.Set("X-CSRF-Token", csrf)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}
func loginTest(t *testing.T, a *App) (*http.Cookie, string) {
	t.Helper()
	s := a.Store.Read()
	w := request(t, a, "POST", "/api/setup", map[string]string{"token": s.SetupToken, "username": "admin", "password": "correct-test-password"}, nil, "", "http://127.0.0.1:8787")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var out map[string]string
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Result().Cookies()[0], out["csrf"]
}

func TestStoreEncryptionRollbackAndLock(t *testing.T) {
	dir := t.TempDir()
	s, e := OpenStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	secret := "persisted-secret-not-plaintext"
	if e = s.Update(func(s *State) error { s.Settings.Telegram.Token = secret; return nil }); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenStore(dir); e == nil {
		t.Fatal("two centers opened the same database")
	}
	if e = s.Update(func(s *State) error { s.Settings.Telegram.Token = "bad"; return errors.New("rollback") }); e == nil {
		t.Fatal("expected rejected mutation")
	}
	if s.Read().Settings.Telegram.Token != secret {
		t.Fatal("memory changed despite rejected mutation")
	}
	s.Close()
	b, _ := os.ReadFile(filepath.Join(dir, "relaydeck.db"))
	if bytes.Contains(b, []byte(secret)) {
		t.Fatal("plaintext secret in SQLite")
	}
	s, e = OpenStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	if s.Read().Settings.Telegram.Token != secret {
		t.Fatal("persistence lost")
	}
	s.Close()
	os.Remove(filepath.Join(dir, "master.key"))
	if _, e = OpenStore(dir); e == nil {
		t.Fatal("missing master key must refuse startup")
	}
	if _, e = os.Stat(filepath.Join(dir, "master.key")); !os.IsNotExist(e) {
		t.Fatal("missing key was silently replaced")
	}
}
func TestPortableBackup(t *testing.T) {
	s := testStore(t)
	s.Update(func(s *State) error {
		*s = fixture()
		s.PasswordHash = hashPassword("correct-test-password")
		return nil
	})
	b, e := s.Export("independent-backup-password")
	if e != nil {
		t.Fatal(e)
	}
	other := testStore(t)
	if e = other.Import(b, "wrong"); e == nil {
		t.Fatal("wrong backup password accepted")
	}
	if e = other.Import(b, "independent-backup-password"); e != nil {
		t.Fatal(e)
	}
	if other.Read().Users[0].Token != s.Read().Users[0].Token {
		t.Fatal("backup did not preserve subscriptions")
	}
	b[len(b)-1] ^= 1
	if e = other.Import(b, "independent-backup-password"); e == nil {
		t.Fatal("tampered backup accepted")
	}
}
func TestAuthenticationSetupOriginAndCSRF(t *testing.T) {
	s := testStore(t)
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe session cookie")
	}
	if w := request(t, a, "GET", "/api/state", nil, nil, "", ""); w.Code != 401 {
		t.Fatal("anonymous state access")
	}
	input := map[string]string{"name": "server", "address": "example.com"}
	for _, v := range []struct{ csrf, origin string }{{"", ""}, {csrf, "https://evil.example"}} {
		if w := request(t, a, "POST", "/api/servers", input, cookie, v.csrf, v.origin); w.Code != 403 {
			t.Fatal("CSRF bypass", w.Code)
		}
	}
	if w := request(t, a, "POST", "/api/servers", input, cookie, csrf, "http://127.0.0.1:8787"); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := request(t, a, "POST", "/api/setup", map[string]string{"token": s.Read().SetupToken, "username": "another", "password": "correct-test-password"}, nil, "", ""); w.Code != 403 {
		t.Fatal("setup replay accepted")
	}
	if w := request(t, a, "GET", "/api/servers", nil, cookie, "", ""); w.Code != 405 {
		t.Fatal("GET mutation accepted")
	}
	request(t, a, "POST", "/api/logout", map[string]string{}, cookie, csrf, "")
	if w := request(t, a, "GET", "/api/state", nil, cookie, "", ""); w.Code != 401 {
		t.Fatal("logout did not revoke session")
	}
}
func TestCredentialIsolationAndPublicationGate(t *testing.T) {
	s := fixture()
	u, nodes, e := subscriptionNodes(s, s.Users[1].Token)
	if e != nil || len(nodes) != 1 || nodes[0].ID != s.Nodes[1].ID {
		t.Fatal("unauthorized nodes exposed")
	}
	b, e := clashConfig(s, u, nodes)
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{s.Users[0].Credentials[s.Nodes[1].ID], s.Servers[0].AgentToken, s.Servers[1].BackhaulKey, s.Nodes[0].PrivateKey} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("unrelated or internal secret in subscription")
		}
	}
	if !bytes.Contains(b, []byte(u.Credentials[s.Nodes[1].ID])) {
		t.Fatal("own credential omitted")
	}
	s.Servers[1].Applied = 2
	_, nodes, e = subscriptionNodes(s, u.Token)
	if e != nil || len(nodes) != 0 {
		t.Fatal("unapplied authorization exposed")
	}
	s.Users[1].Expires = time.Now().Add(-time.Minute).Format(time.RFC3339)
	if _, _, e = subscriptionNodes(s, u.Token); e == nil {
		t.Fatal("expired subscription served")
	}
}
func TestCompileRealityBackhaulAndConflict(t *testing.T) {
	s := fixture()
	s.Nodes[0].ExitID = "srv_b"
	d, e := Compile(s, "srv_a", "/var/lib/relaydeck/agent")
	if e != nil {
		t.Fatal(e)
	}
	var cfg map[string]any
	json.Unmarshal(d.Config, &cfg)
	if !bytes.Contains(d.Config, []byte("10.0.0.2")) || bytes.Contains(d.Config, []byte("exit.example.com")) {
		t.Fatal("backhaul must use private address")
	}
	route := cfg["route"].(map[string]any)
	rules := route["rules"].([]any)
	if rules[0].(map[string]any)["outbound"] != "via_srv_b" {
		t.Fatal("entry does not use exit")
	}
	d, e = Compile(s, "srv_b", "/var/lib/relaydeck/agent")
	if e != nil || len(d.BackhaulSources) != 1 || d.BackhaulSources[0] != "10.0.0.1" {
		t.Fatal("landing source guard missing")
	}
	if !bytes.Contains(d.Config, []byte("internal-backhaul")) {
		t.Fatal("internal listener missing")
	}
	s.Nodes[1].ExitID = "srv_a"
	if e = validateNode(&s, s.Nodes[1]); e == nil {
		t.Fatal("cycle accepted")
	}
	s = fixture()
	n := s.Nodes[0]
	n.ID = "new"
	if e = validateNode(&s, n); e == nil {
		t.Fatal("port collision accepted")
	}
	n.Protocol = "hy2"
	n.SNI = "hy.example.com"
	n.TLSMode = "auto"
	n.HopStart = 20000
	n.HopEnd = 20100
	n.HopInterval = 30
	if e = validateNode(&s, n); e != nil {
		t.Fatal("TCP and UDP 443 should coexist", e)
	}
	s.Nodes[1].ServerID = "srv_a"
	s.Nodes[1].Port = 20050
	if e = validateNode(&s, n); e == nil {
		t.Fatal("SS UDP overlap accepted")
	}
	n.Target = "www.microsoft.com:evil"
	n.Protocol = "reality"
	if e = validateNode(&s, n); e == nil {
		t.Fatal("non-numeric reality port accepted")
	}
}
func TestPublicStateRedactsSecrets(t *testing.T) {
	s := fixture()
	s.PasswordHash = "hash-secret"
	s.Settings.Telegram.Token = "tg-secret"
	s.Settings.HTTPS.CloudflareToken = "cf-secret"
	b, _ := json.Marshal(publicState(cloneState(s)))
	for _, secret := range []string{s.SetupToken, s.PasswordHash, s.Settings.Telegram.Token, s.Settings.HTTPS.CloudflareToken, s.Users[0].Token, s.Nodes[0].PrivateKey, s.Nodes[1].ServerKey, s.Servers[0].AgentToken, s.Servers[0].BackhaulKey} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("public state leaked secret")
		}
	}
}
func TestHTTPSValidationAndPendingStatus(t *testing.T) {
	crt, key := cert(t, "panel.example.com")
	h := HTTPS{Domain: "panel.example.com", Mode: "import", Certificate: crt, Key: key}
	if _, e := Caddyfile(h, "127.0.0.1:8787", "/var/lib/relaydeck/panel"); e != nil {
		t.Fatal(e)
	}
	h.SubscriptionDomain = "sub.example.com"
	if _, e := Caddyfile(h, "127.0.0.1:8787", "/var/lib/relaydeck/panel"); e == nil {
		t.Fatal("certificate missing subscription SAN accepted")
	}
	h.Mode = "auto"
	h.Domain = "example.com\n evil"
	if _, e := Caddyfile(h, "127.0.0.1:8787", "/tmp"); e == nil {
		t.Fatal("Caddyfile injection accepted")
	}
	if _, e := parseCertificate(crt, key, "other.example.com"); e == nil {
		t.Fatal("wrong hostname accepted")
	}
}
func TestEnrollmentBoundToMachineAndReplay(t *testing.T) {
	s := testStore(t)
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	code := randomToken(24)
	s.Update(func(s *State) error {
		s.Servers = []Server{{ID: "srv_test", AgentToken: randomToken(32), EnrollmentHash: digest(code), EnrollmentExpires: time.Now().Add(time.Minute)}}
		return nil
	})
	in := map[string]string{"serverId": "srv_test", "code": code, "machineId": "machine-one"}
	first := request(t, a, "POST", "/api/agent/enroll", in, nil, "", "")
	if first.Code != 200 {
		t.Fatal(first.Body.String())
	}
	if w := request(t, a, "POST", "/api/agent/enroll", in, nil, "", ""); w.Code != 200 || w.Body.String() != first.Body.String() {
		t.Fatal("lost-response retry changed identity")
	}
	in["machineId"] = "machine-two"
	if w := request(t, a, "POST", "/api/agent/enroll", in, nil, "", ""); w.Code != 403 {
		t.Fatal("registration code reused across machines")
	}
}

func TestRegistrationRenewalInvalidatesOldCodeAndProtectsBoundIdentity(t *testing.T) {
	s := testStore(t)
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	oldCode := randomToken(24)
	token := randomToken(32)
	s.Update(func(s *State) error {
		s.Servers = []Server{{ID: "srv_test", AgentToken: token, Desired: 7, EnrollmentHash: digest(oldCode), EnrollmentExpires: time.Now().Add(-time.Minute)}}
		return nil
	})
	path := "/api/servers/srv_test/registration"
	for _, credentials := range []struct {
		cookie *http.Cookie
		csrf   string
	}{{nil, ""}, {cookie, "wrong-csrf"}} {
		if w := request(t, a, "POST", path, nil, credentials.cookie, credentials.csrf, "http://127.0.0.1:8787"); w.Code < 400 {
			t.Fatal("registration renewal bypassed administrator authentication or CSRF")
		}
	}
	w := request(t, a, "POST", path, nil, cookie, csrf, "http://127.0.0.1:8787")
	var renewal struct {
		Code    string    `json:"registrationCode"`
		Expires time.Time `json:"expires"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &renewal); e != nil || w.Code != 200 || renewal.Code == "" || renewal.Code == oldCode || time.Until(renewal.Expires) < 9*time.Minute {
		t.Fatal("valid installation code not renewed")
	}
	if v := s.Read().Servers[0]; v.AgentToken != token || v.Desired != 7 {
		t.Fatal("renewal changed server identity or node configuration")
	}
	// Even an otherwise unexpired old code must no longer register the server.
	in := map[string]string{"serverId": "srv_test", "code": oldCode, "machineId": "machine-one"}
	if w := request(t, a, "POST", "/api/agent/enroll", in, nil, "", ""); w.Code != 403 {
		t.Fatal("old installation code remained valid")
	}
	in["code"] = renewal.Code
	if w := request(t, a, "POST", "/api/agent/enroll", in, nil, "", ""); w.Code != 200 {
		t.Fatal("new installation code cannot register server")
	}
	if v := publicState(s.Read()).Servers[0]; !v.Enrolled || v.MachineID != "" || v.AgentToken != "" {
		t.Fatal("public enrollment state missing or exposes private identity")
	}
	if w := request(t, a, "POST", path, nil, cookie, csrf, "http://127.0.0.1:8787"); w.Code != 422 {
		t.Fatal("bound identity allowed another installation code")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestTelegramNoTokenLeakAndRetryAfter(t *testing.T) {
	s := testStore(t)
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	a.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		payload := `{"ok":false,"error_code":429,"description":"sensitive-token","parameters":{"retry_after":23}}`
		code := 429
		if strings.HasSuffix(r.URL.Path, "getMe") {
			payload = `{"ok":true,"result":{"is_bot":true,"username":"test_bot"}}`
			code = 200
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(payload)), Header: http.Header{}}, nil
	})}
	tg := Telegram{Token: "12345:sensitive-token", ChatID: "123"}
	if _, e := a.telegramCall(context.Background(), tg.Token, "getMe", url.Values{}); e != nil {
		t.Fatal(e)
	}
	e := a.sendTelegram(context.Background(), tg, "test")
	te, ok := e.(telegramError)
	if !ok || te.retry != 23 {
		t.Fatal("retry_after lost")
	}
	if strings.Contains(e.Error(), "sensitive-token") {
		t.Fatal("token leaked in Telegram error")
	}
	state := initial()
	state.Settings.Telegram.Enabled = true
	enqueueNotification(&state, "failure", "first")
	enqueueNotification(&state, "failure", "duplicate")
	if len(state.Notifications) != 1 {
		t.Fatal("duplicate pending alerts")
	}
}

func TestWriteDeploymentRejectsTraversal(t *testing.T) {
	for _, p := range []string{"../../escape", "/tmp/escape"} {
		if e := WriteDeployment(Deployment{Files: map[string]string{p: "bad"}}, t.TempDir()); e == nil {
			t.Fatal("path traversal accepted")
		}
	}
}
func TestSubscriptionHTTPFormatsAndEmptyGate(t *testing.T) {
	store := testStore(t)
	s := fixture()
	store.Update(func(st *State) error { *st = s; return nil })
	a := New(store, "http://127.0.0.1:8787", store.dir, true, nil)
	p := "/s/" + s.Users[0].Token
	w := request(t, a, "GET", p+"?format=shadowrocket", nil, nil, "", "")
	b, e := base64.StdEncoding.DecodeString(w.Body.String())
	if w.Code != 200 || e != nil || !strings.Contains(string(b), "vless://") {
		t.Fatal("invalid URI subscription")
	}
	w = request(t, a, "GET", p+"?format=clash", nil, nil, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "proxy-groups:") {
		t.Fatal("full Clash configuration missing")
	}
	store.Update(func(s *State) error {
		for i := range s.Servers {
			s.Servers[i].Applied = 0
		}
		return nil
	})
	w = request(t, a, "GET", p+"?format=clash", nil, nil, "", "")
	if w.Code != 503 || w.Header().Get("Retry-After") == "" {
		t.Fatal("empty subscription became a silent direct configuration")
	}
}
func TestHTTPSActualInstanceAndLoadedConfigurationGate(t *testing.T) {
	s := testStore(t)
	a := New(s, "https://panel.example.com", s.dir, false, nil)
	h := HTTPS{Domain: "panel.example.com", SubscriptionDomain: "sub.example.com", Mode: "auto", Status: "pending"}
	s.Update(func(s *State) error { s.Settings.HTTPS = h; return nil })
	a.ProbeTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"instance":"` + a.Instance + `"}`)), TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{NotAfter: time.Now().Add(30 * 24 * time.Hour)}}}}, nil
	})
	a.checkHTTPS(context.Background())
	if s.Read().Settings.HTTPS.Status != "pending" {
		t.Fatal("unloaded settings marked active")
	}
	if a.subscriptionBase(s.Read()) != a.BaseURL {
		t.Fatal("unverified subscription domain was published")
	}
	s.Update(func(s *State) error { s.Settings.HTTPS.LoadedHash = httpsFingerprint(s.Settings.HTTPS); return nil })
	a.checkHTTPS(context.Background())
	if s.Read().Settings.HTTPS.Status != "active" {
		t.Fatal("matching loaded instance not verified")
	}
	if a.subscriptionBase(s.Read()) != "https://sub.example.com" {
		t.Fatal("verified subscription domain not used for delivery")
	}
	a.ProbeTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) { return nil, errors.New("unavailable") })
	a.checkHTTPS(context.Background())
	if s.Read().Settings.HTTPS.Status == "active" {
		t.Fatal("lost HTTPS probe left stale active status")
	}
	if a.subscriptionBase(s.Read()) != "https://sub.example.com" {
		t.Fatal("transient probe failure changed an already published subscription address")
	}
}

func TestPublishedSubscriptionDeliveryAndSettingsProtection(t *testing.T) {
	s := testStore(t)
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	s.Update(func(s *State) error {
		f := fixture()
		s.Users, s.Nodes, s.Servers = f.Users, f.Nodes, f.Servers
		s.Settings.HTTPS = HTTPS{Domain: "panel.example.com", SubscriptionDomain: "sub.example.com", PublishedDomain: "sub.example.com", Mode: "auto", Status: "pending"}
		return nil
	})
	u := s.Read().Users[0]
	for _, path := range []string{"/api/users/" + u.ID + "/delivery", "/delivery/" + u.Token} {
		w := request(t, a, "GET", path, nil, cookie, csrf, "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), "https://sub.example.com/s/"+u.Token) || strings.Contains(w.Body.String(), a.BaseURL+"/s/") {
			t.Fatal("delivery contains wrong subscription origin")
		}
	}
	settings := s.Read().Settings
	settings.HTTPS.PublishedDomain = "forged.example.com"
	w := request(t, a, "POST", "/api/settings", settings, cookie, csrf, "http://127.0.0.1:8787")
	if w.Code != 200 || s.Read().Settings.HTTPS.PublishedDomain != "sub.example.com" {
		t.Fatal("client could forge the published subscription domain")
	}
	settings.HTTPS.SubscriptionDomain = ""
	w = request(t, a, "POST", "/api/settings", settings, cookie, csrf, "http://127.0.0.1:8787")
	if w.Code != 422 || a.subscriptionBase(s.Read()) != "https://sub.example.com" {
		t.Fatal("settings silently removed an already published subscription domain")
	}
}

func TestInstallerHTTPSBootstrapPreservesSavedSettings(t *testing.T) {
	s := testStore(t)
	a := New(s, "https://panel.example.com", s.dir, false, nil)
	if e := a.BootstrapHTTPS(); e != nil {
		t.Fatal(e)
	}
	h := s.Read().Settings.HTTPS
	if h.Domain != "panel.example.com" || h.Status != "pending" || h.LoadedHash != httpsFingerprint(h) {
		t.Fatal("installer HTTPS configuration missing or prematurely verified")
	}
	s.Update(func(s *State) error {
		s.Settings.HTTPS.Mode = "dns"
		s.Settings.HTTPS.CloudflareToken = "existing-token"
		return nil
	})
	if e := a.BootstrapHTTPS(); e != nil {
		t.Fatal(e)
	}
	if h := s.Read().Settings.HTTPS; h.Mode != "dns" || h.CloudflareToken != "existing-token" {
		t.Fatal("installation retry overwrote saved HTTPS settings")
	}
}

func TestHTTPSFailedReloadPreservesPreviousCertificatesAndConfiguration(t *testing.T) {
	s := testStore(t)
	a := New(s, "https://panel.example.com", s.dir, false, nil)
	a.ProbeTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("test has no public TLS endpoint")
	})
	oldCert, oldKey := cert(t, "panel.example.com")
	old := HTTPS{Domain: "panel.example.com", Mode: "import", Certificate: oldCert, Key: oldKey, Status: "active"}
	if e := stageHTTPSAssets(old, s.dir); e != nil {
		t.Fatal(e)
	}
	previousConfig, _ := Caddyfile(old, "127.0.0.1:8787", s.dir)
	configPath := filepath.Join(s.dir, "Caddyfile")
	if e := os.WriteFile(configPath, []byte(previousConfig), 0600); e != nil {
		t.Fatal(e)
	}
	newCert, newKey := cert(t, "panel.example.com")
	next := HTTPS{Domain: old.Domain, Mode: "import", Certificate: newCert, Key: newKey, LoadedHash: httpsFingerprint(old), Status: "pending"}
	s.Update(func(s *State) error { s.Settings.HTTPS = next; return nil })
	a.Caddy = filepath.Join(t.TempDir(), "caddy")
	for _, failedStep := range []string{"validate", "reload"} {
		t.Run(failedStep, func(t *testing.T) {
			script := "#!/bin/sh\nif [ \"$1\" = \"" + failedStep + "\" ]; then exit 1; fi\nexit 0\n"
			if e := os.WriteFile(a.Caddy, []byte(script), 0700); e != nil {
				t.Fatal(e)
			}
			if e := a.ApplyHTTPS(context.Background()); e == nil {
				t.Fatal("failed Caddy operation reported success")
			}
			for name, expected := range map[string]string{"panel.crt": oldCert, "panel.key": oldKey} {
				b, e := os.ReadFile(filepath.Join(httpsAssetsDir(old, s.dir), name))
				if e != nil || string(b) != expected {
					t.Fatal("failed reload modified the previously active certificate pair")
				}
			}
			b, _ := os.ReadFile(configPath)
			if string(b) != previousConfig || s.Read().Settings.HTTPS.LoadedHash != httpsFingerprint(old) {
				t.Fatal("failed reload replaced persisted configuration or loaded fingerprint")
			}
		})
	}
	if e := os.WriteFile(a.Caddy, []byte("#!/bin/sh\nexit 0\n"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := a.ApplyHTTPS(context.Background()); e != nil {
		t.Fatal(e)
	}
	config, _ := os.ReadFile(configPath)
	if !strings.Contains(string(config), httpsAssetsDir(next, s.dir)) || strings.Contains(string(config), httpsAssetsDir(old, s.dir)) || s.Read().Settings.HTTPS.LoadedHash != httpsFingerprint(next) {
		t.Fatal("successful reload failed to persist the new certificate revision")
	}
	if s.Read().Settings.HTTPS.Status == "active" {
		t.Fatal("fake Caddy success bypassed actual public TLS verification")
	}
}

func TestCloudflareSecretIsPrivateAndIndependentOfReloadEnvironment(t *testing.T) {
	dir := t.TempDir()
	h := HTTPS{Domain: "panel.example.com", Mode: "dns", CloudflareToken: "test-cloudflare-token-not-for-real-api"}
	config, e := Caddyfile(h, "127.0.0.1:8787", dir)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(config, h.CloudflareToken) || strings.Contains(config, "{env.") || !strings.Contains(config, "{file.") {
		t.Fatal("Cloudflare credentials leaked or depend on a short-lived reload process environment")
	}
	if e := stageHTTPSAssets(h, dir); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(httpsAssetsDir(h, dir), "cloudflare.token")
	b, e := os.ReadFile(path)
	info, statErr := os.Stat(path)
	if e != nil || statErr != nil || string(b) != h.CloudflareToken || info.Mode().Perm() != 0600 {
		t.Fatal("Cloudflare token not persisted with private permissions")
	}
	h.CloudflareToken = "replacement-cloudflare-token"
	if e := stageHTTPSAssets(h, dir); e != nil {
		t.Fatal(e)
	}
	if b, _ := os.ReadFile(path); string(b) != "test-cloudflare-token-not-for-real-api" {
		t.Fatal("token replacement overwrote the active configuration's credential")
	}
}
