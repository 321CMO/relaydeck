package panel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoginProxySourceIsolation(t *testing.T) {
	s := testStore(t)
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	loginTest(t, a)
	h := HTTPS{Domain: "panel.example.com", Mode: "auto", AdminPort: 38443, AdminPath: "security-entry"}
	if err := s.Update(func(s *State) error { s.Settings.HTTPS = h; return nil }); err != nil {
		t.Fatal(err)
	}
	a.Development = false
	attempt := func(ip, password string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", a.AdminURL(h)+"api/login", strings.NewReader(fmt.Sprintf(`{"username":"admin","password":%q}`, password)))
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set(clientIPHeader, ip)
		// This untrusted header must not select the failure bucket.
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", len(a.auth.failures)+10))
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		return w
	}
	for i := 0; i < 5; i++ {
		if w := attempt("198.51.100.10", "wrong"); w.Code != 401 {
			t.Fatalf("wrong attempt %d: %d", i, w.Code)
		}
	}
	if w := attempt("198.51.100.10", "correct-test-password"); w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("blocked source escaped")
	}
	if w := attempt("203.0.113.20", "correct-test-password"); w.Code != 200 {
		t.Fatalf("other source locked out: %d %s", w.Code, w.Body.String())
	}
}

func TestLoginSourceTrustBoundary(t *testing.T) {
	a := &App{}
	cases := []struct {
		peer, header, want string
		ok                 bool
	}{
		{"127.0.0.1:1", "198.51.100.10", "198.51.100.10", true},
		{"[::1]:1", "2001:db8::10", "2001:db8::10", true},
		{"[::ffff:127.0.0.1]:1", "::ffff:198.51.100.10", "198.51.100.10", true},
		{"203.0.113.20:1", "198.51.100.10", "203.0.113.20", true},
		{"127.0.0.1:1", "", "", false},
		{"127.0.0.1:1", "198.51.100.10, 203.0.113.20", "", false},
		{"127.0.0.1:1", "0.0.0.0", "", false},
		{"127.0.0.1:1", "fe80::1%eth0", "", false},
		{"invalid", "198.51.100.10", "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/", nil)
		r.RemoteAddr = c.peer
		if c.header != "" {
			r.Header.Set(clientIPHeader, c.header)
		}
		ip, ok := a.loginSource(r)
		if ip != c.want || ok != c.ok {
			t.Fatalf("%+v => %q %v", c, ip, ok)
		}
	}
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header[http.CanonicalHeaderKey(clientIPHeader)] = []string{"198.51.100.10", "203.0.113.20"}
	if _, ok := a.loginSource(r); ok {
		t.Fatal("duplicate identity headers accepted")
	}
}

func TestLoginBusyAndRequestBounds(t *testing.T) {
	s := testStore(t)
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	loginTest(t, a)
	a.auth.credentials.Lock()
	w := request(t, a, "POST", "/api/login", map[string]string{"username": "admin", "password": "correct-test-password"}, nil, "", "")
	a.auth.credentials.Unlock()
	if w.Code != 429 {
		t.Fatal("login queued behind password verification")
	}
	if w = request(t, a, "POST", "/api/login", map[string]string{"username": "admin", "password": strings.Repeat("x", 5000)}, nil, "", ""); w.Code != 400 {
		t.Fatal("oversized login accepted")
	}
	a.auth.failures = make(map[string]failure)
	for i := 0; i < 10000; i++ {
		a.auth.failures[fmt.Sprint(i)] = failure{Until: time.Now().Add(time.Hour), Count: 1}
	}
	if a.auth.loginRetryAfter("another-source") == 0 || len(a.auth.failures) != 10000 {
		t.Fatal("failure cache not bounded")
	}
	a.auth.failures["expired"] = failure{Until: time.Now().Add(-time.Second)}
	a.auth.loginRetryAfter("another-source")
	if _, ok := a.auth.failures["expired"]; ok {
		t.Fatal("expired entries not reclaimed")
	}
}

func TestProxyHeaderMigrationKeepsPendingHTTPS(t *testing.T) {
	s := testStore(t)
	a := New(s, "https://panel.example.com", s.dir, false, nil)
	if err := a.BootstrapHTTPS(); err != nil {
		t.Fatal(err)
	}
	if err := a.ConfigureAccess(0, false); err != nil {
		t.Fatal(err)
	}
	h := s.Read().Settings.HTTPS
	path := filepath.Join(s.dir, "Caddyfile")
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	old := strings.ReplaceAll(string(current), " {\n   header_up X-RelayDeck-Client-IP {http.request.remote.host}\n  }", "")
	if old == string(current) {
		t.Fatal("test did not construct old configuration")
	}
	if err = os.WriteFile(path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.Update(func(s *State) error { s.Settings.HTTPS.Email = "pending@example.com"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err = a.ConfigureAccess(0, false); err != nil {
		t.Fatal(err)
	}
	migrated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(migrated, current) || s.Read().Settings.HTTPS.AdminPath != h.AdminPath || s.Read().Settings.HTTPS.Email != "pending@example.com" {
		t.Fatal("migration applied pending settings or changed entry")
	}
}

func TestOfficialCaddyOverwritesClientIP(t *testing.T) {
	core := os.Getenv("CADDY_BIN")
	if core == "" {
		t.Skip("official Caddy not installed")
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.Header.Get(clientIPHeader)) }))
	defer backend.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	dir := t.TempDir()
	config, err := Caddyfile(HTTPS{Domain: "panel.example.com", Mode: "auto"}, strings.TrimPrefix(backend.URL, "http://"), dir)
	if err != nil {
		t.Fatal(err)
	}
	config = strings.ReplaceAll(config, "admin 127.0.0.1:2019", "admin off")
	config = strings.Replace(config, "panel.example.com {", "http://"+address+" {", 1)
	path := filepath.Join(dir, "Caddyfile")
	if err = os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, core, "run", "--config", path, "--adapter", "caddyfile")
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+dir, "XDG_CONFIG_HOME="+dir)
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait() }()
	client := &http.Client{Timeout: time.Second}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		req, _ := http.NewRequest("GET", "http://"+address+"/healthz", nil)
		req.Header.Set(clientIPHeader, "203.0.113.99")
		req.Header.Set("X-Forwarded-For", "203.0.113.99")
		res, err := client.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 || string(b) != "127.0.0.1" {
			t.Fatalf("client identity spoofed: %d %q", res.StatusCode, b)
		}
		return
	}
	t.Fatal("Caddy did not become ready")
}
