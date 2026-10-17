package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccountPasswordChange(t *testing.T) {
	s := testStore(t)
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	origin := "http://127.0.0.1:8787"
	second := request(t, a, "POST", "/api/login", map[string]string{"username": "admin", "password": "correct-test-password"}, nil, "", origin).Result().Cookies()[0]
	oldHash := s.Read().PasswordHash
	input := map[string]string{"currentPassword": "correct-test-password", "newPassword": "new-test-password-2026", "confirmPassword": "new-test-password-2026"}
	for _, token := range []string{"", "wrong-csrf"} {
		if w := request(t, a, "POST", "/api/account/password", input, cookie, token, origin); w.Code != 403 {
			t.Fatal("password change accepted without CSRF")
		}
	}
	for _, bad := range []map[string]string{
		{"currentPassword": "wrong", "newPassword": input["newPassword"], "confirmPassword": input["confirmPassword"]},
		{"currentPassword": input["currentPassword"], "newPassword": "short", "confirmPassword": "short"},
		{"currentPassword": input["currentPassword"], "newPassword": input["newPassword"], "confirmPassword": "different-password"},
		{"currentPassword": input["currentPassword"], "newPassword": input["currentPassword"], "confirmPassword": input["currentPassword"]},
	} {
		if w := request(t, a, "POST", "/api/account/password", bad, cookie, csrf, origin); w.Code != 422 {
			t.Fatalf("invalid password change: %d", w.Code)
		}
		if s.Read().PasswordHash != oldHash || request(t, a, "GET", "/api/state", nil, cookie, "", "").Code != 200 {
			t.Fatal("failed change modified password or revoked session")
		}
	}
	w := request(t, a, "POST", "/api/account/password", input, cookie, csrf, origin)
	if w.Code != 200 || !verifyPassword(input["newPassword"], s.Read().PasswordHash) || verifyPassword(input["currentPassword"], s.Read().PasswordHash) {
		t.Fatal("new password was not committed")
	}
	if w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("session cookie was not expired")
	}
	for _, c := range []*http.Cookie{cookie, second} {
		if w := request(t, a, "GET", "/api/state", nil, c, "", ""); w.Code != 401 {
			t.Fatal("previous session remains valid")
		}
	}
	for password, code := range map[string]int{"correct-test-password": 401, input["newPassword"]: 200} {
		if w := request(t, a, "POST", "/api/login", map[string]string{"username": "admin", "password": password}, nil, "", origin); w.Code != code {
			t.Fatal("login password validation after change")
		}
	}
	backup, err := s.Export("backup-test-password")
	if err != nil {
		t.Fatal(err)
	}
	restored := testStore(t)
	if err := restored.Import(backup, "backup-test-password"); err != nil || !verifyPassword(input["newPassword"], restored.Read().PasswordHash) {
		t.Fatal("backup did not retain the new password")
	}
}

func TestAccountPasswordThrottle(t *testing.T) {
	s := testStore(t)
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	for i := 0; i < 6; i++ {
		w := request(t, a, "POST", "/api/account/password", map[string]string{"currentPassword": "wrong", "newPassword": "new-test-password", "confirmPassword": "new-test-password"}, cookie, csrf, "http://127.0.0.1:8787")
		want := 422
		if i == 5 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
}

func TestCustomAccessPath(t *testing.T) {
	s := testStore(t)
	h := HTTPS{Domain: "panel.example.com", Mode: "auto", AdminPort: 38443, AdminPath: randomToken(24)}
	s.Update(func(s *State) error { *s = fixture(); s.Settings.HTTPS = h; return nil })
	a := New(s, "https://panel.example.com", s.dir, false, nil)
	a.Caddy = filepath.Join(s.dir, "caddy-test")
	if err := os.WriteFile(a.Caddy, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	oldEntry := a.AdminURL(h)
	w := request(t, a, "POST", oldEntry+"api/setup", map[string]string{"token": s.Read().SetupToken, "username": "admin", "password": "correct-test-password"}, nil, "", "https://panel.example.com:38443")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	var auth map[string]string
	json.Unmarshal(w.Body.Bytes(), &auth)
	before := s.Read()
	for _, path := range []string{"", "short", "has space", "foo/bar", "../secret", "a?query", strings.Repeat("a", 97), "中文路径abcd"} {
		w = request(t, a, "POST", oldEntry+"api/https/access", map[string]any{"path": path}, cookie, auth["csrf"], "https://panel.example.com:38443")
		if w.Code != 422 || s.Read().Settings.HTTPS.AdminPath != h.AdminPath {
			t.Fatalf("invalid custom path accepted: %q", path)
		}
	}
	w = request(t, a, "POST", oldEntry+"api/https/access", map[string]any{"path": "/My_panel-2026/"}, cookie, auth["csrf"], "https://panel.example.com:38443")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	after := s.Read()
	if after.Settings.HTTPS.AdminPath != "My_panel-2026" || after.Users[0].Token != before.Users[0].Token || after.Servers[0].AgentToken != before.Servers[0].AgentToken {
		t.Fatal("path normalization or credential preservation failed")
	}
	if request(t, a, "GET", oldEntry+"api/session", nil, nil, "", "").Code != 404 {
		t.Fatal("old path is accessible")
	}
	entry := a.AdminURL(after.Settings.HTTPS)
	if request(t, a, "GET", entry+"api/state", nil, cookie, "", "").Code != 401 {
		t.Fatal("old session remains valid")
	}
	if request(t, a, "POST", entry+"api/login", map[string]string{"username": "admin", "password": "correct-test-password"}, nil, "", "https://panel.example.com:38443").Code != 200 {
		t.Fatal("new path login failed")
	}
	if b, _ := os.ReadFile(filepath.Join(s.dir, "admin-entry.txt")); string(b) != entry+"\n" {
		t.Fatal("recovery entry not updated")
	}
	// A rejected Caddy configuration leaves the working custom path unchanged.
	os.WriteFile(a.Caddy, []byte("#!/bin/sh\nexit 1\n"), 0700)
	path := "another-entry"
	if _, err := a.ChangeAccessWithPath(context.Background(), 0, false, &path); err == nil || s.Read().Settings.HTTPS.AdminPath != "My_panel-2026" {
		t.Fatal("failed Caddy load changed entry")
	}
	if _, err := a.ChangeAccessWithPath(context.Background(), 0, true, &path); err == nil {
		t.Fatal("ambiguous path accepted")
	}
}
