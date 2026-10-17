package panel

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func webBackupPreview(t *testing.T, a *App, cookie *http.Cookie, csrf string, b []byte, pass string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	m := multipart.NewWriter(&buf)
	f, _ := m.CreateFormFile("file", "backup.bin")
	_, _ = f.Write(b)
	_ = m.WriteField("password", pass)
	_ = m.Close()
	r := httptest.NewRequest("POST", "/api/backup/preview", &buf)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Content-Type", m.FormDataContentType())
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}
func TestWebRestorePreservesAccessAndRequiresFreshAgentEpoch(t *testing.T) {
	store := testStore(t)
	f := fixture()
	store.Update(func(s *State) error { *s = f; return nil })
	a := New(store, "http://127.0.0.1:8787", store.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	original := store.Read()
	source := cloneState(original)
	source.Username = "backup-admin"
	source.PasswordHash = hashPassword("backup-different-password")
	source.Users[0].Name = "来自备份"
	source.Settings.HTTPS.Domain = "backup.example.com"
	source.Settings.HTTPS.AdminPort = 39443
	source.Settings.HTTPS.AdminPath = "backup-entry"
	source.Epoch = randomToken(16)
	b, e := exportState(source, "web-restore-backup-password")
	if e != nil {
		t.Fatal(e)
	}
	w := webBackupPreview(t, a, cookie, csrf, b, "web-restore-backup-password")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var preview struct {
		PlanID string `json:"planId"`
	}
	json.Unmarshal(w.Body.Bytes(), &preview)
	if store.Read().Users[0].Name != original.Users[0].Name {
		t.Fatal("preview changed live state")
	}
	w = securityRequest(t, a, "backup/restore", map[string]any{"planId": preview.PlanID, "currentPassword": "wrong", "confirm": true}, cookie, csrf, "")
	if w.Code != 422 {
		t.Fatal("wrong administrator password accepted")
	}
	// Concurrent traffic and heartbeats are compatible with the preview.
	store.Update(func(s *State) error {
		s.Users[0].Upload++
		s.Users[0].Used++
		s.Servers[0].LastSeen = time.Now()
		s.Servers[0].Applied = 2
		return nil
	})
	w = securityRequest(t, a, "backup/restore", map[string]any{"planId": preview.PlanID, "currentPassword": "correct-test-password", "confirm": true}, cookie, csrf, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	after := store.Read()
	if after.Notifications == nil || publicState(after).Tasks == nil {
		t.Fatal("restored state exposes null required arrays")
	}
	if after.Username != original.Username || after.PasswordHash != original.PasswordHash || after.Settings.HTTPS.Domain != original.Settings.HTTPS.Domain || after.Settings.HTTPS.AdminPath != original.Settings.HTTPS.AdminPath || after.Users[0].Name != "来自备份" {
		t.Fatal("web restore lost preserved entry/account or business data")
	}
	if after.Epoch == source.Epoch || after.Epoch == original.Epoch || after.Servers[0].Applied != 0 || nodePublished(after, after.Users[0], after.Nodes[0]) {
		t.Fatal("restored grants published before fresh Agent acknowledgement")
	}
	if request(t, a, "GET", "/api/state", nil, cookie, "", "").Code != 401 {
		t.Fatal("pre-restore session remains valid")
	}
	w = request(t, a, "POST", "/api/login", map[string]string{"username": original.Username, "password": "correct-test-password"}, nil, "", "http://127.0.0.1:8787")
	if w.Code != 200 {
		t.Fatal("preserved administrator cannot login")
	}
	if len(after.Audit) == 0 || after.Audit[len(after.Audit)-1].Action != "backup.restore" {
		t.Fatal("restore is not audited")
	}
	if a.restorePlans.plan != nil {
		t.Fatal("restore plan reused or sensitive staged state retained")
	}
}
func TestWebRestoreRejectsChangedExpiredAndInvalidPreviews(t *testing.T) {
	store := testStore(t)
	f := fixture()
	store.Update(func(s *State) error { *s = f; return nil })
	a := New(store, "http://127.0.0.1:8787", store.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	b, _ := store.Export("web-restore-backup-password")
	if webBackupPreview(t, a, nil, "", b, "web-restore-backup-password").Code != 401 {
		t.Fatal("unauthenticated upload allowed")
	}
	if webBackupPreview(t, a, cookie, "wrong", b, "web-restore-backup-password").Code != 403 {
		t.Fatal("missing CSRF allowed")
	}
	if webBackupPreview(t, a, cookie, csrf, b, "wrong-backup-password").Code != 422 {
		t.Fatal("wrong backup password accepted")
	}
	w := webBackupPreview(t, a, cookie, csrf, b, "web-restore-backup-password")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var preview struct {
		PlanID string `json:"planId"`
	}
	json.Unmarshal(w.Body.Bytes(), &preview)
	store.Update(func(s *State) error { s.Users[0].Name = "新的配置"; return nil })
	w = securityRequest(t, a, "backup/restore", map[string]any{"planId": preview.PlanID, "currentPassword": "correct-test-password", "confirm": true}, cookie, csrf, "")
	if w.Code != 409 || store.Read().Users[0].Name != "新的配置" {
		t.Fatal("changed state was overwritten")
	}
	a.restorePlans.mu.Lock()
	a.restorePlans.plan.Expires = time.Now().Add(-time.Second)
	a.restorePlans.mu.Unlock()
	if securityRequest(t, a, "backup/restore", map[string]any{"planId": preview.PlanID, "currentPassword": "correct-test-password", "confirm": true}, cookie, csrf, "").Code != 409 {
		t.Fatal("expired plan accepted")
	}
	broken := store.Read()
	broken.Nodes[0].ID = "../invalid"
	b, _ = exportState(broken, "web-restore-backup-password")
	if webBackupPreview(t, a, cookie, csrf, b, "web-restore-backup-password").Code != 422 {
		t.Fatal("invalid imported identity accepted")
	}
}

func TestWebRestoreCheckpointsArePrivatePortableAndBounded(t *testing.T) {
	store := testStore(t)
	a := New(store, "http://127.0.0.1:8787", store.dir, true, nil)
	loginTest(t, a)
	s := store.Read()
	last := ""
	for i := 0; i < 4; i++ {
		id, e := a.restoreCheckpoint(s)
		if e != nil {
			t.Fatal(e)
		}
		last = id
	}
	files, e := filepath.Glob(filepath.Join(store.dir, "web-restore-checkpoints", "*.rdbak"))
	if e != nil || len(files) != 3 {
		t.Fatal("checkpoint retention not bounded", e)
	}
	file := filepath.Join(store.dir, "web-restore-checkpoints", last+".rdbak")
	passFile := filepath.Join(store.dir, "web-restore-checkpoints", last+".pass")
	b, e := os.ReadFile(file)
	if e != nil {
		t.Fatal("latest checkpoint pruned", e)
	}
	pass, e := os.ReadFile(passFile)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyBackup(b, strings.TrimSpace(string(pass))); e != nil {
		t.Fatal("checkpoint not independently recoverable", e)
	}
	for _, p := range []string{file, passFile} {
		st, e := os.Stat(p)
		if e != nil || st.Mode().Perm() != 0600 {
			t.Fatal("checkpoint not private")
		}
	}
}
