package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func securityRequest(t *testing.T, a *App, path string, value any, cookie *http.Cookie, csrf, key string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(value)
	r := httptest.NewRequest("POST", "/api/"+path, bytes.NewReader(b))
	if cookie != nil {
		r.AddCookie(cookie)
	}
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}
func rotationPreview(t *testing.T, a *App, cookie *http.Cookie, csrf, id string, in userRotationInput) userRotationInput {
	t.Helper()
	w := securityRequest(t, a, "users/"+id+"/security/preview", in, cookie, csrf, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var out struct {
		Version string `json:"version"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	in.Version = out.Version
	in.Confirm = true
	return in
}
func TestUserRotationScopeIdempotencyAndPublication(t *testing.T) {
	store := testStore(t)
	f := fixture()
	store.Update(func(s *State) error { *s = f; return nil })
	a := New(store, "http://127.0.0.1:8787", store.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	before := store.Read()
	uid := before.Users[0].ID
	in := rotationPreview(t, a, cookie, csrf, uid, userRotationInput{RotateToken: true})
	w := securityRequest(t, a, "users/"+uid+"/security/rotate", in, cookie, csrf, "rotate-token-idempotency-1")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	after := store.Read()
	if after.Users[0].Token == before.Users[0].Token || after.Users[1].Token != before.Users[1].Token || after.Servers[0].Desired != before.Servers[0].Desired {
		t.Fatal("token rotation affected unrelated credentials or deployed core")
	}
	if _, _, e := subscriptionNodes(after, before.Users[0].Token); e == nil {
		t.Fatal("old subscription token remains active")
	}
	if after.Users[0].Credentials[before.Nodes[0].ID] != before.Users[0].Credentials[before.Nodes[0].ID] {
		t.Fatal("address reset changed node UUID")
	}
	firstToken := after.Users[0].Token
	events := len(after.Audit)
	w = securityRequest(t, a, "users/"+uid+"/security/rotate", in, cookie, csrf, "rotate-token-idempotency-1")
	if w.Code != 200 || store.Read().Users[0].Token != firstToken || len(store.Read().Audit) != events {
		t.Fatal("retry rotated twice or duplicated audit")
	}
	in = rotationPreview(t, a, cookie, csrf, uid, userRotationInput{NodeIDs: []string{before.Nodes[1].ID}})
	// Traffic arriving after a preview must not make an otherwise valid plan stale.
	store.Update(func(s *State) error { s.Users[0].Used += 123; s.Users[0].Upload += 123; return nil })
	w = securityRequest(t, a, "users/"+uid+"/security/rotate", in, cookie, csrf, "rotate-selected-idempotency-2")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	after = store.Read()
	if after.Users[0].Token != firstToken || after.Users[0].Credentials[before.Nodes[0].ID] != before.Users[0].Credentials[before.Nodes[0].ID] || after.Users[1].Credentials[before.Nodes[1].ID] != before.Users[1].Credentials[before.Nodes[1].ID] || after.Nodes[1].ServerKey != before.Nodes[1].ServerKey {
		t.Fatal("selected credential rotation escaped user/node scope")
	}
	if after.Users[0].Credentials[before.Nodes[1].ID] == before.Users[0].Credentials[before.Nodes[1].ID] || !validSSKeys(after.Users[0].Credentials[before.Nodes[1].ID], ssMethod(after.Nodes[1].ProtocolOptions), false) {
		t.Fatal("selected SS credential not regenerated")
	}
	if nodePublished(after, after.Users[0], after.Nodes[1]) || !nodePublished(after, after.Users[0], after.Nodes[0]) {
		t.Fatal("publication gate did not isolate affected server")
	}
	if after.Users[0].Used != 123 || after.Users[0].Expires != before.Users[0].Expires {
		t.Fatal("rotation changed usage or expiry")
	}
	after.Servers[1].Applied = after.Servers[1].Desired
	if !nodePublished(after, after.Users[0], after.Nodes[1]) {
		t.Fatal("new credentials unavailable after apply")
	}
	b, _ := json.Marshal(after.Audit)
	for _, secret := range []string{firstToken, before.Users[0].Token, after.Users[0].Credentials[before.Nodes[1].ID], before.Nodes[1].ServerKey} {
		if strings.Contains(string(b), secret) {
			t.Fatal("audit contains authentication values")
		}
	}
}
func TestUserRotationRejectsStaleAndUnconfirmedPlans(t *testing.T) {
	store := testStore(t)
	f := fixture()
	store.Update(func(s *State) error { *s = f; return nil })
	a := New(store, "http://127.0.0.1:8787", store.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	uid := f.Users[0].ID
	path := "users/" + uid + "/security/rotate"
	in := rotationPreview(t, a, cookie, csrf, uid, userRotationInput{RotateToken: true})
	if securityRequest(t, a, path, in, nil, "", "some-operation-key").Code != 401 {
		t.Fatal("missing auth accepted")
	}
	if securityRequest(t, a, path, in, cookie, "wrong", "some-operation-key").Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	if securityRequest(t, a, path, in, cookie, csrf, "").Code != 428 {
		t.Fatal("missing idempotency accepted")
	}
	no := in
	no.Confirm = false
	if securityRequest(t, a, path, no, cookie, csrf, "some-operation-key").Code != 422 {
		t.Fatal("unconfirmed rotation accepted")
	}
	store.Update(func(s *State) error { s.Users[0].Name = "另一页面修改"; return nil })
	before := store.Read().Users[0].Token
	if securityRequest(t, a, path, in, cookie, csrf, "some-operation-key").Code != 409 || store.Read().Users[0].Token != before {
		t.Fatal("stale plan changed token")
	}
	in = userRotationInput{NodeIDs: []string{f.Nodes[0].ID}}
	if securityRequest(t, a, "users/"+f.Users[1].ID+"/security/preview", in, cookie, csrf, "").Code != 422 {
		t.Fatal("foreign grant allowed")
	}
}
func TestAuditRetentionPrivacyAndBackup(t *testing.T) {
	store := testStore(t)
	a := New(store, "http://127.0.0.1:8787", store.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	w := request(t, a, "POST", "/api/servers", map[string]string{"name": "test", "address": "a.example.com"}, cookie, csrf, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if store.Read().Schema != 7 || len(store.Read().Audit) != 1 {
		t.Fatal("audit not committed with mutation")
	}
	if w = request(t, a, "GET", "/api/audit", nil, nil, "", ""); w.Code != 401 {
		t.Fatal("audit not authenticated")
	}
	store.Update(func(s *State) error {
		for i := 0; i < auditRetention+5; i++ {
			a.audit(s, nil, "update", "nodes", []string{"node_test"}, []string{"privateKey"})
		}
		return nil
	})
	s := store.Read()
	if len(s.Audit) != auditRetention || s.AuditDropped != 6 {
		t.Fatal("audit retention is unbounded")
	}
	w = request(t, a, "GET", "/api/audit", nil, cookie, "", "")
	var page struct {
		Items []AuditEvent `json:"items"`
		Next  string       `json:"next"`
	}
	json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Items) != 50 || page.Next == "" {
		t.Fatal("audit paging failed")
	}
	backup, e := store.Export("audit-backup-password")
	if e != nil {
		t.Fatal(e)
	}
	restored := testStore(t)
	if e = restored.Import(backup, "audit-backup-password"); e != nil || len(restored.Read().Audit) != auditRetention {
		t.Fatal("audit backup lost", e)
	}
}
