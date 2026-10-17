package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Audit records contain identifiers and field names, never request/response values.
// They share the encrypted transaction with the change they describe.
type AuditEvent struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Actor     string    `json:"actor"`
	Source    string    `json:"source"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	TargetIDs []string  `json:"targetIds"`
	Fields    []string  `json:"fields,omitempty"`
}

const auditRetention = 2000

func (a *App) audit(s *State, r *http.Request, action, resource string, ids, fields []string) {
	source := "local-cli"
	if r != nil {
		source = "unknown"
		if ip, ok := a.loginSource(r); ok {
			source = ip
		}
	}
	ids = append([]string(nil), ids...)
	fields = append([]string(nil), fields...)
	slices.Sort(fields)
	s.Audit = append(s.Audit, AuditEvent{ID: newID("audit"), Time: time.Now().UTC(), Actor: s.Username, Source: source, Action: action, Resource: resource, TargetIDs: ids, Fields: fields})
	if len(s.Audit) > auditRetention {
		n := len(s.Audit) - auditRetention
		s.AuditDropped += int64(n)
		s.Audit = s.Audit[n:]
	}
	s.Schema = max(s.Schema, 7)
}
func (a *App) mutationAudit(s *State, r *http.Request, input, response any) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/"), "/")
	if len(parts) == 0 {
		return
	}
	resource := parts[0]
	action := "create"
	ids := []string{}
	if len(parts) > 1 {
		action = "update"
		ids = append(ids, parts[1])
	}
	if r.Method == "DELETE" {
		action = "delete"
	}
	if len(parts) > 2 && parts[2] == "security" {
		action = "credentials.rotate"
		ids = []string{parts[1]}
	}
	if len(parts) > 1 && parts[1] == "import" {
		action = "import"
		ids = nil
	}
	var out struct {
		ID string `json:"id"`
	}
	b, _ := json.Marshal(response)
	_ = json.Unmarshal(b, &out)
	if out.ID != "" && len(parts) == 1 {
		ids = []string{out.ID}
	}
	fields := []string{}
	var values map[string]json.RawMessage
	b, _ = json.Marshal(input)
	_ = json.Unmarshal(b, &values)
	for k := range values {
		fields = append(fields, k)
	}
	a.audit(s, r, action, resource, ids, fields)
}
func (a *App) auditAPI(w http.ResponseWriter, r *http.Request) {
	s := a.Store.Read()
	end := len(s.Audit)
	cursor := r.URL.Query().Get("before")
	if cursor != "" {
		end = slices.IndexFunc(s.Audit, func(e AuditEvent) bool { return e.ID == cursor })
		if end < 0 {
			jsonResponse(w, 409, map[string]string{"error": "审计游标已过期，请刷新列表"})
			return
		}
	}
	start := max(0, end-50)
	items := append([]AuditEvent{}, s.Audit[start:end]...)
	slices.Reverse(items)
	next := ""
	if start > 0 {
		next = s.Audit[start].ID
	}
	jsonResponse(w, 200, map[string]any{"items": items, "next": next, "retention": auditRetention, "dropped": s.AuditDropped})
}

type auditRequestKey struct{}

func withAuditRequest(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, auditRequestKey{}, r)
}
func (a *App) auditContext(s *State, ctx context.Context, action, resource string, ids, fields []string) {
	r, _ := ctx.Value(auditRequestKey{}).(*http.Request)
	a.audit(s, r, action, resource, ids, fields)
}
