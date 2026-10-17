package panel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

type restorePlan struct {
	ID, BaseVersion string
	Expires         time.Time
	Payload         State
}
type restorePlans struct {
	mu   sync.Mutex
	plan *restorePlan
}

func (p *restorePlans) expire(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.plan != nil && !now.Before(p.plan.Expires) {
		p.plan = nil
	}
}
func (a *App) restoreVersion(s State) string {
	s = cloneState(s)
	s.Audit = nil
	s.AuditDropped = 0
	s.Notifications = nil
	s.Mutations = nil
	s.Tasks = nil
	s.Compiler = ""
	for i := range s.Servers {
		v := &s.Servers[i]
		v.LastSeen = time.Time{}
		v.TrafficLastSeen = time.Time{}
		v.Desired = 0
		v.Applied = 0
		v.CoreVersion = ""
		v.Error = ""
		v.TrafficCursors = nil
	}
	for i := range s.Users {
		v := &s.Users[i]
		v.Upload = 0
		v.Download = 0
		v.Used = 0
		v.UsageSince = time.Time{}
		v.UsageUpdated = time.Time{}
		v.Required = nil
	}
	s.Schema = 0
	s.Settings.HTTPS.Status = ""
	s.Settings.HTTPS.Expires = ""
	s.Settings.Telegram.Status = ""
	b, _ := json.Marshal(s)
	m := hmac.New(sha256.New, a.Store.key)
	_, _ = m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}
func restoreCounts(s State) map[string]int {
	return map[string]int{"servers": len(s.Servers), "nodes": len(s.Nodes), "users": len(s.Users), "routes": len(s.Routes), "outbounds": len(s.Outbounds)}
}

// A manually confirmed restore retains a same-host undo point. It is not a
// scheduled/offsite backup and is only useful while this host is available.
func (a *App) restoreCheckpoint(s State) (string, error) {
	dir := filepath.Join(a.DataDir, "web-restore-checkpoints")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	id := time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + randomToken(9)
	pass := randomToken(32)
	b, e := exportState(s, pass)
	if e != nil {
		return "", e
	}
	if e = writePrivateFile(filepath.Join(dir, id+".pass"), []byte(pass+"\n")); e != nil {
		return "", e
	}
	if e = WriteBackup(filepath.Join(dir, id+".rdbak"), b); e != nil {
		_ = os.Remove(filepath.Join(dir, id+".pass"))
		return "", e
	}
	// Keep at most three completed checkpoints, never unbounded restore history.
	files, _ := filepath.Glob(filepath.Join(dir, "*.rdbak"))
	slices.Sort(files)
	for len(files) > 3 {
		old := files[0]
		files = files[1:]
		_ = os.Remove(old)
		_ = os.Remove(old[:len(old)-len(".rdbak")] + ".pass")
	}
	return id, nil
}
func validateWebRestore(s State) error {
	if len(s.Servers) > 200 || len(s.Nodes) > 2000 || len(s.Users) > 1000 || len(s.Routes) > 5000 || len(s.Outbounds) > 2000 {
		return errors.New("备份超过网页恢复支持规模，请使用终端隔离恢复")
	}
	seen := map[string]bool{}
	check := func(id string) bool {
		if len(id) < 5 || len(id) > 100 || !safeTag.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
		return true
	}
	for _, v := range s.Servers {
		if !check(v.ID) || !nameValid(v.Name) || !hostValid(v.Address) || v.AgentToken == "" {
			return errors.New("备份服务器身份或地址无效")
		}
	}
	for _, v := range s.Nodes {
		if !check(v.ID) || serverByID(&s, v.ServerID) == nil || v.ExitID != "" && serverByID(&s, v.ExitID) == nil || !slices.Contains([]string{"reality", "hy2", "ss2022"}, v.Protocol) || v.Port < 1 || v.Port > 65535 {
			return errors.New("备份节点或服务器引用无效")
		}
		if e := validateNode(&s, v); e != nil {
			return errors.New("备份节点配置无效或证书已失效，请先通过终端隔离恢复检查")
		}
	}
	for _, v := range s.Users {
		if !check(v.ID) || v.Token == "" || !nameValid(v.Name) {
			return errors.New("备份订阅身份无效")
		}
		granted := map[string]bool{}
		for _, id := range v.NodeIDs {
			if nodeByID(&s, id) == nil || v.Credentials[id] == "" || granted[id] {
				return errors.New("备份授权或节点认证不完整")
			}
			granted[id] = true
		}
	}
	for _, v := range s.Outbounds {
		if !check(v.ID) {
			return errors.New("备份出站 ID 无效")
		}
	}
	for _, v := range s.Routes {
		if !check(v.ID) {
			return errors.New("备份规则 ID 无效")
		}
	}
	if e := validateRoutingState(s); e != nil {
		return errors.New("备份路由引用或参数无效")
	}
	for _, v := range s.Servers {
		if _, e := Compile(s, v.ID, "/var/lib/relaydeck/agent"); e != nil {
			return errors.New("备份无法生成服务器配置，请先通过终端隔离恢复检查")
		}
	}
	return nil
}
func (a *App) restoreAPI(w http.ResponseWriter, r *http.Request, path string) bool {
	if path != "backup/preview" && path != "backup/restore" {
		return false
	}
	if r.Method != "POST" {
		failureResponse(w, 405, errors.New("请求方式无效"))
		return true
	}
	if path == "backup/preview" {
		if !a.backupMu.TryLock() {
			failureResponse(w, 409, errors.New("已有备份处理任务，请稍后重试"))
			return true
		}
		defer a.backupMu.Unlock()
		a.restorePlans.mu.Lock()
		a.restorePlans.plan = nil
		a.restorePlans.mu.Unlock()
		r.Body = http.MaxBytesReader(w, r.Body, (33 << 20))
		if e := r.ParseMultipartForm(1 << 20); e != nil {
			if r.MultipartForm != nil {
				_ = r.MultipartForm.RemoveAll()
			}
			failureResponse(w, 422, errors.New("请上传不超过 32 MiB 的 RelayDeck 加密备份"))
			return true
		}
		defer r.MultipartForm.RemoveAll()
		if len(r.MultipartForm.File) != 1 || len(r.MultipartForm.File["file"]) != 1 || len(r.MultipartForm.Value["password"]) != 1 {
			failureResponse(w, 422, errors.New("请选择一个备份文件并填写备份口令"))
			return true
		}
		f, _, e := r.FormFile("file")
		if e != nil {
			failureResponse(w, 422, errors.New("无法读取备份文件"))
			return true
		}
		defer f.Close()
		b, e := io.ReadAll(io.LimitReader(f, (32<<20)+1))
		if e != nil || len(b) > 32<<20 {
			failureResponse(w, 422, errors.New("备份文件超过 32 MiB 或读取失败"))
			return true
		}
		next, e := decodeBackup(b, r.FormValue("password"))
		if e != nil {
			failureResponse(w, 422, e)
			return true
		}
		if e = validateWebRestore(next); e != nil {
			failureResponse(w, 422, e)
			return true
		}
		current := a.Store.Read()
		p := &restorePlan{ID: randomToken(24), BaseVersion: a.restoreVersion(current), Expires: time.Now().Add(10 * time.Minute), Payload: next}
		a.restorePlans.mu.Lock()
		a.restorePlans.plan = p
		a.restorePlans.mu.Unlock()
		jsonResponse(w, 200, map[string]any{"planId": p.ID, "expires": p.Expires, "current": restoreCounts(current), "backup": restoreCounts(next), "backupVersion": next.Schema, "preserveAdministrator": true, "preserveHTTPS": true, "agentReapplyRequired": true})
		return true
	}
	var in struct {
		PlanID   string `json:"planId"`
		Password string `json:"currentPassword"`
		Confirm  bool   `json:"confirm"`
	}
	if e := body(r, &in); e != nil {
		failureResponse(w, 422, e)
		return true
	}
	if !in.Confirm {
		failureResponse(w, 422, errors.New("请核对恢复影响并明确确认"))
		return true
	}
	if !a.backupMu.TryLock() {
		failureResponse(w, 409, errors.New("已有备份处理任务，请稍后重试"))
		return true
	}
	defer a.backupMu.Unlock()
	if !a.auth.credentials.TryLock() {
		failureResponse(w, 429, errors.New("管理员验证正在进行，请稍后重试"))
		return true
	}
	defer a.auth.credentials.Unlock()
	if _, ok := a.auth.lookup(r); !ok {
		failureResponse(w, 401, errors.New("请重新登录"))
		return true
	}
	if a.auth.blocked("backup-restore") {
		failureResponse(w, 429, errors.New("管理员密码验证失败过多，请 15 分钟后重试"))
		return true
	}
	current := a.Store.Read()
	if len(in.Password) > 128 || !verifyPassword(in.Password, current.PasswordHash) {
		a.auth.recordFailure("backup-restore")
		failureResponse(w, 422, errors.New("当前管理员密码错误"))
		return true
	}
	a.restorePlans.mu.Lock()
	defer a.restorePlans.mu.Unlock()
	p := a.restorePlans.plan
	if p == nil || !equal(p.ID, in.PlanID) || !time.Now().Before(p.Expires) {
		a.restorePlans.plan = nil
		failureResponse(w, 409, errors.New("恢复预览已过期或已执行，请重新上传预览；不要重复导入"))
		return true
	}
	// Settings changes and access reloads must not race the preserved entry.
	a.httpsMu.Lock()
	defer a.httpsMu.Unlock()
	checkpoint := ""
	e := a.Store.Update(func(s *State) error {
		if s.PasswordHash != current.PasswordHash || !equal(a.restoreVersion(*s), p.BaseVersion) {
			return errors.New("配置已在预览后变化，请重新上传并核对，当前数据未改变")
		}
		var e error
		checkpoint, e = a.restoreCheckpoint(*s)
		if e != nil {
			return errors.New("无法创建导入前的加密恢复点，当前数据未改变")
		}
		next := cloneState(p.Payload)
		next.Username = s.Username
		next.PasswordHash = s.PasswordHash
		next.SetupToken = ""
		next.SetupExpires = s.SetupExpires
		next.Settings.HTTPS = s.Settings.HTTPS
		next.Audit = s.Audit
		next.AuditDropped = s.AuditDropped
		next.Epoch = randomToken(16)
		next.Compiler = Version
		next.Schema = 7
		next.Tasks = []Task{}
		next.Mutations = nil
		next.Notifications = []Notification{}
		for i := range next.Servers {
			v := &next.Servers[i]
			v.Applied = 0
			v.Error = ""
			v.LastSeen = time.Time{}
			queue(&next, []string{v.ID}, "网页导入后重新同步授权")
		}
		a.audit(&next, r, "backup.restore", "backup", []string{checkpoint}, []string{"nodes", "users", "servers", "routing", "telegram"})
		*s = next
		return nil
	})
	if e != nil {
		failureResponse(w, 409, e)
		return true
	}
	a.restorePlans.plan = nil
	a.auth.clearFailures("backup-restore")
	// Revoke every pre-restore management session. The working HTTPS entry and
	// current administrator remain valid; restored data awaits a fresh Agent epoch.
	a.auth.mu.Lock()
	a.auth.sessions = map[string]session{}
	a.auth.mu.Unlock()
	a.auth.logout(w, r, adminCookiePath(current.Settings.HTTPS))
	jsonResponse(w, 200, map[string]any{"restored": true, "reauthenticate": true, "recoveryPoint": checkpoint, "message": "导入完成，当前管理员与 HTTPS 入口保留。请重新登录，等待 Agent 同步后交付。"})
	return true
}
