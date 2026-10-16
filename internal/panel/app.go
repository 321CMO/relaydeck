package panel

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type App struct {
	httpsMu        sync.Mutex
	ProbeTransport http.RoundTripper
	Store          *Store
	auth           *auth
	BaseURL        string
	DataDir        string
	AgentDir       string
	Development    bool
	assets         fs.FS
	Caddy          string
	Instance       string
	TelegramBase   string
	client         *http.Client
}

func New(store *Store, baseURL, dir string, development bool, assets fs.FS) *App {
	return &App{Store: store, auth: newAuth(development), BaseURL: strings.TrimRight(baseURL, "/"), DataDir: dir, AgentDir: "/var/lib/relaydeck/agent", Development: development, assets: assets, Instance: randomToken(16), TelegramBase: "https://api.telegram.org", client: &http.Client{Timeout: 10 * time.Second}}
}
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func failureResponse(w http.ResponseWriter, status int, e error) {
	jsonResponse(w, status, map[string]string{"error": e.Error()})
}
func body(r *http.Request, v any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return errors.New("请求内容格式无效")
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return errors.New("请求包含多余内容")
	}
	return nil
}
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, map[string]string{"status": "ok", "version": Version, "instance": a.Instance})
	})
	mux.HandleFunc("GET /api/session", a.session)
	mux.HandleFunc("POST /api/setup", a.setup)
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/agent/enroll", a.enroll)
	mux.HandleFunc("POST /api/agent/sync", a.syncAgent)
	mux.HandleFunc("GET /s/{token}", a.subscription)
	mux.HandleFunc("GET /delivery/{token}", a.delivery)
	mux.HandleFunc("GET /delivery/{token}/portal.js", portalScript)
	mux.Handle("/api/", a.requireAuth(http.HandlerFunc(a.api)))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if a.assets == nil {
			http.Error(w, "请先 npm run build", 503)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		b, e := fs.ReadFile(a.assets, p)
		if e != nil {
			if strings.Contains(p, ".") {
				http.NotFound(w, r)
				return
			}
			b, e = fs.ReadFile(a.assets, "index.html")
		}
		if e != nil {
			http.NotFound(w, r)
			return
		}
		switch filepath.Ext(p) {
		case ".js":
			w.Header().Set("Content-Type", "text/javascript")
		case ".css":
			w.Header().Set("Content-Type", "text/css")
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		}
		w.Write(b)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		settings := a.Store.Read().Settings.HTTPS
		if settings.SubscriptionDomain != "" && settings.SubscriptionDomain != settings.Domain {
			host := r.Host
			if h, _, e := net.SplitHostPort(host); e == nil {
				host = h
			}
			if host == settings.SubscriptionDomain && !strings.HasPrefix(r.URL.Path, "/s/") && !strings.HasPrefix(r.URL.Path, "/delivery/") && r.URL.Path != "/healthz" {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		if !publicEndpoint(r.URL.Path) {
			secured, ok := a.adminRequest(r, settings)
			if !ok {
				http.NotFound(w, r)
				return
			}
			r = secured
		}
		mux.ServeHTTP(w, r)
	})
}
func (a *App) sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, e := url.Parse(origin)
	if e != nil {
		return false
	}
	configured, _ := url.Parse(a.AdminURL(a.Store.Read().Settings.HTTPS))
	return u.Host == configured.Host && u.Scheme == configured.Scheme || a.Development && u.Scheme == "http" && u.Host == r.Host
}
func (a *App) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.auth.lookup(r)
		if !ok {
			failureResponse(w, 401, errors.New("请先登录"))
			return
		}
		if r.Method != "GET" && (!a.sameOrigin(r) || !equal(r.Header.Get("X-CSRF-Token"), s.CSRF)) {
			failureResponse(w, 403, errors.New("请求验证失败，请刷新页面"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (a *App) session(w http.ResponseWriter, r *http.Request) {
	s, ok := a.auth.lookup(r)
	state := a.Store.Read()
	jsonResponse(w, 200, map[string]any{"authenticated": ok, "setupRequired": state.PasswordHash == "", "csrf": s.CSRF, "username": func() string {
		if ok {
			return state.Username
		}
		return ""
	}(), "version": Version})
}
func (a *App) setup(w http.ResponseWriter, r *http.Request) {
	a.auth.credentials.Lock()
	defer a.auth.credentials.Unlock()
	if !a.sameOrigin(r) {
		failureResponse(w, 403, errors.New("来源验证失败"))
		return
	}
	var in struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if e := body(r, &in); e != nil {
		failureResponse(w, 400, e)
		return
	}
	if !nameValid(in.Username) || utf8.RuneCountInString(in.Password) < 8 || len(in.Password) > 128 {
		failureResponse(w, 422, errors.New("用户名无效或密码少于 8 位"))
		return
	}
	e := a.Store.Update(func(s *State) error {
		if s.PasswordHash != "" || !equal(s.SetupToken, in.Token) || !time.Now().Before(s.SetupExpires) {
			return errors.New("首次设置码已使用、错误或过期，请在终端重新生成")
		}
		s.Username = in.Username
		s.PasswordHash = hashPassword(in.Password)
		s.SetupToken = ""
		return nil
	})
	if e != nil {
		failureResponse(w, 403, e)
		return
	}
	_ = os.Remove(filepath.Join(a.DataDir, "bootstrap.txt"))
	auth := a.auth.login(w, adminCookiePath(a.Store.Read().Settings.HTTPS))
	jsonResponse(w, 200, map[string]string{"csrf": auth.CSRF})
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		failureResponse(w, 403, errors.New("来源验证失败"))
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if e := body(r, &in); e != nil {
		failureResponse(w, 400, e)
		return
	}
	ip, ok := a.loginSource(r)
	if !ok {
		failureResponse(w, 503, errors.New("登录入口尚未就绪，请检查反向代理配置"))
		return
	}
	if retry := a.auth.loginRetryAfter(ip); retry != 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		failureResponse(w, 429, errors.New("登录尝试过多，请稍后再试"))
		return
	}
	if !a.auth.credentials.TryLock() {
		w.Header().Set("Retry-After", "1")
		failureResponse(w, 429, errors.New("登录验证忙，请稍后重试"))
		return
	}
	defer a.auth.credentials.Unlock()
	s := a.Store.Read()
	if len(in.Password) > 128 || in.Username != s.Username || !verifyPassword(in.Password, s.PasswordHash) {
		a.auth.recordFailure(ip)
		failureResponse(w, 401, errors.New("账号或密码错误"))
		return
	}
	a.auth.clearFailures(ip)
	auth := a.auth.login(w, adminCookiePath(a.Store.Read().Settings.HTTPS))
	jsonResponse(w, 200, map[string]string{"csrf": auth.CSRF})
}
func queue(s *State, ids []string, summary string) {
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		v := serverByID(s, id)
		if v == nil {
			continue
		}
		v.Desired++
		for i := range s.Tasks {
			if s.Tasks[i].ServerID == id && s.Tasks[i].Status == "pending" {
				s.Tasks[i].Status = "superseded"
			}
		}
		s.Tasks = append(s.Tasks, Task{ID: newID("task"), ServerID: id, Revision: v.Desired, Status: "pending", Summary: summary, Created: time.Now().UTC()})
	}
	if len(s.Tasks) > 500 {
		s.Tasks = s.Tasks[len(s.Tasks)-500:]
	}
}
func (a *App) api(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	id := ""
	if len(parts) > 1 {
		id = parts[1]
	}
	if path == "settings/section" && r.Method == "POST" {
		a.settingsSection(w, r)
		return
	}
	if path == "state" && r.Method == "GET" {
		s := a.Store.Read()
		jsonResponse(w, 200, map[string]any{"state": publicState(s), "baseUrl": a.BaseURL, "settingsVersions": settingsVersions(s.Settings), "adminUrl": a.AdminURL(s.Settings.HTTPS)})
		return
	}
	if path == "logout" && r.Method == "POST" {
		a.auth.logout(w, r, adminCookiePath(a.Store.Read().Settings.HTTPS))
		jsonResponse(w, 200, map[string]bool{"ok": true})
		return
	}
	if path == "account/password" && r.Method == "POST" {
		a.changePassword(w, r)
		return
	}
	if path == "backup" && r.Method == "POST" {
		var in struct {
			Password string `json:"password"`
		}
		if e := body(r, &in); e != nil {
			failureResponse(w, 400, e)
			return
		}
		b, e := a.Store.Export(in.Password)
		if e != nil {
			failureResponse(w, 500, e)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="relaydeck-encrypted-backup.bin"`)
		w.Header().Set("Cache-Control", "no-store")
		w.Write(b)
		return
	}
	if path == "https/caddyfile" && r.Method == "GET" {
		c, e := Caddyfile(a.Store.Read().Settings.HTTPS, "127.0.0.1:8787", a.DataDir)
		if e != nil {
			failureResponse(w, 422, e)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(c))
		return
	}
	if path == "https/access" && r.Method == "POST" {
		a.auth.credentials.Lock()
		defer a.auth.credentials.Unlock()
		if _, ok := a.auth.lookup(r); !ok {
			failureResponse(w, 401, errors.New("请重新登录"))
			return
		}
		var in struct {
			Port   int     `json:"port"`
			Rotate bool    `json:"rotate"`
			Path   *string `json:"path"`
		}
		if e := body(r, &in); e != nil {
			failureResponse(w, 400, e)
			return
		}
		next, e := a.ChangeAccessWithPath(r.Context(), in.Port, in.Rotate, in.Path)
		if e != nil {
			failureResponse(w, 422, e)
			return
		}
		jsonResponse(w, 200, map[string]string{"adminUrl": next})
		return
	}
	if path == "https/apply" && r.Method == "POST" {
		if e := a.ApplyHTTPS(r.Context()); e != nil {
			failureResponse(w, 422, e)
			return
		}
		jsonResponse(w, 200, map[string]bool{"loaded": true})
		return
	}
	if path == "telegram/test" && r.Method == "POST" {
		s := a.Store.Read()
		if e := a.sendTelegram(r.Context(), s.Settings.Telegram, "RelayDeck 测试通知：此接收目标可投递。"); e != nil {
			failureResponse(w, 502, e)
			return
		}
		jsonResponse(w, 200, map[string]bool{"delivered": true})
		return
	}
	if path == "telegram/verify" && r.Method == "POST" {
		a.verifyTelegram(w, r)
		return
	}
	if parts[0] == "users" && len(parts) == 3 && parts[2] == "delivery" && r.Method == "GET" {
		s := a.Store.Read()
		u := userByID(&s, id)
		if u == nil {
			http.NotFound(w, r)
			return
		}
		base := a.subscriptionBase(s)
		jsonResponse(w, 200, map[string]any{"subscription": base + "/s/" + u.Token, "delivery": base + "/delivery/" + u.Token, "readiness": deliveryReadiness(s, *u)})
		return
	}
	if parts[0] == "servers" && len(parts) == 3 && parts[2] == "registration" && r.Method == "POST" {
		code := randomToken(24)
		expires := time.Now().Add(10 * time.Minute)
		e := a.Store.Update(func(s *State) error {
			v := serverByID(s, id)
			if v == nil {
				return errors.New("服务器不存在")
			}
			if v.MachineID != "" {
				return errors.New("此服务器已绑定设备；重新部署前请先备份 Agent 身份，不可重新生成安装码")
			}
			v.EnrollmentHash = digest(code)
			v.EnrollmentExpires = expires
			return nil
		})
		if e != nil {
			failureResponse(w, 422, e)
			return
		}
		jsonResponse(w, 200, map[string]any{"id": id, "registrationCode": code, "expires": expires})
		return
	}
	if a.protocolAPI(w, r, parts) {
		return
	}
	if a.routingAPI(w, r, parts) {
		return
	}
	if (r.Method != "POST" && r.Method != "DELETE") || len(parts) > 2 || (r.Method == "DELETE" && id == "") {
		failureResponse(w, 405, errors.New("请求方式无效"))
		return
	}
	var response any = map[string]bool{"ok": true}
	var e error
	switch parts[0] {
	case "servers":
		var in struct {
			Name      string `json:"name"`
			Address   string `json:"address"`
			PrivateIP string `json:"privateIp"`
			Region    string `json:"region"`
		}
		if r.Method != "DELETE" {
			e = body(r, &in)
		}
		if e == nil {
			e = a.updateMutation(r, in, &response, func(s *State) error {
				if r.Method == "DELETE" {
					for _, n := range s.Nodes {
						if n.ServerID == id || n.ExitID == id {
							return errors.New("此服务器仍有节点或落地依赖，请先移除或切换")
						}
					}
					for _, o := range s.Outbounds {
						if o.ServerID == id {
							return errors.New("此服务器仍有出站，请先删除出站")
						}
					}
					for _, r := range s.Routes {
						if r.ServerID == id {
							return errors.New("此服务器仍有路由规则，请先删除规则")
						}
					}
					s.RoutingPolicies = slices.DeleteFunc(s.RoutingPolicies, func(p RoutingPolicy) bool { return p.ServerID == id })
					before := len(s.Servers)
					s.Servers = slices.DeleteFunc(s.Servers, func(v Server) bool { return v.ID == id })
					if before == len(s.Servers) {
						return errors.New("服务器不存在")
					}
					return nil
				}
				if !nameValid(in.Name) || !hostValid(in.Address) || in.PrivateIP != "" && !privateIP(in.PrivateIP) {
					return errors.New("名称、地址或内网 IP 无效")
				}
				if id != "" {
					v := serverByID(s, id)
					if v == nil {
						return errors.New("服务器不存在")
					}
					v.Name = in.Name
					v.Address = in.Address
					v.PrivateIP = in.PrivateIP
					v.Region = in.Region
					affected := []string{id}
					for _, n := range s.Nodes {
						if n.ExitID == id {
							affected = append(affected, n.ServerID)
						}
					}
					queue(s, affected, "更新服务器配置")
					return nil
				}
				code := randomToken(24)
				v := Server{ID: newID("srv"), Name: in.Name, Address: in.Address, PrivateIP: in.PrivateIP, Region: in.Region, AgentToken: randomToken(32), BackhaulKey: ssKey(), EnrollmentHash: digest(code), EnrollmentExpires: time.Now().Add(10 * time.Minute)}
				s.Servers = append(s.Servers, v)
				response = map[string]any{"id": v.ID, "registrationCode": code, "expires": v.EnrollmentExpires}
				return nil
			})
		}
	case "nodes":
		var in Node
		if r.Method != "DELETE" {
			e = body(r, &in)
		}
		if e == nil {
			e = a.updateMutation(r, in, &response, func(s *State) error {
				if r.Method == "DELETE" {
					n := nodeByID(s, id)
					if n == nil {
						return errors.New("节点不存在")
					}
					for _, route := range s.Routes {
						if route.NodeID == id || slices.Contains(route.NodeIDs, id) {
							return errors.New("节点被分流规则引用，请先修改规则")
						}
					}
					servers := []string{n.ServerID, n.ExitID}
					s.Nodes = slices.DeleteFunc(s.Nodes, func(v Node) bool { return v.ID == id })
					for i := range s.Users {
						s.Users[i].NodeIDs = slices.DeleteFunc(s.Users[i].NodeIDs, func(n string) bool { return n == id })
						delete(s.Users[i].Credentials, id)
					}
					if e := validateRoutingState(*s); e != nil {
						return e
					}
					queue(s, servers, "删除节点")
					return nil
				}
				old := nodeByID(s, id)
				if id != "" && old == nil {
					return errors.New("节点不存在")
				}
				if old != nil {
					if in.ServerID != old.ServerID || in.Protocol != old.Protocol {
						return errors.New("请通过新建节点变更服务器或协议")
					}
					in.ID = old.ID
					if in.Certificate == "" {
						in.Certificate = old.Certificate
					}
					if in.Key == "" {
						in.Key = old.Key
					}
				} else {
					in.ID = newID("node")
				}
				if e := prepareNodeOptions(s, &in, old); e != nil {
					return e
				}

				if e := validateNode(s, in); e != nil {
					return e
				}
				oldExit := ""
				if old != nil {
					oldExit = old.ExitID
					*old = in
				} else {
					s.Nodes = append(s.Nodes, in)
				}
				if e := validateRoutingState(*s); e != nil {
					return e
				}
				queue(s, []string{in.ServerID, in.ExitID, oldExit}, "更新节点 "+in.Name)
				n := nodeByID(s, in.ID)
				s.Schema = max(s.Schema, 5)
				n.RequiredRevision = serverByID(s, in.ServerID).Desired
				response = map[string]string{"id": in.ID}
				return nil
			})
		}
	case "users":
		var in User
		if r.Method != "DELETE" {
			e = body(r, &in)
		}
		if e == nil {
			e = a.updateMutation(r, in, &response, func(s *State) error {
				old := userByID(s, id)
				if r.Method == "DELETE" {
					if old == nil {
						return errors.New("用户不存在")
					}
					for _, route := range s.Routes {
						if slices.Contains(route.UserIDs, id) {
							return errors.New("此订阅仍被路由规则引用，请先修改规则")
						}
					}
					servers := []string{}
					for _, n := range old.NodeIDs {
						if v := nodeByID(s, n); v != nil {
							servers = append(servers, v.ServerID)
						}
					}
					s.Users = slices.DeleteFunc(s.Users, func(u User) bool { return u.ID == id })
					queue(s, servers, "撤销用户授权")
					return nil
				}
				if in.Limit != 0 {
					return errors.New("流量统计已接入，额度限制尚未开放，当前不能设置流量额度")
				}
				if !nameValid(in.Name) || in.Limit < 0 || in.Limit > 1<<53 {
					return errors.New("名称或额度无效")
				}
				if in.Expires != "" {
					if _, e := time.Parse(time.RFC3339, in.Expires); e != nil {
						return errors.New("到期时间无效")
					}
				}
				seen := map[string]bool{}
				servers := []string{}
				for _, nid := range in.NodeIDs {
					n := nodeByID(s, nid)
					if n == nil || seen[nid] {
						return errors.New("授权节点不存在或重复")
					}
					seen[nid] = true
					servers = append(servers, n.ServerID)
				}
				if id != "" && old == nil {
					return errors.New("用户不存在")
				}
				if old != nil {
					in.ID = old.ID
					in.Token = old.Token
					in.Used = old.Used
					in.Upload = old.Upload
					in.Download = old.Download
					in.UsageSince = old.UsageSince
					in.UsageUpdated = old.UsageUpdated
					in.Credentials = old.Credentials
					for _, nid := range old.NodeIDs {
						if n := nodeByID(s, nid); n != nil {
							servers = append(servers, n.ServerID)
						}
					}
				} else {
					in.ID = newID("user")
					in.Token = randomToken(32)
					in.Used = 0
					in.Upload = 0
					in.Download = 0
					in.UsageSince = time.Time{}
					in.UsageUpdated = time.Time{}
					in.Credentials = map[string]string{}
				}
				for _, nid := range in.NodeIDs {
					if in.Credentials[nid] == "" {
						n := nodeByID(s, nid)
						in.Credentials[nid] = credential(n.Protocol)
						if n.Protocol == "ss2022" {
							in.Credentials[nid] = ssKeyFor(ssMethod(n.ProtocolOptions))
						}
					}
				}
				for nid := range in.Credentials {
					if !seen[nid] {
						delete(in.Credentials, nid)
					}
				}
				in.Required = map[string]int64{}
				if old != nil {
					*old = in
				} else {
					s.Users = append(s.Users, in)
				}
				queue(s, servers, "更新订阅授权 "+in.Name)
				u := userByID(s, in.ID)
				for _, sid := range servers {
					u.Required[sid] = serverByID(s, sid).Desired
				}
				response = map[string]string{"id": in.ID}
				return nil
			})
		}
	case "settings":
		var in Settings
		e = body(r, &in)
		if e == nil {
			e = a.Store.Update(func(s *State) error {
				return a.saveSettings(s, in)
			})
		}
	case "tasks":
		if r.Method != "POST" {
			e = errors.New("请求方式无效")
		} else {
			e = a.Store.Update(func(s *State) error {
				for _, t := range s.Tasks {
					if t.ID == id {
						queue(s, []string{t.ServerID}, "重试配置任务")
						return nil
					}
				}
				return errors.New("任务不存在")
			})
		}
	default:
		http.NotFound(w, r)
		return
	}
	if e != nil {
		failureResponse(w, 422, e)
		return
	}
	jsonResponse(w, 200, response)
}

// Enrollment returns the same identity after a lost response, while the short code is still valid.
func (a *App) enroll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ServerID  string `json:"serverId"`
		Code      string `json:"code"`
		MachineID string `json:"machineId"`
	}
	if e := body(r, &in); e != nil {
		failureResponse(w, 400, e)
		return
	}
	var token string
	e := a.Store.Update(func(s *State) error {
		v := serverByID(s, in.ServerID)
		if v == nil || !time.Now().Before(v.EnrollmentExpires) || !equal(v.EnrollmentHash, digest(in.Code)) {
			return errors.New("注册码错误或已过期")
		}
		if !nameValid(in.MachineID) || v.MachineID != "" && v.MachineID != in.MachineID {
			return errors.New("注册码已绑定另一台设备")
		}
		v.MachineID = in.MachineID
		token = v.AgentToken
		v.LastSeen = time.Now().UTC()
		return nil
	})
	if e != nil {
		failureResponse(w, 403, e)
		return
	}
	jsonResponse(w, 200, map[string]string{"serverId": in.ServerID, "token": token})
}
func (a *App) syncAgent(w http.ResponseWriter, r *http.Request) {
	var in struct {
		StatsSupported bool           `json:"statsSupported"`
		Traffic        *TrafficReport `json:"traffic,omitempty"`
		Epoch          string         `json:"epoch"`
		ServerID       string         `json:"serverId"`
		Applied        int64          `json:"applied"`
		CoreVersion    string         `json:"coreVersion"`
		Error          string         `json:"error"`
	}
	if e := body(r, &in); e != nil {
		failureResponse(w, 400, e)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var deployment *Deployment
	e := a.Store.Update(func(s *State) error {
		v := serverByID(s, in.ServerID)
		if v == nil || token == "" || !equal(token, v.AgentToken) {
			return errors.New("Agent 身份验证失败")
		}
		if e := ingestTraffic(s, v, in.Traffic); e != nil {
			return e
		}
		if v.StatsSupported != in.StatsSupported {
			v.StatsSupported = in.StatsSupported
			queue(s, []string{v.ID}, "更新用户流量统计能力")
		}
		if in.Applied < 0 || !validEpoch(in.Epoch) {
			return errors.New("生效版本无效")
		}
		applied := in.Applied
		if in.Epoch != s.Epoch {
			applied = 0
		}
		if applied > v.Desired {
			return errors.New("生效版本无效")
		}
		v.LastSeen = time.Now().UTC()
		v.CoreVersion = in.CoreVersion
		v.Applied = applied
		oldError := v.Error
		v.Error = ""
		if in.Error != "" {
			v.Error = "配置检查或核心启动失败，请查看 Agent 诊断日志"
			if oldError == "" {
				enqueueNotification(s, "config-error:"+v.ID, "RelayDeck：服务器「"+v.Name+"」配置未应用，请检查生效版本")
			}
		}
		for i := range s.Tasks {
			t := &s.Tasks[i]
			if t.ServerID == v.ID && t.Status == "pending" {
				if t.Revision <= v.Applied {
					t.Status = "applied"
					t.Finished = time.Now().UTC()
				} else if in.Error != "" {
					t.Status = "failed"
					t.Error = "Agent 配置检查或服务启动失败，请查看服务器诊断"
					t.Finished = time.Now().UTC()
				}
			}
		}
		if v.Applied < v.Desired {
			d, e := Compile(*s, v.ID, a.AgentDir)
			if e != nil {
				return e
			}
			deployment = &d
		}
		return nil
	})
	if e != nil {
		failureResponse(w, 403, e)
		return
	}
	jsonResponse(w, 200, map[string]any{"deployment": deployment, "leaseExpires": time.Now().Add(20 * time.Minute).UTC().Format(time.RFC3339)})
}
func (a *App) ResetPassword(password string) error {
	a.auth.credentials.Lock()
	defer a.auth.credentials.Unlock()
	if utf8.RuneCountInString(password) < 8 || len(password) > 128 {
		return errors.New("密码至少 8 个字符，最多 128 字节")
	}
	e := a.Store.Update(func(s *State) error { s.PasswordHash = hashPassword(password); s.SetupToken = ""; return nil })
	if e == nil {
		a.auth.mu.Lock()
		a.auth.sessions = map[string]session{}
		a.auth.mu.Unlock()
	}
	return e
}
func (a *App) NewSetupToken() (string, error) {
	token := randomToken(24)
	e := a.Store.Update(func(s *State) error {
		if s.PasswordHash != "" {
			return errors.New("管理员已初始化，请使用密码重置")
		}
		s.SetupToken = token
		s.SetupExpires = time.Now().Add(15 * time.Minute)
		return nil
	})
	if e == nil {
		e = os.WriteFile(filepath.Join(a.DataDir, "bootstrap.txt"), []byte(token), 0600)
	}
	return token, e
}
func nodePublished(s State, u User, n Node) bool {
	v := serverByID(&s, n.ServerID)
	if v == nil || !n.Enabled || v.Applied < n.RequiredRevision || v.Applied < u.Required[n.ServerID] {
		return false
	}
	if n.ExitID != "" {
		b := serverByID(&s, n.ExitID)
		if b == nil || b.Applied < b.Desired || b.Applied == 0 {
			return false
		}
	}
	return u.Credentials[n.ID] != ""
}
func (s Server) online() bool { return !s.LastSeen.IsZero() && time.Since(s.LastSeen) < 90*time.Second }
