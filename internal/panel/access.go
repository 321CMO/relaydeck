package panel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// A software upgrade must recompile remote Agents even if grants did not change.
func (a *App) PrepareRuntime() error {
	if a.Store.Read().Compiler == Version {
		return nil
	}
	return a.Store.Update(func(s *State) error {
		ids := []string{}
		for _, v := range s.Servers {
			ids = append(ids, v.ID)
		}
		queue(s, ids, "程序升级后重新检查核心配置")
		s.Compiler = Version
		return nil
	})
}

// A failed bind, validation, reload or database commit keeps the previous entry.
func (a *App) ChangeAccess(ctx context.Context, port int, rotate bool) (string, error) {
	a.httpsMu.Lock()
	defer a.httpsMu.Unlock()
	old := a.Store.Read().Settings.HTTPS
	next := old
	if port != 0 {
		next.AdminPort = port
	}
	if rotate {
		next.AdminPath = randomToken(24)
	}
	if !validAdminAccess(next) {
		return "", errors.New("管理端口或安全路径无效")
	}
	if next.AdminPort != old.AdminPort {
		listener, e := net.Listen("tcp", ":"+strconv.Itoa(next.AdminPort))
		if e != nil {
			return "", errors.New("新端口已被占用，原入口保持可用")
		}
		listener.Close()
	}
	for _, n := range a.Store.Read().Nodes {
		if n.Enabled && n.Protocol != "hy2" && n.Port == next.AdminPort {
			return "", errors.New("管理端口与节点 TCP 端口冲突")
		}
	}
	text, e := Caddyfile(next, "127.0.0.1:8787", a.DataDir)
	if e != nil {
		return "", e
	}
	path := filepath.Join(a.DataDir, "Caddyfile.access-pending")
	defer os.Remove(path)
	transition := text
	if next.AdminPort != old.AdminPort && validAdminAccess(old) {
		previous, err := Caddyfile(old, "127.0.0.1:8787", a.DataDir)
		if err != nil {
			return "", err
		}
		marker := "\n" + old.Domain + ":" + strconv.Itoa(old.AdminPort) + " {"
		index := strings.LastIndex(previous, marker)
		if index < 0 {
			return "", errors.New("原管理入口配置无效")
		}
		// Keep this listener until the initiating HTTP response is delivered.
		// The Go host/path guard rejects old requests immediately after commit.
		transition += previous[index:]
	}
	if e = writePrivateFile(path, []byte(transition)); e != nil {
		return "", e
	}
	bin := a.Caddy
	if bin == "" {
		bin = "/opt/relaydeck/core/caddy"
	}
	load := func(path string) error {
		for _, verb := range []string{"validate", "reload"} {
			args := []string{verb, "--config", path, "--adapter", "caddyfile"}
			if verb == "reload" {
				args = append(args, "--address", "127.0.0.1:2019")
			}
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			if e := cmd.Run(); e != nil {
				return e
			}
		}
		return nil
	}
	if e = load(path); e != nil {
		return "", errors.New("新入口未通过 Caddy 检查或加载，原入口保留")
	}
	configPath, entryPath := filepath.Join(a.DataDir, "Caddyfile"), filepath.Join(a.DataDir, "admin-entry.txt")
	previousConfig, _ := os.ReadFile(configPath)
	previousEntry, _ := os.ReadFile(entryPath)
	rollback := func() {
		_ = writePrivateFile(configPath, previousConfig)
		_ = writePrivateFile(entryPath, previousEntry)
		_ = load(configPath)
	}
	if e = writePrivateFile(configPath, []byte(text)); e == nil {
		e = writePrivateFile(entryPath, []byte(a.AdminURL(next)+"\n"))
	}
	if e == nil {
		e = a.Store.Update(func(s *State) error {
			if httpsFingerprint(s.Settings.HTTPS) != httpsFingerprint(old) {
				return errors.New("HTTPS 设置已变化，请刷新后重试")
			}
			s.Schema = max(s.Schema, 3)
			s.Settings.HTTPS = next
			s.Settings.HTTPS.Status = "pending"
			s.Settings.HTTPS.LoadedHash = httpsFingerprint(next)
			return nil
		})
	}
	if e != nil {
		rollback()
		return "", errors.New("入口保存失败，已尝试恢复原入口")
	}
	a.auth.mu.Lock()
	a.auth.sessions = map[string]session{}
	a.auth.mu.Unlock()
	if transition != text {
		go func() {
			time.Sleep(2 * time.Second)
			a.httpsMu.Lock()
			defer a.httpsMu.Unlock()
			if httpsFingerprint(a.Store.Read().Settings.HTTPS) != httpsFingerprint(next) {
				return
			}
			cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(cleanup, bin, "reload", "--config", configPath, "--adapter", "caddyfile", "--address", "127.0.0.1:2019")
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			_ = cmd.Run() // A failed cleanup leaves only a rejected old listener until restart.
		}()
	}
	return a.AdminURL(next), nil
}

func validAdminAccess(h HTTPS) bool {
	if h.AdminPort < 1024 || h.AdminPort > 65535 || h.AdminPort == 8787 || h.AdminPort == 2019 || h.AdminPort == 18999 || h.AdminPort == 10085 {
		return false
	}
	if len(h.AdminPath) < 24 || len(h.AdminPath) > 96 {
		return false
	}
	for _, c := range h.AdminPath {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func (a *App) AdminURL(h HTTPS) string {
	if !validAdminAccess(h) {
		return a.BaseURL + "/"
	}
	u, _ := url.Parse(a.BaseURL)
	u.Host = net.JoinHostPort(h.Domain, strconv.Itoa(h.AdminPort))
	u.Path = "/" + h.AdminPath + "/"
	return u.String()
}

func adminCookiePath(h HTTPS) string {
	if validAdminAccess(h) {
		return "/" + h.AdminPath + "/"
	}
	return "/"
}

func publicEndpoint(p string) bool {
	return strings.HasPrefix(p, "/s/") || strings.HasPrefix(p, "/delivery/") || p == "/api/agent/enroll" || p == "/api/agent/sync" || p == "/healthz"
}

// Host and path are checked by both Caddy and the application; no trusted-header bypass.
func (a *App) adminRequest(r *http.Request, h HTTPS) (*http.Request, bool) {
	if !validAdminAccess(h) {
		return r, a.Development
	}
	u, _ := url.Parse(a.AdminURL(h))
	prefix := "/" + h.AdminPath + "/"
	if !strings.EqualFold(r.Host, u.Host) || !strings.HasPrefix(r.URL.Path, prefix) || r.URL.RawPath != "" || strings.Contains(r.URL.Path, "//") || strings.Contains(r.URL.Path, "/../") || strings.Contains(r.URL.Path, "/./") {
		return r, false
	}
	copy := r.Clone(r.Context())
	copy.URL.Path = "/" + strings.TrimPrefix(r.URL.Path, prefix)
	return copy, true
}

// Called while the panel is stopped, or before its HTTP listener starts.
func (a *App) ConfigureAccess(port int, rotate bool) error {
	h := a.Store.Read().Settings.HTTPS
	if !hostValid(h.Domain) {
		return errors.New("请先配置面板域名")
	}
	changed := false
	if port != 0 && port != h.AdminPort {
		h.AdminPort = port
		changed = true
	}
	if h.AdminPort == 0 {
		listener, e := net.Listen("tcp", ":0")
		if e != nil {
			return e
		}
		h.AdminPort = listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		changed = true
	}
	if h.AdminPath == "" || rotate {
		h.AdminPath = randomToken(24)
		changed = true
	}
	if !validAdminAccess(h) {
		return errors.New("管理端口应为 1024–65535，且不能使用内部保留端口")
	}
	for _, n := range a.Store.Read().Nodes {
		// Caddy occupies TCP only; HY2 UDP may use the same numeric port.
		if n.Enabled && n.Protocol != "hy2" && n.Port == h.AdminPort {
			return errors.New("管理端口与节点 TCP 端口冲突")
		}
	}
	if changed {
		listener, e := net.Listen("tcp", ":"+strconv.Itoa(h.AdminPort))
		if e != nil {
			return errors.New("管理端口已被占用，请选择其他端口")
		}
		listener.Close()
		h.Status = "pending"
		h.LoadedHash = ""
	}
	if !changed && h.LoadedHash != "" {
		if _, e := os.Stat(filepath.Join(a.DataDir, "Caddyfile")); e == nil {
			if e := writePrivateFile(filepath.Join(a.DataDir, "admin-entry.txt"), []byte(a.AdminURL(h)+"\n")); e != nil {
				return e
			}
			if a.Store.Read().Schema < 3 {
				return a.Store.Update(func(s *State) error { s.Schema = max(s.Schema, 3); return nil })
			}
			return nil
		}
	}
	c, e := Caddyfile(h, "127.0.0.1:8787", a.DataDir)
	if e != nil {
		return e
	}
	if e = stageHTTPSAssets(h, a.DataDir); e != nil {
		return e
	}
	if e = writePrivateFile(filepath.Join(a.DataDir, "Caddyfile"), []byte(c)); e != nil {
		return e
	}
	if e = writePrivateFile(filepath.Join(a.DataDir, "admin-entry.txt"), []byte(a.AdminURL(h)+"\n")); e != nil {
		return e
	}
	return a.Store.Update(func(s *State) error {
		s.Schema = max(s.Schema, 3)
		s.Settings.HTTPS = h
		s.Settings.HTTPS.LoadedHash = httpsFingerprint(h)
		return nil
	})
}
