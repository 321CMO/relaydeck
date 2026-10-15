package panel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// BootstrapHTTPS records the installer's initial automatic HTTPS configuration.
// The public TLS probe still has to verify this exact instance before it is active.
func (a *App) BootstrapHTTPS() error {
	if !validBaseURL(a.BaseURL, false) {
		return errors.New("首次 HTTPS 配置需要完整 HTTPS 中心地址")
	}
	u, _ := url.Parse(a.BaseURL)
	return a.Store.Update(func(s *State) error {
		if s.Settings.HTTPS.Domain != "" {
			return nil
		}
		s.Settings.HTTPS = HTTPS{Domain: u.Hostname(), Mode: "auto", Status: "pending"}
		s.Settings.HTTPS.LoadedHash = httpsFingerprint(s.Settings.HTTPS)
		return nil
	})
}

func (a *App) ApplyHTTPS(ctx context.Context) error {
	a.httpsMu.Lock()
	defer a.httpsMu.Unlock()
	s := a.Store.Read()
	h := s.Settings.HTTPS
	c, e := Caddyfile(h, "127.0.0.1:8787", a.DataDir)
	if e != nil {
		return e
	}
	base, _ := url.Parse(a.BaseURL)
	if !a.Development && h.Domain != base.Hostname() {
		return errors.New("面板域名必须与安装时的中心地址一致；域名迁移需先更新中心和 Agent 地址")
	}
	bin := a.Caddy
	if bin == "" {
		bin = "/opt/relaydeck/core/caddy"
	}
	if h.Mode == "dns" {
		modules, e := exec.CommandContext(ctx, bin, "list-modules").Output()
		if e != nil || !strings.Contains(string(modules), "dns.providers.cloudflare") {
			return errors.New("当前 Caddy 未包含 Cloudflare DNS 模块，请安装对应构建")
		}
	}
	dir := a.DataDir
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	path := filepath.Join(dir, "Caddyfile.pending")
	if e = os.WriteFile(path, []byte(c), 0600); e != nil {
		return e
	}
	if h.Mode == "import" {
		if e = os.WriteFile(filepath.Join(a.DataDir, "panel.crt"), []byte(h.Certificate), 0600); e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(a.DataDir, "panel.key"), []byte(h.Key), 0600); e != nil {
			return e
		}
	}
	for _, args := range [][]string{{"validate", "--config", path, "--adapter", "caddyfile"}, {"reload", "--address", "127.0.0.1:2019", "--config", path, "--adapter", "caddyfile"}} {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = append(os.Environ(), "CF_API_TOKEN="+h.CloudflareToken)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if e = cmd.Run(); e != nil {
			_ = a.Store.Update(func(s *State) error {
				s.Settings.HTTPS.Status = "failed"
				enqueueNotification(s, "https-apply", "RelayDeck：HTTPS 配置加载失败，请在终端诊断 Caddy 服务")
				return nil
			})
			return errors.New("Caddy 配置检查或加载失败，原配置未替换；请检查 Caddy 安装与服务")
		}
	}
	if e = os.Rename(path, filepath.Join(dir, "Caddyfile")); e != nil {
		return errors.New("HTTPS 已加载，但配置文件持久化失败，请检查目录权限")
	}
	_ = a.Store.Update(func(s *State) error {
		s.Settings.HTTPS.Status = "pending"
		s.Settings.HTTPS.LoadedHash = httpsFingerprint(h)
		return nil
	})
	a.checkHTTPS(ctx)
	return nil
}

func httpsFingerprint(h HTTPS) string {
	h.Status = ""
	h.Expires = ""
	h.LoadedHash = ""
	b, _ := json.Marshal(h)
	return digest(string(b))
}

// Probe the public URL with normal CA validation and verify this exact panel instance.
func (a *App) checkHTTPS(ctx context.Context) {
	s := a.Store.Read()
	h := s.Settings.HTTPS
	if h.Domain == "" || h.Status == "unconfigured" || h.LoadedHash != httpsFingerprint(h) {
		return
	}
	domains := []string{h.Domain}
	if h.SubscriptionDomain != "" && h.SubscriptionDomain != h.Domain {
		domains = append(domains, h.SubscriptionDomain)
	}
	unavailable := func() {
		_ = a.Store.Update(func(s *State) error {
			if s.Settings.HTTPS.LoadedHash == h.LoadedHash && s.Settings.HTTPS.Status == "active" {
				s.Settings.HTTPS.Status = "pending"
				enqueueNotification(s, "https-unavailable", "RelayDeck：面板 HTTPS 对外访问验证失败，请检查证书、DNS 与 Caddy")
			}
			return nil
		})
	}
	expires := ""
	for _, domain := range domains {
		req, e := http.NewRequestWithContext(ctx, "GET", "https://"+domain+"/healthz", nil)
		if e != nil {
			unavailable()
			return
		}
		client := &http.Client{Transport: a.ProbeTransport, Timeout: 5 * time.Second, CheckRedirect: func(r *http.Request, v []*http.Request) error { return http.ErrUseLastResponse }}
		res, e := client.Do(req)
		if e != nil {
			unavailable()
			return
		}
		var result struct {
			Instance string `json:"instance"`
		}
		e = json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&result)
		res.Body.Close()
		if e != nil || res.StatusCode != 200 || res.TLS == nil || len(res.TLS.PeerCertificates) == 0 || result.Instance != a.Instance {
			unavailable()
			return
		}
		expiry := res.TLS.PeerCertificates[0].NotAfter.UTC().Format(time.RFC3339)
		if expires == "" || expiry < expires {
			expires = expiry
		}
	}
	_ = a.Store.Update(func(s *State) error {
		if httpsFingerprint(s.Settings.HTTPS) != httpsFingerprint(h) {
			return nil
		}
		s.Settings.HTTPS.Status = "active"
		s.Settings.HTTPS.Expires = expires
		expiry, _ := time.Parse(time.RFC3339, expires)
		if time.Until(expiry) < 7*24*time.Hour {
			enqueueNotification(s, "certificate-expiry:"+expires, "RelayDeck：面板 HTTPS 证书将在 7 天内到期，请检查自动续期")
		}
		return nil
	})
}
