package panel

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func subscriptionNodes(s State, token string) (User, []Node, error) {
	var u *User
	for i := range s.Users {
		if equal(s.Users[i].Token, token) {
			u = &s.Users[i]
			break
		}
	}
	if u == nil {
		return User{}, nil, errors.New("订阅不存在")
	}
	if !activeUser(*u, time.Now()) {
		return *u, nil, errors.New("此订阅已停用或到期")
	}
	nodes := []Node{}
	for _, n := range s.Nodes {
		if slices.Contains(u.NodeIDs, n.ID) && nodePublished(s, *u, n) {
			nodes = append(nodes, n)
		}
	}
	return *u, nodes, nil
}
func nodeName(n Node) string { return n.Name + " · " + n.ID[len(n.ID)-5:] }
func uri(n Node, u User) string {
	host := net.JoinHostPort(n.Address, strconv.Itoa(n.Port))
	q := url.Values{}
	name := url.PathEscape(nodeName(n))
	switch n.Protocol {
	case "reality":
		q.Set("encryption", "none")
		q.Set("security", "reality")
		q.Set("sni", n.SNI)
		q.Set("fp", "chrome")
		q.Set("pbk", n.PublicKey)
		q.Set("sid", n.ShortID)
		q.Set("flow", "xtls-rprx-vision")
		q.Set("type", "tcp")
		return "vless://" + u.Credentials[n.ID] + "@" + host + "?" + q.Encode() + "#" + name
	case "hy2":
		q.Set("sni", n.SNI)
		return "hysteria2://" + url.QueryEscape(u.Credentials[n.ID]) + "@" + host + "/?" + q.Encode() + "#" + name
	default:
		password := n.ServerKey + ":" + u.Credentials[n.ID]
		auth := base64.RawURLEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:" + password))
		return "ss://" + auth + "@" + host + "#" + name
	}
}
func clashConfig(s State, u User, nodes []Node) ([]byte, error) {
	proxies := []map[string]any{}
	names := []string{}
	for _, n := range nodes {
		p := map[string]any{"name": nodeName(n), "server": n.Address, "port": n.Port, "udp": true}
		names = append(names, nodeName(n))
		switch n.Protocol {
		case "reality":
			p["type"] = "vless"
			p["uuid"] = u.Credentials[n.ID]
			p["network"] = "tcp"
			p["tls"] = true
			p["flow"] = "xtls-rprx-vision"
			p["servername"] = n.SNI
			p["client-fingerprint"] = "chrome"
			p["reality-opts"] = map[string]string{"public-key": n.PublicKey, "short-id": n.ShortID}
		case "hy2":
			p["type"] = "hysteria2"
			p["password"] = u.Credentials[n.ID]
			p["sni"] = n.SNI
			p["skip-cert-verify"] = false
			if n.HopStart > 0 {
				p["ports"] = fmt.Sprintf("%d-%d", n.HopStart, n.HopEnd)
				p["hop-interval"] = n.HopInterval
			}
		case "ss2022":
			p["type"] = "ss"
			p["cipher"] = "2022-blake3-aes-128-gcm"
			p["password"] = n.ServerKey + ":" + u.Credentials[n.ID]
		}
		proxies = append(proxies, p)
	}
	rules := []string{"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", "IP-CIDR6,::1/128,DIRECT,no-resolve", "IP-CIDR6,fc00::/7,DIRECT,no-resolve"}
	for _, r := range s.Routes {
		if r.Scope != "client" {
			continue
		}
		if r.NodeID != "" && !slices.Contains(u.NodeIDs, r.NodeID) {
			continue
		}
		kind := map[string]string{"domain": "DOMAIN", "suffix": "DOMAIN-SUFFIX", "cidr": "IP-CIDR"}[r.Kind]
		if strings.Contains(r.Value, ":") {
			kind = "IP-CIDR6"
		}
		action := map[string]string{"direct": "DIRECT", "reject": "REJECT", "proxy": "代理选择"}[r.Action]
		rules = append(rules, kind+","+r.Value+","+action)
	}
	if s.Settings.RoutingPreset == "china-direct" {
		rules = append(rules, "GEOIP,CN,DIRECT")
	}
	rules = append(rules, "MATCH,代理选择")
	selected := append([]string{"自动选择"}, names...)
	cfg := map[string]any{"mixed-port": 7890, "allow-lan": false, "mode": "rule", "log-level": "warning", "ipv6": true, "proxies": proxies, "proxy-groups": []map[string]any{{"name": "代理选择", "type": "select", "proxies": selected}, {"name": "自动选择", "type": "url-test", "proxies": names, "url": "https://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50}}, "rules": rules, "dns": map[string]any{"enable": true, "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16", "fake-ip-filter": []string{"*.lan", "*.local"}, "default-nameserver": []string{"223.5.5.5", "1.1.1.1"}, "nameserver": []string{"https://dns.alidns.com/dns-query"}, "fallback": []string{"https://1.1.1.1/dns-query"}, "fallback-filter": map[string]any{"geoip": true, "geoip-code": "CN"}}}
	return yaml.Marshal(cfg)
}
func (a *App) subscription(w http.ResponseWriter, r *http.Request) {
	s := a.Store.Read()
	u, nodes, e := subscriptionNodes(s, r.PathValue("token"))
	if e != nil {
		status := 403
		if u.ID == "" {
			status = 404
		}
		failureResponse(w, status, e)
		return
	}
	format := r.URL.Query().Get("format")
	ua := strings.ToLower(r.UserAgent())
	if format == "" {
		switch {
		case strings.Contains(ua, "clash") || strings.Contains(ua, "mihomo"):
			format = "clash"
		case strings.Contains(ua, "shadowrocket"):
			format = "shadowrocket"
		default:
			http.Redirect(w, r, "/delivery/"+u.Token, http.StatusSeeOther)
			return
		}
	}
	if format != "clash" && format != "shadowrocket" {
		failureResponse(w, 400, errors.New("仅支持 Clash Verge 和 Shadowrocket"))
		return
	}
	if len(nodes) == 0 {
		w.Header().Set("Retry-After", "15")
		failureResponse(w, 503, errors.New("授权节点尚未应用，请稍后刷新订阅"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Profile-Update-Interval", "6")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="relaydeck-subscription.txt"`)
	// Usage headers are omitted until a verified per-user traffic source is connected.
	if format == "clash" {
		b, e := clashConfig(s, u, nodes)
		if e != nil {
			failureResponse(w, 500, errors.New("订阅生成失败"))
			return
		}
		w.Write(b)
		return
	}
	links := []string{}
	for _, n := range nodes {
		links = append(links, uri(n, u))
	}
	w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))))
}

var deliveryTemplate = template.Must(template.New("delivery").Parse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RelayDeck · 订阅交付</title><style>body{font:16px system-ui;background:#f4f6fb;color:#172132;margin:0;padding:48px 20px}main{max-width:600px;margin:auto;background:white;padding:32px;border-radius:20px}h1{font-size:28px}a{display:block;padding:16px;margin:12px 0;background:#eeefff;color:#4938bf;border-radius:12px;text-decoration:none}code{display:block;overflow-wrap:anywhere;font-size:13px;background:#f5f6f8;padding:16px}p{line-height:1.7;color:#596479}small{color:#687286}</style><main><small>RELAYDECK / PERSONAL SUBSCRIPTION</small><h1>{{.Name}}的订阅</h1><p>{{.Status}}</p><code>{{.URL}}</code><a href="{{.Clash}}">下载 Clash Verge 配置（含分流与 HY2 跳跃）</a><a href="{{.Shadow}}">下载 Shadowrocket 节点订阅</a><p>在客户端添加上方固定订阅地址，客户端将识别自己的格式。此地址包含访问凭据，请仅保留在自己的设备中。</p><small>Shadowrocket 分流配置与端口跳跃仍需实际客户端验证；当前导出使用固定 HY2 端口。节点列表随管理员授权更新。</small></main></html>`))

func (a *App) delivery(w http.ResponseWriter, r *http.Request) {
	s := a.Store.Read()
	u, nodes, e := subscriptionNodes(s, r.PathValue("token"))
	if e != nil {
		status := 403
		if u.ID == "" {
			status = 404
		}
		failureResponse(w, status, e)
		return
	}
	status := fmt.Sprintf("已应用 %d 个授权节点。实际网络连通性请在客户端检测。", len(nodes))
	if len(nodes) == 0 {
		status = "节点正在配置中，稍后刷新同一订阅地址即可。"
	}
	base := a.BaseURL + "/s/" + u.Token
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = deliveryTemplate.Execute(w, map[string]string{"Name": u.Name, "Status": status, "URL": base, "Clash": base + "?format=clash", "Shadow": base + "?format=shadowrocket"})
}
