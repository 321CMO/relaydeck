package panel

import (
	"encoding/base64"
	"errors"
	"fmt"
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
	format := r.URL.Query().Get("format")
	ua := strings.ToLower(r.UserAgent())
	if format == "" && !strings.Contains(ua, "clash") && !strings.Contains(ua, "mihomo") && !strings.Contains(ua, "shadowrocket") {
		a.delivery(w, r)
		return
	}
	u, nodes, e := subscriptionNodes(s, r.PathValue("token"))
	if e != nil {
		status := 403
		if u.ID == "" {
			status = 404
		}
		failureResponse(w, status, e)
		return
	}
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
	if header := clientUsageHeader(u); header != "" {
		w.Header().Set("Subscription-Userinfo", header)
	}
	w.Header().Set("Profile-Web-Page-Url", a.subscriptionBase(s)+"/s/"+u.Token)
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

// Keep already published subscription addresses stable during transient TLS probe failures.
func (a *App) subscriptionBase(s State) string {
	if domain := s.Settings.HTTPS.PublishedDomain; domain != "" {
		return "https://" + domain
	}
	return a.BaseURL
}
