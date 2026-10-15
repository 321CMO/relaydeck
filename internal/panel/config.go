package panel

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

func parseCertificate(cert, key, domain string) (*x509.Certificate, error) {
	pair, e := tls.X509KeyPair([]byte(cert), []byte(key))
	if e != nil {
		return nil, errors.New("证书链或私钥无效，或两者不匹配")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, errors.New("证书格式无效")
	}
	if e = leaf.VerifyHostname(domain); e != nil {
		return nil, errors.New("证书未覆盖此域名")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("证书尚未生效或已过期")
	}
	return leaf, nil
}

type Deployment struct {
	TrafficUsers    []string          `json:"trafficUsers"`
	Epoch           string            `json:"epoch,omitempty"`
	Revision        int64             `json:"revision"`
	Config          json.RawMessage   `json:"config"`
	Files           map[string]string `json:"files"`
	Hops            []Hop             `json:"hops"`
	BackhaulSources []string          `json:"backhaulSources"`
	Expires         map[string]string `json:"expires"`
}

func VersionDir(base string, revision int64, epoch string) (string, error) {
	if revision < 1 || !validEpoch(epoch) {
		return "", errors.New("配置版本或恢复标识无效")
	}
	if epoch != "" {
		return filepath.Join(base, "versions", epoch, strconv.FormatInt(revision, 10)), nil
	}
	return filepath.Join(base, "versions", strconv.FormatInt(revision, 10)), nil
}

type Hop struct {
	NodeID string `json:"nodeId"`
	Start  int    `json:"start"`
	End    int    `json:"end"`
	Port   int    `json:"port"`
}

// Compile uses managed tags and never exposes internal backhaul credentials in subscriptions.
func Compile(s State, serverID, dir string) (Deployment, error) {
	server := serverByID(&s, serverID)
	if server == nil {
		return Deployment{}, errors.New("服务器不存在")
	}
	baseDir := dir
	var e error
	dir, e = VersionDir(dir, server.Desired, s.Epoch)
	if e != nil {
		return Deployment{}, e
	}
	d := Deployment{Epoch: s.Epoch, Revision: server.Desired, Files: map[string]string{}, Hops: []Hop{}, Expires: map[string]string{}}
	in := []map[string]any{}
	out := []map[string]any{{"type": "direct", "tag": "direct"}}
	rules := []map[string]any{}
	providers := []map[string]any{}
	for _, n := range s.Nodes {
		if n.ServerID != serverID || !n.Enabled {
			continue
		}
		users := []map[string]any{}
		for _, u := range s.Users {
			if !activeUser(u, time.Now()) {
				continue
			}
			auth, ok := u.Credentials[n.ID]
			if !ok {
				continue
			}
			entry := map[string]any{"name": u.ID}
			switch n.Protocol {
			case "reality":
				entry["uuid"] = auth
				entry["flow"] = "xtls-rprx-vision"
			default:
				entry["password"] = auth
			}
			users = append(users, entry)
			if u.Expires != "" {
				d.Expires[u.ID] = u.Expires
			}
		}
		if len(users) == 0 {
			continue
		}
		entry := map[string]any{"tag": n.ID, "listen": "::", "listen_port": n.Port, "users": users}
		switch n.Protocol {
		case "reality":
			host, port, _ := net.SplitHostPort(n.Target)
			p, _ := strconv.Atoi(port)
			entry["type"] = "vless"
			entry["tls"] = map[string]any{"enabled": true, "server_name": n.SNI, "reality": map[string]any{"enabled": true, "handshake": map[string]any{"server": host, "server_port": p}, "private_key": n.PrivateKey, "short_id": []string{n.ShortID}}}
		case "hy2":
			entry["type"] = "hysteria2"
			tlsConf := map[string]any{"enabled": true, "server_name": n.SNI}
			if n.TLSMode == "import" {
				cert := filepath.Join(dir, "certificates", n.ID+".crt")
				key := filepath.Join(dir, "certificates", n.ID+".key")
				d.Files["certificates/"+n.ID+".crt"] = n.Certificate
				d.Files["certificates/"+n.ID+".key"] = n.Key
				tlsConf["certificate_path"] = cert
				tlsConf["key_path"] = key
			} else {
				tag := "cert_" + n.ID
				providers = append(providers, map[string]any{"type": "acme", "tag": tag, "domain": []string{n.SNI}, "data_directory": filepath.Join(baseDir, "acme", n.ID), "disable_tls_alpn_challenge": true})
				tlsConf["certificate_provider"] = tag
			}
			entry["tls"] = tlsConf
			if n.HopStart > 0 {
				d.Hops = append(d.Hops, Hop{n.ID, n.HopStart, n.HopEnd, n.Port})
			}
		case "ss2022":
			entry["type"] = "shadowsocks"
			entry["method"] = "2022-blake3-aes-128-gcm"
			entry["password"] = n.ServerKey
		}
		in = append(in, entry)
		if n.ExitID != "" {
			b := serverByID(&s, n.ExitID)
			if b == nil || !privateIP(b.PrivateIP) {
				return d, errors.New("落地内网地址不可用")
			}
			tag := "via_" + n.ExitID
			already := false
			for _, o := range out {
				if o["tag"] == tag {
					already = true
				}
			}
			if !already {
				out = append(out, map[string]any{"type": "shadowsocks", "tag": tag, "server": b.PrivateIP, "server_port": 18999, "method": "2022-blake3-aes-128-gcm", "password": backhaulKey(s, n.ServerID, n.ExitID)})
			}
			rules = append(rules, map[string]any{"inbound": []string{n.ID}, "action": "route", "outbound": tag})
		}
	}
	// Each entry server gets a separate authenticated private listener on the exit.
	sources := map[string]bool{}
	for _, n := range s.Nodes {
		if n.ExitID == serverID && n.Enabled {
			sources[n.ServerID] = true
		}
	}
	if len(sources) > 0 {
		if !privateIP(server.PrivateIP) {
			return d, errors.New("落地机缺少有效内网地址")
		}
		ssUsers := []map[string]any{}
		for src := range sources {
			source := serverByID(&s, src)
			if source == nil || !privateIP(source.PrivateIP) {
				return d, errors.New("入口机缺少内网地址")
			}
			d.BackhaulSources = append(d.BackhaulSources, source.PrivateIP)
			ssUsers = append(ssUsers, map[string]any{"name": "backhaul_" + src, "password": backhaulUserKey(s, src, serverID)})
		}
		in = append(in, map[string]any{"type": "shadowsocks", "tag": "internal-backhaul", "listen": server.PrivateIP, "listen_port": 18999, "method": "2022-blake3-aes-128-gcm", "password": backhaulServerKey(s, serverID), "users": ssUsers})
		rules = append([]map[string]any{{"inbound": []string{"internal-backhaul"}, "action": "route", "outbound": "direct"}}, rules...)
	}
	custom := []map[string]any{}
	for _, r := range s.Routes {
		if r.Scope != "server" {
			continue
		}
		rule := map[string]any{}
		if r.NodeID != "" {
			n := nodeByID(&s, r.NodeID)
			if n == nil || n.ServerID != serverID {
				continue
			}
			rule["inbound"] = []string{r.NodeID}
		}
		switch r.Kind {
		case "suffix":
			rule["domain_suffix"] = []string{r.Value}
		case "domain":
			rule["domain"] = []string{r.Value}
		case "cidr":
			rule["ip_cidr"] = []string{r.Value}
		default:
			return d, errors.New("规则匹配类型无效")
		}
		if r.Action == "reject" {
			rule["action"] = "reject"
		} else if r.Action == "direct" {
			rule["action"] = "route"
			rule["outbound"] = "direct"
		} else {
			return d, errors.New("服务端规则仅支持直连或拒绝，落地在节点中选择")
		}
		custom = append(custom, rule)
	}
	// Internal ingress bypasses public ingress rules to prevent loops.
	if len(sources) > 0 {
		rules = append(rules[:1], append(custom, rules[1:]...)...)
	} else {
		rules = append(custom, rules...)
	}
	slices.Sort(d.BackhaulSources)
	config := map[string]any{"log": map[string]any{"level": "warn", "timestamp": true}, "inbounds": in, "outbounds": out, "route": map[string]any{"rules": rules, "final": "direct"}}
	if server.StatsSupported {
		users := []string{}
		for _, u := range s.Users {
			for _, n := range s.Nodes {
				if n.ServerID == serverID && slices.Contains(u.NodeIDs, n.ID) {
					users = append(users, u.ID)
					break
				}
			}
		}
		d.TrafficUsers = users
		config["experimental"] = map[string]any{"v2ray_api": map[string]any{"listen": "127.0.0.1:10085", "stats": map[string]any{"enabled": true, "users": users}}}
	}
	if len(providers) > 0 {
		config["certificate_providers"] = providers
	}
	b, e := json.MarshalIndent(config, "", "  ")
	d.Config = b
	return d, e
}

// Secrets are generated once as part of server enrollment; the stable key is never public.
func deriveSS(secret, context string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(context))
	return base64.StdEncoding.EncodeToString(h.Sum(nil)[:16])
}
func backhaulServerKey(s State, exit string) string {
	for _, v := range s.Servers {
		if v.ID == exit {
			return v.BackhaulKey
		}
	}
	return ""
}
func backhaulUserKey(s State, entry, exit string) string {
	for _, v := range s.Servers {
		if v.ID == exit {
			return deriveSS(v.BackhaulKey, "backhaul-user:"+entry)
		}
	}
	return ""
}
func backhaulKey(s State, entry, exit string) string {
	return backhaulServerKey(s, exit) + ":" + backhaulUserKey(s, entry, exit)
}
func Caddyfile(h HTTPS, backend string, dir string) (string, error) {
	if !hostValid(h.Domain) || strings.Contains(h.Domain, ":") {
		return "", errors.New("请输入有效的面板域名")
	}
	if h.Mode != "auto" && h.Mode != "dns" && h.Mode != "import" {
		return "", errors.New("HTTPS 方式无效")
	}
	domains := h.Domain
	if h.SubscriptionDomain != "" && h.SubscriptionDomain != h.Domain {
		if !hostValid(h.SubscriptionDomain) {
			return "", errors.New("订阅域名无效")
		}
		domains += " , " + h.SubscriptionDomain
	}
	var b strings.Builder
	b.WriteString("{\n admin 127.0.0.1:2019\n servers {\n  protocols h1 h2\n }\n")
	if h.Email != "" {
		if strings.ContainsAny(h.Email, "\r\n{}\"") {
			return "", errors.New("邮箱格式无效")
		}
		fmt.Fprintf(&b, " email %s\n", h.Email)
	}
	b.WriteString("}\n")
	if (h.AdminPort != 0 || h.AdminPath != "") && !validAdminAccess(h) {
		return "", errors.New("管理端口或安全路径无效")
	}
	writeTLS := func() error {
		switch h.Mode {
		case "dns":
			if h.CloudflareToken == "" {
				return errors.New("请填写 Cloudflare Token")
			}
			// Caddy resolves this private file in its own process, including after restart.
			fmt.Fprintf(&b, " tls {\n  dns cloudflare %q\n }\n", "{file."+filepath.Join(httpsAssetsDir(h, dir), "cloudflare.token")+"}")
		case "import":
			if _, e := parseCertificate(h.Certificate, h.Key, h.Domain); e != nil {
				return e
			}
			if h.SubscriptionDomain != "" {
				if _, e := parseCertificate(h.Certificate, h.Key, h.SubscriptionDomain); e != nil {
					return e
				}
			}
			certDir := httpsAssetsDir(h, dir)
			fmt.Fprintf(&b, " tls %q %q\n", filepath.Join(certDir, "panel.crt"), filepath.Join(certDir, "panel.key"))
		}
		return nil
	}
	fmt.Fprintf(&b, "%s {\n", domains)
	b.WriteString(" @public path /s/* /delivery/* /api/agent/enroll /api/agent/sync /healthz\n handle @public {\n")
	fmt.Fprintf(&b, "  reverse_proxy %s\n }\n handle {\n  respond 404\n }\n", backend)
	if e := writeTLS(); e != nil {
		return "", e
	}
	b.WriteString("}\n")
	if validAdminAccess(h) {
		fmt.Fprintf(&b, "%s:%d {\n @admin path /%s/*\n handle @admin {\n  reverse_proxy %s\n }\n handle {\n  respond 404\n }\n", h.Domain, h.AdminPort, h.AdminPath, backend)
		if e := writeTLS(); e != nil {
			return "", e
		}
		b.WriteString("}\n")
	}
	return b.String(), nil
}
func WriteDeployment(d Deployment, dir string) error {
	for p, content := range d.Files {
		clean := filepath.Clean(p)
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
			return errors.New("配置文件路径无效")
		}
		dest := filepath.Join(dir, clean)
		if e := os.MkdirAll(filepath.Dir(dest), 0700); e != nil {
			return e
		}
		if e := os.WriteFile(dest, []byte(content), 0600); e != nil {
			return e
		}
	}
	return nil
}
