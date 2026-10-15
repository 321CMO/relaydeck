package panel

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type Outbound struct {
	ProtocolOptions
	HopPorts    string `json:"hopPorts,omitempty"`
	ID          string `json:"id"`
	ServerID    string `json:"serverId"`
	Name        string `json:"name"`
	Tag         string `json:"tag"`
	Type        string `json:"type"`
	Enabled     bool   `json:"enabled"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	HasPassword bool   `json:"hasPassword"`
	UUID        string `json:"uuid,omitempty"`
	HasUUID     bool   `json:"hasUuid"`
	TLS         bool   `json:"tls"`
	SNI         string `json:"sni"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	DetourID    string `json:"detourId"`
	HopStart    int    `json:"hopStart"`
	HopEnd      int    `json:"hopEnd"`
	HopInterval int    `json:"hopInterval"`
}

type RoutingPolicy struct {
	ServerID          string `json:"serverId"`
	DefaultOutboundID string `json:"defaultOutboundId"`
	Sniff             bool   `json:"sniff"`
	ResolveDomains    bool   `json:"resolveDomains"`
}

func routeEnabled(r Route) bool { return r.Enabled == nil || *r.Enabled }
func normalizedRoute(r Route) Route {
	if r.Scope == "server" && r.Kind != "" {
		switch r.Kind {
		case "domain":
			r.Domains = "full:" + r.Value
		case "suffix":
			r.Domains = "domain:" + r.Value
		case "cidr":
			r.IPs = r.Value
		}
	}
	if r.NodeID != "" && len(r.NodeIDs) == 0 {
		r.NodeIDs = []string{r.NodeID}
	}
	return r
}
func outboundByID(s *State, id string) *Outbound {
	for i := range s.Outbounds {
		if s.Outbounds[i].ID == id {
			return &s.Outbounds[i]
		}
	}
	return nil
}
func policyFor(s State, id string) RoutingPolicy {
	for _, p := range s.RoutingPolicies {
		if p.ServerID == id {
			return p
		}
	}
	return RoutingPolicy{ServerID: id, DefaultOutboundID: "direct"}
}
func savePolicy(s *State, p RoutingPolicy) {
	for i := range s.RoutingPolicies {
		if s.RoutingPolicies[i].ServerID == p.ServerID {
			s.RoutingPolicies[i] = p
			return
		}
	}
	s.RoutingPolicies = append(s.RoutingPolicies, p)
}

var safeTag = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
var geoCategory = regexp.MustCompile(`^[a-z0-9][a-z0-9_@!.-]{0,79}$`)

func managedExit(s State, server, id string) string {
	if !strings.HasPrefix(id, "via_") {
		return ""
	}
	exit := strings.TrimPrefix(id, "via_")
	for _, n := range s.Nodes {
		if n.Enabled && n.ServerID == server && n.ExitID == exit {
			return exit
		}
	}
	return ""
}
func outboundTag(s State, server, id string) (string, error) {
	if id == "" || id == "direct" {
		return "direct", nil
	}
	if id == "reject" {
		return "", errors.New("拒绝不能作为默认出站或链式代理")
	}
	if managedExit(s, server, id) != "" {
		return id, nil
	}
	o := outboundByID(&s, id)
	if o == nil || o.ServerID != server || !o.Enabled {
		return "", errors.New("出站不存在、已停用或属于其他服务器")
	}
	return o.Tag, nil
}
func validateOutbound(s State, o Outbound) error {
	if !nameValid(o.Name) || serverByID(&s, o.ServerID) == nil || !safeTag.MatchString(o.Tag) || o.Tag == "direct" || o.Tag == "reject" || strings.HasPrefix(o.Tag, "via_") || strings.HasPrefix(o.Tag, "internal-") {
		return errors.New("出站名称、标签或服务器无效；系统标签不能重复使用")
	}
	for _, other := range s.Outbounds {
		if other.ID != o.ID && other.ServerID == o.ServerID && other.Tag == o.Tag {
			return errors.New("同一服务器的出站标签不能重复")
		}
	}
	if !hostValid(o.Address) || o.Port < 1 || o.Port > 65535 {
		return errors.New("出站服务器地址或端口无效")
	}
	if o.Port == 2019 || o.Port == 8787 || o.Port == 10085 {
		return errors.New("此端口保留给管理与统计服务")
	}
	if len(o.Password) > 512 || len(o.Username) > 128 {
		return errors.New("认证信息过长")
	}
	if o.Type == "http" && o.Network != "" {
		return errors.New("HTTP 出站仅支持 TCP，不设置 network 参数")
	}
	if o.Type == "reality" && o.Insecure {
		return errors.New("Reality 使用公钥校验，不支持开启 insecure")
	}
	if e := validateProtocol(o.ProtocolOptions, o.Type); e != nil {
		return e
	}
	if o.HopPorts != "" {
		if _, _, e := ports(o.HopPorts); e != nil {
			return e
		}
		if o.Type != "hy2" || o.HopInterval < 5 || o.HopInterval > 3600 {
			return errors.New("跳跃端口仅用于 HY2，间隔为 5–3600 秒")
		}
	}
	switch o.Type {
	case "socks", "http":
		if (o.Username == "") != (o.Password == "") {
			return errors.New("用户名和密码需要同时填写，或同时留空")
		}
	case "ss2022":
		if !validSSKeys(o.Password, ssMethod(o.ProtocolOptions), true) {
			return errors.New("SS2022 密钥长度与加密方式不匹配，应为 Base64 主密钥或 主密钥:用户密钥")
		}

	case "reality":
		b, e := hex.DecodeString(strings.ReplaceAll(o.UUID, "-", ""))
		if e != nil || len(b) != 16 {
			return errors.New("Reality UUID 无效")
		}
		key, e := base64.RawURLEncoding.DecodeString(o.PublicKey)
		if e != nil || len(key) != 32 {
			return errors.New("Reality 公钥无效")
		}
		short, e := hex.DecodeString(o.ShortID)
		if e != nil || len(short) > 8 {
			return errors.New("Reality Short ID 应为至多 16 位偶数长度十六进制")
		}
		if !hostValid(o.SNI) {
			return errors.New("Reality SNI 无效")
		}
	case "hy2":
		if o.Password == "" || o.SNI != "" && !hostValid(o.SNI) {
			return errors.New("HY2 需要密码与证书域名")
		}
		if o.HopStart != 0 && (o.HopStart < 1 || o.HopEnd < o.HopStart || o.HopEnd > 65535 || o.HopInterval < 5 || o.HopInterval > 3600) {
			return errors.New("HY2 出站跳跃范围或间隔无效")
		}
	default:
		return errors.New("出站支持 SOCKS5、HTTP、Reality、HY2 和 SS2022")
	}
	if o.TLS && o.SNI != "" && !hostValid(o.SNI) {
		return errors.New("TLS 证书域名无效")
	}
	if o.DetourID != "" && o.DetourID != "direct" {
		if o.DetourID == o.ID || managedExit(s, o.ServerID, o.DetourID) != "" {
			return errors.New("链式代理不能指向自身或系统内网出口")
		}
		visited := map[string]bool{o.ID: true}
		id := o.DetourID
		for id != "" && id != "direct" {
			if visited[id] {
				return errors.New("出站代理链不能成环")
			}
			visited[id] = true
			next := outboundByID(&s, id)
			if next == nil || next.ServerID != o.ServerID || o.Enabled && !next.Enabled {
				return errors.New("链式出站不存在、已停用或属于其他服务器")
			}
			if o.Type == "hy2" && next.Type == "http" {
				return errors.New("HY2 使用 UDP，不能通过仅 TCP 的 HTTP 前置出站")
			}
			id = next.DetourID
		}
	}
	return nil
}

func lines(v string) []string {
	r := []string{}
	for _, l := range strings.Split(strings.ReplaceAll(v, "\r", ""), "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			r = append(r, l)
		}
	}
	return r
}
func ipPrefix(v string) (string, error) {
	if p, e := netip.ParsePrefix(v); e == nil {
		return p.Masked().String(), nil
	}
	if a, e := netip.ParseAddr(v); e == nil {
		return netip.PrefixFrom(a, a.BitLen()).String(), nil
	}
	return "", errors.New("IP 或 CIDR 无效")
}
func ports(v string) ([]int, []string, error) {
	single := []int{}
	ranges := []string{}
	if strings.TrimSpace(v) == "" {
		return single, ranges, nil
	}
	for _, item := range strings.Split(v, ",") {
		p := strings.ReplaceAll(strings.TrimSpace(item), "-", ":")
		parts := strings.Split(p, ":")
		if len(parts) > 2 {
			return nil, nil, errors.New("端口使用 443,1000-2000 格式")
		}
		a, e := strconv.Atoi(parts[0])
		if e != nil || a < 1 || a > 65535 {
			return nil, nil, errors.New("端口必须在 1–65535 之间")
		}
		if len(parts) == 1 {
			single = append(single, a)
			continue
		}
		b, e := strconv.Atoi(parts[1])
		if e != nil || b < a || b > 65535 {
			return nil, nil, errors.New("端口范围无效")
		}
		ranges = append(ranges, fmt.Sprintf("%d:%d", a, b))
	}
	return single, ranges, nil
}

// Logical groups preserve AND between criteria, OR within each criterion.
// Geo data comes from MetaCubeX's published sing-box rule sets, not Xray .dat files.
func matchGroups(r Route, sets map[string]map[string]any) ([]any, error) {
	groups := []any{}
	addOR := func(items []any) {
		if len(items) == 1 {
			groups = append(groups, items[0])
		} else if len(items) > 1 {
			groups = append(groups, map[string]any{"type": "logical", "mode": "or", "rules": items})
		}
	}
	geo := func(kind, category string) (map[string]any, error) {
		category = strings.ToLower(category)
		if !geoCategory.MatchString(category) || strings.Contains(category, "..") {
			return nil, errors.New("地理规则集名称无效")
		}
		tag := kind + "_" + category
		sets[tag] = map[string]any{"type": "remote", "tag": tag, "format": "binary", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/" + kind + "/" + url.PathEscape(category) + ".srs", "update_interval": "1d"}
		return map[string]any{"rule_set": []string{tag}}, nil
	}
	domains := []any{}
	for _, d := range lines(r.Domains) {
		kind, value, has := strings.Cut(d, ":")
		if !has {
			kind = "domain"
			value = d
		}
		field := ""
		switch kind {
		case "domain":
			field = "domain_suffix"
			value = strings.TrimPrefix(value, ".")
		case "full":
			field = "domain"
		case "keyword":
			field = "domain_keyword"
		case "regexp":
			field = "domain_regex"
			if len(value) > 512 {
				return nil, errors.New("域名正则过长")
			}
			if _, e := regexp.Compile(value); e != nil {
				return nil, errors.New("域名正则无效")
			}
		case "geosite":
			item, e := geo("geosite", value)
			if e != nil {
				return nil, e
			}
			domains = append(domains, item)
			continue
		default:
			return nil, errors.New("域名前缀支持 domain/full/keyword/regexp/geosite")
		}
		if value == "" || len(value) > 512 {
			return nil, errors.New("域名条件为空或过长")
		}
		if (kind == "domain" || kind == "full") && !hostValid(value) {
			return nil, errors.New("域名格式无效")
		}
		domains = append(domains, map[string]any{field: []string{value}})
	}
	addOR(domains)
	ips := []any{}
	for _, ip := range lines(r.IPs) {
		if strings.HasPrefix(ip, "geoip:") {
			category := strings.TrimPrefix(ip, "geoip:")
			if category == "private" {
				ips = append(ips, map[string]any{"ip_is_private": true})
			} else {
				item, e := geo("geoip", category)
				if e != nil {
					return nil, e
				}
				ips = append(ips, item)
			}
			continue
		}
		prefix, e := ipPrefix(ip)
		if e != nil {
			return nil, e
		}
		ips = append(ips, map[string]any{"ip_cidr": []string{prefix}})
	}
	addOR(ips)
	for _, condition := range []struct{ value, field string }{{r.Ports, "port"}, {r.SourcePorts, "source_port"}} {
		p, ranges, e := ports(condition.value)
		if e != nil {
			return nil, e
		}
		items := []any{}
		if len(p) > 0 {
			items = append(items, map[string]any{condition.field: p})
		}
		if len(ranges) > 0 {
			items = append(items, map[string]any{condition.field + "_range": ranges})
		}
		addOR(items)
	}
	sources := []any{}
	for _, source := range lines(r.SourceIPs) {
		if source == "geoip:private" {
			sources = append(sources, map[string]any{"source_ip_is_private": true})
			continue
		}
		prefix, e := ipPrefix(source)
		if e != nil {
			return nil, e
		}
		sources = append(sources, map[string]any{"source_ip_cidr": []string{prefix}})
	}
	addOR(sources)
	for _, n := range r.Networks {
		if n != "tcp" && n != "udp" {
			return nil, errors.New("网络类型仅支持 TCP/UDP")
		}
	}
	if len(r.Networks) > 0 {
		groups = append(groups, map[string]any{"network": r.Networks})
	}
	for _, p := range r.Protocols {
		if !slices.Contains([]string{"http", "tls", "quic", "dns", "bittorrent", "ssh", "stun"}, p) {
			return nil, errors.New("协议匹配类型无效")
		}
	}
	if len(r.Protocols) > 0 {
		groups = append(groups, map[string]any{"protocol": r.Protocols})
	}
	if len(r.UserIDs) > 0 {
		groups = append(groups, map[string]any{"auth_user": r.UserIDs})
	}
	return groups, nil
}

func validateRoute(s State, r Route) error {
	if r.Scope != "client" && r.Scope != "server" {
		return errors.New("请选择客户端或服务端规则")
	}
	if r.Scope == "client" {
		if r.Kind != "suffix" && r.Kind != "domain" && r.Kind != "cidr" {
			return errors.New("客户端匹配方式无效")
		}
		if r.Kind == "cidr" {
			if _, e := netip.ParsePrefix(r.Value); e != nil {
				return errors.New("CIDR 无效")
			}
		} else if !hostValid(r.Value) {
			return errors.New("域名无效")
		}
		if r.Action != "direct" && r.Action != "reject" && r.Action != "proxy" {
			return errors.New("客户端规则动作无效")
		}
		if r.NodeID != "" && nodeByID(&s, r.NodeID) == nil {
			return errors.New("节点不存在")
		}
		return nil
	}
	r = normalizedRoute(r)
	if r.ServerID != "" && serverByID(&s, r.ServerID) == nil {
		return errors.New("服务器不存在")
	}
	if len(r.Name) > 100 || len(r.Domains)+len(r.IPs)+len(r.SourceIPs) > 16000 || len(r.NodeIDs) > 200 || len(r.UserIDs) > 200 || len(lines(r.Domains))+len(lines(r.IPs)) > 200 {
		return errors.New("规则内容过长")
	}
	if r.Action != "direct" && r.Action != "reject" && r.Action != "outbound" {
		return errors.New("请选择直连、拒绝或指定出站")
	}
	if r.Action == "outbound" {
		if r.ServerID == "" {
			return errors.New("指定出站的规则必须选择一台服务器")
		}
		if r.OutboundID == "" || r.OutboundID == "direct" {
			return errors.New("请选择代理出站")
		}
		if !routeEnabled(r) {
			o := outboundByID(&s, r.OutboundID)
			if o == nil || o.ServerID != r.ServerID {
				if managedExit(s, r.ServerID, r.OutboundID) == "" {
					return errors.New("引用出站不存在或属于其他服务器")
				}
			}
		} else if _, e := outboundTag(s, r.ServerID, r.OutboundID); e != nil {
			return e
		}
	}
	for _, id := range r.NodeIDs {
		n := nodeByID(&s, id)
		if n == nil || r.ServerID != "" && n.ServerID != r.ServerID {
			return errors.New("入站节点不存在或属于其他服务器")
		}
	}
	for _, id := range r.UserIDs {
		if userByID(&s, id) == nil {
			return errors.New("引用的订阅不存在")
		}
	}
	groups, e := matchGroups(r, map[string]map[string]any{})
	if e != nil {
		return e
	}
	if len(groups) == 0 && len(r.NodeIDs) == 0 && !r.MatchAll {
		return errors.New("至少填写一个匹配条件，或明确勾选匹配全部流量")
	}
	return nil
}

func validateRoutingState(s State) error {
	for _, n := range s.Nodes {
		if n.Enabled && n.OutboundID != "" {
			if _, e := outboundTag(s, n.ServerID, n.OutboundID); e != nil {
				return e
			}
		}
	}
	for _, o := range s.Outbounds {
		if e := validateOutbound(s, o); e != nil {
			return e
		}
	}
	for _, r := range s.Routes {
		if e := validateRoute(s, r); e != nil {
			return e
		}
	}
	for _, p := range s.RoutingPolicies {
		if serverByID(&s, p.ServerID) == nil {
			return errors.New("路由设置的服务器不存在")
		}
		if _, e := outboundTag(s, p.ServerID, p.DefaultOutboundID); e != nil {
			return e
		}
		if !p.Sniff {
			for _, r := range s.Routes {
				if r.Scope == "server" && routeEnabled(r) && (r.ServerID == p.ServerID || r.ServerID == "") && len(r.Protocols) > 0 {
					return errors.New("仍有协议匹配规则，请保持嗅探开启")
				}
			}
		}
	}
	return nil
}

func compileOutbound(s State, o Outbound) (map[string]any, error) {
	if e := validateOutbound(s, o); e != nil {
		return nil, e
	}
	m := map[string]any{"tag": o.Tag, "server": o.Address, "server_port": o.Port}
	switch o.Type {
	case "socks", "http":
		m["type"] = o.Type
		if o.Type == "socks" {
			m["version"] = "5"
		}
		if o.Username != "" {
			m["username"] = o.Username
			m["password"] = o.Password
		}
		if o.Type == "http" && o.TLS {
			m["tls"] = map[string]any{"enabled": true, "server_name": o.SNI}
		}
	case "ss2022":
		m["type"] = "shadowsocks"
		m["method"] = ssMethod(o.ProtocolOptions)
		m["password"] = o.Password
	case "reality":
		m["type"] = "vless"
		m["uuid"] = o.UUID
		m["flow"] = protocolFlow(o.ProtocolOptions)
		m["tls"] = map[string]any{"enabled": true, "server_name": o.SNI, "utls": map[string]any{"enabled": true, "fingerprint": fingerprint(o.ProtocolOptions)}, "reality": map[string]any{"enabled": true, "public_key": o.PublicKey, "short_id": o.ShortID}}
	case "hy2":
		m["type"] = "hysteria2"
		m["password"] = o.Password
		m["tls"] = map[string]any{"enabled": true, "server_name": o.SNI}
		hy2Options(o.ProtocolOptions, m)
		if o.HopStart > 0 {
			delete(m, "server_port")
			m["server_ports"] = []string{fmt.Sprintf("%d:%d", o.HopStart, o.HopEnd)}
			m["hop_interval"] = fmt.Sprintf("%ds", o.HopInterval)
		}
	}
	if tls, ok := m["tls"].(map[string]any); ok {
		if len(o.ALPN) > 0 {
			tls["alpn"] = o.ALPN
		}
		if o.Insecure {
			tls["insecure"] = true
		}
	}
	if o.Network != "" {
		m["network"] = o.Network
	}
	if o.Type == "hy2" && o.HopPorts != "" {
		single, ranges, _ := ports(o.HopPorts)
		ps := []string{}
		for _, v := range single {
			ps = append(ps, strconv.Itoa(v))
		}
		ps = append(ps, ranges...)
		delete(m, "server_port")
		m["server_ports"] = ps
		m["hop_interval"] = fmt.Sprintf("%ds", o.HopInterval)
	}
	if o.DetourID != "" && o.DetourID != "direct" {
		tag, e := outboundTag(s, o.ServerID, o.DetourID)
		if e != nil {
			return nil, e
		}
		m["detour"] = tag
	}
	return m, nil
}

func compileRouting(s State, serverID string, in []map[string]any) ([]map[string]any, []map[string]any, []map[string]any, error) {
	public := []string{}
	for _, i := range in {
		tag, _ := i["tag"].(string)
		if tag != "internal-backhaul" {
			public = append(public, tag)
		}
	}
	custom := []map[string]any{}
	sets := map[string]map[string]any{}
	out := []map[string]any{}
	for _, o := range s.Outbounds {
		if o.ServerID == serverID && o.Enabled {
			v, e := compileOutbound(s, o)
			if e != nil {
				return nil, nil, nil, e
			}
			out = append(out, v)
		}
	}
	p := policyFor(s, serverID)
	if len(public) > 0 && p.Sniff {
		custom = append(custom, map[string]any{"inbound": public, "action": "sniff", "timeout": "300ms"})
	}
	if len(public) > 0 && p.ResolveDomains {
		custom = append(custom, map[string]any{"inbound": public, "action": "resolve", "server": "routing-local", "strategy": "prefer_ipv4"})
	}
	for _, raw := range s.Routes {
		if raw.Scope != "server" || !routeEnabled(raw) || raw.ServerID != "" && raw.ServerID != serverID || len(public) == 0 {
			continue
		}
		r := normalizedRoute(raw)
		if e := validateRoute(s, r); e != nil {
			return nil, nil, nil, e
		}
		inbounds := public
		if len(r.NodeIDs) > 0 {
			inbounds = []string{}
			for _, id := range r.NodeIDs {
				if n := nodeByID(&s, id); n != nil && slices.Contains(public, inboundTag(*n)) {
					inbounds = append(inbounds, inboundTag(*n))
				}
			}
			if len(inbounds) == 0 {
				continue
			}
		}
		conditions, e := matchGroups(r, sets)
		if e != nil {
			return nil, nil, nil, e
		}
		conditions = append([]any{map[string]any{"inbound": inbounds}}, conditions...)
		rule := map[string]any{"type": "logical", "mode": "and", "rules": conditions, "action": "route"}
		switch r.Action {
		case "reject":
			rule["action"] = "reject"
		case "direct":
			rule["outbound"] = "direct"
		case "outbound":
			tag, e := outboundTag(s, serverID, r.OutboundID)
			if e != nil {
				return nil, nil, nil, e
			}
			rule["outbound"] = tag
		}
		custom = append(custom, rule)
	}
	keys := []string{}
	for k := range sets {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	rulesets := []map[string]any{}
	for _, k := range keys {
		rulesets = append(rulesets, sets[k])
	}
	return custom, out, rulesets, nil
}

func redactedRouting(config json.RawMessage) (map[string]any, error) {
	var v map[string]any
	if e := json.Unmarshal(config, &v); e != nil {
		return nil, e
	}
	var scrub func(any)
	scrub = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, value := range x {
				if slices.Contains([]string{"password", "uuid", "private_key", "username", "obfsPassword"}, k) {
					x[k] = "••••••"
				} else {
					scrub(value)
				}
			}
		case []any:
			for _, v := range x {
				scrub(v)
			}
		}
	}
	scrub(v)
	return map[string]any{"route": v["route"], "outbounds": v["outbounds"], "dns": v["dns"]}, nil
}
