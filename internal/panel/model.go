package panel

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const Version = "0.1.0-alpha.8"

type Server struct {
	TrafficLastSeen   time.Time                            `json:"trafficLastSeen"`
	StatsSupported    bool                                 `json:"statsSupported"`
	TrafficCursors    map[string]map[string]TrafficCounter `json:"trafficCursors,omitempty"`
	ID                string                               `json:"id"`
	Name              string                               `json:"name"`
	Address           string                               `json:"address"`
	PrivateIP         string                               `json:"privateIp"`
	Region            string                               `json:"region"`
	AgentToken        string                               `json:"agentToken,omitempty"`
	BackhaulKey       string                               `json:"backhaulKey,omitempty"`
	EnrollmentHash    string                               `json:"enrollmentHash,omitempty"`
	EnrollmentExpires time.Time                            `json:"enrollmentExpires"`
	MachineID         string                               `json:"machineId,omitempty"`
	Enrolled          bool                                 `json:"enrolled"`
	LastSeen          time.Time                            `json:"lastSeen"`
	Desired           int64                                `json:"desired"`
	Applied           int64                                `json:"applied"`
	CoreVersion       string                               `json:"coreVersion"`
	Error             string                               `json:"error,omitempty"`
}
type Node struct {
	ProtocolOptions
	OutboundID        string   `json:"outboundId,omitempty"`
	Tag               string   `json:"tag,omitempty"`
	Listen            string   `json:"listen,omitempty"`
	PublicPort        int      `json:"publicPort,omitempty"`
	ShortIDs          []string `json:"shortIds,omitempty"`
	MaxTimeDifference string   `json:"maxTimeDifference,omitempty"`
	Masquerade        string   `json:"masquerade,omitempty"`
	HasPrivateKey     bool     `json:"hasPrivateKey"`
	HasServerKey      bool     `json:"hasServerKey"`
	RotateCredentials bool     `json:"rotateCredentials,omitempty"`
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	ServerID          string   `json:"serverId"`
	Protocol          string   `json:"protocol"`
	Address           string   `json:"address"`
	Port              int      `json:"port"`
	Enabled           bool     `json:"enabled"`
	SNI               string   `json:"sni"`
	Target            string   `json:"target"`
	PublicKey         string   `json:"publicKey"`
	PrivateKey        string   `json:"privateKey,omitempty"`
	ShortID           string   `json:"shortId"`
	ServerKey         string   `json:"serverKey,omitempty"`
	TLSMode           string   `json:"tlsMode"`
	Certificate       string   `json:"certificate,omitempty"`
	Key               string   `json:"key,omitempty"`
	HopStart          int      `json:"hopStart"`
	HopEnd            int      `json:"hopEnd"`
	HopInterval       int      `json:"hopInterval"`
	ExitID            string   `json:"exitId"`
	RequiredRevision  int64    `json:"requiredRevision"`
}
type User struct {
	Upload       int64             `json:"upload"`
	Download     int64             `json:"download"`
	UsageSince   time.Time         `json:"usageSince"`
	UsageUpdated time.Time         `json:"usageUpdated"`
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Enabled      bool              `json:"enabled"`
	Limit        int64             `json:"limit"`
	Used         int64             `json:"used"`
	Expires      string            `json:"expires"`
	Token        string            `json:"token,omitempty"`
	NodeIDs      []string          `json:"nodeIds"`
	Credentials  map[string]string `json:"credentials,omitempty"`
	Required     map[string]int64  `json:"required,omitempty"`
}
type Route struct {
	Name        string   `json:"name"`
	Enabled     *bool    `json:"enabled,omitempty"`
	ServerID    string   `json:"serverId"`
	Domains     string   `json:"domains"`
	IPs         string   `json:"ips"`
	Ports       string   `json:"ports"`
	SourceIPs   string   `json:"sourceIps"`
	SourcePorts string   `json:"sourcePorts"`
	Networks    []string `json:"networks"`
	Protocols   []string `json:"protocols"`
	NodeIDs     []string `json:"nodeIds"`
	UserIDs     []string `json:"userIds"`
	OutboundID  string   `json:"outboundId"`
	MatchAll    bool     `json:"matchAll"`

	ID     string `json:"id"`
	Scope  string `json:"scope"`
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Action string `json:"action"`
	NodeID string `json:"nodeId"`
}
type Task struct {
	ID       string    `json:"id"`
	ServerID string    `json:"serverId"`
	Revision int64     `json:"revision"`
	Status   string    `json:"status"`
	Summary  string    `json:"summary"`
	Error    string    `json:"error,omitempty"`
	Created  time.Time `json:"created"`
	Finished time.Time `json:"finished"`
}
type HTTPS struct {
	AdminPort          int    `json:"adminPort"`
	AdminPath          string `json:"adminPath,omitempty"`
	LoadedHash         string `json:"loadedHash,omitempty"`
	PublishedDomain    string `json:"publishedDomain,omitempty"`
	Domain             string `json:"domain"`
	SubscriptionDomain string `json:"subscriptionDomain"`
	Mode               string `json:"mode"`
	Email              string `json:"email"`
	CloudflareToken    string `json:"cloudflareToken,omitempty"`
	Certificate        string `json:"certificate,omitempty"`
	Key                string `json:"key,omitempty"`
	Status             string `json:"status"`
	Expires            string `json:"expires"`
}
type Telegram struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token,omitempty"`
	ChatID  string `json:"chatId"`
	Daily   bool   `json:"daily"`
	Hour    int    `json:"hour"`
	Status  string `json:"status"`
}
type Notification struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"`
	Text     string    `json:"text"`
	Status   string    `json:"status"`
	Attempts int       `json:"attempts"`
	Next     time.Time `json:"next"`
	Created  time.Time `json:"created"`
}
type Settings struct {
	HTTPS         HTTPS    `json:"https"`
	Telegram      Telegram `json:"telegram"`
	RoutingPreset string   `json:"routingPreset"`
	Timezone      string   `json:"timezone"`
}
type State struct {
	Mutations       []MutationReceipt `json:"mutations,omitempty"`
	Compiler        string            `json:"compiler"`
	Schema          int               `json:"schema"`
	Epoch           string            `json:"epoch,omitempty"`
	Username        string            `json:"username"`
	PasswordHash    string            `json:"passwordHash,omitempty"`
	SetupToken      string            `json:"setupToken,omitempty"`
	SetupExpires    time.Time         `json:"setupExpires"`
	Servers         []Server          `json:"servers"`
	Nodes           []Node            `json:"nodes"`
	Users           []User            `json:"users"`
	Outbounds       []Outbound        `json:"outbounds"`
	RoutingPolicies []RoutingPolicy   `json:"routingPolicies"`
	Routes          []Route           `json:"routes"`
	Tasks           []Task            `json:"tasks"`
	Settings        Settings          `json:"settings"`
	Notifications   []Notification    `json:"notifications"`
}

func initial() State {
	return State{Schema: 1, SetupToken: randomToken(24), SetupExpires: time.Now().Add(15 * time.Minute), Servers: []Server{}, Nodes: []Node{}, Users: []User{}, Outbounds: []Outbound{}, RoutingPolicies: []RoutingPolicy{}, Routes: []Route{}, Tasks: []Task{}, Notifications: []Notification{}, Settings: Settings{HTTPS: HTTPS{Mode: "auto", Status: "unconfigured"}, Telegram: Telegram{Hour: 9, Status: "unconfigured"}, RoutingPreset: "china-direct", Timezone: "Asia/Shanghai"}}
}
func randomToken(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func validEpoch(value string) bool {
	if value == "" {
		return true
	}
	b, e := base64.RawURLEncoding.DecodeString(value)
	return e == nil && len(b) == 16
}
func newID(prefix string) string { return prefix + "_" + randomToken(9) }
func uuid() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
func ssKey() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.StdEncoding.EncodeToString(b)
}
func realityKeys() (string, string, error) {
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return "", "", e
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()), base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}
func hostValid(s string) bool {
	if s == "" || strings.ContainsAny(s, " /\\\r\n\t?#@") {
		return false
	}
	if _, e := netip.ParseAddr(s); e == nil {
		return true
	}
	if len(s) > 253 {
		return false
	}
	for _, v := range strings.Split(s, ".") {
		if v == "" || len(v) > 63 || strings.HasPrefix(v, "-") || strings.HasSuffix(v, "-") {
			return false
		}
		for _, r := range v {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func nameValid(v string) bool {
	return len(v) > 0 && len(v) <= 100 && !strings.ContainsAny(v, "\r\n\t,")
}
func privateIP(v string) bool { a, e := netip.ParseAddr(v); return e == nil && a.IsPrivate() }
func serverByID(s *State, id string) *Server {
	for i := range s.Servers {
		if s.Servers[i].ID == id {
			return &s.Servers[i]
		}
	}
	return nil
}
func nodeByID(s *State, id string) *Node {
	for i := range s.Nodes {
		if s.Nodes[i].ID == id {
			return &s.Nodes[i]
		}
	}
	return nil
}
func userByID(s *State, id string) *User {
	for i := range s.Users {
		if s.Users[i].ID == id {
			return &s.Users[i]
		}
	}
	return nil
}
func activeUser(u User, now time.Time) bool {
	if !u.Enabled || u.Limit > 0 && u.Used >= u.Limit {
		return false
	}
	if u.Expires != "" {
		t, e := time.Parse(time.RFC3339, u.Expires)
		if e != nil || !now.Before(t) {
			return false
		}
	}
	return true
}
func validateNode(s *State, n Node) error {
	if n.ExitID != "" && n.OutboundID != "" {
		return errors.New("内网落地和指定出站不能同时选择")
	}
	if n.OutboundID != "" && n.Enabled {
		if _, e := outboundTag(*s, n.ServerID, n.OutboundID); e != nil {
			return e
		}
	}
	if e := validateNodeOptions(n); e != nil {
		return e
	}
	for _, o := range s.Nodes {
		if o.ID != n.ID && o.ServerID == n.ServerID && inboundTag(o) == inboundTag(n) {
			return errors.New("本台服务器的入站 Tag 不能重复")
		}
	}
	if n.Protocol == "reality" {
		seen := map[string]bool{}
		for _, id := range shortIDs(n) {
			b, e := hex.DecodeString(id)
			if e != nil || len(b) == 0 || len(b) > 8 {
				return errors.New("Short ID 应为 2–16 位偶数长度十六进制，推荐自动生成 16 位")
			}
			if seen[id] {
				return errors.New("Short ID 列表不能重复")
			}
			seen[id] = true
		}
		if len(n.ShortIDs) > 32 {
			return errors.New("Short ID 最多 32 个")
		}
	}
	if n.Protocol == "ss2022" && !validSSKeys(n.ServerKey, ssMethod(n.ProtocolOptions), false) {
		return errors.New("服务端密钥与 SS2022 加密方式不匹配")
	}
	if n.Masquerade != "" {
		u, e := url.Parse(n.Masquerade)
		if e != nil || u.Hostname() == "" || u.Scheme != "https" && u.Scheme != "http" || u.User != nil {
			return errors.New("伪装目标使用 HTTP 或 HTTPS URL")
		}
	}

	if !nameValid(n.Name) || !hostValid(n.Address) || serverByID(s, n.ServerID) == nil {
		return errors.New("节点名称、地址或服务器无效")
	}
	for _, port := range []int{2019, 8787, 10085, 18999} {
		if n.Port == port {
			return errors.New("此端口保留给面板、统计或内网转发，请选择其他监听端口")
		}
	}
	if tcp, _ := nodeTransports(n); tcp && s.Settings.HTTPS.AdminPort != 0 && n.Port == s.Settings.HTTPS.AdminPort {
		return errors.New("节点 TCP 端口与管理端口冲突")
	}
	if n.Port < 1 || n.Port > 65535 {
		return errors.New("端口必须在 1–65535 之间")
	}
	if n.Protocol != "reality" && n.Protocol != "hy2" && n.Protocol != "ss2022" {
		return errors.New("不支持此协议")
	}
	if n.Protocol == "reality" {
		if !hostValid(n.SNI) {
			return errors.New("请填写有效的 Reality SNI")
		}
		h, p, e := net.SplitHostPort(n.Target)
		port, pe := strconv.Atoi(p)
		if e != nil || pe != nil || !hostValid(h) || port < 1 || port > 65535 {
			return errors.New("Reality 目标应为 域名:端口")
		}
	}
	if n.Protocol == "hy2" {
		if !hostValid(n.SNI) {
			return errors.New("请填写 HY2 证书域名")
		}
		if n.TLSMode != "auto" && n.TLSMode != "import" {
			return errors.New("请选择自动证书或导入证书")
		}
		if n.TLSMode == "import" {
			if _, e := parseCertificate(n.Certificate, n.Key, n.SNI); e != nil {
				return e
			}
		}
		if n.HopStart != 0 && (n.HopStart < 1 || n.HopEnd < n.HopStart || n.HopEnd > 65535 || n.HopInterval < 5 || n.HopInterval > 3600 || n.HopEnd-n.HopStart+1 > 4096) {
			return errors.New("跳跃范围须为 1–65535 且最多 4096 个连续端口；间隔为 5–3600 秒")
		}
		if n.HopStart == 0 && n.HopEnd != 0 {
			return errors.New("未启用端口跳跃时结束端口须为 0")
		}
		for _, port := range []int{2019, 8787, 10085, 18999} {
			if n.HopStart > 0 && n.HopStart <= port && port <= n.HopEnd {
				return errors.New("跳跃范围包含系统保留端口，请调整范围")
			}
		}
		if n.HopStart > 0 && n.PublicPort != 0 && n.PublicPort != n.Port {
			return errors.New("端口映射与跳跃范围不能同时使用；请使用原端口或关闭跳跃")
		}
	}
	ranges := func(v Node) [][2]int {
		r := [][2]int{{v.Port, v.Port}}
		if v.Protocol == "hy2" && v.HopStart > 0 {
			r = append(r, [2]int{v.HopStart, v.HopEnd})
		}
		return r
	}
	for _, o := range s.Nodes {
		if o.ID == n.ID || o.ServerID != n.ServerID || !o.Enabled || !n.Enabled {
			continue
		}
		if !sharedTransport(o, n) {
			continue
		}
		for _, a := range ranges(n) {
			for _, b := range ranges(o) {
				if a[0] <= b[1] && b[0] <= a[1] {
					return errors.New("端口或 UDP 跳跃范围与已有节点冲突")
				}
			}
		}
	}
	if n.ExitID != "" {
		entry := serverByID(s, n.ServerID)
		exit := serverByID(s, n.ExitID)
		if exit == nil || exit.ID == n.ServerID || !privateIP(exit.PrivateIP) || !privateIP(entry.PrivateIP) {
			return errors.New("请选择不同服务器，并填写两台机器的原生内网 IP")
		}
		graph := map[string][]string{}
		for _, o := range s.Nodes {
			if o.ID != n.ID && o.ExitID != "" {
				graph[o.ServerID] = append(graph[o.ServerID], o.ExitID)
			}
		}
		graph[n.ServerID] = append(graph[n.ServerID], n.ExitID)
		visited := map[string]bool{}
		var reaches func(string) bool
		reaches = func(id string) bool {
			if id == n.ServerID {
				return true
			}
			if visited[id] {
				return false
			}
			visited[id] = true
			for _, next := range graph[id] {
				if reaches(next) {
					return true
				}
			}
			return false
		}
		if reaches(n.ExitID) {
			return errors.New("线路不能成环")
		}
	}
	for _, o := range s.Nodes {
		if o.ExitID == n.ServerID && n.Enabled {
			for _, r := range ranges(n) {
				if r[0] <= 18999 && 18999 <= r[1] {
					return errors.New("18999 端口已保留给内网转发")
				}
			}
		}
		if n.ExitID != "" && o.ServerID == n.ExitID && o.Enabled {
			for _, r := range ranges(o) {
				if r[0] <= 18999 && 18999 <= r[1] {
					return errors.New("落地机的 18999 端口与公开节点冲突")
				}
			}
		}
	}

	return nil
}
func shortID() string {
	b := make([]byte, 8)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func credential(protocol string) string {
	if protocol == "reality" {
		return uuid()
	}
	if protocol == "ss2022" {
		return ssKey()
	}
	return randomToken(24)
}
func publicState(s State) State {
	for i := range s.Servers {
		s.Servers[i].Error = redactDiagnostic(s, s.Servers[i].Error)
	}
	for i := range s.Tasks {
		s.Tasks[i].Error = redactDiagnostic(s, s.Tasks[i].Error)
	}
	s.Mutations = nil
	s.Epoch = ""
	for i := range s.Outbounds {
		s.Outbounds[i].HasPassword = s.Outbounds[i].Password != ""
		s.Outbounds[i].HasUUID = s.Outbounds[i].UUID != ""
		s.Outbounds[i].HasObfsPassword = s.Outbounds[i].ObfsPassword != ""
		s.Outbounds[i].ObfsPassword = ""
		s.Outbounds[i].Password = ""
		s.Outbounds[i].UUID = ""
	}
	for i := range s.Routes {
		s.Routes[i] = normalizedRoute(s.Routes[i])
	}
	if s.Outbounds == nil {
		s.Outbounds = []Outbound{}
	}
	if s.RoutingPolicies == nil {
		s.RoutingPolicies = []RoutingPolicy{}
	}
	s.PasswordHash = ""
	s.SetupToken = ""
	for i := range s.Servers {
		s.Servers[i].Enrolled = s.Servers[i].MachineID != ""
		s.Servers[i].AgentToken = ""
		s.Servers[i].BackhaulKey = ""
		s.Servers[i].EnrollmentHash = ""
		s.Servers[i].MachineID = ""
		s.Servers[i].TrafficCursors = nil
	}
	for i := range s.Nodes {
		s.Nodes[i].HasPrivateKey = s.Nodes[i].PrivateKey != ""
		s.Nodes[i].HasServerKey = s.Nodes[i].ServerKey != ""
		s.Nodes[i].HasObfsPassword = s.Nodes[i].ObfsPassword != ""
		s.Nodes[i].ObfsPassword = ""
		s.Nodes[i].PrivateKey = ""
		s.Nodes[i].ServerKey = ""
		s.Nodes[i].Certificate = ""
		s.Nodes[i].Key = ""
	}
	for i := range s.Users {
		s.Users[i].Token = ""
		s.Users[i].Credentials = nil
		s.Users[i].Required = nil
	}
	s.Settings.HTTPS.LoadedHash = ""
	s.Settings.HTTPS.AdminPath = ""
	s.Settings.HTTPS.CloudflareToken = ""
	s.Settings.HTTPS.Certificate = ""
	s.Settings.HTTPS.Key = ""
	s.Settings.Telegram.Token = ""
	return s
}
func validBaseURL(v string, development bool) bool {
	u, e := url.Parse(v)
	return e == nil && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Path == "" || u.Path == "/") && (u.Scheme == "https" || development && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost"))
}
func cloneState(s State) State {
	b, _ := json.Marshal(s)
	var c State
	_ = json.Unmarshal(b, &c)
	return c
}
