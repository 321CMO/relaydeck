package panel

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// A nil Flow retains the pre-alpha.5 Vision default. An explicit empty value disables it.
type ProtocolOptions struct {
	Flow            *string  `json:"flow,omitempty"`
	Fingerprint     string   `json:"fingerprint,omitempty"`
	Method          string   `json:"method,omitempty"`
	Network         string   `json:"network,omitempty"`
	ALPN            []string `json:"alpn,omitempty"`
	Insecure        bool     `json:"insecure,omitempty"`
	Obfs            string   `json:"obfs,omitempty"`
	ObfsPassword    string   `json:"obfsPassword,omitempty"`
	HasObfsPassword bool     `json:"hasObfsPassword"`
	UpMbps          int      `json:"upMbps,omitempty"`
	DownMbps        int      `json:"downMbps,omitempty"`
}

func protocolFlow(p ProtocolOptions) string {
	if p.Flow == nil {
		return "xtls-rprx-vision"
	}
	return *p.Flow
}
func fingerprint(p ProtocolOptions) string {
	if p.Fingerprint == "" {
		return "chrome"
	}
	return p.Fingerprint
}
func ssMethod(p ProtocolOptions) string {
	if p.Method == "" {
		return "2022-blake3-aes-128-gcm"
	}
	return p.Method
}
func ssKeySize(method string) int {
	if method == "2022-blake3-aes-128-gcm" {
		return 16
	}
	return 32
}
func validSSKeys(password, method string, multi bool) bool {
	parts := strings.Split(password, ":")
	if !multi && len(parts) != 1 || len(parts) > 8 {
		return false
	}
	for _, p := range parts {
		b, e := base64.StdEncoding.DecodeString(p)
		if e != nil || len(b) != ssKeySize(method) {
			return false
		}
	}
	return true
}
func validateProtocol(p ProtocolOptions, protocol string) error {
	if len(p.ALPN) > 10 {
		return errors.New("ALPN 项目过多")
	}
	for _, v := range p.ALPN {
		if v == "" || len(v) > 255 || strings.ContainsAny(v, "\r\n\x00") {
			return errors.New("ALPN 无效")
		}
	}
	if protocol == "hy2" && len(p.ALPN) > 0 && !slices.Contains(p.ALPN, "h3") {
		return errors.New("HY2 的 ALPN 需要包含 h3，或留空使用核心默认值")
	}
	if p.UpMbps < 0 || p.DownMbps < 0 || p.UpMbps > 1000000 || p.DownMbps > 1000000 {
		return errors.New("上下行带宽必须在 0–1000000 Mbps 之间")
	}
	if p.Network != "" && p.Network != "tcp" && p.Network != "udp" {
		return errors.New("网络类型仅支持 TCP、UDP 或两者")
	}
	if p.Obfs != "" && p.Obfs != "salamander" {
		return errors.New("当前混淆支持 Salamander")
	}
	if p.Obfs != "" && (p.ObfsPassword == "" || len(p.ObfsPassword) > 512) {
		return errors.New("请填写有效的混淆密码")
	}
	if protocol == "reality" {
		if protocolFlow(p) != "" && protocolFlow(p) != "xtls-rprx-vision" {
			return errors.New("Flow 支持空值或 xtls-rprx-vision")
		}
		if !slices.Contains([]string{"chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"}, fingerprint(p)) {
			return errors.New("客户端指纹无效")
		}
	}
	if protocol == "ss2022" && !slices.Contains([]string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"}, ssMethod(p)) {
		return errors.New("SS2022 当前支持 AES-128 和 AES-256")
	}
	return nil
}
func clientPort(n Node) int {
	if n.PublicPort > 0 {
		return n.PublicPort
	}
	return n.Port
}
func inboundTag(n Node) string {
	if n.Tag != "" {
		return n.Tag
	}
	return n.ID
}
func shortIDs(n Node) []string {
	if len(n.ShortIDs) > 0 {
		return n.ShortIDs
	}
	return []string{n.ShortID}
}
func hy2Options(p ProtocolOptions, m map[string]any) {
	if p.Obfs != "" {
		m["obfs"] = map[string]any{"type": p.Obfs, "password": p.ObfsPassword}
	}
	if p.UpMbps > 0 {
		m["up_mbps"] = p.UpMbps
	}
	if p.DownMbps > 0 {
		m["down_mbps"] = p.DownMbps
	}
}
func validateNodeOptions(n Node) error {
	if n.Insecure {
		return errors.New("insecure 仅用于出站证书校验，不适用于服务端入站")
	}
	if e := validateProtocol(n.ProtocolOptions, n.Protocol); e != nil {
		return e
	}
	if n.Listen != "" {
		if _, e := netip.ParseAddr(n.Listen); e != nil {
			return errors.New("监听地址须为 IPv4 或 IPv6 地址")
		}
	}
	if n.PublicPort < 0 || n.PublicPort > 65535 {
		return errors.New("对外端口无效")
	}
	if n.Tag != "" && (!safeTag.MatchString(n.Tag) || n.Tag == "internal-backhaul" || strings.HasPrefix(n.Tag, "internal-")) {
		return errors.New("入站 Tag 无效或属于系统保留标签")
	}
	if n.MaxTimeDifference != "" {
		d, e := time.ParseDuration(n.MaxTimeDifference)
		if e != nil || d < 0 || d > 24*time.Hour {
			return errors.New("最大时间差使用 30s 或 1m 等时长，最多 24h")
		}
	}
	return nil
}

// Socket conflicts follow the enabled transports, not just the protocol name.
func nodeTransports(n Node) (tcp, udp bool) {
	switch n.Protocol {
	case "reality":
		return true, false
	case "hy2":
		return false, true
	case "ss2022":
		return n.Network != "udp", n.Network != "tcp"
	}
	return false, false
}
func sharedTransport(a, b Node) bool {
	at, au := nodeTransports(a)
	bt, bu := nodeTransports(b)
	return at && bt || au && bu
}
