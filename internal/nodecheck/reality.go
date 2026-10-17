// Package nodecheck performs bounded, read-only checks from the entry server.
package nodecheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type Request struct {
	ID     string `json:"id"`
	Target string `json:"target"`
	SNI    string `json:"sni"`
}
type Result struct {
	ID                 string    `json:"id"`
	Success            bool      `json:"success"`
	Stage              string    `json:"stage"`
	Message            string    `json:"message"`
	ALPN               string    `json:"alpn,omitempty"`
	Latency            int64     `json:"latencyMs,omitempty"`
	Checked            time.Time `json:"checked"`
	CertificateExpires time.Time `json:"certificateExpires,omitempty"`
}

func Validate(r Request) error {
	h, p, e := net.SplitHostPort(r.Target)
	n, pe := strconv.Atoi(p)
	if e != nil || pe != nil || n < 1 || n > 65535 || !dnsName(h) || !dnsName(r.SNI) {
		return errors.New("检测需要有效的公网目标域名:端口，以及不含通配符的 SNI 域名")
	}
	return nil
}
func dnsName(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

var restricted = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/32"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("2002::/16"),
}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range restricted {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// Runner has injectable network operations for deterministic security tests.
// The public entry point always uses the system resolver and verified TLS.
type runner struct {
	lookup func(context.Context, string, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
	roots  *x509.CertPool
}

func Reality(ctx context.Context, q Request) Result {
	d := &net.Dialer{Timeout: 4 * time.Second}
	return (runner{lookup: net.DefaultResolver.LookupNetIP, dial: d.DialContext}).run(ctx, q)
}
func (r runner) run(ctx context.Context, q Request) Result {
	result := Result{ID: q.ID, Checked: time.Now().UTC(), Stage: "input"}
	fail := func(stage, message string) Result { result.Stage = stage; result.Message = message; return result }
	if e := Validate(q); e != nil {
		return fail("input", e.Error())
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	h, port, _ := net.SplitHostPort(q.Target)
	ips, e := r.lookup(ctx, "ip", h)
	if e != nil || len(ips) == 0 {
		return fail("dns", "目标域名解析失败，请检查入口服务器 DNS")
	}
	// Reject mixed public/private answers; pin the checked address when dialing.
	for _, ip := range ips {
		if !publicIP(ip) {
			return fail("address", "目标解析包含非公网地址，已拒绝检测")
		}
	}
	var conn net.Conn
	start := time.Now()
	for i, ip := range ips {
		if i >= 4 {
			break
		}
		attempt, c := context.WithTimeout(ctx, 2*time.Second)
		conn, e = r.dial(attempt, "tcp", net.JoinHostPort(ip.String(), port))
		c()
		if e == nil {
			break
		}
	}
	if e != nil || conn == nil {
		return fail("tcp", "入口服务器无法连接目标 TCP 端口")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	client := tls.Client(conn, &tls.Config{ServerName: q.SNI, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"h2", "http/1.1"}, RootCAs: r.roots})
	if e = client.HandshakeContext(ctx); e != nil {
		return fail("tls", "TLS 1.3 / X25519 握手或 SNI 证书校验失败，请更换目标或检查服务器时间")
	}
	s := client.ConnectionState()
	result.ALPN = s.NegotiatedProtocol
	result.Latency = time.Since(start).Milliseconds()
	if len(s.PeerCertificates) > 0 {
		result.CertificateExpires = s.PeerCertificates[0].NotAfter.UTC()
	}
	if s.NegotiatedProtocol != "h2" {
		return fail("alpn", "目标未协商 HTTP/2，建议更换支持 h2 的站点")
	}
	result.Success = true
	result.Stage = "complete"
	result.Message = "入口服务器检测通过：TLS 1.3、X25519、SNI 证书与 HTTP/2。未检查网页重定向，也不代表客户端代理链路已通过。"
	return result
}
