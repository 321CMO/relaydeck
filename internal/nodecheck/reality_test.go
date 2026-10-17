package nodecheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRealityPinnedAddressAndTLSVerification(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"target.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &k.PublicKey, k)
	if e != nil {
		t.Fatal(e)
	}
	crt, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(crt)
	for _, tc := range []struct {
		name, sni, alpn string
		roots           bool
		version         uint16
		want            string
	}{
		{"valid", "target.example.com", "h2", true, tls.VersionTLS13, "complete"},
		{"wrong SNI", "wrong.example.com", "h2", true, tls.VersionTLS13, "tls"},
		{"untrusted chain", "target.example.com", "h2", false, tls.VersionTLS13, "tls"},
		{"no h2", "target.example.com", "http/1.1", true, tls.VersionTLS13, "alpn"},
		{"old TLS", "target.example.com", "h2", true, tls.VersionTLS12, "tls"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var target string
			r := runner{lookup: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("93.184.215.14")}, nil
			}, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				target = address
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					c := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}, MinVersion: tc.version, MaxVersion: tc.version, CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{tc.alpn}})
					_ = c.HandshakeContext(context.Background())
				}()
				return client, nil
			}}
			if tc.roots {
				r.roots = roots
			} else {
				r.roots = x509.NewCertPool()
			}
			got := r.run(context.Background(), Request{ID: "test", Target: "target.example.com:443", SNI: tc.sni})
			if got.Stage != tc.want || got.Success != (tc.want == "complete") {
				t.Fatalf("unexpected result: %+v", got)
			}
			if target != "93.184.215.14:443" {
				t.Fatalf("DNS result was not pinned: %s", target)
			}
		})
	}
}
func TestRealityRejectsInternalAndMixedAnswers(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.1.0.1", "169.254.169.254", "100.64.0.1", "198.18.1.1", "192.0.2.1", "224.0.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "2001:db8::1", "2002:7f00:1::1"} {
		t.Run(address, func(t *testing.T) {
			r := runner{lookup: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("93.184.215.14"), netip.MustParseAddr(address)}, nil
			}, dial: func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("restricted address reached network dial")
				return nil, nil
			}}
			got := r.run(context.Background(), Request{Target: "target.example.com:443", SNI: "target.example.com"})
			if got.Stage != "address" {
				t.Fatalf("address accepted: %+v", got)
			}
		})
	}
	for _, q := range []Request{{Target: "localhost:443", SNI: "a.example.com"}, {Target: "127.0.0.1:443", SNI: "a.example.com"}, {Target: "a.example.com:0", SNI: "a.example.com"}, {Target: "a.example.com:443", SNI: "*.example.com"}, {Target: "a.example.com:443", SNI: strings.Repeat("a", 64) + ".com"}} {
		if Validate(q) == nil {
			t.Fatalf("bad request accepted: %+v", q)
		}
	}
}
