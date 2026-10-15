package panel

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This test only runs against an explicitly supplied, privately stored test
// specification. No server address, subscription token or password is in source.
func TestRealVPSPublishedSubscriptions(t *testing.T) {
	path := os.Getenv("RELAYDECK_VPS_SPEC")
	if path == "" {
		t.Skip("requires an explicitly authorized VPS and private test specification")
	}
	core := networkCore(t)
	var spec struct {
		RootCertificate string `json:"rootCertificate"`
		HYCertificate   string `json:"hyCertificate"`
		HTTPTarget      string `json:"httpTarget"`
		UDPTarget       int    `json:"udpTarget"`
		Subscriptions   []struct {
			URL    string `json:"url"`
			Cached string `json:"cached"`
		} `json:"subscriptions"`
	}
	b, e := os.ReadFile(path)
	if e != nil || json.Unmarshal(b, &spec) != nil || len(spec.Subscriptions) != 2 {
		t.Fatal("invalid private VPS specification")
	}
	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	if spec.RootCertificate != "" && !roots.AppendCertsFromPEM([]byte(spec.RootCertificate)) {
		t.Fatal("invalid test CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	for i, sub := range spec.Subscriptions {
		t.Run(fmt.Sprintf("friend-%d", i+1), func(t *testing.T) {
			denied := i == 1 && os.Getenv("RELAYDECK_VPS_DENY_SECOND") == "1"
			res, err := client.Get(sub.URL)
			if err != nil {
				t.Fatal("VPS subscription TLS or connection failed")
			}
			body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
			res.Body.Close()
			if err != nil {
				t.Fatal("cannot read VPS subscription")
			}
			if denied {
				if res.StatusCode != 403 {
					t.Fatal("disabled friend can still retrieve subscription")
				}
				body = []byte(sub.Cached)
			} else if res.StatusCode != 200 {
				t.Fatalf("subscription HTTP status %d", res.StatusCode)
			}
			decoded, err := base64.StdEncoding.DecodeString(string(body))
			if err != nil {
				t.Fatal("invalid published URI subscription")
			}
			links := strings.Split(strings.TrimSpace(string(decoded)), "\n")
			if len(links) != 3 {
				t.Fatal("aggregate subscription must contain three managed protocols")
			}
			for _, link := range links {
				out, protocol, err := vpsOutbound(link, spec.HYCertificate)
				if err != nil {
					t.Fatal("published URI cannot be parsed by test client")
				}
				t.Run(protocol, func(t *testing.T) {
					proxy, socks := proxyClient(t, core, out)
					proxy.Timeout = 10 * time.Second
					tcpErr := getThrough(t, proxy, spec.HTTPTarget)
					udp, udpErr := udpThrough(socks, spec.UDPTarget)
					if denied {
						if tcpErr == nil || udpErr == nil {
							t.Fatal("cached credentials survived applied friend revocation")
						}
						return
					}
					if tcpErr != nil || udpErr != nil || udp != "managed-udp" {
						t.Fatalf("real VPS TCP/UDP failed: TCP=%v UDP=%v", tcpErr, udpErr)
					}
					if protocol == "hysteria2" && i == 0 {
						for _, port := range []int{20000, 20005, 20010} {
							out["server_port"] = port
							probe, relay := proxyClient(t, core, out)
							probe.Timeout = 10 * time.Second
							if err := getThrough(t, probe, spec.HTTPTarget); err != nil {
								t.Fatalf("public hopping port %d failed: %v", port, err)
							}
							if reply, err := udpThrough(relay, spec.UDPTarget); err != nil || reply != "managed-udp" {
								t.Fatalf("UDP via public hopping port %d failed", port)
							}
						}
						delete(out, "server_port")
						out["server_ports"] = []string{"20000:20010"}
						out["hop_interval"] = "5s"
						probe, relay := proxyClient(t, core, out)
						probe.Timeout = 10 * time.Second
						for attempt := 0; attempt < 3; attempt++ {
							if attempt > 0 {
								time.Sleep(6 * time.Second)
							}
							if err := getThrough(t, probe, spec.HTTPTarget); err != nil {
								t.Fatal("TCP failed while HY2 was hopping")
							}
							udpReady := false
							for probeAttempt := 0; probeAttempt < 3; probeAttempt++ {
								if reply, err := udpThrough(relay, spec.UDPTarget); err == nil && reply == "managed-udp" {
									udpReady = true
									if probeAttempt > 0 {
										t.Logf("UDP probe recovered after %d retry during a port transition", probeAttempt)
									}
									break
								}
							}
							if !udpReady {
								t.Fatal("UDP remained unavailable after HY2 port transition")
							}
						}
					}
				})
			}
		})
	}
}

func vpsOutbound(raw, certificate string) (map[string]any, string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return nil, "", fmt.Errorf("invalid URI")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, "", err
	}
	q := u.Query()
	out := map[string]any{"server": u.Hostname(), "server_port": port}
	switch u.Scheme {
	case "vless":
		out["type"], out["uuid"], out["flow"] = "vless", u.User.Username(), q.Get("flow")
		out["tls"] = map[string]any{"enabled": true, "server_name": q.Get("sni"), "utls": map[string]any{"enabled": true, "fingerprint": q.Get("fp")}, "reality": map[string]any{"enabled": true, "public_key": q.Get("pbk"), "short_id": q.Get("sid")}}
	case "hysteria2":
		out["type"], out["password"] = "hysteria2", u.User.Username()
		tlsConfig := map[string]any{"enabled": true, "server_name": q.Get("sni")}
		if certificate != "" {
			tlsConfig["certificate"] = []string{certificate}
		}
		out["tls"] = tlsConfig
	case "ss":
		decoded, err := base64.RawURLEncoding.DecodeString(u.User.Username())
		if err != nil {
			return nil, "", err
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return nil, "", fmt.Errorf("invalid SS credentials")
		}
		out["type"], out["method"], out["password"] = "shadowsocks", parts[0], parts[1]
	default:
		return nil, "", fmt.Errorf("unsupported protocol")
	}
	return out, u.Scheme, nil
}
