package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestRealVPSMihomoSubscription(t *testing.T) {
	core, specPath := os.Getenv("MIHOMO_BIN"), os.Getenv("RELAYDECK_VPS_SPEC")
	if core == "" || specPath == "" {
		t.Skip("requires official Mihomo and an authorized VPS specification")
	}
	var spec struct {
		HTTPTarget    string `json:"httpTarget"`
		UDPTarget     int    `json:"udpTarget"`
		Subscriptions []struct {
			URL string `json:"url"`
		} `json:"subscriptions"`
	}
	b, e := os.ReadFile(specPath)
	if e != nil || json.Unmarshal(b, &spec) != nil || len(spec.Subscriptions) == 0 {
		t.Fatal("invalid private VPS specification")
	}
	subURL, e := url.Parse(spec.Subscriptions[0].URL)
	if e != nil || subURL.Scheme != "https" {
		t.Fatal("invalid subscription origin")
	}
	q := subURL.Query()
	q.Set("format", "clash")
	subURL.RawQuery = q.Encode()
	client := &http.Client{Timeout: 20 * time.Second}
	res, e := client.Get(subURL.String())
	if e != nil {
		t.Fatal("public subscription TLS verification failed")
	}
	defer res.Body.Close()
	b, e = io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if e != nil || res.StatusCode != 200 {
		t.Fatal("cannot retrieve Clash subscription")
	}
	var cfg map[string]any
	if e = yaml.Unmarshal(b, &cfg); e != nil {
		t.Fatal("invalid Clash YAML")
	}
	proxies, ok := cfg["proxies"].([]any)
	if !ok || len(proxies) != 3 {
		t.Fatal("missing three protocol proxies")
	}
	port, control := freePort(t), freePort(t)
	secret := randomToken(24)
	cfg["mixed-port"], cfg["external-controller"], cfg["secret"] = port, fmt.Sprintf("127.0.0.1:%d", control), secret
	if dns, ok := cfg["dns"].(map[string]any); ok {
		dns["listen"] = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	b, e = yaml.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(configPath, b, 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(core, "-d", dir, "-f", configPath)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if e = cmd.Start(); e != nil {
		t.Fatal("cannot start official Mihomo")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	defer func() {
		select {
		case <-done:
			return
		default:
		}
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}()
	ready := false
	for attempt := 0; attempt < 300; attempt++ {
		select {
		case <-done:
			t.Fatal("Mihomo rejected subscription or exited during startup")
		default:
		}
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", control), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Mihomo controller did not become ready")
	}
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	proxy := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	localTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("through-managed-core")) }))
	defer localTarget.Close()
	if e = getThrough(t, proxy, localTarget.URL); e != nil {
		t.Fatal("private-address DIRECT routing failed")
	}
	controller := func(method, path string, input any) {
		b, _ := json.Marshal(input)
		req, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d", control)+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Content-Type", "application/json")
		res, e := client.Do(req)
		if e != nil {
			t.Fatal("Mihomo controller unavailable")
		}
		res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			t.Fatalf("Mihomo controller HTTP %d", res.StatusCode)
		}
	}
	controller("PATCH", "/configs", map[string]string{"mode": "global"})
	for _, raw := range proxies {
		p, ok := raw.(map[string]any)
		if !ok {
			t.Fatal("invalid proxy entry")
		}
		kind, _ := p["type"].(string)
		name, _ := p["name"].(string)
		t.Run(kind, func(t *testing.T) {
			controller("PUT", "/proxies/GLOBAL", map[string]string{"name": name})
			if e := getThrough(t, proxy, spec.HTTPTarget); e != nil {
				t.Fatal("real Mihomo TCP failed:", e)
			}
			if reply, e := udpThrough(port, spec.UDPTarget); e != nil || reply != "managed-udp" {
				t.Fatal("real Mihomo UDP failed", e)
			}
			if kind == "hysteria2" {
				if ports, _ := p["ports"].(string); !strings.Contains(ports, "-") {
					t.Fatal("exported HY2 hopping range missing")
				}
				time.Sleep(6 * time.Second)
				if e := getThrough(t, proxy, spec.HTTPTarget); e != nil {
					t.Fatal("Mihomo TCP failed after exported hopping interval")
				}
				if reply, e := udpThrough(port, spec.UDPTarget); e != nil || reply != "managed-udp" {
					t.Fatal("Mihomo UDP failed after exported hopping interval", e)
				}
			}
		})
	}
}
