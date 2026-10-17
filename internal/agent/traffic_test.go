package agent

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/321CMO/relaydeck/internal/panel"
)

func TestStatisticsCoreCountsUsersAndPersistsAcrossRestart(t *testing.T) {
	core := os.Getenv("SING_BOX_BIN")
	if core == "" {
		t.Skip("statistics-enabled pinned upstream core required")
	}
	v, e := exec.Command(core, "version").Output()
	if e != nil || !strings.Contains(string(v), "with_v2ray_api") {
		t.Fatal("core lacks user statistics")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { data, _ := io.ReadAll(r.Body); w.Write(data) }))
	defer target.Close()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	uuid := "11111111-1111-4111-8111-111111111111"
	cfg := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "vless", "tag": "test-ingress", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]any{"name": "user_alice", "uuid": uuid}}}}, "outbounds": []any{map[string]any{"type": "direct"}}, "experimental": map[string]any{"v2ray_api": map[string]any{"listen": "127.0.0.1:10085", "stats": map[string]any{"enabled": true, "users": []string{"user_alice"}}}}}
	b, _ := json.Marshal(cfg)
	os.WriteFile(path, b, 0600)
	a := New(dir, core, true)
	a.current = &panel.Deployment{TrafficUsers: []string{"user_alice"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer a.stop()
	if e := a.start(ctx, path); e != nil {
		t.Fatal(e)
	}
	first := a.sampleTraffic(ctx)
	if first == nil || first.Users["user_alice"].Upload != 0 {
		t.Fatal("new verified counter not initialized")
	}
	request := func() {
		transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, e := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if e != nil {
				return nil, e
			}
			_, rawPort, _ := net.SplitHostPort(address)
			p, _ := strconv.Atoi(rawPort)
			header := []byte{0, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0, 1, byte(p >> 8), byte(p), 1, 127, 0, 0, 1}
			if _, e = conn.Write(header); e != nil {
				conn.Close()
				return nil, e
			}
			// The first server response is a two-byte VLESS prefix, before HTTP.
			return &vlessTestConn{Conn: conn}, nil
		}}
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		data := strings.Repeat("verified-user-data", 2048)
		res, e := client.Post(target.URL, "text/plain", strings.NewReader(data))
		if e != nil {
			t.Fatal(e)
		}
		got, _ := io.ReadAll(res.Body)
		res.Body.Close()
		transport.CloseIdleConnections()
		if string(got) != data {
			t.Fatal("proxy payload changed")
		}
	}
	request()
	after := a.sampleTraffic(ctx)
	if after == nil || after.Users["user_alice"].Upload < 32768 || after.Users["user_alice"].Download < 32768 {
		t.Fatal("real bidirectional user traffic missing")
	}
	stable := a.sampleTraffic(ctx)
	if stable.Users["user_alice"] != after.Users["user_alice"] {
		t.Fatal("sampling counted bytes twice")
	}
	a.stop()
	if e := a.start(ctx, path); e != nil {
		t.Fatal(e)
	}
	request()
	restarted := a.sampleTraffic(ctx)
	if restarted == nil || restarted.Stream != after.Stream || restarted.Users["user_alice"].Upload < 2*after.Users["user_alice"].Upload {
		t.Fatal("core restart lost persistent totals")
	}
}

type vlessTestConn struct {
	net.Conn
	ready bool
}

func (c *vlessTestConn) Read(b []byte) (int, error) {
	if !c.ready {
		var h [2]byte
		if _, e := io.ReadFull(c.Conn, h[:]); e != nil {
			return 0, e
		}
		c.ready = true
	}
	return c.Conn.Read(b)
}
