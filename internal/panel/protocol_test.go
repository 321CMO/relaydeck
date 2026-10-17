package panel

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func networkCore(t *testing.T) string {
	t.Helper()
	core := os.Getenv("SING_BOX_BIN")
	if core == "" || os.Getenv("RELAYDECK_CORE_NETWORK_TEST") != "1" {
		t.Skip("real core network checks require explicit local/CI opt-in")
	}
	return core
}
func freePort(t *testing.T) int {
	t.Helper()
	tcp, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	port := tcp.Addr().(*net.TCPAddr).Port
	udp, e := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if e != nil {
		t.Fatal(e)
	}
	udp.Close()
	return port
}
func coreProcess(t *testing.T, core string, config any, tcpPort int) func() {
	t.Helper()
	dir := t.TempDir()
	b, e := json.Marshal(config)
	if e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(dir, "config.json")
	if e = os.WriteFile(file, b, 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(core, "run", "-c", file)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	stop := func() {
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
	}
	t.Cleanup(stop)
	if tcpPort == 0 {
		select {
		case <-done:
			t.Fatal("official core exited at startup")
		case <-time.After(150 * time.Millisecond):
		}
		return stop
	}
	for i := 0; i < 100; i++ {
		select {
		case <-done:
			t.Fatal("official core exited before readiness")
		default:
		}
		conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpPort)), 50*time.Millisecond)
		if e == nil {
			conn.Close()
			return stop
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal("official core did not open its listener")
	return stop
}
func localCompile(t *testing.T, s State, id string) map[string]any {
	t.Helper()
	dir := t.TempDir()
	d, e := Compile(s, id, dir)
	if e != nil {
		t.Fatal(e)
	}
	if e = WriteDeployment(d, filepath.Join(dir, "versions", strconv.FormatInt(d.Revision, 10))); e != nil {
		t.Fatal(e)
	}
	var cfg map[string]any
	if e = json.Unmarshal(d.Config, &cfg); e != nil {
		t.Fatal(e)
	}
	for _, raw := range cfg["inbounds"].([]any) {
		raw.(map[string]any)["listen"] = "127.0.0.1"
	}
	return cfg
}
func proxyClient(t *testing.T, core string, out map[string]any) (*http.Client, int) {
	t.Helper()
	port := freePort(t)
	out["tag"] = "proxy"
	coreProcess(t, core, map[string]any{"log": map[string]any{"level": "error"}, "inbounds": []any{map[string]any{"type": "mixed", "listen": "127.0.0.1", "listen_port": port}}, "outbounds": []any{out}, "route": map[string]any{"final": "proxy"}}, port)
	u, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	transport := &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}, port
}
func getThrough(t *testing.T, client *http.Client, target string) error {
	t.Helper()
	res, e := client.Get(target)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	b, e := io.ReadAll(res.Body)
	if e != nil {
		return e
	}
	if res.StatusCode != 200 || string(b) != "through-managed-core" {
		return fmt.Errorf("proxy response status %d", res.StatusCode)
	}
	return nil
}
func udpThrough(port, targetPort int) (string, error) {
	conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if e != nil {
		return "", e
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, e = conn.Write([]byte{5, 1, 0}); e != nil {
		return "", e
	}
	auth := make([]byte, 2)
	if _, e = io.ReadFull(conn, auth); e != nil {
		return "", e
	}
	if auth[1] != 0 {
		return "", io.ErrUnexpectedEOF
	}
	if _, e = conn.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
		return "", e
	}
	header := make([]byte, 4)
	if _, e = io.ReadFull(conn, header); e != nil {
		return "", e
	}
	if header[1] != 0 {
		return "", io.ErrUnexpectedEOF
	}
	length := 4
	if header[3] == 4 {
		length = 16
	} else if header[3] != 1 {
		return "", io.ErrUnexpectedEOF
	}
	address := make([]byte, length+2)
	if _, e = io.ReadFull(conn, address); e != nil {
		return "", e
	}
	relay := &net.UDPAddr{IP: net.IP(address[:length]), Port: int(binary.BigEndian.Uint16(address[length:]))}
	if relay.IP.IsUnspecified() {
		if length == 4 {
			relay.IP = net.ParseIP("127.0.0.1")
		} else {
			relay.IP = net.ParseIP("::1")
		}
	}
	udp, e := net.DialUDP("udp", nil, relay)
	if e != nil {
		return "", e
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(2 * time.Second))
	packet := []byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(packet[8:], uint16(targetPort))
	packet = append(packet, []byte("managed-udp")...)
	if _, e = udp.Write(packet); e != nil {
		return "", e
	}
	buffer := make([]byte, 1024)
	n, e := udp.Read(buffer)
	if e != nil {
		return "", e
	}
	offset := 10
	if n < 4 {
		return "", io.ErrUnexpectedEOF
	}
	if buffer[3] == 4 {
		offset = 22
	}
	if n < offset {
		return "", io.ErrUnexpectedEOF
	}
	return string(buffer[offset:n]), nil
}
func echoTargets(t *testing.T) (string, int, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	tcpCount, udpCount := new(atomic.Int64), new(atomic.Int64)
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tcpCount.Add(1)
		io.WriteString(w, "through-managed-core")
	}))
	t.Cleanup(httpServer.Close)
	udp, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { udp.Close() })
	go func() {
		b := make([]byte, 1024)
		for {
			n, addr, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			udpCount.Add(1)
			_, _ = udp.WriteTo(b[:n], addr)
		}
	}()
	return httpServer.URL, udp.LocalAddr().(*net.UDPAddr).Port, tcpCount, udpCount
}
func nodeOutbound(n Node, credential string, certificate string) map[string]any {
	out := map[string]any{"server": "127.0.0.1", "server_port": n.Port}
	switch n.Protocol {
	case "ss2022":
		out["type"] = "shadowsocks"
		out["method"] = "2022-blake3-aes-128-gcm"
		out["password"] = n.ServerKey + ":" + credential
	case "hy2":
		out["type"] = "hysteria2"
		out["password"] = credential
		out["tls"] = map[string]any{"enabled": true, "server_name": n.SNI, "certificate": []string{certificate}}
	case "reality":
		out["type"] = "vless"
		out["uuid"] = credential
		out["flow"] = "xtls-rprx-vision"
		out["tls"] = map[string]any{"enabled": true, "server_name": n.SNI, "utls": map[string]any{"enabled": true, "fingerprint": "chrome"}, "reality": map[string]any{"enabled": true, "public_key": n.PublicKey, "short_id": n.ShortID}}
	}
	return out
}
func TestOfficialProtocolTCPUDPAndCredentialIsolation(t *testing.T) {
	core := networkCore(t)
	for _, protocol := range []string{"ss2022", "hy2", "reality"} {
		t.Run(protocol, func(t *testing.T) {
			s := fixture()
			n := s.Nodes[0]
			n.Protocol = protocol
			n.Port = freePort(t)
			n.ServerKey = ssKey()
			n.SNI = protocol + ".example.com"
			crt, key := cert(t, n.SNI)
			n.Certificate = crt
			n.Key = key
			n.TLSMode = "import"
			n.ExitID = ""
			if protocol == "reality" {
				pair, e := tls.X509KeyPair([]byte(crt), []byte(key))
				if e != nil {
					t.Fatal(e)
				}
				camouflage := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
				camouflage.Config.ErrorLog = log.New(io.Discard, "", 0)
				camouflage.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
				camouflage.StartTLS()
				t.Cleanup(camouflage.Close)
				n.Target = camouflage.Listener.Addr().String()
			}
			s.Nodes = []Node{n}
			for i := range s.Users {
				s.Users[i].NodeIDs = []string{n.ID}
				s.Users[i].Credentials = map[string]string{n.ID: credential(protocol)}
			}
			coreProcess(t, core, localCompile(t, s, "srv_a"), func() int {
				if protocol == "hy2" {
					return 0
				}
				return n.Port
			}())
			target, udpPort, tcpCount, _ := echoTargets(t)
			for _, u := range s.Users {
				client, socks := proxyClient(t, core, nodeOutbound(n, u.Credentials[n.ID], crt))
				if e := getThrough(t, client, target); e != nil {
					t.Fatal("authorized TCP failed:", e)
				}
				reply, e := udpThrough(socks, udpPort)
				if e != nil || reply != "managed-udp" {
					t.Fatal("authorized UDP failed", e)
				}
			}
			before := tcpCount.Load()
			invalid, _ := proxyClient(t, core, nodeOutbound(n, credential(protocol), crt))
			if e := getThrough(t, invalid, target); e == nil {
				t.Fatal("unknown user credential accepted")
			}
			if tcpCount.Load() != before {
				t.Fatal("invalid credential reached destination")
			}
		})
	}
}
func TestOfficialBackhaulFailsClosed(t *testing.T) {
	core := networkCore(t)
	s := fixture()
	n := s.Nodes[1]
	n.ServerID = "srv_a"
	n.Port = freePort(t)
	n.ExitID = "srv_b"
	s.Nodes = []Node{n}
	for i := range s.Users {
		s.Users[i].NodeIDs = []string{n.ID}
		s.Users[i].Credentials = map[string]string{n.ID: ssKey()}
	}
	internalPort := freePort(t)
	landing := localCompile(t, s, "srv_b")
	for _, raw := range landing["inbounds"].([]any) {
		raw.(map[string]any)["listen_port"] = internalPort
	}
	stopLanding := coreProcess(t, core, landing, internalPort)
	entry := localCompile(t, s, "srv_a")
	for _, raw := range entry["outbounds"].([]any) {
		v := raw.(map[string]any)
		if v["type"] == "shadowsocks" {
			v["server"] = "127.0.0.1"
			v["server_port"] = internalPort
		}
	}
	coreProcess(t, core, entry, n.Port)
	target, udpPort, tcpCount, udpCount := echoTargets(t)
	client, socks := proxyClient(t, core, nodeOutbound(n, s.Users[0].Credentials[n.ID], ""))
	if e := getThrough(t, client, target); e != nil {
		t.Fatal(e)
	}
	if reply, e := udpThrough(socks, udpPort); e != nil || reply != "managed-udp" {
		t.Fatal("backhaul UDP failed", e)
	}
	stopLanding()
	beforeTCP, beforeUDP := tcpCount.Load(), udpCount.Load()
	if e := getThrough(t, client, target); e == nil {
		t.Fatal("landing failure silently fell back to entry direct")
	}
	if _, e := udpThrough(socks, udpPort); e == nil {
		t.Fatal("landing failure allowed UDP fallback")
	}
	if tcpCount.Load() != beforeTCP || udpCount.Load() != beforeUDP {
		t.Fatal("blocked traffic still reached destination")
	}
}
