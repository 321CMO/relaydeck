package panel

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func boolp(v bool) *bool { return &v }
func routingFixture() State {
	s := fixture()
	s.Outbounds = []Outbound{{ID: "out_a", ServerID: "srv_a", Name: "代理出口", Tag: "proxy-a", Type: "socks", Enabled: true, Address: "proxy.example.com", Port: 1080, Username: "account", Password: "private-outbound-password"}}
	return s
}

func TestRoutingReferencesSecretsAndOrderingAPI(t *testing.T) {
	s := testStore(t)
	f := routingFixture()
	s.Update(func(s *State) error { *s = f; return nil })
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	cookie, csrf := loginTest(t, a)
	rule := Route{Name: "自定义出口", Scope: "server", ServerID: "srv_a", Enabled: boolp(true), Domains: "domain:example.com\nfull:api.example.org", Ports: "443,8000-9000", Networks: []string{"tcp"}, NodeIDs: []string{f.Nodes[0].ID}, UserIDs: []string{f.Users[0].ID}, Action: "outbound", OutboundID: "out_a"}
	w := request(t, a, "POST", "/api/routes", rule, cookie, csrf, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	first := result["id"]
	rule.Name = "第二条"
	rule.Action = "reject"
	rule.OutboundID = ""
	w = request(t, a, "POST", "/api/routes", rule, cookie, csrf, "")
	json.Unmarshal(w.Body.Bytes(), &result)
	second := result["id"]
	w = request(t, a, "POST", "/api/routes/reorder", map[string]any{"scope": "server", "serverId": "srv_a", "ids": []string{second, first}}, cookie, csrf, "")
	if w.Code != 200 || s.Read().Routes[0].ID != second {
		t.Fatal("ordered route mutation failed")
	}
	w = request(t, a, "POST", "/api/routes/reorder", map[string]any{"scope": "server", "serverId": "srv_a", "ids": []string{first, first}}, cookie, csrf, "")
	if w.Code != 422 || s.Read().Routes[0].ID != second {
		t.Fatal("invalid reorder changed rules")
	}
	w = request(t, a, "DELETE", "/api/outbounds/out_a", nil, cookie, csrf, "")
	if w.Code != 422 {
		t.Fatal("referenced outbound deleted")
	}
	o := s.Read().Outbounds[0]
	o.Enabled = false
	w = request(t, a, "POST", "/api/outbounds/out_a", o, cookie, csrf, "")
	if w.Code != 422 {
		t.Fatal("active rule lost outbound")
	}
	o.Enabled = true
	o.Tag = "renamed-proxy"
	o.Password = ""
	w = request(t, a, "POST", "/api/outbounds/out_a", o, cookie, csrf, "")
	if w.Code != 200 || s.Read().Outbounds[0].Password != "private-outbound-password" {
		t.Fatal("saved password lost during tag rename")
	}
	w = request(t, a, "GET", "/api/state", nil, cookie, "", "")
	if strings.Contains(w.Body.String(), "private-outbound-password") || !strings.Contains(w.Body.String(), `"hasPassword":true`) {
		t.Fatal("state leaked outbound secret or missing presence flag")
	}
	w = request(t, a, "GET", "/api/routing/preview?server=srv_a", nil, cookie, "", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "private-outbound-password") || strings.Contains(w.Body.String(), f.Users[0].Credentials[f.Nodes[0].ID]) {
		t.Fatal("preview leaks credentials")
	}
	if s.Read().Schema != 5 {
		t.Fatal("new routing data is readable by an incompatible old binary")
	}
	// Disable referencing rule first, then the outbound; deleting still needs explicit unlink.
	r := s.Read().Routes[1]
	r.Enabled = boolp(false)
	w = request(t, a, "POST", "/api/routes/"+r.ID, r, cookie, csrf, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	o = s.Read().Outbounds[0]
	o.Enabled = false
	w = request(t, a, "POST", "/api/outbounds/out_a", o, cookie, csrf, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
}

func TestRoutingValidationAndLogicalConditions(t *testing.T) {
	s := routingFixture()
	r := Route{Scope: "server", ServerID: "srv_a", Action: "outbound", OutboundID: "out_a", Domains: "domain:example.com\ngeosite:cn", IPs: "geoip:cn\ngeoip:private\n2001:db8::/32", Ports: "443,8000-9000", SourceIPs: "192.0.2.0/24", SourcePorts: "1000-2000", Networks: []string{"tcp"}, Protocols: []string{"tls"}, UserIDs: []string{s.Users[0].ID}}
	if e := validateRoute(s, r); e != nil {
		t.Fatal(e)
	}
	sets := map[string]map[string]any{}
	groups, e := matchGroups(r, sets)
	if e != nil || len(groups) != 8 || len(sets) != 2 {
		t.Fatal("criteria groups or geographic datasets missing")
	}
	r.ServerID = "srv_b"
	if validateRoute(s, r) == nil {
		t.Fatal("cross-server outbound reference allowed")
	}
	r.ServerID = "srv_a"
	r.Domains = "regexp:("
	if validateRoute(s, r) == nil {
		t.Fatal("invalid regex accepted")
	}
	r = Route{Scope: "server", ServerID: "srv_a", Action: "direct"}
	if validateRoute(s, r) == nil {
		t.Fatal("empty rule silently matched all traffic")
	}
	r.MatchAll = true
	if e := validateRoute(s, r); e != nil {
		t.Fatal(e)
	}
	a := s.Outbounds[0]
	b := a
	b.ID = "out_b"
	b.Tag = "proxy-b"
	b.DetourID = a.ID
	a.DetourID = b.ID
	s.Outbounds = []Outbound{a, b}
	if validateRoutingState(s) == nil {
		t.Fatal("outbound detour cycle allowed")
	}
}

func TestRoutingPolicyAndUpgradeRecompile(t *testing.T) {
	s := testStore(t)
	f := routingFixture()
	s.Update(func(s *State) error { *s = f; return nil })
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	before := s.Read().Servers[0].Desired
	if e := a.PrepareRuntime(); e != nil {
		t.Fatal(e)
	}
	after := s.Read().Servers[0].Desired
	if after <= before {
		t.Fatal("upgrade did not schedule new compilation")
	}
	a.PrepareRuntime()
	if s.Read().Servers[0].Desired != after {
		t.Fatal("every restart requeued unchanged compiler")
	}
	p := RoutingPolicy{ServerID: "srv_a", DefaultOutboundID: "out_a", Sniff: true, ResolveDomains: true}
	f = s.Read()
	savePolicy(&f, p)
	f.Routes = []Route{{Scope: "server", ServerID: "srv_a", Action: "reject", Domains: "geosite:cn", Protocols: []string{"tls"}}}
	d, e := Compile(f, "srv_a", t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	var cfg map[string]any
	json.Unmarshal(d.Config, &cfg)
	route := cfg["route"].(map[string]any)
	if route["final"] != "proxy-a" || cfg["dns"] == nil || route["rule_set"] == nil {
		t.Fatal("default outbound, resolver or ruleset missing")
	}
	if strings.Contains(string(d.Config), `"inbound": ["internal-backhaul"]`) {
		t.Fatal("public routing unexpectedly changed internal ingress")
	}
	// Backhaul bypass remains before public routing and cannot override the port guard.
	f.Nodes[0].ExitID = "srv_b"
	d, e = Compile(f, "srv_b", t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	json.Unmarshal(d.Config, &cfg)
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	if rules[0].(map[string]any)["action"] != "reject" || rules[1].(map[string]any)["outbound"] != "direct" {
		t.Fatal("internal egress or management guard precedence changed")
	}
}

func TestOfficialRoutingAndOutboundConfigurations(t *testing.T) {
	core := os.Getenv("SING_BOX_BIN")
	if core == "" {
		t.Skip("pinned core required")
	}
	s := routingFixture()
	_, pub, _ := realityKeys()
	s.Outbounds = append(s.Outbounds, Outbound{ID: "out_http", ServerID: "srv_a", Name: "HTTPS", Tag: "http-proxy", Type: "http", Enabled: true, Address: "proxy.example.com", Port: 8443, TLS: true, SNI: "proxy.example.com"}, Outbound{ID: "out_ss", ServerID: "srv_a", Name: "SS2022", Tag: "ss-proxy", Type: "ss2022", Enabled: true, Address: "ss.example.com", Port: 20838, Password: ssKey() + ":" + ssKey()}, Outbound{ID: "out_vless", ServerID: "srv_a", Name: "Reality", Tag: "vless-proxy", Type: "reality", Enabled: true, Address: "vless.example.com", Port: 443, UUID: uuid(), SNI: "www.microsoft.com", PublicKey: pub, ShortID: "01234567"}, Outbound{ID: "out_hy", ServerID: "srv_a", Name: "HY2", Tag: "hy-proxy", Type: "hy2", Enabled: true, Address: "hy.example.com", Port: 443, Password: "test-password", SNI: "hy.example.com", HopStart: 20000, HopEnd: 20010, HopInterval: 5})
	s.Routes = []Route{{Name: "组合条件", Scope: "server", ServerID: "srv_a", Domains: "domain:example.com\nfull:api.example.org\nkeyword:stream\nregexp:^api\\.", IPs: "geoip:private\n203.0.113.0/24", Ports: "443,8000-9000", SourceIPs: "192.0.2.0/24", SourcePorts: "1000-2000", Networks: []string{"tcp", "udp"}, Protocols: []string{"tls", "http"}, UserIDs: []string{s.Users[0].ID}, Action: "outbound", OutboundID: "out_vless"}, {Name: "地理规则", Scope: "server", ServerID: "srv_a", Domains: "geosite:cn", IPs: "geoip:cn", Action: "direct"}}
	savePolicy(&s, RoutingPolicy{ServerID: "srv_a", DefaultOutboundID: "out_a", Sniff: true, ResolveDomains: true})
	dir := t.TempDir()
	d, e := Compile(s, "srv_a", dir)
	if e != nil {
		t.Fatal(e)
	}
	versionDir, _ := VersionDir(dir, d.Revision, d.Epoch)
	os.MkdirAll(versionDir, 0700)
	WriteDeployment(d, versionDir)
	path := filepath.Join(versionDir, "config.json")
	os.WriteFile(path, d.Config, 0600)
	out, e := exec.CommandContext(context.Background(), core, "check", "-c", path).CombinedOutput()
	if e != nil {
		t.Fatalf("pinned core rejected routing/outbound config: %s", out)
	}
}

func TestOfficialUserScopedOutboundAndNoFallback(t *testing.T) {
	core := networkCore(t)
	s := fixture()
	entry := s.Nodes[0]
	exit := s.Nodes[1]
	entry.Protocol = "ss2022"
	entry.ServerKey = ssKey()
	entry.Port = freePort(t)
	exit.Port = freePort(t)
	s.Nodes = []Node{entry, exit}
	for i := range s.Users {
		s.Users[i].NodeIDs = []string{entry.ID, exit.ID}
		s.Users[i].Credentials = map[string]string{entry.ID: ssKey(), exit.ID: ssKey()}
	}
	s.Outbounds = []Outbound{{ID: "out_exit", ServerID: "srv_a", Name: "测试落地", Tag: "test-exit", Type: "ss2022", Enabled: true, Address: "127.0.0.1", Port: exit.Port, Password: exit.ServerKey + ":" + s.Users[0].Credentials[exit.ID]}}
	s.Routes = []Route{{ID: "rule_a", Name: "指定订阅走落地", Scope: "server", ServerID: "srv_a", UserIDs: []string{s.Users[0].ID}, NodeIDs: []string{entry.ID}, Action: "outbound", OutboundID: "out_exit"}}
	stopExit := coreProcess(t, core, localCompile(t, s, "srv_b"), exit.Port)
	coreProcess(t, core, localCompile(t, s, "srv_a"), entry.Port)
	target, udpPort, tcpCount, udpCount := echoTargets(t)
	alice, aliceUDP := proxyClient(t, core, nodeOutbound(entry, s.Users[0].Credentials[entry.ID], ""))
	bob, bobUDP := proxyClient(t, core, nodeOutbound(entry, s.Users[1].Credentials[entry.ID], ""))
	if e := getThrough(t, alice, target); e != nil {
		t.Fatal(e)
	}
	if v, e := udpThrough(aliceUDP, udpPort); e != nil || v != "managed-udp" {
		t.Fatal("outbound UDP failed", e)
	}
	if e := getThrough(t, bob, target); e != nil {
		t.Fatal(e)
	}
	stopExit()
	beforeTCP, beforeUDP := tcpCount.Load(), udpCount.Load()
	if getThrough(t, alice, target) == nil {
		t.Fatal("unavailable selected outbound fell back to direct")
	}
	if _, e := udpThrough(aliceUDP, udpPort); e == nil {
		t.Fatal("UDP fell back to direct")
	}
	if tcpCount.Load() != beforeTCP || udpCount.Load() != beforeUDP {
		t.Fatal("failed outbound reached direct target")
	}
	if e := getThrough(t, bob, target); e != nil {
		t.Fatal("another subscription was affected", e)
	}
	if v, e := udpThrough(bobUDP, udpPort); e != nil || v != "managed-udp" {
		t.Fatal("unmatched subscription UDP failed", e)
	}
}
