package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/321CMO/relaydeck/internal/panel"
)

func TestFirewallScopesAndValidation(t *testing.T) {
	d := panel.Deployment{Hops: []panel.Hop{{Start: 20000, End: 20100, Port: 443}}, BackhaulSources: []string{"10.0.0.1", "fd00::1"}}
	rules, e := Firewall(d, true)
	if e != nil {
		t.Fatal(e)
	}
	for _, wanted := range []string{"delete table inet relaydeck", "ip saddr { 10.0.0.1 }", "ip6 saddr { fd00::1 }", "th dport 18999 drop", "udp dport 20000-20100 redirect to :443"} {
		if !strings.Contains(rules, wanted) {
			t.Fatal("missing rule", wanted)
		}
	}
	if strings.Contains(rules, "flush ruleset") {
		t.Fatal("must not touch other firewall tables")
	}
	d.BackhaulSources = []string{"1.1.1.1"}
	if _, e = Firewall(d, false); e == nil {
		t.Fatal("public source accepted")
	}
}
func TestApplyFailureKeepsPreviousRevision(t *testing.T) {
	dir := t.TempDir()
	core := filepath.Join(t.TempDir(), "fake-core")
	script := `#!/bin/sh
case "$1" in
check) if test "$RELAYDECK_TEST_REJECT" = "1"; then exit 1; fi ;;
run) exec sleep 60 ;;
*) exit 0 ;;
esac
`
	if e := os.WriteFile(core, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	a := New(dir, core, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer a.stop()
	d := panel.Deployment{Revision: 1, Config: json.RawMessage(`{"inbounds":[],"outbounds":[{"type":"direct"}]}`), Files: map[string]string{}}
	if e := a.Apply(ctx, d); e != nil {
		t.Fatal(e)
	}
	t.Setenv("RELAYDECK_TEST_REJECT", "1")
	d.Revision = 2
	if e := a.Apply(ctx, d); e == nil {
		t.Fatal("invalid deployment accepted")
	}
	if a.applied != 1 || !a.alive() {
		t.Fatal("failed validation interrupted working revision")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "current.json"))
	var saved panel.Deployment
	json.Unmarshal(b, &saved)
	if saved.Revision != 1 {
		t.Fatal("failed revision persisted as applied")
	}
}
func TestEndpointPolicy(t *testing.T) {
	for _, v := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/path", "https://example.com?token=bad"} {
		if endpointValid(v, false) {
			t.Fatal("unsafe endpoint", v)
		}
	}
	if !endpointValid("https://panel.example.com", false) || !endpointValid("http://127.0.0.1:8787", true) {
		t.Fatal("valid endpoint rejected")
	}
}

func TestRestoredEpochReplacesHigherAppliedRevision(t *testing.T) {
	dir := t.TempDir()
	core := filepath.Join(t.TempDir(), "fake-core")
	if e := os.WriteFile(core, []byte("#!/bin/sh\nif [ \"$1\" = run ]; then exec sleep 60; fi\nexit 0\n"), 0700); e != nil {
		t.Fatal(e)
	}
	a := New(dir, core, true)
	defer a.stop()
	d := panel.Deployment{Revision: 99, Config: json.RawMessage(`{"inbounds":[],"outbounds":[{"type":"direct"}]}`)}
	if e := a.Apply(context.Background(), d); e != nil {
		t.Fatal(e)
	}
	d.Epoch, d.Revision = "AAAAAAAAAAAAAAAAAAAAAA", 4
	if e := a.Apply(context.Background(), d); e != nil {
		t.Fatal(e)
	}
	if a.applied != 4 || a.current.Epoch != d.Epoch || !a.alive() {
		t.Fatal("restored configuration skipped because its revision was lower")
	}
	old, _ := panel.VersionDir(dir, 99, "")
	newDir, _ := panel.VersionDir(dir, 4, d.Epoch)
	for _, path := range []string{old, newDir} {
		if _, e := os.Stat(filepath.Join(path, "config.json")); e != nil {
			t.Fatal("epoch transition overwrote previous configuration")
		}
	}
	if _, e := panel.VersionDir(dir, 4, "../../escape"); e == nil {
		t.Fatal("unsafe epoch accepted as a path")
	}
}
func TestExpiryBeforeRestartRemovesEmptyPublicListener(t *testing.T) {
	d := panel.Deployment{Config: json.RawMessage(`{"inbounds":[{"tag":"node","users":[{"name":"expired","uuid":"credential"}]},{"tag":"internal-backhaul","users":[{"name":"backhaul_a","password":"internal"}]}]}`), Expires: map[string]string{"expired": time.Now().Add(-time.Minute).Format(time.RFC3339)}}
	clean, changed, e := RemoveExpired(d, time.Now())
	if e != nil || !changed {
		t.Fatal("expiry not detected", e)
	}
	if strings.Contains(string(clean.Config), "credential") || strings.Contains(string(clean.Config), `"tag":"node"`) {
		t.Fatal("expired public listener retained")
	}
	if !strings.Contains(string(clean.Config), "internal-backhaul") {
		t.Fatal("unrelated protected ingress removed")
	}
	if len(d.Expires) != 1 || len(clean.Expires) != 0 {
		t.Fatal("original state mutated by expiry cleanup")
	}
}
