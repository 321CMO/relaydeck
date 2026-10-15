package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/321CMO/relaydeck/internal/panel"
	"golang.org/x/sys/unix"
)

type Identity struct {
	Endpoint  string `json:"endpoint"`
	ServerID  string `json:"serverId"`
	Token     string `json:"token"`
	MachineID string `json:"machineId"`
}
type Agent struct {
	Dir, Core  string
	generation string
	Dev        bool
	identity   Identity
	client     *http.Client
	process    *exec.Cmd
	done       chan error
	applied    int64
	lastError  string
	current    *panel.Deployment
	lease      time.Time
	mu         sync.Mutex
}

func New(dir, core string, dev bool) *Agent {
	return &Agent{Dir: dir, Core: core, Dev: dev, client: &http.Client{Timeout: 20 * time.Second}}
}
func endpointValid(raw string, dev bool) bool {
	u, e := url.Parse(raw)
	return e == nil && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Path == "" || u.Path == "/") && u.Host != "" && (u.Scheme == "https" || dev && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost"))
}
func (a *Agent) post(ctx context.Context, path string, input, output any) error {
	b, e := json.Marshal(input)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", a.identity.Endpoint+path, bytes.NewReader(b))
	if e != nil {
		return errors.New("中心地址无效")
	}
	req.Header.Set("Content-Type", "application/json")
	if a.identity.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.identity.Token)
	}
	res, e := a.client.Do(req)
	if e != nil {
		return errors.New("中心连接失败")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("中心拒绝请求（HTTP %d）", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(output)
}
func (a *Agent) Enroll(ctx context.Context, endpoint, serverID, code string) error {
	if !endpointValid(endpoint, a.Dev) {
		return errors.New("中心地址必须是 HTTPS；仅本机开发允许 HTTP")
	}
	if e := os.MkdirAll(a.Dir, 0700); e != nil {
		return e
	}
	path := filepath.Join(a.Dir, "identity.json")
	if b, e := os.ReadFile(path); e == nil {
		var old Identity
		if json.Unmarshal(b, &old) != nil {
			return errors.New("Agent 身份文件损坏")
		}
		if old.Endpoint != strings.TrimRight(endpoint, "/") || old.ServerID != serverID {
			return errors.New("此 Agent 已属于其他服务器，请先撤销旧身份")
		}
		a.identity = old
		return nil
	}
	machinePath := filepath.Join(a.Dir, "machine-id")
	machine, e := os.ReadFile(machinePath)
	if os.IsNotExist(e) {
		b := make([]byte, 16)
		if _, e = rand.Read(b); e != nil {
			return e
		}
		machine = []byte(hex.EncodeToString(b))
		e = os.WriteFile(machinePath, machine, 0600)
	}
	if e != nil {
		return e
	}
	a.identity = Identity{Endpoint: strings.TrimRight(endpoint, "/"), ServerID: serverID, MachineID: string(machine)}
	var out struct {
		Token string `json:"token"`
	}
	if e = a.post(ctx, "/api/agent/enroll", map[string]string{"serverId": serverID, "code": code, "machineId": string(machine)}, &out); e != nil {
		return e
	}
	if len(out.Token) < 32 {
		return errors.New("中心返回的 Agent 身份无效")
	}
	a.identity.Token = out.Token
	b, _ := json.Marshal(a.identity)
	return atomicWrite(path, b)
}
func (a *Agent) Load() error {
	b, e := os.ReadFile(filepath.Join(a.Dir, "identity.json"))
	if e != nil {
		return e
	}
	if e = json.Unmarshal(b, &a.identity); e != nil {
		return e
	}
	if !endpointValid(a.identity.Endpoint, a.Dev) {
		return errors.New("Agent 中心地址无效")
	}
	return nil
}
func atomicWrite(path string, b []byte) error {
	tmp := path + ".next"
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		os.Remove(tmp)
		return e
	}
	return os.Rename(tmp, path)
}
func (a *Agent) coreCheck(ctx context.Context, path string) error {
	c := exec.CommandContext(ctx, a.Core, "check", "-c", path)
	c.Stdout = io.Discard
	c.Stderr = io.Discard
	if e := c.Run(); e != nil {
		return errors.New("sing-box 配置检查失败")
	}
	return nil
}
func (a *Agent) start(ctx context.Context, path string) error {
	c := exec.CommandContext(ctx, a.Core, "run", "-c", path)
	c.Stdout = io.Discard
	c.Stderr = os.Stderr
	if e := c.Start(); e != nil {
		return errors.New("sing-box 启动失败")
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case <-done:
		return errors.New("sing-box 启动后退出")
	case <-ctx.Done():
		c.Process.Kill()
		<-done
		return ctx.Err()
	case <-time.After(700 * time.Millisecond):
		a.generation = fmt.Sprintf("%d-%d", c.Process.Pid, time.Now().UnixNano())
		a.process = c
		a.done = done
		return nil
	}
}
func (a *Agent) stop() {
	if a.process != nil {
		a.sampleTraffic(context.Background())
	}
	if a.process == nil {
		return
	}
	_ = a.process.Process.Signal(unix.SIGTERM)
	select {
	case <-a.done:
	case <-time.After(5 * time.Second):
		_ = a.process.Process.Kill()
		<-a.done
	}
	a.process = nil
	a.done = nil
}
func (a *Agent) alive() bool {
	if a.process == nil {
		return false
	}
	select {
	case <-a.done:
		a.process = nil
		a.done = nil
		return false
	default:
		return true
	}
}
func Firewall(d panel.Deployment, exists bool) (string, error) {
	var b strings.Builder
	if exists {
		b.WriteString("delete table inet relaydeck\n")
	}
	b.WriteString("table inet relaydeck {\n chain ingress { type filter hook input priority -5; policy accept;\n")
	if len(d.BackhaulSources) > 0 {
		v4, v6 := []string{}, []string{}
		for _, s := range d.BackhaulSources {
			a, e := netip.ParseAddr(s)
			if e != nil || !a.IsPrivate() {
				return "", errors.New("内网源地址无效")
			}
			if a.Is4() {
				v4 = append(v4, a.String())
			} else {
				v6 = append(v6, a.String())
			}
		}
		if len(v4) > 0 {
			fmt.Fprintf(&b, " ip saddr { %s } meta l4proto { tcp, udp } th dport 18999 accept\n", strings.Join(v4, ", "))
		}
		if len(v6) > 0 {
			fmt.Fprintf(&b, " ip6 saddr { %s } meta l4proto { tcp, udp } th dport 18999 accept\n", strings.Join(v6, ", "))
		}
		b.WriteString(" meta l4proto { tcp, udp } th dport 18999 drop\n")
	}
	b.WriteString(" }\n chain hopping { type nat hook prerouting priority dstnat; policy accept;\n")
	for _, h := range d.Hops {
		if h.Start < 1 || h.End < h.Start || h.End > 65535 || h.Port < 1 || h.Port > 65535 {
			return "", errors.New("跳跃端口无效")
		}
		fmt.Fprintf(&b, " udp dport %d-%d redirect to :%d\n", h.Start, h.End, h.Port)
	}
	b.WriteString(" }\n}\n")
	return b.String(), nil
}
func (a *Agent) firewall(d panel.Deployment) error {
	if runtime.GOOS != "linux" {
		if len(d.Hops) > 0 || len(d.BackhaulSources) > 0 {
			return errors.New("端口跳跃与内网防火墙需要 Linux")
		}
		return nil
	}
	list := exec.Command("nft", "list", "table", "inet", "relaydeck")
	exists := list.Run() == nil
	if !exists && len(d.Hops) == 0 && len(d.BackhaulSources) == 0 {
		return nil
	}
	rules, e := Firewall(d, exists)
	if e != nil {
		return e
	}
	for _, args := range [][]string{{"-c", "-f", "-"}, {"-f", "-"}} {
		cmd := exec.Command("nft", args...)
		cmd.Stdin = strings.NewReader(rules)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if e = cmd.Run(); e != nil {
			return errors.New("RelayDeck 专用 nftables 规则应用失败")
		}
	}
	return nil
}
func (a *Agent) Apply(ctx context.Context, d panel.Deployment) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	clean, _, err := RemoveExpired(d, time.Now())
	if err != nil {
		return err
	}
	d = clean
	if d.Revision <= a.applied && a.current != nil && d.Epoch == a.current.Epoch && a.alive() {
		return nil
	}
	if d.Revision < 1 || !json.Valid(d.Config) {
		return errors.New("配置版本或内容无效")
	}
	dir, pathErr := panel.VersionDir(a.Dir, d.Revision, d.Epoch)
	if pathErr != nil {
		return pathErr
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	if e := panel.WriteDeployment(d, dir); e != nil {
		return e
	}
	path := filepath.Join(dir, "config.json")
	if e := atomicWrite(path, d.Config); e != nil {
		return e
	}
	checkCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if e := a.coreCheck(checkCtx, path); e != nil {
		return e
	}
	old := a.current
	if e := a.firewall(d); e != nil {
		return e
	}
	a.stop()
	rollback := func() {
		if old != nil {
			_ = a.firewall(*old)
			oldDir, pathErr := panel.VersionDir(a.Dir, old.Revision, old.Epoch)
			if pathErr != nil {
				return
			}
			oldPath := filepath.Join(oldDir, "config.json")
			safe, _, e := RemoveExpired(*old, time.Now())
			if e == nil {
				_ = atomicWrite(oldPath, safe.Config)
				_ = a.start(ctx, oldPath)
			}
		}
	}
	if e := a.start(ctx, path); e != nil {
		rollback()
		return e
	}
	b, _ := json.Marshal(d)
	if e := atomicWrite(filepath.Join(a.Dir, "current.json"), b); e != nil {
		a.stop()
		rollback()
		return errors.New("生效版本记录失败，已尝试恢复旧服务")
	}
	a.current = &d
	a.applied = d.Revision
	return nil
}

// RemoveExpired runs before every startup, including restoration of a persisted config.
func RemoveExpired(d panel.Deployment, now time.Time) (panel.Deployment, bool, error) {
	expired := map[string]bool{}
	for id, raw := range d.Expires {
		expiry, e := time.Parse(time.RFC3339, raw)
		if e != nil || !now.Before(expiry) {
			expired[id] = true
		}
	}
	if len(expired) == 0 {
		return d, false, nil
	}
	var cfg map[string]any
	if e := json.Unmarshal(d.Config, &cfg); e != nil {
		return d, false, e
	}
	rawInbounds, _ := cfg["inbounds"].([]any)
	inbounds := []any{}
	for _, raw := range rawInbounds {
		in, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		users, has := in["users"].([]any)
		kept := []any{}
		for _, u := range users {
			user, _ := u.(map[string]any)
			id, _ := user["name"].(string)
			if !expired[id] {
				kept = append(kept, u)
			}
		}
		if has {
			if len(kept) == 0 && in["tag"] != "internal-backhaul" {
				continue
			}
			in["users"] = kept
		}
		inbounds = append(inbounds, in)
	}
	cfg["inbounds"] = inbounds
	d.Config, _ = json.Marshal(cfg)
	remaining := map[string]string{}
	for id, raw := range d.Expires {
		if !expired[id] {
			remaining[id] = raw
		}
	}
	d.Expires = remaining
	return d, true, nil
}
func (a *Agent) expire(ctx context.Context) error {
	if a.current == nil {
		return nil
	}
	d, changed, e := RemoveExpired(*a.current, time.Now())
	if e != nil {
		return e
	}
	if !changed {
		return nil
	}
	a.stop()
	a.applied = 0
	if e = a.Apply(ctx, d); e != nil {
		a.stop()
		a.applied = 0
		return e
	}
	return nil
}
func (a *Agent) Run(ctx context.Context) error {
	if e := a.Load(); e != nil {
		return e
	}
	lock, e := os.OpenFile(filepath.Join(a.Dir, "agent.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errors.New("已有 Agent 实例运行")
	}
	defer a.stop()
	if b, e := os.ReadFile(filepath.Join(a.Dir, "current.json")); e == nil {
		var d panel.Deployment
		if json.Unmarshal(b, &d) == nil {
			leaseBytes, _ := os.ReadFile(filepath.Join(a.Dir, "lease.txt"))
			a.lease, _ = time.Parse(time.RFC3339, string(leaseBytes))
			if time.Now().Before(a.lease) {
				if e = a.Apply(ctx, d); e != nil {
					a.lastError = "previous configuration failed"
				}
			}
		}
	}
	versionBytes, _ := exec.Command(a.Core, "version").Output()
	version := strings.SplitN(string(versionBytes), "\n", 2)[0]
	statsSupported := strings.Contains(string(versionBytes), "with_v2ray_api")
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		if !a.lease.IsZero() && !time.Now().Before(a.lease) {
			a.stop()
			a.applied = 0
			a.lastError = "authorization lease expired"
		}
		if time.Now().Before(a.lease) {
			if e := a.expire(ctx); e != nil {
				a.lastError = "expiry enforcement failed"
			}
		}
		if !a.alive() && a.applied > 0 {
			a.applied = 0
			a.lastError = "core stopped"
		}
		var out struct {
			Deployment   *panel.Deployment `json:"deployment"`
			LeaseExpires string            `json:"leaseExpires"`
		}
		epoch := ""
		if a.current != nil {
			epoch = a.current.Epoch
		}
		e := a.post(ctx, "/api/agent/sync", map[string]any{"serverId": a.identity.ServerID, "applied": a.applied, "epoch": epoch, "coreVersion": version, "error": a.lastError, "statsSupported": statsSupported, "traffic": a.sampleTraffic(ctx)}, &out)
		if e == nil {
			lease, le := time.Parse(time.RFC3339, out.LeaseExpires)
			if le != nil || !lease.After(time.Now()) || time.Until(lease) > 21*time.Minute {
				return errors.New("中心授权租期无效")
			}
			a.lease = lease
			if le = atomicWrite(filepath.Join(a.Dir, "lease.txt"), []byte(out.LeaseExpires)); le != nil {
				return le
			}
		}
		if e == nil && out.Deployment != nil {
			if e = a.Apply(ctx, *out.Deployment); e != nil {
				a.lastError = e.Error()
			} else {
				a.lastError = ""
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
