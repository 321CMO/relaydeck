package panel

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// This checks the real pinned core's parser, rather than duplicating its schema.
func TestOfficialCoreConfigurations(t *testing.T) {
	core := os.Getenv("SING_BOX_BIN")
	if core == "" {
		t.Skip("official core not installed; CI runs this check with the SHA256-verified binary")
	}
	s := fixture()
	s.Nodes[0].ExitID = "srv_b"
	crt, key := cert(t, "hy.example.com")
	hy := Node{ID: "node_hy2123", Name: "HY2", ServerID: "srv_a", Protocol: "hy2", Address: "entry.example.com", Port: 8443, Enabled: true, SNI: "hy.example.com", TLSMode: "import", Certificate: crt, Key: key, HopStart: 20000, HopEnd: 20100, HopInterval: 30}
	s.Nodes = append(s.Nodes, hy)
	s.Users[0].Credentials[hy.ID] = randomToken(24)
	s.Users[0].NodeIDs = append(s.Users[0].NodeIDs, hy.ID)
	for _, mode := range []string{"import", "auto"} {
		s.Nodes[2].TLSMode = mode
		for _, id := range []string{"srv_a", "srv_b"} {
			t.Run(mode+"/"+id, func(t *testing.T) {
				dir := t.TempDir()
				d, e := Compile(s, id, dir)
				if e != nil {
					t.Fatal(e)
				}
				versionDir := filepath.Join(dir, "versions", "3")
				os.MkdirAll(versionDir, 0700)
				if e = WriteDeployment(d, versionDir); e != nil {
					t.Fatal(e)
				}
				path := filepath.Join(versionDir, "config.json")
				os.WriteFile(path, d.Config, 0600)
				out, e := exec.Command(core, "check", "-c", path).CombinedOutput()
				if e != nil {
					t.Fatalf("official core rejected generated config: %s", out)
				}
			})
		}
	}
}

func TestOfficialCaddyConfigurations(t *testing.T) {
	core := os.Getenv("CADDY_BIN")
	if core == "" {
		t.Skip("official Caddy not installed")
	}
	dir := t.TempDir()
	bootstrap, err := exec.Command("bash", "-c", `source "$1"; bootstrap_caddyfile panel.example.com`, "test", filepath.Join("..", "..", "scripts", "lib", "lifecycle.sh")).Output()
	if err != nil {
		t.Fatal(err)
	}
	crt, key := cert(t, "panel.example.com")
	cases := map[string][]byte{"installer": bootstrap}
	for name, h := range map[string]HTTPS{"protected-admin": {Domain: "panel.example.com", Mode: "auto", AdminPort: 38443, AdminPath: randomToken(24)}, "auto": {Domain: "panel.example.com", Mode: "auto"}, "separate-subscription": {Domain: "panel.example.com", SubscriptionDomain: "sub.example.com", Mode: "auto"}, "import": {Domain: "panel.example.com", Mode: "import", Certificate: crt, Key: key}} {
		text, err := Caddyfile(h, "127.0.0.1:8787", dir)
		if err != nil {
			t.Fatal(err)
		}
		if err = stageHTTPSAssets(h, dir); err != nil {
			t.Fatal(err)
		}
		cases[name] = []byte(text)
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".Caddyfile")
			if err := os.WriteFile(path, content, 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(core, "adapt", "--config", path, "--adapter", "caddyfile")
			var diagnostics bytes.Buffer
			cmd.Stderr = &diagnostics
			adapted, err := cmd.Output()
			if err != nil {
				t.Fatalf("Caddy rejected generated configuration: %s", diagnostics.String())
			}
			var parsed struct {
				Apps struct {
					HTTP struct {
						Servers map[string]struct {
							Protocols []string `json:"protocols"`
						} `json:"servers"`
					} `json:"http"`
				} `json:"apps"`
			}
			if err = json.Unmarshal(adapted, &parsed); err != nil || len(parsed.Apps.HTTP.Servers) == 0 {
				t.Fatal("invalid Caddy HTTP configuration")
			}
			for _, server := range parsed.Apps.HTTP.Servers {
				if len(server.Protocols) != 2 || server.Protocols[0] != "h1" || server.Protocols[1] != "h2" {
					t.Fatal("panel must leave UDP 443 available for HY2")
				}
			}
			if name == "import" {
				cmd = exec.Command(core, "validate", "--config", path, "--adapter", "caddyfile")
				cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+dir, "XDG_CONFIG_HOME="+dir)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("Caddy rejected imported certificate assets: %s", out)
				}
			}
		})
	}
}
