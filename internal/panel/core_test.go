package panel

import (
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
