package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/321CMO/relaydeck/internal/agent"
)

func TestReinstallEnrollmentReusesIdentityWithoutStdin(t *testing.T) {
	dir := t.TempDir()
	identity := agent.Identity{Endpoint: "https://panel.example.com", ServerID: "srv_test", Token: strings.Repeat("fixture", 8), MachineID: "fixture-machine"}
	b, _ := json.Marshal(identity)
	path := filepath.Join(dir, "identity.json")
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	reader, writer, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	writer.Close()
	defer reader.Close()
	oldArgs, oldStdin := os.Args, os.Stdin
	defer func() { os.Args, os.Stdin = oldArgs, oldStdin }()
	os.Stdin = reader
	for _, endpoint := range []string{identity.Endpoint, "https://other.example.com"} {
		os.Args = []string{"relaydeck", "enroll", "--data", dir, "--endpoint", endpoint, "--server", identity.ServerID}
		e := run()
		if endpoint == identity.Endpoint && e != nil {
			t.Fatal("existing identity still requires a registration code:", e)
		}
		if endpoint != identity.Endpoint && e == nil {
			t.Fatal("reinstall accepted a different center")
		}
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(b) {
		t.Fatal("reinstall changed the existing Agent identity")
	}
}

func TestBackupPasswordFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "backup.pass")
	if err := os.WriteFile(path, []byte("private-backup-pass\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if pass, err := backupPassword(path); err != nil || pass != "private-backup-pass" {
		t.Fatal("private password file rejected", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := backupPassword(path); err == nil {
		t.Fatal("public password file accepted")
	}
	os.Chmod(path, 0600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := backupPassword(link); err == nil {
		t.Fatal("symlink password file accepted")
	}
	for _, bad := range []string{"short", strings.Repeat("x", 129), "valid-password\nsecond-line"} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := backupPassword(path); err == nil {
			t.Fatal("invalid password accepted")
		}
	}
}
