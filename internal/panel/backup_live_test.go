package panel

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestLiveBackupConcurrentSnapshotAndNewMachineRestore(t *testing.T) {
	s := testStore(t)
	a := New(s, "http://127.0.0.1:8787", s.dir, true, nil)
	loginTest(t, a)
	if err := s.Update(func(s *State) error {
		user, hash := s.Username, s.PasswordHash
		*s = fixture()
		s.Username = user
		s.PasswordHash = hash
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			if err := s.Update(func(s *State) error { u := &s.Users[0]; u.Upload++; u.Download += 2; u.Used += 3; return nil }); err != nil {
				errCh <- err
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	const pass = "portable-audit-backup-password"
	var backup []byte
	for i := 0; i < 4; i++ {
		b, err := ExportLive(s.dir, pass)
		if err != nil {
			t.Fatal(err)
		}
		state, err := decodeBackup(b, pass)
		if err != nil {
			t.Fatal(err)
		}
		if state.Users[0].Used != state.Users[0].Upload+state.Users[0].Download {
			t.Fatal("mixed transactions in live backup")
		}
		backup = b
	}
	wg.Wait()
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
	if _, err := OpenStore(s.dir); err == nil {
		t.Fatal("snapshot bypassed writer exclusivity")
	}
	restored := testStore(t)
	if bytes.Equal(restored.key, s.key) {
		t.Fatal("restore did not simulate independent master key")
	}
	if err := restored.Import(backup, pass); err != nil {
		t.Fatal(err)
	}
	before, after := s.Read(), restored.Read()
	if before.Users[0].Token != after.Users[0].Token || before.Users[0].Credentials[before.Nodes[0].ID] != after.Users[0].Credentials[after.Nodes[0].ID] || before.Servers[0].AgentToken != after.Servers[0].AgentToken || !verifyPassword("correct-test-password", after.PasswordHash) {
		t.Fatal("portable restore lost authentication")
	}
	if after.Epoch == before.Epoch || after.Servers[0].Applied != 0 {
		t.Fatal("restored grants published before resync")
	}
	oldEpoch := s.Read().Epoch
	if err := VerifyBackup(backup, pass); err != nil || s.Read().Epoch != oldEpoch {
		t.Fatal("verification mutated live state")
	}
	if err := VerifyBackup(backup, "wrong-backup-password"); err == nil {
		t.Fatal("wrong password accepted")
	}
	corrupt := append([]byte{}, backup...)
	corrupt[len(corrupt)-1] ^= 1
	if err := VerifyBackup(corrupt, pass); err == nil {
		t.Fatal("corrupted backup accepted")
	}
	if _, err := ExportLive(t.TempDir(), pass); err == nil {
		t.Fatal("missing live database accepted")
	}
}

func TestBackupAtomicPrivateReplacement(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "backup.rdbak")
	other := filepath.Join(dir, "untouched")
	if err := os.WriteFile(other, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, target); err != nil {
		t.Fatal(err)
	}
	if err := WriteBackup(target, []byte("encrypted-backup")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(other)
	if string(b) != "original" {
		t.Fatal("followed destination symlink")
	}
	info, _ := os.Lstat(target)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("backup not private regular file")
	}
	b, _ = os.ReadFile(target)
	if string(b) != "encrypted-backup" {
		t.Fatal("bad backup bytes")
	}
}
