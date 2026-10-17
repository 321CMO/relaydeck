package panel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"
)

var backupMagic = []byte("RELAYDECK-BACKUP-1\n")

func (s *Store) Export(pass string) ([]byte, error) {
	return exportState(s.Read(), pass)
}

func exportState(state State, pass string) ([]byte, error) {
	if len(pass) < 12 || len(pass) > 128 {
		return nil, errors.New("备份口令需要 12–128 位")
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return nil, e
	}
	key := argon2.IDKey([]byte(pass), salt, 2, 64*1024, 2, 32)
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	nonce := make([]byte, g.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return nil, e
	}
	b, e := json.Marshal(state)
	if e != nil {
		return nil, e
	}
	if len(b) > (32<<20)-len(backupMagic)-16-12-16 {
		return nil, errors.New("备份超出当前支持的 32 MiB 上限")
	}
	head := append(append(append([]byte{}, backupMagic...), salt...), nonce...)
	return g.Seal(head, nonce, b, backupMagic), nil
}
func decodeBackup(b []byte, pass string) (State, error) {
	var next State
	if len(pass) < 12 || len(pass) > 128 {
		return next, errors.New("备份口令需要 12–128 位")
	}
	if len(b) < len(backupMagic)+16+12+16 || len(b) > 32<<20 || !bytes.HasPrefix(b, backupMagic) {
		return next, errors.New("备份格式无效")
	}
	start := len(backupMagic)
	key := argon2.IDKey([]byte(pass), b[start:start+16], 2, 64*1024, 2, 32)
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	plain, e := g.Open(nil, b[start+16:start+28], b[start+28:], backupMagic)
	if e != nil {
		return next, errors.New("备份口令错误或文件损坏")
	}
	if json.Unmarshal(plain, &next) != nil || (next.Schema != 1 && next.Schema != 2 && next.Schema != 3 && next.Schema != 4 && next.Schema != 5 && next.Schema != 6 && next.Schema != 7) {
		return next, errors.New("备份版本不兼容")
	}
	if next.PasswordHash == "" {
		return next, errors.New("不支持恢复未初始化的备份")
	}
	return next, nil
}

// VerifyBackup authenticates and decodes without changing the live database or
// resetting grant epochs. Successful decryption is not a full recovery drill.
func VerifyBackup(b []byte, pass string) error {
	_, err := decodeBackup(b, pass)
	return err
}

// ExportLive reads one committed encrypted SQLite row in read-only mode. The
// panel remains the exclusive writer; do not bypass its lock with OpenStore.
// This snapshot is portable with its backup password, without master.key.
func ExportLive(dir, pass string) ([]byte, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(filepath.Join(abs, "master.key"))
	if err != nil || len(key) != 32 {
		return nil, errors.New("无法读取有效的中心数据密钥")
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.Join(abs, "relaydeck.db"), RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var encrypted []byte
	if err = db.QueryRowContext(ctx, "SELECT payload FROM state WHERE id=1").Scan(&encrypted); err != nil {
		return nil, errors.New("读取中心已提交快照失败")
	}
	reader := &Store{key: key}
	plain, err := reader.decrypt(encrypted)
	if err != nil {
		return nil, errors.New("中心快照无法解密")
	}
	var state State
	if err = json.Unmarshal(plain, &state); err != nil {
		return nil, errors.New("中心快照格式无效")
	}
	if state.PasswordHash == "" {
		return nil, errors.New("请先完成管理员初始化")
	}
	return exportState(state, pass)
}

// WriteBackup uses a private temporary file and atomic rename, so interrupted
// exports cannot truncate an existing valid backup or follow a destination link.
func WriteBackup(path string, b []byte) error { return writePrivateFile(path, b) }

func (s *Store) Import(b []byte, pass string) error {
	next, err := decodeBackup(b, pass)
	if err != nil {
		return err
	}
	// Revisions in an older backup may be lower than those already on Agents.
	// A fresh epoch forces a full reapply before any restored grant is published.
	previousSchema := next.Schema
	next.Epoch = randomToken(16)
	next.Schema = 2
	if validAdminAccess(next.Settings.HTTPS) {
		next.Schema = 3
	}
	if previousSchema >= 4 {
		next.Schema = previousSchema
	}
	next.Settings.HTTPS.LoadedHash = ""
	if next.Settings.HTTPS.Domain != "" {
		next.Settings.HTTPS.Status = "pending"
	} else {
		next.Settings.HTTPS.Status = "unconfigured"
	}
	next.Tasks = []Task{}
	for i := range next.Servers {
		next.Servers[i].Applied = 0
		next.Servers[i].Error = ""
		next.Servers[i].LastSeen = time.Time{}
		queue(&next, []string{next.Servers[i].ID}, "恢复备份后重新同步授权")
	}
	return s.Update(func(s *State) error { *s = next; return nil })
}
