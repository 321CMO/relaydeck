package panel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/argon2"
)

var backupMagic = []byte("RELAYDECK-BACKUP-1\n")

func (s *Store) Export(pass string) ([]byte, error) {
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
	b, e := json.Marshal(s.Read())
	if e != nil {
		return nil, e
	}
	head := append(append(append([]byte{}, backupMagic...), salt...), nonce...)
	return g.Seal(head, nonce, b, backupMagic), nil
}
func (s *Store) Import(b []byte, pass string) error {
	if len(b) < len(backupMagic)+16+12+16 || len(b) > 32<<20 || !bytes.HasPrefix(b, backupMagic) {
		return errors.New("备份格式无效")
	}
	start := len(backupMagic)
	key := argon2.IDKey([]byte(pass), b[start:start+16], 2, 64*1024, 2, 32)
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	plain, e := g.Open(nil, b[start+16:start+28], b[start+28:], backupMagic)
	if e != nil {
		return errors.New("备份口令错误或文件损坏")
	}
	var next State
	if json.Unmarshal(plain, &next) != nil || next.Schema != 1 {
		return errors.New("备份版本不兼容")
	}
	if next.PasswordHash == "" {
		return errors.New("不支持恢复未初始化的备份")
	}
	return s.Update(func(s *State) error { *s = next; return nil })
}
