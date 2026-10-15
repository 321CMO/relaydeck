package panel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"sync"
)

type Store struct {
	mu    sync.Mutex
	db    *sql.DB
	state State
	key   []byte
	dir   string
	lock  *os.File
}

func OpenStore(dir string) (*Store, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	if e := os.Chmod(dir, 0700); e != nil {
		return nil, e
	}
	lock, e := os.OpenFile(filepath.Join(dir, "state.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		lock.Close()
		return nil, errors.New("该数据目录已有中心实例运行")
	}
	fail := func(e error) (*Store, error) { lock.Close(); return nil, e }
	keyPath := filepath.Join(dir, "master.key")
	key, e := os.ReadFile(keyPath)
	if os.IsNotExist(e) {
		if _, de := os.Stat(filepath.Join(dir, "relaydeck.db")); de == nil {
			return fail(errors.New("数据库已存在但 master.key 缺失，请恢复原密钥"))
		}
		key = make([]byte, 32)
		if _, e = rand.Read(key); e != nil {
			return fail(e)
		}
		if e = os.WriteFile(keyPath, key, 0600); e != nil {
			return fail(e)
		}
	} else if e != nil {
		return fail(e)
	}
	if len(key) != 32 {
		return fail(errors.New("数据加密密钥无效，请恢复原 master.key"))
	}
	db, e := sql.Open("sqlite", filepath.Join(dir, "relaydeck.db"))
	if e != nil {
		return fail(e)
	}
	db.SetMaxOpenConns(1)
	if _, e = db.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), payload BLOB NOT NULL)"); e != nil {
		db.Close()
		return fail(e)
	}
	s := &Store{db: db, key: key, dir: dir, lock: lock}
	var encrypted []byte
	e = db.QueryRow("SELECT payload FROM state WHERE id=1").Scan(&encrypted)
	if e == sql.ErrNoRows {
		s.state = initial()
		e = s.save(s.state)
		if e == nil {
			e = os.WriteFile(filepath.Join(dir, "bootstrap.txt"), []byte(s.state.SetupToken), 0600)
		}
	} else if e == nil {
		var plain []byte
		plain, e = s.decrypt(encrypted)
		if e == nil {
			e = json.Unmarshal(plain, &s.state)
		}
	}
	if e != nil {
		s.Close()
		return nil, e
	}
	if (s.state.Schema != 1 && s.state.Schema != 2) || !validEpoch(s.state.Epoch) || s.state.Schema == 2 && s.state.Epoch == "" {
		s.Close()
		return nil, errors.New("数据版本不兼容，禁止使用旧程序打开")
	}
	_ = os.Chmod(filepath.Join(dir, "relaydeck.db"), 0600)
	return s, nil
}
func (s *Store) encrypt(b []byte) ([]byte, error) {
	block, e := aes.NewCipher(s.key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	return g.Seal(nonce, nonce, b, []byte("relaydeck-state-v1")), nil
}
func (s *Store) decrypt(b []byte) ([]byte, error) {
	block, e := aes.NewCipher(s.key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	if len(b) < g.NonceSize() {
		return nil, errors.New("数据库损坏")
	}
	return g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], []byte("relaydeck-state-v1"))
}
func (s *Store) save(next State) error {
	b, e := json.Marshal(next)
	if e != nil {
		return e
	}
	b, e = s.encrypt(b)
	if e != nil {
		return e
	}
	_, e = s.db.Exec("INSERT INTO state(id,payload) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", b)
	return e
}
func (s *Store) Read() State { s.mu.Lock(); defer s.mu.Unlock(); return cloneState(s.state) }
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	if e := fn(&next); e != nil {
		return e
	}
	if e := s.save(next); e != nil {
		return e
	}
	s.state = next
	return nil
}
func (s *Store) Close() error {
	if s.db != nil {
		_ = s.db.Close()
	}
	if s.lock != nil {
		_ = unix.Flock(int(s.lock.Fd()), unix.LOCK_UN)
		return s.lock.Close()
	}
	return nil
}
func (s *Store) Backup() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.encryptJSON(s.state)
}
func (s *Store) encryptJSON(state State) ([]byte, error) {
	b, e := json.Marshal(state)
	if e != nil {
		return nil, e
	}
	return s.encrypt(b)
}
