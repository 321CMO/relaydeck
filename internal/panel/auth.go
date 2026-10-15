package panel

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"net/http"
	"strings"
	"sync"
	"time"
)

func hashPassword(p string) string {
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		panic(e)
	}
	h := argon2.IDKey([]byte(p), salt, 2, 64*1024, 2, 32)
	return base64.RawStdEncoding.EncodeToString(salt) + ":" + base64.RawStdEncoding.EncodeToString(h)
}
func verifyPassword(p, hash string) bool {
	parts := strings.Split(hash, ":")
	if len(parts) != 2 {
		return false
	}
	salt, e := base64.RawStdEncoding.DecodeString(parts[0])
	if e != nil || len(salt) != 16 {
		return false
	}
	wanted, e := base64.RawStdEncoding.DecodeString(parts[1])
	if e != nil || len(wanted) != 32 {
		return false
	}
	actual := argon2.IDKey([]byte(p), salt, 2, 64*1024, 2, 32)
	return subtle.ConstantTimeCompare(actual, wanted) == 1
}
func digest(s string) string { h := sha256.Sum256([]byte(s)); return fmt.Sprintf("%x", h) }

type session struct {
	CSRF    string
	Expires time.Time
}
type failure struct {
	Count int
	Until time.Time
}
type auth struct {
	mu          sync.Mutex
	sessions    map[string]session
	failures    map[string]failure
	development bool
}

func newAuth(dev bool) *auth {
	return &auth{sessions: map[string]session{}, failures: map[string]failure{}, development: dev}
}
func (a *auth) lookup(r *http.Request) (session, bool) {
	cookie, e := r.Cookie("relaydeck_session")
	if e != nil {
		return session{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[digest(cookie.Value)]
	if !ok || !time.Now().Before(s.Expires) {
		delete(a.sessions, digest(cookie.Value))
		return session{}, false
	}
	return s, true
}
func (a *auth) login(w http.ResponseWriter, path string) session {
	token := randomToken(32)
	s := session{CSRF: randomToken(24), Expires: time.Now().Add(12 * time.Hour)}
	a.mu.Lock()
	a.sessions[digest(token)] = s
	for k, v := range a.sessions {
		if !time.Now().Before(v.Expires) {
			delete(a.sessions, k)
		}
	}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "relaydeck_session", Value: token, Path: path, Secure: !a.development, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: s.Expires})
	return s
}
func (a *auth) logout(w http.ResponseWriter, r *http.Request, path string) {
	if c, e := r.Cookie("relaydeck_session"); e == nil {
		a.mu.Lock()
		delete(a.sessions, digest(c.Value))
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "relaydeck_session", Path: path, MaxAge: -1, Secure: !a.development, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}
func (a *auth) blocked(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.failures[key]
	return f.Count >= 5 && time.Now().Before(f.Until)
}
func (a *auth) recordFailure(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.failures[key]
	if !time.Now().Before(f.Until) {
		f = failure{Until: time.Now().Add(15 * time.Minute)}
	}
	f.Count++
	a.failures[key] = f
	if len(a.failures) > 10000 {
		for k, v := range a.failures {
			if !time.Now().Before(v.Until) {
				delete(a.failures, k)
			}
		}
	}
}
func (a *auth) clearFailures(key string) { a.mu.Lock(); defer a.mu.Unlock(); delete(a.failures, key) }
func equal(a, b string) bool             { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
