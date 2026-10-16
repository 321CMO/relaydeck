package panel

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
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
	credentials sync.Mutex // Serialize password verification with changes and session issuance.
	mu          sync.Mutex
	sessions    map[string]session
	failures    map[string]failure
	loginTokens float64
	loginRefill time.Time
	development bool
}

func newAuth(dev bool) *auth {
	return &auth{sessions: map[string]session{}, failures: map[string]failure{}, development: dev, loginTokens: 8, loginRefill: time.Now()}
}

// Caddy overwrites this header with its socket peer, never with a user-provided
// forwarding chain. Only the local proxy may supply it. CDN client-IP support
// needs an explicit trusted-proxy policy; arbitrary X-Forwarded-For is ignored.
const clientIPHeader = "X-RelayDeck-Client-IP"

func (a *App) loginSource(r *http.Request) (string, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	peer, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || peer.Zone() != "" {
		return "", false
	}
	peer = peer.Unmap()
	if peer.IsLoopback() && !a.Development {
		values := r.Header.Values(clientIPHeader)
		if len(values) != 1 {
			return "", false
		}
		client, err := netip.ParseAddr(values[0])
		if err != nil || client.Zone() != "" || client.IsUnspecified() || client.IsMulticast() {
			return "", false
		}
		return client.Unmap().String(), true
	}
	return peer.String(), true
}

// Bound both hashing work and the number of remembered sources. A global short
// budget replaces an account-wide long lockout, so one source cannot impose a
// 15-minute lockout on every other administrator.
func (a *auth) loginRetryAfter(key string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if f := a.failures[key]; f.Count >= 5 && now.Before(f.Until) {
		return max(1, int(math.Ceil(f.Until.Sub(now).Seconds())))
	}
	if len(a.failures) >= 10000 {
		for k, f := range a.failures {
			if !now.Before(f.Until) {
				delete(a.failures, k)
			}
		}
		if _, known := a.failures[key]; !known && len(a.failures) >= 10000 {
			return 60
		}
	}
	a.loginTokens = min(8, a.loginTokens+now.Sub(a.loginRefill).Seconds())
	a.loginRefill = now
	if a.loginTokens < 1 {
		return 1
	}
	a.loginTokens--
	return 0
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

func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	a.auth.credentials.Lock()
	defer a.auth.credentials.Unlock()
	// Recheck after acquiring the lock: another password change may have revoked this request.
	if _, ok := a.auth.lookup(r); !ok {
		failureResponse(w, 401, fmt.Errorf("请重新登录"))
		return
	}
	var in struct {
		Current string `json:"currentPassword"`
		New     string `json:"newPassword"`
		Confirm string `json:"confirmPassword"`
	}
	if e := body(r, &in); e != nil {
		failureResponse(w, 400, e)
		return
	}
	if len(in.Current) > 128 || utf8.RuneCountInString(in.New) < 8 || len(in.New) > 128 || in.New != in.Confirm || in.New == in.Current {
		failureResponse(w, 422, fmt.Errorf("新密码至少 8 个字符、最多 128 字节，两次输入必须一致，且不能与当前密码相同"))
		return
	}
	// Account-scoped throttling cannot be bypassed by opening another session.
	key := "account-password"
	if a.auth.blocked(key) {
		failureResponse(w, 429, fmt.Errorf("当前密码验证失败过多，请 15 分钟后重试"))
		return
	}
	old := a.Store.Read().PasswordHash
	if !verifyPassword(in.Current, old) {
		a.auth.recordFailure(key)
		failureResponse(w, 422, fmt.Errorf("当前密码错误"))
		return
	}
	next := hashPassword(in.New)
	if e := a.Store.Update(func(s *State) error {
		if s.PasswordHash != old {
			return fmt.Errorf("账号信息已变化，请重新登录")
		}
		s.PasswordHash = next
		s.SetupToken = ""
		return nil
	}); e != nil {
		failureResponse(w, 409, e)
		return
	}
	a.auth.mu.Lock()
	a.auth.sessions = map[string]session{}
	a.auth.mu.Unlock()
	a.auth.clearFailures(key)
	a.auth.logout(w, r, adminCookiePath(a.Store.Read().Settings.HTTPS))
	jsonResponse(w, 200, map[string]bool{"ok": true})
}
