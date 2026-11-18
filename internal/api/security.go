package api

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxLoginFailures   = 5
	loginBlockDuration = 15 * time.Minute
	defaultIdleTimeout = 30 * time.Minute
)

type rateLimitEntry struct {
	failures     int
	blockedUntil time.Time
}

type loginRateLimiter struct {
	mu      sync.Mutex
	entries map[string]rateLimitEntry
	nowFunc func() time.Time
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{
		entries: make(map[string]rateLimitEntry),
		nowFunc: func() time.Time { return time.Now().UTC() },
	}
}

func (l *loginRateLimiter) isBlocked(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.nowFunc()
	entry, ok := l.entries[ip]
	if !ok {
		return false, 0
	}
	if !entry.blockedUntil.IsZero() {
		if now.Before(entry.blockedUntil) {
			return true, entry.blockedUntil.Sub(now)
		}
		delete(l.entries, ip)
	}
	return false, 0
}

func (l *loginRateLimiter) recordFailure(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.nowFunc()
	entry := l.entries[ip]
	if !entry.blockedUntil.IsZero() && now.After(entry.blockedUntil) {
		entry = rateLimitEntry{}
	}
	entry.failures++
	blocked := false
	if entry.failures >= maxLoginFailures {
		entry.blockedUntil = now.Add(loginBlockDuration)
		blocked = true
	}
	l.entries[ip] = entry
	return blocked
}

func (l *loginRateLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

type sessionStore struct {
	mu          sync.Mutex
	sessions    map[string]time.Time
	idleTimeout time.Duration
	nowFunc     func() time.Time
}

func newSessionStore(idleTimeout time.Duration) *sessionStore {
	if idleTimeout <= 0 {
		idleTimeout = defaultIdleTimeout
	}
	return &sessionStore{
		sessions:    make(map[string]time.Time),
		idleTimeout: idleTimeout,
		nowFunc:     func() time.Time { return time.Now().UTC() },
	}
}

func (s *sessionStore) create(sessionID string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.nowFunc()
	s.sessions[sessionID] = now
	return now.Add(s.idleTimeout)
}

func (s *sessionStore) touch(sessionID string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.nowFunc()
	lastActive, ok := s.sessions[sessionID]
	if !ok {
		return time.Time{}, false
	}
	if now.Sub(lastActive) > s.idleTimeout {
		delete(s.sessions, sessionID)
		return time.Time{}, false
	}
	s.sessions[sessionID] = now
	return now.Add(s.idleTimeout), true
}

func (s *sessionStore) revoke(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	const csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		if ip := strings.TrimSpace(first); ip != "" {
			return ip
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func isIPAllowed(allowedList, ipStr string) bool {
	trimmed := strings.TrimSpace(allowedList)
	if trimmed == "" {
		return true
	}
	parsedIP := net.ParseIP(strings.TrimSpace(ipStr))
	if parsedIP == nil {
		return false
	}

	for _, rawEntry := range strings.Split(trimmed, ",") {
		entry := strings.TrimSpace(rawEntry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, cidr, err := net.ParseCIDR(entry); err == nil && cidr.Contains(parsedIP) {
				return true
			}
			continue
		}
		if allowedIP := net.ParseIP(entry); allowedIP != nil && allowedIP.Equal(parsedIP) {
			return true
		}
	}
	return false
}

// verifyTOTP validates a 6-digit RFC 6238 TOTP code against a Base32-encoded secret
// with +/- 1 step (30s) clock skew tolerance.
func verifyTOTP(secretBase32, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}

	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secretBase32), " ", ""))
	if normalized == "" {
		return false
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(normalized, "="))
	if err != nil {
		return false
	}

	counter := now.UTC().Unix() / 30
	for offset := int64(-1); offset <= 1; offset++ {
		expected := computeTOTP(key, counter+offset)
		if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
			return true
		}
	}
	return false
}

func computeTOTP(key []byte, counter int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))

	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binCode := (int(sum[offset]&0x7f) << 24) |
		(int(sum[offset+1]&0xff) << 16) |
		(int(sum[offset+2]&0xff) << 8) |
		int(sum[offset+3]&0xff)

	return fmt.Sprintf("%06d", binCode%1000000)
}

func parseSessionTimeout(raw string) time.Duration {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaultIdleTimeout
	}
	if d, err := time.ParseDuration(trimmed); err == nil && d > 0 {
		return d
	}
	if mins, err := strconv.Atoi(trimmed); err == nil && mins > 0 {
		return time.Duration(mins) * time.Minute
	}
	return defaultIdleTimeout
}
