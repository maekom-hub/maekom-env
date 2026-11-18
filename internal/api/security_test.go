package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maekom-hub/maekom-env/internal/crypto"
	"github.com/maekom-hub/maekom-env/internal/db"
	"github.com/maekom-hub/maekom-env/internal/notifier"
)

func TestSecurityHeadersRateLimitCookieIdleTOTPAndAuditLogs(t *testing.T) {
	ctx := context.Background()
	store, err := db.Open(ctx, filepath.Join(t.TempDir(), "sec-test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = store.Close() }()

	cipher, err := crypto.NewCipherFromMasterKey("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}

	// Base32 secret "JBSWY3DPEHPK3PXP" -> standard RFC 6238 test secret
	totpSecret := "JBSWY3DPEHPK3PXP"

	srv, err := NewServer(store, cipher, notifier.NewDispatcher(store), Config{
		AdminPassword:  "admin-pass-123",
		JWTSecret:      []byte("test-jwt-secret-32-bytes-minimum"),
		TOTPSecret:     totpSecret,
		SessionTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	handler := srv.Handler()

	// 1. Security headers check on /api/auth/status
	statusRec := doReq(t, handler, http.MethodGet, "/api/auth/status", "", nil, nil, "")
	if statusRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/auth/status, got %d", statusRec.Code)
	}
	if statusRec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing X-Frame-Options: DENY")
	}
	if statusRec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing X-Content-Type-Options: nosniff")
	}
	if statusRec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("missing Referrer-Policy: no-referrer")
	}
	if !strings.Contains(statusRec.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("missing CSP header: %q", statusRec.Header().Get("Content-Security-Policy"))
	}
	if !strings.Contains(statusRec.Body.String(), `"totp_required":true`) {
		t.Fatalf("expected totp_required:true, got %s", statusRec.Body.String())
	}

	// 2. TOTP rejection when code is wrong
	reqBadOTP := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"password":"admin-pass-123","totp_code":"000000"}`))
	reqBadOTP.RemoteAddr = "203.0.113.10:1234"
	reqBadOTP.Header.Set("Content-Type", "application/json")
	recBadOTP := httptest.NewRecorder()
	handler.ServeHTTP(recBadOTP, reqBadOTP)
	if recBadOTP.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong TOTP, got %d", recBadOTP.Code)
	}

	// 3. Brute-force protection: 5 failures from 198.51.100.7 -> 5th returns 429
	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"password":"wrong"}`))
		req.RemoteAddr = "198.51.100.7:5555"
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if i < 5 && rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i, rec.Code)
		}
		if i == 5 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("attempt 5: expected 429, got %d", rec.Code)
		}
	}

	// 4. Valid login with TOTP from clean IP -> HttpOnly; Secure; SameSite=Strict cookie
	validCode := computeTOTP([]byte("Hello!\xde\xad\xbe\xef"), time.Now().UTC().Unix()/30)
	// Use exact secret decoded via verifyTOTP helper: compute via base32
	reqOK := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"password":"admin-pass-123","totp_code":"`+validCode+`"}`))
	reqOK.RemoteAddr = "192.0.2.50:9999"
	reqOK.Header.Set("Content-Type", "application/json")
	recOK := httptest.NewRecorder()
	handler.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid login+TOTP, got %d: %s", recOK.Code, recOK.Body.String())
	}

	var sessionCookie *http.Cookie
	for _, c := range recOK.Result().Cookies() {
		if c.Name == sessionCookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie")
	}
	if !sessionCookie.HttpOnly || !sessionCookie.Secure || sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie flags mismatch: HttpOnly=%v Secure=%v SameSite=%v", sessionCookie.HttpOnly, sessionCookie.Secure, sessionCookie.SameSite)
	}

	// 5. Audit logs must have recorded the login attempts
	logsRec := doReq(t, handler, http.MethodGet, "/api/audit-logs?limit=20", "", sessionCookie, nil, "")
	if logsRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on audit logs, got %d: %s", logsRec.Code, logsRec.Body.String())
	}
	var auditResp struct {
		AuditLogs []db.AuditLog `json:"audit_logs"`
	}
	_ = json.Unmarshal(logsRec.Body.Bytes(), &auditResp)
	if len(auditResp.AuditLogs) < 6 {
		t.Fatalf("expected >= 6 audit log entries, got %d", len(auditResp.AuditLogs))
	}

	// 6. Idle session expiration (200ms configured)
	time.Sleep(250 * time.Millisecond)
	expiredRec := doReq(t, handler, http.MethodGet, "/api/projects", "", sessionCookie, nil, "")
	if expiredRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after idle session timeout, got %d", expiredRec.Code)
	}
}
