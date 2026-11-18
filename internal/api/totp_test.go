package api

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maekom-hub/maekom-env/internal/crypto"
	"github.com/maekom-hub/maekom-env/internal/db"
	"github.com/maekom-hub/maekom-env/internal/notifier"
)

func codeForSecret(t *testing.T, secret string) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(strings.ToUpper(secret), "="))
	if err != nil {
		t.Fatalf("decode base32 secret: %v", err)
	}
	return computeTOTP(key, time.Now().UTC().Unix()/30)
}

func TestTOTPSetupVerifyResetAndBoundaryEnforcement(t *testing.T) {
	ctx := context.Background()
	store, err := db.Open(ctx, filepath.Join(t.TempDir(), "totp-test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = store.Close() }()

	cipher, err := crypto.NewCipherFromMasterKey("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}

	srv, err := NewServer(store, cipher, notifier.NewDispatcher(store), Config{
		AdminPassword: "admin-password-123",
		JWTSecret:     []byte("test-jwt-secret-32-bytes-minimum"),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	h := srv.Handler()

	// 1. First login -> must return totp_setup_required and NO session cookie
	login1 := doReq(t, h, http.MethodPost, "/api/auth/login", "", nil, map[string]string{
		"password": "admin-password-123",
	}, "")
	if login1.Code != http.StatusOK {
		t.Fatalf("expected 200 on first login, got %d: %s", login1.Code, login1.Body.String())
	}
	var setupResp struct {
		Status     string `json:"status"`
		TempToken  string `json:"temp_token"`
		Secret     string `json:"secret"`
		OTPAuthURI string `json:"otpauth_uri"`
	}
	_ = json.Unmarshal(login1.Body.Bytes(), &setupResp)
	if setupResp.Status != "totp_setup_required" || setupResp.TempToken == "" || setupResp.Secret == "" {
		t.Fatalf("unexpected setup response: %s", login1.Body.String())
	}
	if !strings.HasPrefix(setupResp.OTPAuthURI, "otpauth://totp/") {
		t.Fatalf("expected otpauth URI, got %q", setupResp.OTPAuthURI)
	}
	for _, c := range login1.Result().Cookies() {
		if c.Name == sessionCookieName {
			t.Fatal("must not issue full session cookie before 2FA setup completes")
		}
	}

	// 2. Temp token must NOT access protected resources
	for _, path := range []string{"/api/projects", "/api/audit-logs", "/api/settings/totp/begin"} {
		method := http.MethodGet
		if strings.Contains(path, "settings") {
			method = http.MethodPost
		}
		rec := doReq(t, h, method, path, "Bearer "+setupResp.TempToken, nil, nil, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 when using setup temp_token on %s, got %d", path, rec.Code)
		}
	}

	// 3. Complete 2FA setup with valid 6-digit code -> issues session cookie & stores encrypted secret in DB
	code1 := codeForSecret(t, setupResp.Secret)
	finishSetup := doReq(t, h, http.MethodPost, "/api/auth/totp/setup", "", nil, map[string]string{
		"temp_token": setupResp.TempToken,
		"totp_code":  code1,
	}, "")
	if finishSetup.Code != http.StatusOK {
		t.Fatalf("expected 200 on totp setup, got %d: %s", finishSetup.Code, finishSetup.Body.String())
	}

	// Verify DB stored encrypted secret (not plaintext)
	storedTOTP, err := store.GetAdminTOTP(ctx)
	if err != nil || !storedTOTP.Enabled {
		t.Fatalf("expected enabled admin_totp row in DB, err=%v", err)
	}
	if strings.Contains(string(storedTOTP.EncryptedSecret), setupResp.Secret) {
		t.Fatal("TOTP secret must be encrypted in DB, not plaintext")
	}

	// 4. Subsequent login -> returns totp_verify_required
	login2 := doReq(t, h, http.MethodPost, "/api/auth/login", "", nil, map[string]string{
		"password": "admin-password-123",
	}, "")
	var verifyPrompt struct {
		Status    string `json:"status"`
		TempToken string `json:"temp_token"`
	}
	_ = json.Unmarshal(login2.Body.Bytes(), &verifyPrompt)
	if verifyPrompt.Status != "totp_verify_required" || verifyPrompt.TempToken == "" {
		t.Fatalf("expected totp_verify_required, got %s", login2.Body.String())
	}

	// Pending verify token must NOT access /api/projects
	if rec := doReq(t, h, http.MethodGet, "/api/projects", "Bearer "+verifyPrompt.TempToken, nil, nil, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for verify temp_token on /api/projects, got %d", rec.Code)
	}

	// Complete verify
	verifyRec := doReq(t, h, http.MethodPost, "/api/auth/totp/verify", "", nil, map[string]string{
		"temp_token": verifyPrompt.TempToken,
		"totp_code":  code1,
	}, "")
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on totp verify, got %d: %s", verifyRec.Code, verifyRec.Body.String())
	}
	var adminCookie *http.Cookie
	for _, c := range verifyRec.Result().Cookies() {
		if c.Name == sessionCookieName {
			adminCookie = c
		}
	}
	if adminCookie == nil {
		t.Fatal("expected admin session cookie after 2FA verify")
	}

	// 5. Settings OTP reset: must re-verify password/OTP, and closing without confirm preserves old secret
	badBegin := doReq(t, h, http.MethodPost, "/api/settings/totp/begin", "", adminCookie, map[string]string{
		"password": "wrong-password",
	}, "")
	if badBegin.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong password on settings/totp/begin, got %d", badBegin.Code)
	}

	beginRec := doReq(t, h, http.MethodPost, "/api/settings/totp/begin", "", adminCookie, map[string]string{
		"password": "admin-password-123",
	}, "")
	if beginRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on settings/totp/begin, got %d: %s", beginRec.Code, beginRec.Body.String())
	}
	var resetBegin struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(beginRec.Body.Bytes(), &resetBegin)
	if resetBegin.Secret == "" || resetBegin.Secret == setupResp.Secret {
		t.Fatalf("expected fresh TOTP secret on reset")
	}

	// Confirm with new secret's code
	newCode := codeForSecret(t, resetBegin.Secret)
	confirmRec := doReq(t, h, http.MethodPost, "/api/settings/totp/confirm", "", adminCookie, map[string]string{
		"totp_code": newCode,
	}, "")
	if confirmRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on settings/totp/confirm, got %d: %s", confirmRec.Code, confirmRec.Body.String())
	}

	// 6. Service token boundary check on admin/settings routes + Korean secret value & key validation
	projRec := doReq(t, h, http.MethodPost, "/api/projects", "", adminCookie, map[string]string{"name": "p1"}, "")
	var proj db.Project
	_ = json.Unmarshal(projRec.Body.Bytes(), &proj)
	envRec := doReq(t, h, http.MethodPost, "/api/projects/"+proj.ID+"/environments", "", adminCookie, map[string]string{"name": "dev"}, "")
	var env db.Environment
	_ = json.Unmarshal(envRec.Body.Bytes(), &env)

	tokRec := doReq(t, h, http.MethodPost, "/api/projects/"+proj.ID+"/tokens", "", adminCookie, map[string]any{
		"env_id": env.ID,
		"name":   "dev-writer",
		"scope":  "write",
	}, "")
	var tokResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(tokRec.Body.Bytes(), &tokResp)

	// Service token must be 403 on settings/totp/begin
	if rec := doReq(t, h, http.MethodPost, "/api/settings/totp/begin", "Bearer "+tokResp.Token, nil, map[string]string{"password": "admin-password-123"}, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for service token on settings/totp/begin, got %d", rec.Code)
	}

	// Invalid POSIX key rejected with 400
	if rec := doReq(t, h, http.MethodPost, "/api/projects/"+proj.ID+"/environments/"+env.ID+"/secrets", "Bearer "+tokResp.Token, nil, map[string]string{
		"key":   "123_INVALID-KEY",
		"value": "abc",
	}, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid secret key, got %d", rec.Code)
	}

	// Korean & special character secret value stored and decrypted intact
	koreanVal := "안녕하세요! 시크릿 값 #123\n둘째줄"
	if rec := doReq(t, h, http.MethodPost, "/api/projects/"+proj.ID+"/environments/"+env.ID+"/secrets", "Bearer "+tokResp.Token, nil, map[string]string{
		"key":   "KOREAN_GREETING",
		"value": koreanVal,
	}, ""); rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid Korean secret value, got %d: %s", rec.Code, rec.Body.String())
	}

	revealRec := doReq(t, h, http.MethodGet, "/api/projects/"+proj.ID+"/environments/"+env.ID+"/secrets/KOREAN_GREETING", "Bearer "+tokResp.Token, nil, nil, "")
	if revealRec.Code != http.StatusOK || !strings.Contains(revealRec.Body.String(), "안녕하세요! 시크릿 값 #123") {
		t.Fatalf("expected Korean secret value intact, got %d: %s", revealRec.Code, revealRec.Body.String())
	}
}

func TestSecretEditAndDateParsing(t *testing.T) {
	_, _, h := setupTestServer(t)

	// Login + TOTP setup
	loginRec := doReq(t, h, http.MethodPost, "/api/auth/login", "", nil, map[string]string{"password": "super-admin-password"}, "")
	var setupResp struct {
		TempToken string `json:"temp_token"`
		Secret    string `json:"secret"`
	}
	_ = json.Unmarshal(loginRec.Body.Bytes(), &setupResp)
	totpRec := doReq(t, h, http.MethodPost, "/api/auth/totp/setup", "", nil, map[string]string{
		"temp_token": setupResp.TempToken,
		"totp_code":  codeForSecret(t, setupResp.Secret),
	}, "")
	var cookie *http.Cookie
	for _, c := range totpRec.Result().Cookies() {
		if c.Name == sessionCookieName {
			cookie = c
		}
	}

	projRec := doReq(t, h, http.MethodPost, "/api/projects", "", cookie, map[string]string{"name": "date-test"}, "")
	var proj db.Project
	_ = json.Unmarshal(projRec.Body.Bytes(), &proj)
	envRec := doReq(t, h, http.MethodPost, "/api/projects/"+proj.ID+"/environments", "", cookie, map[string]string{"name": "dev"}, "")
	var env db.Environment
	_ = json.Unmarshal(envRec.Body.Bytes(), &env)

	// Create secret with YYYY-MM-DD expires_at
	createRec := doReq(t, h, http.MethodPost, "/api/projects/"+proj.ID+"/environments/"+env.ID+"/secrets", "", cookie, map[string]any{
		"key":        "BLOG_ID",
		"value":      "초기값",
		"expires_at": "2027-12-31",
	}, "")
	if createRec.Code != http.StatusOK {
		t.Fatalf("create failed (%d): %s", createRec.Code, createRec.Body.String())
	}
	if !strings.Contains(createRec.Body.String(), "2027-12-31") {
		t.Fatalf("expected 2027-12-31 in response, got %s", createRec.Body.String())
	}

	// Update via PUT and clear expires_at
	putRec := doReq(t, h, http.MethodPut, "/api/projects/"+proj.ID+"/environments/"+env.ID+"/secrets/BLOG_ID", "", cookie, map[string]any{
		"value":      "수정된 한글 값",
		"expires_at": nil,
	}, "")
	if putRec.Code != http.StatusOK {
		t.Fatalf("put failed (%d): %s", putRec.Code, putRec.Body.String())
	}
	var updated secretResponse
	_ = json.Unmarshal(putRec.Body.Bytes(), &updated)
	if updated.Value != "수정된 한글 값" || updated.ExpiresAt != nil {
		t.Fatalf("unexpected updated secret: %+v", updated)
	}
}
