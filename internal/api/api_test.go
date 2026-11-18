package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maekom-hub/maekom-env/internal/crypto"
	"github.com/maekom-hub/maekom-env/internal/db"
	"github.com/maekom-hub/maekom-env/internal/notifier"
)

func setupTestServer(t *testing.T) (*Server, *db.DB, http.Handler) {
	t.Helper()

	ctx := context.Background()
	store, err := db.Open(ctx, filepath.Join(t.TempDir(), "api-test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cipher, err := crypto.NewCipherFromMasterKey("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}

	disp := notifier.NewDispatcher(store)
	srv, err := NewServer(store, cipher, disp, Config{
		AdminPassword: "super-admin-password",
		JWTSecret:     []byte("test-jwt-signing-secret-32-bytes"),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv, store, srv.Handler()
}

func doReq(t *testing.T, h http.Handler, method, path, authHeader string, cookie *http.Cookie, body any, contentType string) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			reader = strings.NewReader(v)
		default:
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			reader = bytes.NewReader(b)
		}
	}

	req := httptest.NewRequest(method, path, reader)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	} else if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestEndToEndAPIAuthSecretsTokensAndWebhooks(t *testing.T) {
	_, _, handler := setupTestServer(t)

	// 1. Admin login (wrong password -> 401, right password -> 200 + JWT + Cookie)
	badLogin := doReq(t, handler, http.MethodPost, "/api/auth/login", "", nil, map[string]string{"password": "wrong"}, "")
	if badLogin.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad password, got %d", badLogin.Code)
	}

	loginRec := doReq(t, handler, http.MethodPost, "/api/auth/login", "", nil, map[string]string{"password": "super-admin-password"}, "")
	if loginRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for login, got %d: %s", loginRec.Code, loginRec.Body.String())
	}
	var setupResp struct {
		Status    string `json:"status"`
		TempToken string `json:"temp_token"`
		Secret    string `json:"secret"`
	}
	_ = json.Unmarshal(loginRec.Body.Bytes(), &setupResp)
	if setupResp.Status != "totp_setup_required" || setupResp.TempToken == "" {
		t.Fatalf("expected totp_setup_required, got %s", loginRec.Body.String())
	}

	totpRec := doReq(t, handler, http.MethodPost, "/api/auth/totp/setup", "", nil, map[string]string{
		"temp_token": setupResp.TempToken,
		"totp_code":  codeForSecret(t, setupResp.Secret),
	}, "")
	if totpRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for totp setup, got %d: %s", totpRec.Code, totpRec.Body.String())
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(totpRec.Body.Bytes(), &loginResp)
	if loginResp.Token == "" {
		t.Fatal("expected JWT token from totp setup")
	}

	var sessionCookie *http.Cookie
	for _, c := range totpRec.Result().Cookies() {
		if c.Name == sessionCookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected maekom_session cookie")
	}

	adminAuth := "Bearer " + loginResp.Token

	// 2. Project & Environment CRUD (using session cookie on create, JWT on list)
	projRec := doReq(t, handler, http.MethodPost, "/api/projects", "", sessionCookie, map[string]string{
		"name":        "maekom-api",
		"description": "core backend",
	}, "")
	if projRec.Code != http.StatusCreated {
		t.Fatalf("create project failed (%d): %s", projRec.Code, projRec.Body.String())
	}
	var proj db.Project
	_ = json.Unmarshal(projRec.Body.Bytes(), &proj)

	envProdRec := doReq(t, handler, http.MethodPost, "/api/projects/"+proj.ID+"/environments", adminAuth, nil, map[string]string{"name": "prod"}, "")
	if envProdRec.Code != http.StatusCreated {
		t.Fatalf("create prod env failed (%d): %s", envProdRec.Code, envProdRec.Body.String())
	}
	var envProd db.Environment
	_ = json.Unmarshal(envProdRec.Body.Bytes(), &envProd)

	envDevRec := doReq(t, handler, http.MethodPost, "/api/projects/"+proj.ID+"/environments", adminAuth, nil, map[string]string{"name": "dev"}, "")
	if envDevRec.Code != http.StatusCreated {
		t.Fatalf("create dev env failed (%d): %s", envDevRec.Code, envDevRec.Body.String())
	}
	var envDev db.Environment
	_ = json.Unmarshal(envDevRec.Body.Bytes(), &envDev)

	// 3. Register custom webhook and verify test & async secret.updated delivery (never exposing value!)
	var (
		mu         sync.Mutex
		whBodies   []string
		whSigs     []string
	)
	whSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		whBodies = append(whBodies, string(b))
		whSigs = append(whSigs, r.Header.Get("X-Maekom-Signature"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer whSrv.Close()

	whRec := doReq(t, handler, http.MethodPost, "/api/projects/"+proj.ID+"/webhooks", adminAuth, nil, map[string]any{
		"env_id":     envProd.ID,
		"type":       "custom",
		"target_url": whSrv.URL,
		"secret_key": "whsec_secret",
		"events":     "*",
	}, "")
	if whRec.Code != http.StatusCreated {
		t.Fatalf("create webhook failed (%d): %s", whRec.Code, whRec.Body.String())
	}
	var wh webhookView
	_ = json.Unmarshal(whRec.Body.Bytes(), &wh)

	testWhRec := doReq(t, handler, http.MethodPost, "/api/projects/"+proj.ID+"/webhooks/"+wh.ID+"/test", adminAuth, nil, nil, "")
	if testWhRec.Code != http.StatusOK {
		t.Fatalf("test webhook failed (%d): %s", testWhRec.Code, testWhRec.Body.String())
	}

	// 4. Secret upsert + masked vs plaintext listing
	secretVal := "sk_live_top_secret_999"
	upRec := doReq(t, handler, http.MethodPost, "/api/projects/"+proj.ID+"/environments/"+envProd.ID+"/secrets", adminAuth, nil, map[string]string{
		"key":   "STRIPE_KEY",
		"value": secretVal,
	}, "")
	if upRec.Code != http.StatusOK {
		t.Fatalf("upsert secret failed (%d): %s", upRec.Code, upRec.Body.String())
	}

	// Masked list for UI
	maskedRec := doReq(t, handler, http.MethodGet, "/api/projects/"+proj.ID+"/environments/"+envProd.ID+"/secrets?masked=true", adminAuth, nil, nil, "")
	if maskedRec.Code != http.StatusOK {
		t.Fatalf("list masked secrets failed (%d)", maskedRec.Code)
	}
	if strings.Contains(maskedRec.Body.String(), secretVal) {
		t.Fatal("masked listing must not contain plaintext secret")
	}
	if !strings.Contains(maskedRec.Body.String(), `"********"`) {
		t.Fatalf("expected masked value in response: %s", maskedRec.Body.String())
	}

	// 5. .env Import & Export
	dotenvText := "# comment\nexport DB_HOST=localhost\nDB_PASS=\"p@ss word\"\n"
	impRec := doReq(t, handler, http.MethodPost, "/api/projects/"+proj.ID+"/environments/"+envProd.ID+"/secrets/import", adminAuth, nil, dotenvText, "text/plain")
	if impRec.Code != http.StatusOK {
		t.Fatalf("import .env failed (%d): %s", impRec.Code, impRec.Body.String())
	}

	expRec := doReq(t, handler, http.MethodGet, "/api/projects/"+proj.ID+"/environments/"+envProd.ID+"/secrets/export", adminAuth, nil, nil, "")
	if expRec.Code != http.StatusOK {
		t.Fatalf("export .env failed (%d)", expRec.Code)
	}
	expBody := expRec.Body.String()
	if !strings.Contains(expBody, "DB_HOST=localhost\n") || !strings.Contains(expBody, `DB_PASS="p@ss word"`) || !strings.Contains(expBody, "STRIPE_KEY="+secretVal) {
		t.Fatalf("unexpected exported .env:\n%s", expBody)
	}

	// 6. Service Token (read-only scoped to prod)
	tokRec := doReq(t, handler, http.MethodPost, "/api/projects/"+proj.ID+"/tokens", adminAuth, nil, map[string]any{
		"env_id": envProd.ID,
		"name":   "prod-reader",
		"scope":  "read",
	}, "")
	if tokRec.Code != http.StatusCreated {
		t.Fatalf("create token failed (%d): %s", tokRec.Code, tokRec.Body.String())
	}
	var tokResp struct {
		Token    string           `json:"token"`
		Metadata serviceTokenView `json:"metadata"`
	}
	_ = json.Unmarshal(tokRec.Body.Bytes(), &tokResp)
	if !strings.HasPrefix(tokResp.Token, "mkv_") {
		t.Fatalf("expected mkv_ token prefix, got %q", tokResp.Token)
	}

	svcAuth := "Bearer " + tokResp.Token

	// Read allowed on prod
	cliReadRec := doReq(t, handler, http.MethodGet, "/api/projects/"+proj.ID+"/environments/"+envProd.ID+"/secrets", svcAuth, nil, nil, "")
	if cliReadRec.Code != http.StatusOK || !strings.Contains(cliReadRec.Body.String(), secretVal) {
		t.Fatalf("expected service token to read decrypted secrets (%d): %s", cliReadRec.Code, cliReadRec.Body.String())
	}

	// Write denied (403) on prod for read token
	cliWriteRec := doReq(t, handler, http.MethodPost, "/api/projects/"+proj.ID+"/environments/"+envProd.ID+"/secrets", svcAuth, nil, map[string]string{
		"key":   "NEW_KEY",
		"value": "val",
	}, "")
	if cliWriteRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for read token write attempt, got %d", cliWriteRec.Code)
	}

	// Read denied (403) on dev for prod-scoped token
	cliDevRec := doReq(t, handler, http.MethodGet, "/api/projects/"+proj.ID+"/environments/"+envDev.ID+"/secrets", svcAuth, nil, nil, "")
	if cliDevRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for prod token accessing dev env, got %d", cliDevRec.Code)
	}

	// Admin endpoint denied (403) for service token
	cliAdminRec := doReq(t, handler, http.MethodGet, "/api/projects", svcAuth, nil, nil, "")
	if cliAdminRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for service token on admin endpoint, got %d", cliAdminRec.Code)
	}

	// Revoke token -> subsequent call returns 401
	revRec := doReq(t, handler, http.MethodDelete, "/api/projects/"+proj.ID+"/tokens/"+tokResp.Metadata.ID, adminAuth, nil, nil, "")
	if revRec.Code != http.StatusOK {
		t.Fatalf("revoke token failed (%d)", revRec.Code)
	}
	afterRevRec := doReq(t, handler, http.MethodGet, "/api/projects/"+proj.ID+"/environments/"+envProd.ID+"/secrets", svcAuth, nil, nil, "")
	if afterRevRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after token revocation, got %d", afterRevRec.Code)
	}

	// Wait briefly for async webhook goroutines and verify no secret value leaked.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		count := len(whBodies)
		mu.Unlock()
		if count >= 4 { // 1 test + 1 upsert + 2 import
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(whBodies) < 2 {
		t.Fatalf("expected async webhook deliveries, got %d", len(whBodies))
	}
	for i, body := range whBodies {
		if strings.Contains(body, secretVal) || strings.Contains(body, "p@ss word") {
			t.Fatalf("webhook payload leaked plaintext secret: %s", body)
		}
		if !crypto.VerifyWebhookSignature("whsec_secret", []byte(body), whSigs[i]) {
			t.Fatalf("webhook %d had invalid HMAC signature %q", i, whSigs[i])
		}
	}
}
