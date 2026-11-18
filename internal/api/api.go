package api

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/maekom-hub/maekom-env/internal/crypto"
	"github.com/maekom-hub/maekom-env/internal/db"
	"github.com/maekom-hub/maekom-env/internal/notifier"
)

// Config configures authentication, session timeout, and optional embedded web UI assets.
type Config struct {
	AdminPassword  string
	JWTSecret      []byte
	TOTPSecret     string
	SessionTimeout time.Duration
	WebFS          fs.FS
}

// LoadConfigFromEnv loads API authentication configuration from environment variables.
func LoadConfigFromEnv() Config {
	var jwtSecret []byte
	if raw := os.Getenv("JWT_SECRET"); raw != "" {
		jwtSecret = []byte(raw)
	}
	return Config{
		AdminPassword:  os.Getenv("ADMIN_PASSWORD"),
		JWTSecret:      jwtSecret,
		TOTPSecret:     os.Getenv("TOTP_SECRET"),
		SessionTimeout: parseSessionTimeout(os.Getenv("SESSION_TIMEOUT")),
	}
}

// Server exposes the maekom-env HTTP API handlers and embedded web dashboard.
type Server struct {
	db            *db.DB
	cipher        *crypto.Cipher
	notifier      *notifier.Dispatcher
	adminPassword string
	totpSecret    string
	jwtSecret     []byte
	limiter       *loginRateLimiter
	sessions      *sessionStore
	pendingSetup  *pendingTOTPStore
	pendingVerify *pendingTOTPStore
	pendingReset  *pendingTOTPStore
	webFS         fs.FS
	mux           *http.ServeMux
}

// NewServer constructs a new HTTP API server with all routes registered.
func NewServer(database *db.DB, cipher *crypto.Cipher, disp *notifier.Dispatcher, cfg Config) (*Server, error) {
	jwtSecret := cfg.JWTSecret
	if len(jwtSecret) == 0 {
		var err error
		jwtSecret, err = generateRandomSecret()
		if err != nil {
			return nil, err
		}
	}

	s := &Server{
		db:            database,
		cipher:        cipher,
		notifier:      disp,
		adminPassword: cfg.AdminPassword,
		totpSecret:    strings.TrimSpace(cfg.TOTPSecret),
		jwtSecret:     jwtSecret,
		limiter:       newLoginRateLimiter(),
		sessions:      newSessionStore(cfg.SessionTimeout),
		pendingSetup:  newPendingTOTPStore(),
		pendingVerify: newPendingTOTPStore(),
		pendingReset:  newPendingTOTPStore(),
		webFS:         cfg.WebFS,
		mux:           http.NewServeMux(),
	}
	s.registerRoutes()
	return s, nil
}

// Handler returns the root http.Handler wrapped with security headers middleware.
func (s *Server) Handler() http.Handler {
	return securityHeadersMiddleware(s.mux)
}

func (s *Server) registerRoutes() {
	// Health check
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Auth
	s.mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/auth/totp/setup", s.handleTOTPSetup)
	s.mux.HandleFunc("POST /api/auth/totp/verify", s.handleTOTPVerify)
	s.mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	s.mux.HandleFunc("GET /api/auth/me", s.requireAuth(s.handleMe))

	// Security Settings (Admin only)
	s.mux.HandleFunc("POST /api/settings/totp/begin", s.requireAdmin(s.handleSettingsTOTPBegin))
	s.mux.HandleFunc("POST /api/settings/totp/confirm", s.requireAdmin(s.handleSettingsTOTPConfirm))

	// Projects (Admin)
	s.mux.HandleFunc("GET /api/projects", s.requireAdmin(s.handleListProjects))
	s.mux.HandleFunc("POST /api/projects", s.requireAdmin(s.handleCreateProject))
	s.mux.HandleFunc("GET /api/projects/{projectID}", s.requireAdmin(s.handleGetProject))
	s.mux.HandleFunc("PUT /api/projects/{projectID}", s.requireAdmin(s.handleUpdateProject))
	s.mux.HandleFunc("DELETE /api/projects/{projectID}", s.requireAdmin(s.handleDeleteProject))

	// Environments (List allows scoped service token for its own project; Create/Delete require Admin)
	s.mux.HandleFunc("GET /api/projects/{projectID}/environments", s.requireAuth(s.handleListEnvironments))
	s.mux.HandleFunc("POST /api/projects/{projectID}/environments", s.requireAdmin(s.handleCreateEnvironment))
	s.mux.HandleFunc("DELETE /api/projects/{projectID}/environments/{envID}", s.requireAdmin(s.handleDeleteEnvironment))

	// Secrets (Admin or scoped Service Token)
	s.mux.HandleFunc("GET /api/projects/{projectID}/environments/{envID}/secrets", s.requireAuth(s.handleListSecrets))
	s.mux.HandleFunc("GET /api/projects/{projectID}/environments/{envID}/secrets/{key}", s.requireAuth(s.handleRevealSecret))
	s.mux.HandleFunc("POST /api/projects/{projectID}/environments/{envID}/secrets", s.requireAuth(s.handleUpsertSecret))
	s.mux.HandleFunc("PUT /api/projects/{projectID}/environments/{envID}/secrets/{key}", s.requireAuth(s.handleUpsertSecretByKey))
	s.mux.HandleFunc("DELETE /api/projects/{projectID}/environments/{envID}/secrets/{key}", s.requireAuth(s.handleDeleteSecret))
	s.mux.HandleFunc("POST /api/projects/{projectID}/environments/{envID}/secrets/import", s.requireAuth(s.handleImportSecrets))
	s.mux.HandleFunc("GET /api/projects/{projectID}/environments/{envID}/secrets/export", s.requireAuth(s.handleExportSecrets))

	// Service Tokens (Admin)
	s.mux.HandleFunc("GET /api/projects/{projectID}/tokens", s.requireAdmin(s.handleListTokens))
	s.mux.HandleFunc("POST /api/projects/{projectID}/tokens", s.requireAdmin(s.handleCreateToken))
	s.mux.HandleFunc("DELETE /api/projects/{projectID}/tokens/{tokenID}", s.requireAdmin(s.handleDeleteToken))

	// Webhooks (Admin)
	s.mux.HandleFunc("GET /api/projects/{projectID}/webhooks", s.requireAdmin(s.handleListWebhooks))
	s.mux.HandleFunc("POST /api/projects/{projectID}/webhooks", s.requireAdmin(s.handleCreateWebhook))
	s.mux.HandleFunc("DELETE /api/projects/{projectID}/webhooks/{webhookID}", s.requireAdmin(s.handleDeleteWebhook))
	s.mux.HandleFunc("POST /api/projects/{projectID}/webhooks/{webhookID}/test", s.requireAdmin(s.handleTestWebhook))

	// Audit Logs (Admin)
	s.mux.HandleFunc("GET /api/audit-logs", s.requireAdmin(s.handleListAuditLogs))

	// Embedded Web UI SPA
	if s.webFS != nil {
		s.mux.Handle("/", s.spaHandler())
	}
}

func (s *Server) spaHandler() http.Handler {
	fileServer := http.FileServer(http.FS(s.webFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/healthz" {
			http.NotFound(w, r)
			return
		}

		cleanPath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if cleanPath == "" || cleanPath == "." {
			cleanPath = "index.html"
		}

		if f, err := s.webFS.Open(cleanPath); err == nil {
			_ = f.Close()
			if cleanPath == "index.html" {
				w.Header().Set("Cache-Control", "no-store")
			}
			fileServer.ServeHTTP(w, r)
			return
		}

		// Fallback to index.html for SPA routes.
		w.Header().Set("Cache-Control", "no-store")
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		fileServer.ServeHTTP(w, r2)
	})
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	_, configured := s.resolveActiveTOTPSecret(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"totp_required":   configured,
		"totp_configured": configured,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if blocked, retryAfter := s.limiter.isBlocked(ip); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
		s.recordAudit(r.Context(), db.AuditLog{
			Event:     "auth.login",
			Actor:     "admin",
			IPAddress: ip,
			Success:   false,
			Detail:    "rate limited",
		})
		writeError(w, http.StatusTooManyRequests, "too many failed login attempts; try again later")
		return
	}

	var req struct {
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !s.verifyAdminPassword(req.Password) {
		blockedNow := s.limiter.recordFailure(ip)
		detail := "invalid password"
		if blockedNow {
			detail = "invalid password (IP blocked for 15m)"
		}
		s.recordAudit(r.Context(), db.AuditLog{
			Event:     "auth.login",
			Actor:     "admin",
			IPAddress: ip,
			Success:   false,
			Detail:    detail,
		})
		if blockedNow {
			w.Header().Set("Retry-After", strconv.Itoa(int(loginBlockDuration.Seconds())))
			writeError(w, http.StatusTooManyRequests, "too many failed login attempts; try again later")
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	activeSecret, configured := s.resolveActiveTOTPSecret(r.Context())
	if !configured {
		// First-time login: issue short-lived 2FA setup temp token instead of full session.
		secret, err := generateTOTPSecret()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to generate TOTP secret")
			return
		}
		tempToken, jti, err := s.issuePendingJWT(roleTOTPSetup, 10*time.Minute)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to issue 2FA setup token")
			return
		}
		s.pendingSetup.set(jti, secret, 10*time.Minute)
		s.limiter.reset(ip)

		writeJSON(w, http.StatusOK, map[string]any{
			"status":      "totp_setup_required",
			"temp_token":  tempToken,
			"secret":      secret,
			"otpauth_uri": buildOTPAuthURI("maekom-env", "admin", secret),
		})
		return
	}

	// If caller already supplied a valid 6-digit TOTP code inline, allow direct completion.
	if strings.TrimSpace(req.TOTPCode) != "" {
		if !verifyTOTP(activeSecret, req.TOTPCode, time.Now().UTC()) {
			blockedNow := s.limiter.recordFailure(ip)
			s.recordAudit(r.Context(), db.AuditLog{
				Event:     "auth.login",
				Actor:     "admin",
				IPAddress: ip,
				Success:   false,
				Detail:    "invalid TOTP code",
			})
			if blockedNow {
				w.Header().Set("Retry-After", strconv.Itoa(int(loginBlockDuration.Seconds())))
				writeError(w, http.StatusTooManyRequests, "too many failed login attempts; try again later")
				return
			}
			writeError(w, http.StatusUnauthorized, "invalid TOTP code")
			return
		}
		s.completeAdminLogin(w, r, ip, "admin login succeeded")
		return
	}

	// Password verified; require 2FA verification via short-lived pending token.
	tempToken, jti, err := s.issuePendingJWT(roleTOTPVerify, 5*time.Minute)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue 2FA verification token")
		return
	}
	s.pendingVerify.set(jti, "pending", 5*time.Minute)
	s.limiter.reset(ip)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "totp_verify_required",
		"temp_token": tempToken,
	})
}

func (s *Server) completeAdminLogin(w http.ResponseWriter, r *http.Request, ip, auditDetail string) {
	s.limiter.reset(ip)

	token, _, idleExp, err := s.issueAdminJWT(defaultJWTTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue session token")
		return
	}

	s.setSessionCookie(w, token, idleExp)
	s.recordAudit(r.Context(), db.AuditLog{
		Event:     "auth.login",
		Actor:     "admin",
		IPAddress: ip,
		Success:   true,
		Detail:    auditDetail,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "authenticated",
		"authenticated": true,
		"token":         token,
		"expires_at":    idleExp.Format(time.RFC3339),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		if claims, err := s.verifyAdminJWT(cookie.Value); err == nil {
			s.sessions.revoke(claims.JTI)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	principal, _ := PrincipalFromContext(r.Context())
	writeJSON(w, http.StatusOK, principal)
}

func (s *Server) recordAudit(ctx context.Context, entry db.AuditLog) {
	if s.db == nil {
		return
	}
	_ = s.db.InsertAuditLog(ctx, entry)
}

func decodeJSON(r *http.Request, dst any) error {
	defer func() { _ = r.Body.Close() }()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 2<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeDBError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrNotFound):
		writeError(w, http.StatusNotFound, "resource not found")
	case errors.Is(err, db.ErrConflict):
		writeError(w, http.StatusConflict, "resource already exists")
	default:
		writeError(w, http.StatusInternalServerError, "internal server error")
	}
}
