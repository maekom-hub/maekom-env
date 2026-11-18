package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/maekom-hub/maekom-env/internal/crypto"
	"github.com/maekom-hub/maekom-env/internal/db"
	"github.com/maekom-hub/maekom-env/internal/notifier"
)

// Config configures authentication and server behavior.
type Config struct {
	AdminPassword string
	JWTSecret     []byte
}

// LoadConfigFromEnv loads API authentication configuration from environment variables.
func LoadConfigFromEnv() Config {
	var jwtSecret []byte
	if raw := os.Getenv("JWT_SECRET"); raw != "" {
		jwtSecret = []byte(raw)
	}
	return Config{
		AdminPassword: os.Getenv("ADMIN_PASSWORD"),
		JWTSecret:     jwtSecret,
	}
}

// Server exposes the maekom-env HTTP API handlers.
type Server struct {
	db            *db.DB
	cipher        *crypto.Cipher
	notifier      *notifier.Dispatcher
	adminPassword string
	jwtSecret     []byte
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
		jwtSecret:     jwtSecret,
		mux:           http.NewServeMux(),
	}
	s.registerRoutes()
	return s, nil
}

// Handler returns the root http.Handler for the API server.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) registerRoutes() {
	// Health check
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Auth
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	s.mux.HandleFunc("GET /api/auth/me", s.requireAuth(s.handleMe))

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
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !s.verifyAdminPassword(req.Password) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, exp, err := s.issueAdminJWT(defaultJWTTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue session token")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_at": exp.Format(time.RFC3339),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	principal, _ := PrincipalFromContext(r.Context())
	writeJSON(w, http.StatusOK, principal)
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
