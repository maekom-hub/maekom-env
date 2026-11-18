package api

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/maekom-hub/maekom-env/internal/crypto"
	"github.com/maekom-hub/maekom-env/internal/db"
	"github.com/maekom-hub/maekom-env/internal/notifier"
)

type serviceTokenView struct {
	ID        string        `json:"id"`
	ProjectID string        `json:"project_id"`
	EnvID     *string       `json:"env_id,omitempty"`
	Name      string        `json:"name"`
	Scope     db.TokenScope `json:"scope"`
	ExpiresAt *time.Time    `json:"expires_at,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
}

type webhookView struct {
	ID        string         `json:"id"`
	ProjectID string         `json:"project_id"`
	EnvID     *string        `json:"env_id,omitempty"`
	Type      db.WebhookType `json:"type"`
	TargetURL string         `json:"target_url"`
	HasSecret bool           `json:"has_secret"`
	Events    string         `json:"events"`
	Enabled   bool           `json:"enabled"`
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	if _, err := s.db.GetProject(r.Context(), projectID); err != nil {
		writeDBError(w, err)
		return
	}

	tokens, err := s.db.ListServiceTokens(r.Context(), projectID)
	if err != nil {
		writeDBError(w, err)
		return
	}

	views := make([]serviceTokenView, 0, len(tokens))
	for _, tok := range tokens {
		views = append(views, serviceTokenView{
			ID:        tok.ID,
			ProjectID: tok.ProjectID,
			EnvID:     tok.EnvID,
			Name:      tok.Name,
			Scope:     tok.Scope,
			ExpiresAt: tok.ExpiresAt,
			CreatedAt: tok.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": views})
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	if _, err := s.db.GetProject(r.Context(), projectID); err != nil {
		writeDBError(w, err)
		return
	}

	var req struct {
		EnvID     *string       `json:"env_id"`
		Name      string        `json:"name"`
		Scope     db.TokenScope `json:"scope"`
		ExpiresAt *time.Time    `json:"expires_at"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "token name is required")
		return
	}
	if req.Scope != db.ScopeRead && req.Scope != db.ScopeWrite {
		writeError(w, http.StatusBadRequest, "scope must be 'read' or 'write'")
		return
	}
	if req.EnvID != nil && *req.EnvID != "" {
		if _, err := s.db.GetEnvironment(r.Context(), projectID, *req.EnvID); err != nil {
			writeDBError(w, err)
			return
		}
	} else {
		req.EnvID = nil
	}

	rawToken, err := generateServiceToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate service token")
		return
	}
	tokenHash := crypto.HashToken(rawToken)

	tok, err := s.db.CreateServiceToken(r.Context(), projectID, req.EnvID, req.Name, tokenHash, req.Scope, req.ExpiresAt)
	if err != nil {
		writeDBError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"token": rawToken,
		"metadata": serviceTokenView{
			ID:        tok.ID,
			ProjectID: tok.ProjectID,
			EnvID:     tok.EnvID,
			Name:      tok.Name,
			Scope:     tok.Scope,
			ExpiresAt: tok.ExpiresAt,
			CreatedAt: tok.CreatedAt,
		},
	})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	tokenID := r.PathValue("tokenID")
	if err := s.db.DeleteServiceToken(r.Context(), projectID, tokenID); err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	if _, err := s.db.GetProject(r.Context(), projectID); err != nil {
		writeDBError(w, err)
		return
	}

	hooks, err := s.db.ListWebhooks(r.Context(), projectID)
	if err != nil {
		writeDBError(w, err)
		return
	}

	views := make([]webhookView, 0, len(hooks))
	for _, wh := range hooks {
		views = append(views, webhookView{
			ID:        wh.ID,
			ProjectID: wh.ProjectID,
			EnvID:     wh.EnvID,
			Type:      wh.Type,
			TargetURL: wh.TargetURL,
			HasSecret: wh.SecretKey != "",
			Events:    wh.Events,
			Enabled:   wh.Enabled,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"webhooks": views})
}

func (s *Server) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	if _, err := s.db.GetProject(r.Context(), projectID); err != nil {
		writeDBError(w, err)
		return
	}

	var req struct {
		EnvID     *string        `json:"env_id"`
		Type      db.WebhookType `json:"type"`
		TargetURL string         `json:"target_url"`
		SecretKey string         `json:"secret_key"`
		Events    string         `json:"events"`
		Enabled   *bool          `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	switch req.Type {
	case db.WebhookDiscord, db.WebhookSlack, db.WebhookEmail, db.WebhookCustom:
	default:
		writeError(w, http.StatusBadRequest, "type must be one of discord, slack, email, custom")
		return
	}

	req.TargetURL = strings.TrimSpace(req.TargetURL)
	if req.TargetURL == "" {
		writeError(w, http.StatusBadRequest, "target_url is required")
		return
	}

	if req.EnvID != nil && *req.EnvID != "" {
		if _, err := s.db.GetEnvironment(r.Context(), projectID, *req.EnvID); err != nil {
			writeDBError(w, err)
			return
		}
	} else {
		req.EnvID = nil
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	wh, err := s.db.CreateWebhook(
		r.Context(),
		projectID,
		req.EnvID,
		req.Type,
		req.TargetURL,
		req.SecretKey,
		strings.TrimSpace(req.Events),
		enabled,
	)
	if err != nil {
		writeDBError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, webhookView{
		ID:        wh.ID,
		ProjectID: wh.ProjectID,
		EnvID:     wh.EnvID,
		Type:      wh.Type,
		TargetURL: wh.TargetURL,
		HasSecret: wh.SecretKey != "",
		Events:    wh.Events,
		Enabled:   wh.Enabled,
	})
}

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	webhookID := r.PathValue("webhookID")
	if err := s.db.DeleteWebhook(r.Context(), projectID, webhookID); err != nil {
		writeDBError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	webhookID := r.PathValue("webhookID")

	proj, err := s.db.GetProject(r.Context(), projectID)
	if err != nil {
		writeDBError(w, err)
		return
	}

	wh, err := s.db.GetWebhook(r.Context(), projectID, webhookID)
	if err != nil {
		writeDBError(w, err)
		return
	}

	envName := "*"
	if wh.EnvID != nil {
		if env, err := s.db.GetEnvironment(r.Context(), projectID, *wh.EnvID); err == nil {
			envName = env.Name
		}
	}

	if s.notifier == nil {
		writeError(w, http.StatusInternalServerError, "notifier is not configured")
		return
	}

	ev := notifier.Event{
		Project:     proj.Name,
		Environment: envName,
		Key:         "TEST_WEBHOOK",
		Event:       notifier.EventWebhookTest,
		Timestamp:   time.Now().UTC(),
	}
	if err := s.notifier.Send(r.Context(), wh, ev); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func generateServiceToken() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return serviceTokenPrefix + hex.EncodeToString(b[:]), nil
}
