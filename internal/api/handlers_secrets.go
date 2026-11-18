package api

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/maekom-hub/maekom-env/internal/db"
)

type secretResponse struct {
	ID         string     `json:"id"`
	EnvID      string     `json:"env_id"`
	Key        string     `json:"key"`
	Value      string     `json:"value"`
	Masked     bool       `json:"masked"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Notified7d bool       `json:"notified_7d"`
	Notified1d bool       `json:"notified_1d"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

func (s *Server) authorizeEnvAccess(w http.ResponseWriter, r *http.Request, requireWrite bool) (db.Project, db.Environment, bool) {
	projectID := r.PathValue("projectID")
	envID := r.PathValue("envID")

	principal, ok := PrincipalFromContext(r.Context())
	if !ok || !principal.CanAccessEnv(projectID, envID) {
		writeError(w, http.StatusForbidden, "access denied for this project or environment")
		return db.Project{}, db.Environment{}, false
	}
	if requireWrite && !principal.CanWrite() {
		writeError(w, http.StatusForbidden, "write scope required")
		return db.Project{}, db.Environment{}, false
	}

	proj, err := s.db.GetProject(r.Context(), projectID)
	if err != nil {
		writeDBError(w, err)
		return db.Project{}, db.Environment{}, false
	}
	env, err := s.db.GetEnvironment(r.Context(), projectID, envID)
	if err != nil {
		writeDBError(w, err)
		return db.Project{}, db.Environment{}, false
	}
	return proj, env, true
}

func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	_, env, ok := s.authorizeEnvAccess(w, r, false)
	if !ok {
		return
	}

	masked := strings.EqualFold(r.URL.Query().Get("masked"), "true")

	secrets, err := s.db.ListSecrets(r.Context(), env.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}

	resp := make([]secretResponse, 0, len(secrets))
	for _, sec := range secrets {
		val := ""
		if masked {
			val = "********"
		} else {
			plaintext, err := s.cipher.DecryptString(sec.EncryptedValue, sec.Nonce)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to decrypt secret")
				return
			}
			val = plaintext
		}

		resp = append(resp, secretResponse{
			ID:         sec.ID,
			EnvID:      sec.EnvID,
			Key:        sec.Key,
			Value:      val,
			Masked:     masked,
			ExpiresAt:  sec.ExpiresAt,
			Notified7d: sec.Notified7d,
			Notified1d: sec.Notified1d,
			UpdatedAt:  sec.UpdatedAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"secrets": resp})
}

func (s *Server) handleRevealSecret(w http.ResponseWriter, r *http.Request) {
	proj, env, ok := s.authorizeEnvAccess(w, r, false)
	if !ok {
		return
	}

	key := strings.TrimSpace(r.PathValue("key"))
	if key == "" {
		writeError(w, http.StatusBadRequest, "secret key is required")
		return
	}

	sec, err := s.db.GetSecretByKey(r.Context(), env.ID, key)
	if err != nil {
		writeDBError(w, err)
		return
	}

	plaintext, err := s.cipher.DecryptString(sec.EncryptedValue, sec.Nonce)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to decrypt secret")
		return
	}

	principal, _ := PrincipalFromContext(r.Context())
	s.recordAudit(r.Context(), db.AuditLog{
		Event:     "secret.viewed",
		Actor:     principal.ActorName(),
		IPAddress: clientIP(r),
		ProjectID: &proj.ID,
		EnvID:     &env.ID,
		TargetKey: sec.Key,
		Success:   true,
		Detail:    proj.Name + "/" + env.Name,
	})

	writeJSON(w, http.StatusOK, secretResponse{
		ID:         sec.ID,
		EnvID:      sec.EnvID,
		Key:        sec.Key,
		Value:      plaintext,
		Masked:     false,
		ExpiresAt:  sec.ExpiresAt,
		Notified7d: sec.Notified7d,
		Notified1d: sec.Notified1d,
		UpdatedAt:  sec.UpdatedAt,
	})
}

func parseOptionalExpiresAt(raw *string) (*time.Time, error) {
	if raw == nil {
		return nil, nil
	}
	s := strings.TrimSpace(*raw)
	if s == "" {
		return nil, nil
	}
	if len(s) == 10 {
		t, err := time.Parse("2006-01-02", s)
		if err != nil {
			return nil, fmt.Errorf("invalid expires_at date %q: expected YYYY-MM-DD", s)
		}
		endOfDay := time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, time.UTC)
		return &endOfDay, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, fmt.Errorf("invalid expires_at timestamp %q: expected YYYY-MM-DD or RFC3339", s)
	}
	utc := t.UTC()
	return &utc, nil
}

func (s *Server) handleUpsertSecret(w http.ResponseWriter, r *http.Request) {
	proj, env, ok := s.authorizeEnvAccess(w, r, true)
	if !ok {
		return
	}

	var req struct {
		Key       string  `json:"key"`
		Value     string  `json:"value"`
		ExpiresAt *string `json:"expires_at"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	expiresAt, err := parseOptionalExpiresAt(req.ExpiresAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.upsertAndRespond(w, r, proj, env, req.Key, req.Value, expiresAt)
}

func (s *Server) handleUpsertSecretByKey(w http.ResponseWriter, r *http.Request) {
	proj, env, ok := s.authorizeEnvAccess(w, r, true)
	if !ok {
		return
	}

	key := r.PathValue("key")
	var req struct {
		Value     string  `json:"value"`
		ExpiresAt *string `json:"expires_at"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	expiresAt, err := parseOptionalExpiresAt(req.ExpiresAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.upsertAndRespond(w, r, proj, env, key, req.Value, expiresAt)
}

func (s *Server) upsertAndRespond(
	w http.ResponseWriter,
	r *http.Request,
	proj db.Project,
	env db.Environment,
	key, value string,
	expiresAt *time.Time,
) {
	key = strings.TrimSpace(key)
	if !isValidSecretKey(key) {
		writeError(w, http.StatusBadRequest, "secret key must match ^[A-Za-z_][A-Za-z0-9_]*$")
		return
	}

	ct, nonce, err := s.cipher.EncryptString(value)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to encrypt secret")
		return
	}

	sec, err := s.db.UpsertSecret(r.Context(), env.ID, key, ct, nonce, expiresAt)
	if err != nil {
		writeDBError(w, err)
		return
	}

	if s.notifier != nil {
		s.notifier.NotifySecretUpdatedAsync(proj.ID, proj.Name, env.ID, env.Name, sec.Key)
	}

	principal, _ := PrincipalFromContext(r.Context())
	s.recordAudit(r.Context(), db.AuditLog{
		Event:     "secret.updated",
		Actor:     principal.ActorName(),
		IPAddress: clientIP(r),
		ProjectID: &proj.ID,
		EnvID:     &env.ID,
		TargetKey: sec.Key,
		Success:   true,
		Detail:    proj.Name + "/" + env.Name,
	})

	writeJSON(w, http.StatusOK, secretResponse{
		ID:         sec.ID,
		EnvID:      sec.EnvID,
		Key:        sec.Key,
		Value:      value,
		Masked:     false,
		ExpiresAt:  sec.ExpiresAt,
		Notified7d: sec.Notified7d,
		Notified1d: sec.Notified1d,
		UpdatedAt:  sec.UpdatedAt,
	})
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	proj, env, ok := s.authorizeEnvAccess(w, r, true)
	if !ok {
		return
	}

	key := strings.TrimSpace(r.PathValue("key"))
	if key == "" {
		writeError(w, http.StatusBadRequest, "secret key is required")
		return
	}

	if err := s.db.DeleteSecretByKey(r.Context(), env.ID, key); err != nil {
		writeDBError(w, err)
		return
	}

	if s.notifier != nil {
		s.notifier.NotifySecretUpdatedAsync(proj.ID, proj.Name, env.ID, env.Name, key)
	}

	principal, _ := PrincipalFromContext(r.Context())
	s.recordAudit(r.Context(), db.AuditLog{
		Event:     "secret.deleted",
		Actor:     principal.ActorName(),
		IPAddress: clientIP(r),
		ProjectID: &proj.ID,
		EnvID:     &env.ID,
		TargetKey: key,
		Success:   true,
		Detail:    proj.Name + "/" + env.Name,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleImportSecrets(w http.ResponseWriter, r *http.Request) {
	proj, env, ok := s.authorizeEnvAccess(w, r, true)
	if !ok {
		return
	}

	var rawContent string
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		var req struct {
			Content string `json:"content"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		rawContent = req.Content
	} else {
		defer func() { _ = r.Body.Close() }()
		bodyBytes, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 2<<20))
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to read request body")
			return
		}
		rawContent = string(bodyBytes)
	}

	entries, err := ParseDotEnv(rawContent)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	importedKeys := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !isValidSecretKey(entry.Key) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid secret key %q: must match ^[A-Za-z_][A-Za-z0-9_]*$", entry.Key))
			return
		}
	}
	for _, entry := range entries {
		ct, nonce, err := s.cipher.EncryptString(entry.Value)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to encrypt secret")
			return
		}
		if _, err := s.db.UpsertSecret(r.Context(), env.ID, entry.Key, ct, nonce, nil); err != nil {
			writeDBError(w, err)
			return
		}
		importedKeys = append(importedKeys, entry.Key)
		if s.notifier != nil {
			s.notifier.NotifySecretUpdatedAsync(proj.ID, proj.Name, env.ID, env.Name, entry.Key)
		}
	}

	principal, _ := PrincipalFromContext(r.Context())
	s.recordAudit(r.Context(), db.AuditLog{
		Event:     "secret.imported",
		Actor:     principal.ActorName(),
		IPAddress: clientIP(r),
		ProjectID: &proj.ID,
		EnvID:     &env.ID,
		TargetKey: fmt.Sprintf("%d keys", len(importedKeys)),
		Success:   true,
		Detail:    proj.Name + "/" + env.Name,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"imported": len(importedKeys),
		"keys":     importedKeys,
	})
}

func (s *Server) handleExportSecrets(w http.ResponseWriter, r *http.Request) {
	_, env, ok := s.authorizeEnvAccess(w, r, false)
	if !ok {
		return
	}

	secrets, err := s.db.ListSecrets(r.Context(), env.ID)
	if err != nil {
		writeDBError(w, err)
		return
	}

	entries := make([]DotEnvEntry, 0, len(secrets))
	for _, sec := range secrets {
		plaintext, err := s.cipher.DecryptString(sec.EncryptedValue, sec.Nonce)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to decrypt secret")
			return
		}
		entries = append(entries, DotEnvEntry{
			Key:   sec.Key,
			Value: plaintext,
		})
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", env.Name+".env"))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(FormatDotEnv(entries)))
}
