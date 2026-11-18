package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/maekom-hub/maekom-env/internal/db"
)

func (s *Server) resolveActiveTOTPSecret(ctx context.Context) (string, bool) {
	if s.db != nil && s.cipher != nil {
		rec, err := s.db.GetAdminTOTP(ctx)
		if err == nil && rec.Enabled {
			secret, err := s.cipher.DecryptString(rec.EncryptedSecret, rec.Nonce)
			if err == nil && secret != "" {
				return secret, true
			}
		}
	}
	if s.totpSecret != "" {
		return s.totpSecret, true
	}
	return "", false
}

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if blocked, retryAfter := s.limiter.isBlocked(ip); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too many failed attempts; try again later")
		return
	}

	var req struct {
		TempToken string `json:"temp_token"`
		TOTPCode  string `json:"totp_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	claims, err := s.verifyPendingJWT(req.TempToken, roleTOTPSetup)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired 2FA setup token")
		return
	}

	secret, ok := s.pendingSetup.get(claims.JTI)
	if !ok {
		writeError(w, http.StatusUnauthorized, "2FA setup session expired; please log in again")
		return
	}

	if !verifyTOTP(secret, req.TOTPCode, time.Now().UTC()) {
		blockedNow := s.limiter.recordFailure(ip)
		s.recordAudit(r.Context(), db.AuditLog{
			Event:     "auth.totp_setup",
			Actor:     "admin",
			IPAddress: ip,
			Success:   false,
			Detail:    "invalid setup TOTP code",
		})
		if blockedNow {
			w.Header().Set("Retry-After", strconv.Itoa(int(loginBlockDuration.Seconds())))
			writeError(w, http.StatusTooManyRequests, "too many failed attempts; try again later")
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	s.pendingSetup.consume(claims.JTI)

	ct, nonce, err := s.cipher.EncryptString(secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to encrypt TOTP secret")
		return
	}
	if err := s.db.UpsertAdminTOTP(r.Context(), ct, nonce, true); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to persist TOTP configuration")
		return
	}

	s.recordAudit(r.Context(), db.AuditLog{
		Event:     "auth.totp_setup",
		Actor:     "admin",
		IPAddress: ip,
		Success:   true,
		Detail:    "2FA TOTP enabled",
	})

	s.completeAdminLogin(w, r, ip, "admin login succeeded (2FA setup completed)")
}

func (s *Server) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if blocked, retryAfter := s.limiter.isBlocked(ip); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too many failed attempts; try again later")
		return
	}

	var req struct {
		TempToken string `json:"temp_token"`
		TOTPCode  string `json:"totp_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	claims, err := s.verifyPendingJWT(req.TempToken, roleTOTPVerify)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired 2FA verification token")
		return
	}

	if _, ok := s.pendingVerify.get(claims.JTI); !ok {
		writeError(w, http.StatusUnauthorized, "2FA verification session expired; please log in again")
		return
	}

	activeSecret, configured := s.resolveActiveTOTPSecret(r.Context())
	if !configured {
		writeError(w, http.StatusBadRequest, "2FA is not configured")
		return
	}

	if !verifyTOTP(activeSecret, req.TOTPCode, time.Now().UTC()) {
		blockedNow := s.limiter.recordFailure(ip)
		s.recordAudit(r.Context(), db.AuditLog{
			Event:     "auth.totp_verify",
			Actor:     "admin",
			IPAddress: ip,
			Success:   false,
			Detail:    "invalid TOTP code",
		})
		if blockedNow {
			w.Header().Set("Retry-After", strconv.Itoa(int(loginBlockDuration.Seconds())))
			writeError(w, http.StatusTooManyRequests, "too many failed attempts; try again later")
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	s.pendingVerify.consume(claims.JTI)
	s.completeAdminLogin(w, r, ip, "admin login succeeded (2FA verified)")
}

func (s *Server) handleSettingsTOTPBegin(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok || !principal.IsAdmin || principal.SessionID == "" {
		writeError(w, http.StatusForbidden, "admin session required")
		return
	}

	var req struct {
		Password        string `json:"password"`
		CurrentTOTPCode string `json:"current_totp_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	reverified := false
	if req.Password != "" && s.verifyAdminPassword(req.Password) {
		reverified = true
	} else if strings.TrimSpace(req.CurrentTOTPCode) != "" {
		if activeSecret, configured := s.resolveActiveTOTPSecret(r.Context()); configured {
			if verifyTOTP(activeSecret, req.CurrentTOTPCode, time.Now().UTC()) {
				reverified = true
			}
		}
	}

	if !reverified {
		s.recordAudit(r.Context(), db.AuditLog{
			Event:     "auth.totp_reset_begin",
			Actor:     "admin",
			IPAddress: clientIP(r),
			Success:   false,
			Detail:    "re-verification failed",
		})
		writeError(w, http.StatusUnauthorized, "current password or valid TOTP code is required")
		return
	}

	newSecret, err := generateTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate TOTP secret")
		return
	}

	s.pendingReset.set(principal.SessionID, newSecret, 10*time.Minute)

	writeJSON(w, http.StatusOK, map[string]any{
		"secret":      newSecret,
		"otpauth_uri": buildOTPAuthURI("maekom-env", "admin", newSecret),
	})
}

func (s *Server) handleSettingsTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok || !principal.IsAdmin || principal.SessionID == "" {
		writeError(w, http.StatusForbidden, "admin session required")
		return
	}

	var req struct {
		TOTPCode string `json:"totp_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	newSecret, ok := s.pendingReset.get(principal.SessionID)
	if !ok {
		writeError(w, http.StatusBadRequest, "no pending OTP reset found; please restart OTP setup")
		return
	}

	if !verifyTOTP(newSecret, req.TOTPCode, time.Now().UTC()) {
		s.recordAudit(r.Context(), db.AuditLog{
			Event:     "auth.totp_reset",
			Actor:     "admin",
			IPAddress: clientIP(r),
			Success:   false,
			Detail:    "invalid new TOTP code",
		})
		writeError(w, http.StatusUnauthorized, "invalid TOTP code")
		return
	}

	s.pendingReset.consume(principal.SessionID)

	ct, nonce, err := s.cipher.EncryptString(newSecret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to encrypt TOTP secret")
		return
	}
	if err := s.db.UpsertAdminTOTP(r.Context(), ct, nonce, true); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save new TOTP secret")
		return
	}

	s.recordAudit(r.Context(), db.AuditLog{
		Event:     "auth.totp_reset",
		Actor:     "admin",
		IPAddress: clientIP(r),
		Success:   true,
		Detail:    "admin 2FA TOTP secret rotated",
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "totp_updated"})
}
