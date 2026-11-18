package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/maekom-hub/maekom-env/internal/crypto"
	"github.com/maekom-hub/maekom-env/internal/db"
)

const (
	sessionCookieName  = "maekom_session"
	serviceTokenPrefix = "mkv_"
	defaultJWTTTL      = 24 * time.Hour

	roleAdmin      = "admin"
	roleTOTPSetup  = "totp_setup"
	roleTOTPVerify = "totp_verify"
)

type authContextKey struct{}

// AuthPrincipal represents the authenticated caller (either admin or a scoped service token).
type AuthPrincipal struct {
	IsAdmin      bool             `json:"is_admin"`
	SessionID    string           `json:"-"`
	ServiceToken *db.ServiceToken `json:"service_token,omitempty"`
}

// CanAccessProject checks whether the caller is allowed to access the given project.
func (p AuthPrincipal) CanAccessProject(projectID string) bool {
	if p.IsAdmin {
		return true
	}
	return p.ServiceToken != nil && p.ServiceToken.ProjectID == projectID
}

// CanAccessEnv checks whether the caller is allowed to access the given project and environment.
func (p AuthPrincipal) CanAccessEnv(projectID, envID string) bool {
	if p.IsAdmin {
		return true
	}
	if p.ServiceToken == nil || p.ServiceToken.ProjectID != projectID {
		return false
	}
	if p.ServiceToken.EnvID != nil && *p.ServiceToken.EnvID != envID {
		return false
	}
	return true
}

// CanWrite checks whether the caller has write permission.
func (p AuthPrincipal) CanWrite() bool {
	if p.IsAdmin {
		return true
	}
	return p.ServiceToken != nil && p.ServiceToken.Scope == db.ScopeWrite
}

// ActorName returns a human-readable actor identifier for audit logs.
func (p AuthPrincipal) ActorName() string {
	if p.IsAdmin {
		return "admin"
	}
	if p.ServiceToken != nil {
		return "token:" + p.ServiceToken.Name
	}
	return "unknown"
}

// PrincipalFromContext retrieves the AuthPrincipal from a request context.
func PrincipalFromContext(ctx context.Context) (AuthPrincipal, bool) {
	p, ok := ctx.Value(authContextKey{}).(AuthPrincipal)
	return p, ok
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, renewedExp, usedCookie, err := s.authenticateRequest(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		if usedCookie && !renewedExp.IsZero() {
			if cookie, err := r.Cookie(sessionCookieName); err == nil {
				s.setSessionCookie(w, cookie.Value, renewedExp)
			}
		}
		ctx := context.WithValue(r.Context(), authContextKey{}, principal)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())
		if !ok || !principal.IsAdmin {
			writeError(w, http.StatusForbidden, "admin privileges required")
			return
		}
		next(w, r)
	})
}

func (s *Server) authenticateRequest(r *http.Request) (AuthPrincipal, time.Time, bool, error) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader != "" {
		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			return AuthPrincipal{}, time.Time{}, false, errors.New("invalid authorization header")
		}
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, bearerPrefix))
		if token == "" {
			return AuthPrincipal{}, time.Time{}, false, errors.New("empty bearer token")
		}

		if strings.HasPrefix(token, serviceTokenPrefix) {
			p, err := s.authenticateServiceToken(r.Context(), token, clientIP(r))
			return p, time.Time{}, false, err
		}

		claims, err := s.verifyAdminJWT(token)
		if err != nil {
			return AuthPrincipal{}, time.Time{}, false, errors.New("invalid or expired admin token")
		}
		exp, ok := s.sessions.touch(claims.JTI)
		if !ok {
			return AuthPrincipal{}, time.Time{}, false, errors.New("session expired due to inactivity")
		}
		return AuthPrincipal{IsAdmin: true, SessionID: claims.JTI}, exp, false, nil
	}

	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		claims, err := s.verifyAdminJWT(cookie.Value)
		if err != nil {
			return AuthPrincipal{}, time.Time{}, false, errors.New("invalid or expired session")
		}
		exp, ok := s.sessions.touch(claims.JTI)
		if !ok {
			return AuthPrincipal{}, time.Time{}, false, errors.New("session expired due to inactivity")
		}
		return AuthPrincipal{IsAdmin: true, SessionID: claims.JTI}, exp, true, nil
	}

	return AuthPrincipal{}, time.Time{}, false, errors.New("authentication required")
}

func (s *Server) authenticateServiceToken(ctx context.Context, rawToken, ip string) (AuthPrincipal, error) {
	hash := crypto.HashToken(rawToken)
	tok, err := s.db.GetServiceTokenByHash(ctx, hash)
	if err != nil {
		return AuthPrincipal{}, errors.New("invalid service token")
	}
	if tok.ExpiresAt != nil && time.Now().UTC().After(*tok.ExpiresAt) {
		return AuthPrincipal{}, errors.New("service token expired")
	}
	if !isIPAllowed(tok.AllowedIPs, ip) {
		return AuthPrincipal{}, errors.New("service token IP not allowed")
	}
	return AuthPrincipal{
		IsAdmin:      false,
		ServiceToken: &tok,
	}, nil
}

func (s *Server) verifyAdminPassword(candidate string) bool {
	if s.adminPassword == "" || candidate == "" {
		return false
	}
	expectedHash := sha256.Sum256([]byte(s.adminPassword))
	candidateHash := sha256.Sum256([]byte(candidate))
	return hmac.Equal(expectedHash[:], candidateHash[:])
}

type jwtClaims struct {
	JTI  string `json:"jti"`
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

func (s *Server) issueAdminJWT(ttl time.Duration) (token string, sessionID string, idleExp time.Time, err error) {
	token, sessionID, err = s.issueSignedJWT(roleAdmin, ttl)
	if err != nil {
		return "", "", time.Time{}, err
	}
	idleExp = s.sessions.create(sessionID)
	return token, sessionID, idleExp, nil
}

func (s *Server) issuePendingJWT(role string, ttl time.Duration) (string, string, error) {
	return s.issueSignedJWT(role, ttl)
}

func (s *Server) issueSignedJWT(role string, ttl time.Duration) (string, string, error) {
	now := time.Now().UTC()
	exp := now.Add(ttl)

	var jtiBytes [16]byte
	if _, err := rand.Read(jtiBytes[:]); err != nil {
		return "", "", err
	}
	jti := hex.EncodeToString(jtiBytes[:])

	headerJSON, err := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	if err != nil {
		return "", "", err
	}

	claimsJSON, err := json.Marshal(jwtClaims{
		JTI:  jti,
		Sub:  "admin",
		Role: role,
		Iat:  now.Unix(),
		Exp:  exp.Unix(),
	})
	if err != nil {
		return "", "", err
	}

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(claimsJSON)

	mac := hmac.New(sha256.New, s.jwtSecret)
	_, _ = mac.Write([]byte(signingInput))
	sig := enc.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, jti, nil
}

func (s *Server) verifyAdminJWT(token string) (jwtClaims, error) {
	return s.verifySignedJWT(token, roleAdmin)
}

func (s *Server) verifyPendingJWT(token, expectedRole string) (jwtClaims, error) {
	return s.verifySignedJWT(token, expectedRole)
}

func (s *Server) verifySignedJWT(token, expectedRole string) (jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwtClaims{}, errors.New("malformed jwt")
	}

	signingInput := parts[0] + "." + parts[1]
	enc := base64.RawURLEncoding

	gotSig, err := enc.DecodeString(parts[2])
	if err != nil {
		return jwtClaims{}, errors.New("invalid jwt signature encoding")
	}

	mac := hmac.New(sha256.New, s.jwtSecret)
	_, _ = mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(gotSig, expectedSig) {
		return jwtClaims{}, errors.New("invalid jwt signature")
	}

	headerBytes, err := enc.DecodeString(parts[0])
	if err != nil {
		return jwtClaims{}, errors.New("invalid jwt header")
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Alg != "HS256" {
		return jwtClaims{}, errors.New("unsupported jwt alg")
	}

	claimsBytes, err := enc.DecodeString(parts[1])
	if err != nil {
		return jwtClaims{}, errors.New("invalid jwt claims")
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return jwtClaims{}, errors.New("malformed jwt claims")
	}
	if claims.Role != expectedRole || claims.JTI == "" || time.Now().UTC().Unix() >= claims.Exp {
		return jwtClaims{}, errors.New("jwt expired or unauthorized")
	}
	return claims, nil
}

func (s *Server) setSessionCookie(w http.ResponseWriter, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(s.sessions.idleTimeout.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func generateRandomSecret() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
