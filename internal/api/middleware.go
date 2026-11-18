package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
)

type authContextKey struct{}

// AuthPrincipal represents the authenticated caller (either admin or a scoped service token).
type AuthPrincipal struct {
	IsAdmin      bool             `json:"is_admin"`
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

// PrincipalFromContext retrieves the AuthPrincipal from a request context.
func PrincipalFromContext(ctx context.Context) (AuthPrincipal, bool) {
	p, ok := ctx.Value(authContextKey{}).(AuthPrincipal)
	return p, ok
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, err := s.authenticateRequest(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
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

func (s *Server) authenticateRequest(r *http.Request) (AuthPrincipal, error) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader != "" {
		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			return AuthPrincipal{}, errors.New("invalid authorization header")
		}
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, bearerPrefix))
		if token == "" {
			return AuthPrincipal{}, errors.New("empty bearer token")
		}

		if strings.HasPrefix(token, serviceTokenPrefix) {
			return s.authenticateServiceToken(r.Context(), token)
		}

		if err := s.verifyAdminJWT(token); err != nil {
			return AuthPrincipal{}, errors.New("invalid or expired admin token")
		}
		return AuthPrincipal{IsAdmin: true}, nil
	}

	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		if err := s.verifyAdminJWT(cookie.Value); err != nil {
			return AuthPrincipal{}, errors.New("invalid or expired session")
		}
		return AuthPrincipal{IsAdmin: true}, nil
	}

	return AuthPrincipal{}, errors.New("authentication required")
}

func (s *Server) authenticateServiceToken(ctx context.Context, rawToken string) (AuthPrincipal, error) {
	hash := crypto.HashToken(rawToken)
	tok, err := s.db.GetServiceTokenByHash(ctx, hash)
	if err != nil {
		return AuthPrincipal{}, errors.New("invalid service token")
	}
	if tok.ExpiresAt != nil && time.Now().UTC().After(*tok.ExpiresAt) {
		return AuthPrincipal{}, errors.New("service token expired")
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
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

func (s *Server) issueAdminJWT(ttl time.Duration) (string, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(ttl)

	headerJSON, err := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	if err != nil {
		return "", time.Time{}, err
	}

	claimsJSON, err := json.Marshal(jwtClaims{
		Sub:  "admin",
		Role: "admin",
		Iat:  now.Unix(),
		Exp:  exp.Unix(),
	})
	if err != nil {
		return "", time.Time{}, err
	}

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(claimsJSON)

	mac := hmac.New(sha256.New, s.jwtSecret)
	_, _ = mac.Write([]byte(signingInput))
	sig := enc.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, exp, nil
}

func (s *Server) verifyAdminJWT(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("malformed jwt")
	}

	signingInput := parts[0] + "." + parts[1]
	enc := base64.RawURLEncoding

	gotSig, err := enc.DecodeString(parts[2])
	if err != nil {
		return errors.New("invalid jwt signature encoding")
	}

	mac := hmac.New(sha256.New, s.jwtSecret)
	_, _ = mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(gotSig, expectedSig) {
		return errors.New("invalid jwt signature")
	}

	headerBytes, err := enc.DecodeString(parts[0])
	if err != nil {
		return errors.New("invalid jwt header")
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Alg != "HS256" {
		return errors.New("unsupported jwt alg")
	}

	claimsBytes, err := enc.DecodeString(parts[1])
	if err != nil {
		return errors.New("invalid jwt claims")
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return errors.New("malformed jwt claims")
	}
	if claims.Role != "admin" || time.Now().UTC().Unix() >= claims.Exp {
		return errors.New("jwt expired or unauthorized")
	}
	return nil
}

func generateRandomSecret() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
