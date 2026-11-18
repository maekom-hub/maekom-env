package db

import "time"

// TokenScope defines the permission level of a service token.
type TokenScope string

const (
	ScopeRead  TokenScope = "read"
	ScopeWrite TokenScope = "write"
)

// WebhookType defines supported webhook notification channels.
type WebhookType string

const (
	WebhookDiscord WebhookType = "discord"
	WebhookSlack   WebhookType = "slack"
	WebhookEmail   WebhookType = "email"
	WebhookCustom  WebhookType = "custom"
)

// Project represents a secret management project.
type Project struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// Environment represents an environment within a project (e.g. local, dev, staging, prod).
type Environment struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
}

// Secret represents an encrypted key-value secret stored in an environment.
// Only ciphertext and its unique 12-byte AES-GCM nonce are stored in the database.
type Secret struct {
	ID             string     `json:"id"`
	EnvID          string     `json:"env_id"`
	Key            string     `json:"key"`
	EncryptedValue []byte     `json:"-"`
	Nonce          []byte     `json:"-"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	Notified7d     bool       `json:"notified_7d"`
	Notified1d     bool       `json:"notified_1d"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// ServiceToken represents a hashed API/CLI service token scoped to a project (and optionally an environment).
type ServiceToken struct {
	ID        string     `json:"id"`
	ProjectID string     `json:"project_id"`
	EnvID     *string    `json:"env_id,omitempty"`
	Name      string     `json:"name"`
	TokenHash string     `json:"-"`
	Scope     TokenScope `json:"scope"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// Webhook represents an outbound notification endpoint for secret lifecycle events.
type Webhook struct {
	ID        string      `json:"id"`
	ProjectID string      `json:"project_id"`
	EnvID     *string     `json:"env_id,omitempty"`
	Type      WebhookType `json:"type"`
	TargetURL string      `json:"target_url"`
	SecretKey string      `json:"-"`
	Events    string      `json:"events"`
	Enabled   bool        `json:"enabled"`
}
