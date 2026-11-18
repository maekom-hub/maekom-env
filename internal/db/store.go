package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrNotFound is returned when a requested record does not exist.
	ErrNotFound = errors.New("db: record not found")

	// ErrConflict is returned when a unique constraint is violated.
	ErrConflict = errors.New("db: record already exists")
)

// NewID generates a random 16-byte hex identifier.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("db: generate id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// ExpiringSecret pairs an expiring secret with its project and environment names
// without decrypting or exposing the secret value.
type ExpiringSecret struct {
	SecretID        string
	ProjectID       string
	ProjectName     string
	EnvID           string
	EnvironmentName string
	Key             string
	ExpiresAt       time.Time
	Notified7d      bool
	Notified1d      bool
}

// CreateProject inserts a new project.
func (d *DB) CreateProject(ctx context.Context, name, description string) (Project, error) {
	id, err := NewID()
	if err != nil {
		return Project{}, err
	}
	now := time.Now().UTC()

	_, err = d.sqlDB.ExecContext(
		ctx,
		`INSERT INTO projects (id, name, description, created_at) VALUES (?, ?, ?, ?)`,
		id, name, description, now,
	)
	if err != nil {
		return Project{}, mapConstraintErr(err)
	}

	return Project{
		ID:          id,
		Name:        name,
		Description: description,
		CreatedAt:   now,
	}, nil
}

// GetProject fetches a project by ID.
func (d *DB) GetProject(ctx context.Context, id string) (Project, error) {
	var p Project
	err := d.sqlDB.QueryRowContext(
		ctx,
		`SELECT id, name, description, created_at FROM projects WHERE id = ?`,
		id,
	).Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, fmt.Errorf("db: get project: %w", err)
	}
	return p, nil
}

// ListProjects returns all projects ordered by creation time descending.
func (d *DB) ListProjects(ctx context.Context) ([]Project, error) {
	rows, err := d.sqlDB.QueryContext(
		ctx,
		`SELECT id, name, description, created_at FROM projects ORDER BY created_at DESC, name ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list projects: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Project
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan project: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdateProject updates a project's name and description.
func (d *DB) UpdateProject(ctx context.Context, id, name, description string) (Project, error) {
	res, err := d.sqlDB.ExecContext(
		ctx,
		`UPDATE projects SET name = ?, description = ? WHERE id = ?`,
		name, description, id,
	)
	if err != nil {
		return Project{}, mapConstraintErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Project{}, fmt.Errorf("db: update project rows: %w", err)
	}
	if n == 0 {
		return Project{}, ErrNotFound
	}
	return d.GetProject(ctx, id)
}

// DeleteProject deletes a project by ID.
func (d *DB) DeleteProject(ctx context.Context, id string) error {
	res, err := d.sqlDB.ExecContext(ctx, `DELETE FROM projects WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("db: delete project: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("db: delete project rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateEnvironment creates an environment inside a project.
func (d *DB) CreateEnvironment(ctx context.Context, projectID, name string) (Environment, error) {
	id, err := NewID()
	if err != nil {
		return Environment{}, err
	}

	_, err = d.sqlDB.ExecContext(
		ctx,
		`INSERT INTO environments (id, project_id, name) VALUES (?, ?, ?)`,
		id, projectID, name,
	)
	if err != nil {
		return Environment{}, mapConstraintErr(err)
	}

	return Environment{
		ID:        id,
		ProjectID: projectID,
		Name:      name,
	}, nil
}

// GetEnvironment fetches an environment by ID within a project.
func (d *DB) GetEnvironment(ctx context.Context, projectID, envID string) (Environment, error) {
	var env Environment
	err := d.sqlDB.QueryRowContext(
		ctx,
		`SELECT id, project_id, name FROM environments WHERE id = ? AND project_id = ?`,
		envID, projectID,
	).Scan(&env.ID, &env.ProjectID, &env.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return Environment{}, ErrNotFound
	}
	if err != nil {
		return Environment{}, fmt.Errorf("db: get environment: %w", err)
	}
	return env, nil
}

// ListEnvironments returns all environments for a project.
func (d *DB) ListEnvironments(ctx context.Context, projectID string) ([]Environment, error) {
	rows, err := d.sqlDB.QueryContext(
		ctx,
		`SELECT id, project_id, name FROM environments WHERE project_id = ? ORDER BY name ASC`,
		projectID,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list environments: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Environment
	for rows.Next() {
		var env Environment
		if err := rows.Scan(&env.ID, &env.ProjectID, &env.Name); err != nil {
			return nil, fmt.Errorf("db: scan environment: %w", err)
		}
		out = append(out, env)
	}
	return out, rows.Err()
}

// DeleteEnvironment deletes an environment inside a project.
func (d *DB) DeleteEnvironment(ctx context.Context, projectID, envID string) error {
	res, err := d.sqlDB.ExecContext(
		ctx,
		`DELETE FROM environments WHERE id = ? AND project_id = ?`,
		envID, projectID,
	)
	if err != nil {
		return fmt.Errorf("db: delete environment: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("db: delete environment rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpsertSecret inserts or updates an encrypted secret for an environment.
// Updating a secret resets notified_7d and notified_1d so new expiration windows trigger alerts.
func (d *DB) UpsertSecret(
	ctx context.Context,
	envID, key string,
	encryptedValue, nonce []byte,
	expiresAt *time.Time,
) (Secret, error) {
	id, err := NewID()
	if err != nil {
		return Secret{}, err
	}
	now := time.Now().UTC()

	var expVal any
	if expiresAt != nil {
		t := expiresAt.UTC()
		expVal = t
	}

	_, err = d.sqlDB.ExecContext(
		ctx,
		`INSERT INTO secrets (id, env_id, key, encrypted_value, nonce, expires_at, notified_7d, notified_1d, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?)
		 ON CONFLICT(env_id, key) DO UPDATE SET
			encrypted_value = excluded.encrypted_value,
			nonce = excluded.nonce,
			expires_at = excluded.expires_at,
			notified_7d = 0,
			notified_1d = 0,
			updated_at = excluded.updated_at`,
		id, envID, key, encryptedValue, nonce, expVal, now,
	)
	if err != nil {
		return Secret{}, mapConstraintErr(err)
	}

	return d.GetSecretByKey(ctx, envID, key)
}

// GetSecretByKey fetches an encrypted secret by environment ID and key.
func (d *DB) GetSecretByKey(ctx context.Context, envID, key string) (Secret, error) {
	var (
		s          Secret
		exp        sql.NullTime
		n7d, n1d   int
	)
	err := d.sqlDB.QueryRowContext(
		ctx,
		`SELECT id, env_id, key, encrypted_value, nonce, expires_at, notified_7d, notified_1d, updated_at
		 FROM secrets WHERE env_id = ? AND key = ?`,
		envID, key,
	).Scan(&s.ID, &s.EnvID, &s.Key, &s.EncryptedValue, &s.Nonce, &exp, &n7d, &n1d, &s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, ErrNotFound
	}
	if err != nil {
		return Secret{}, fmt.Errorf("db: get secret: %w", err)
	}
	if exp.Valid {
		t := exp.Time.UTC()
		s.ExpiresAt = &t
	}
	s.Notified7d = n7d != 0
	s.Notified1d = n1d != 0
	return s, nil
}

// ListSecrets returns all encrypted secrets in an environment ordered by key.
func (d *DB) ListSecrets(ctx context.Context, envID string) ([]Secret, error) {
	rows, err := d.sqlDB.QueryContext(
		ctx,
		`SELECT id, env_id, key, encrypted_value, nonce, expires_at, notified_7d, notified_1d, updated_at
		 FROM secrets WHERE env_id = ? ORDER BY key ASC`,
		envID,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list secrets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Secret
	for rows.Next() {
		var (
			s        Secret
			exp      sql.NullTime
			n7d, n1d int
		)
		if err := rows.Scan(&s.ID, &s.EnvID, &s.Key, &s.EncryptedValue, &s.Nonce, &exp, &n7d, &n1d, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("db: scan secret: %w", err)
		}
		if exp.Valid {
			t := exp.Time.UTC()
			s.ExpiresAt = &t
		}
		s.Notified7d = n7d != 0
		s.Notified1d = n1d != 0
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeleteSecretByKey removes a secret by environment ID and key.
func (d *DB) DeleteSecretByKey(ctx context.Context, envID, key string) error {
	res, err := d.sqlDB.ExecContext(
		ctx,
		`DELETE FROM secrets WHERE env_id = ? AND key = ?`,
		envID, key,
	)
	if err != nil {
		return fmt.Errorf("db: delete secret: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("db: delete secret rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListExpiringSecrets returns secrets whose expires_at is within 7 days of now
// and that still have pending D-7 or D-1 notifications.
func (d *DB) ListExpiringSecrets(ctx context.Context, now time.Time) ([]ExpiringSecret, error) {
	horizon := now.UTC().Add(7 * 24 * time.Hour)
	rows, err := d.sqlDB.QueryContext(
		ctx,
		`SELECT s.id, p.id, p.name, e.id, e.name, s.key, s.expires_at, s.notified_7d, s.notified_1d
		 FROM secrets s
		 JOIN environments e ON e.id = s.env_id
		 JOIN projects p ON p.id = e.project_id
		 WHERE s.expires_at IS NOT NULL
		   AND s.expires_at > ?
		   AND s.expires_at <= ?
		   AND (s.notified_7d = 0 OR s.notified_1d = 0)`,
		now.UTC(), horizon,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list expiring secrets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []ExpiringSecret
	for rows.Next() {
		var (
			item     ExpiringSecret
			n7d, n1d int
		)
		if err := rows.Scan(
			&item.SecretID,
			&item.ProjectID,
			&item.ProjectName,
			&item.EnvID,
			&item.EnvironmentName,
			&item.Key,
			&item.ExpiresAt,
			&n7d,
			&n1d,
		); err != nil {
			return nil, fmt.Errorf("db: scan expiring secret: %w", err)
		}
		item.ExpiresAt = item.ExpiresAt.UTC()
		item.Notified7d = n7d != 0
		item.Notified1d = n1d != 0
		out = append(out, item)
	}
	return out, rows.Err()
}

// MarkSecretNotified updates the D-7 and D-1 notification flags on a secret.
func (d *DB) MarkSecretNotified(ctx context.Context, secretID string, notified7d, notified1d bool) error {
	n7d := 0
	if notified7d {
		n7d = 1
	}
	n1d := 0
	if notified1d {
		n1d = 1
	}
	_, err := d.sqlDB.ExecContext(
		ctx,
		`UPDATE secrets SET notified_7d = ?, notified_1d = ? WHERE id = ?`,
		n7d, n1d, secretID,
	)
	if err != nil {
		return fmt.Errorf("db: mark secret notified: %w", err)
	}
	return nil
}

// CreateServiceToken stores a hashed service token.
func (d *DB) CreateServiceToken(
	ctx context.Context,
	projectID string,
	envID *string,
	name, tokenHash string,
	scope TokenScope,
	expiresAt *time.Time,
) (ServiceToken, error) {
	id, err := NewID()
	if err != nil {
		return ServiceToken{}, err
	}
	now := time.Now().UTC()

	var envVal any
	if envID != nil && *envID != "" {
		envVal = *envID
	}
	var expVal any
	if expiresAt != nil {
		t := expiresAt.UTC()
		expVal = t
	}

	_, err = d.sqlDB.ExecContext(
		ctx,
		`INSERT INTO service_tokens (id, project_id, env_id, name, token_hash, scope, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, projectID, envVal, name, tokenHash, string(scope), expVal, now,
	)
	if err != nil {
		return ServiceToken{}, mapConstraintErr(err)
	}

	return ServiceToken{
		ID:        id,
		ProjectID: projectID,
		EnvID:     envID,
		Name:      name,
		TokenHash: tokenHash,
		Scope:     scope,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}, nil
}

// GetServiceTokenByHash fetches a service token by its SHA-256 hex digest.
func (d *DB) GetServiceTokenByHash(ctx context.Context, tokenHash string) (ServiceToken, error) {
	var (
		tok   ServiceToken
		envID sql.NullString
		exp   sql.NullTime
		scope string
	)
	err := d.sqlDB.QueryRowContext(
		ctx,
		`SELECT id, project_id, env_id, name, token_hash, scope, expires_at, created_at
		 FROM service_tokens WHERE token_hash = ?`,
		tokenHash,
	).Scan(&tok.ID, &tok.ProjectID, &envID, &tok.Name, &tok.TokenHash, &scope, &exp, &tok.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ServiceToken{}, ErrNotFound
	}
	if err != nil {
		return ServiceToken{}, fmt.Errorf("db: get service token: %w", err)
	}
	if envID.Valid {
		v := envID.String
		tok.EnvID = &v
	}
	if exp.Valid {
		t := exp.Time.UTC()
		tok.ExpiresAt = &t
	}
	tok.Scope = TokenScope(scope)
	return tok, nil
}

// ListServiceTokens returns all service tokens for a project.
func (d *DB) ListServiceTokens(ctx context.Context, projectID string) ([]ServiceToken, error) {
	rows, err := d.sqlDB.QueryContext(
		ctx,
		`SELECT id, project_id, env_id, name, token_hash, scope, expires_at, created_at
		 FROM service_tokens WHERE project_id = ? ORDER BY created_at DESC`,
		projectID,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list service tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []ServiceToken
	for rows.Next() {
		var (
			tok   ServiceToken
			envID sql.NullString
			exp   sql.NullTime
			scope string
		)
		if err := rows.Scan(&tok.ID, &tok.ProjectID, &envID, &tok.Name, &tok.TokenHash, &scope, &exp, &tok.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan service token: %w", err)
		}
		if envID.Valid {
			v := envID.String
			tok.EnvID = &v
		}
		if exp.Valid {
			t := exp.Time.UTC()
			tok.ExpiresAt = &t
		}
		tok.Scope = TokenScope(scope)
		out = append(out, tok)
	}
	return out, rows.Err()
}

// DeleteServiceToken revokes a service token by ID within a project.
func (d *DB) DeleteServiceToken(ctx context.Context, projectID, tokenID string) error {
	res, err := d.sqlDB.ExecContext(
		ctx,
		`DELETE FROM service_tokens WHERE id = ? AND project_id = ?`,
		tokenID, projectID,
	)
	if err != nil {
		return fmt.Errorf("db: delete service token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("db: delete service token rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateWebhook registers a new webhook for a project (and optionally an environment).
func (d *DB) CreateWebhook(
	ctx context.Context,
	projectID string,
	envID *string,
	wType WebhookType,
	targetURL, secretKey, events string,
	enabled bool,
) (Webhook, error) {
	id, err := NewID()
	if err != nil {
		return Webhook{}, err
	}

	var envVal any
	if envID != nil && *envID != "" {
		envVal = *envID
	}
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}

	_, err = d.sqlDB.ExecContext(
		ctx,
		`INSERT INTO webhooks (id, project_id, env_id, type, target_url, secret_key, events, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, projectID, envVal, string(wType), targetURL, secretKey, events, enabledInt,
	)
	if err != nil {
		return Webhook{}, mapConstraintErr(err)
	}

	return Webhook{
		ID:        id,
		ProjectID: projectID,
		EnvID:     envID,
		Type:      wType,
		TargetURL: targetURL,
		SecretKey: secretKey,
		Events:    events,
		Enabled:   enabled,
	}, nil
}

// GetWebhook fetches a webhook by ID within a project.
func (d *DB) GetWebhook(ctx context.Context, projectID, webhookID string) (Webhook, error) {
	var (
		w       Webhook
		envID   sql.NullString
		wType   string
		enabled int
	)
	err := d.sqlDB.QueryRowContext(
		ctx,
		`SELECT id, project_id, env_id, type, target_url, secret_key, events, enabled
		 FROM webhooks WHERE id = ? AND project_id = ?`,
		webhookID, projectID,
	).Scan(&w.ID, &w.ProjectID, &envID, &wType, &w.TargetURL, &w.SecretKey, &w.Events, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return Webhook{}, ErrNotFound
	}
	if err != nil {
		return Webhook{}, fmt.Errorf("db: get webhook: %w", err)
	}
	if envID.Valid {
		v := envID.String
		w.EnvID = &v
	}
	w.Type = WebhookType(wType)
	w.Enabled = enabled != 0
	return w, nil
}

// ListWebhooks returns all webhooks configured for a project.
func (d *DB) ListWebhooks(ctx context.Context, projectID string) ([]Webhook, error) {
	rows, err := d.sqlDB.QueryContext(
		ctx,
		`SELECT id, project_id, env_id, type, target_url, secret_key, events, enabled
		 FROM webhooks WHERE project_id = ? ORDER BY id ASC`,
		projectID,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list webhooks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanWebhooks(rows)
}

// ListActiveWebhooksForEnv returns enabled webhooks matching the project and either the specific env or project-wide (env_id IS NULL).
func (d *DB) ListActiveWebhooksForEnv(ctx context.Context, projectID, envID string) ([]Webhook, error) {
	rows, err := d.sqlDB.QueryContext(
		ctx,
		`SELECT id, project_id, env_id, type, target_url, secret_key, events, enabled
		 FROM webhooks
		 WHERE project_id = ?
		   AND enabled = 1
		   AND (env_id IS NULL OR env_id = ?)`,
		projectID, envID,
	)
	if err != nil {
		return nil, fmt.Errorf("db: list active webhooks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanWebhooks(rows)
}

// DeleteWebhook deletes a webhook by ID within a project.
func (d *DB) DeleteWebhook(ctx context.Context, projectID, webhookID string) error {
	res, err := d.sqlDB.ExecContext(
		ctx,
		`DELETE FROM webhooks WHERE id = ? AND project_id = ?`,
		webhookID, projectID,
	)
	if err != nil {
		return fmt.Errorf("db: delete webhook: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("db: delete webhook rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanWebhooks(rows *sql.Rows) ([]Webhook, error) {
	var out []Webhook
	for rows.Next() {
		var (
			w       Webhook
			envID   sql.NullString
			wType   string
			enabled int
		)
		if err := rows.Scan(&w.ID, &w.ProjectID, &envID, &wType, &w.TargetURL, &w.SecretKey, &w.Events, &enabled); err != nil {
			return nil, fmt.Errorf("db: scan webhook: %w", err)
		}
		if envID.Valid {
			v := envID.String
			w.EnvID = &v
		}
		w.Type = WebhookType(wType)
		w.Enabled = enabled != 0
		out = append(out, w)
	}
	return out, rows.Err()
}

func mapConstraintErr(err error) error {
	msg := err.Error()
	if strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "PRIMARY KEY constraint failed") {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	if strings.Contains(msg, "FOREIGN KEY constraint failed") {
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	return err
}
