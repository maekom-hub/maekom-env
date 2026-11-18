package db

import (
	"context"
	"database/sql"
	"fmt"
)

type migration struct {
	version int
	name    string
	sql     string
}

var migrations = []migration{
	{
		version: 1,
		name:    "initial_schema",
		sql: `
CREATE TABLE IF NOT EXISTS projects (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS environments (
	id TEXT PRIMARY KEY,
	project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	UNIQUE(project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_environments_project_id ON environments(project_id);

CREATE TABLE IF NOT EXISTS secrets (
	id TEXT PRIMARY KEY,
	env_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
	key TEXT NOT NULL,
	encrypted_value BLOB NOT NULL,
	nonce BLOB NOT NULL,
	expires_at DATETIME,
	notified_7d INTEGER NOT NULL DEFAULT 0,
	notified_1d INTEGER NOT NULL DEFAULT 0,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(env_id, key)
);

CREATE INDEX IF NOT EXISTS idx_secrets_env_id ON secrets(env_id);
CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets(expires_at);

CREATE TABLE IF NOT EXISTS service_tokens (
	id TEXT PRIMARY KEY,
	project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
	env_id TEXT REFERENCES environments(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	token_hash TEXT NOT NULL UNIQUE,
	scope TEXT NOT NULL CHECK (scope IN ('read', 'write')),
	expires_at DATETIME,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_service_tokens_project_id ON service_tokens(project_id);

CREATE TABLE IF NOT EXISTS webhooks (
	id TEXT PRIMARY KEY,
	project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
	env_id TEXT REFERENCES environments(id) ON DELETE CASCADE,
	type TEXT NOT NULL CHECK (type IN ('discord', 'slack', 'email', 'custom')),
	target_url TEXT NOT NULL,
	secret_key TEXT NOT NULL DEFAULT '',
	events TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_webhooks_project_id ON webhooks(project_id);
`,
	},
	{
		version: 2,
		name:    "audit_logs_and_token_ip_restriction",
		sql: `
ALTER TABLE service_tokens ADD COLUMN allowed_ips TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS audit_logs (
	id TEXT PRIMARY KEY,
	event TEXT NOT NULL,
	actor TEXT NOT NULL,
	ip_address TEXT NOT NULL DEFAULT '',
	project_id TEXT,
	env_id TEXT,
	target_key TEXT NOT NULL DEFAULT '',
	success INTEGER NOT NULL DEFAULT 1,
	detail TEXT NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_project_id ON audit_logs(project_id);
`,
	},
}

// Migrate applies any pending schema migrations inside transactions.
func (d *DB) Migrate(ctx context.Context) error {
	if _, err := d.sqlDB.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`); err != nil {
		return fmt.Errorf("db: create schema_migrations table: %w", err)
	}

	for _, m := range migrations {
		applied, err := d.isMigrationApplied(ctx, m.version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}

		if err := d.applyMigration(ctx, m); err != nil {
			return err
		}
	}

	return nil
}

func (d *DB) isMigrationApplied(ctx context.Context, version int) (bool, error) {
	var count int
	err := d.sqlDB.QueryRowContext(
		ctx,
		`SELECT COUNT(1) FROM schema_migrations WHERE version = ?`,
		version,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("db: check migration %d: %w", version, err)
	}
	return count > 0, nil
}

func (d *DB) applyMigration(ctx context.Context, m migration) error {
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("db: begin migration %d (%s): %w", m.version, m.name, err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return fmt.Errorf("db: exec migration %d (%s): %w", m.version, m.name, err)
	}

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO schema_migrations (version, name) VALUES (?, ?)`,
		m.version,
		m.name,
	); err != nil {
		return fmt.Errorf("db: record migration %d (%s): %w", m.version, m.name, err)
	}

	if err := tx.Commit(); err != nil && err != sql.ErrTxDone {
		return fmt.Errorf("db: commit migration %d (%s): %w", m.version, m.name, err)
	}

	return nil
}
