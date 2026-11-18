package db

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maekom-hub/maekom-env/internal/crypto"
)

func TestOpenPragmasAndMigrations(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "maekom-test.db")

	store, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

	mode, err := store.JournalMode(ctx)
	if err != nil {
		t.Fatalf("JournalMode failed: %v", err)
	}
	if !strings.EqualFold(mode, "wal") {
		t.Fatalf("expected journal_mode=wal, got %q", mode)
	}

	timeout, err := store.BusyTimeout(ctx)
	if err != nil {
		t.Fatalf("BusyTimeout failed: %v", err)
	}
	if timeout != DefaultBusyTimeoutMs {
		t.Fatalf("expected busy_timeout=%d, got %d", DefaultBusyTimeoutMs, timeout)
	}

	// Verify all required tables and their columns exist.
	expectedTables := map[string][]string{
		"projects":       {"id", "name", "description", "created_at"},
		"environments":   {"id", "project_id", "name"},
		"secrets":        {"id", "env_id", "key", "encrypted_value", "nonce", "expires_at", "notified_7d", "notified_1d", "updated_at"},
		"service_tokens": {"id", "project_id", "env_id", "name", "token_hash", "scope", "expires_at", "created_at"},
		"webhooks":       {"id", "project_id", "env_id", "type", "target_url", "secret_key", "events", "enabled"},
	}

	for table, cols := range expectedTables {
		actualCols := tableColumns(t, ctx, store, table)
		for _, col := range cols {
			if !actualCols[col] {
				t.Fatalf("table %q missing expected column %q", table, col)
			}
		}
	}

	// Re-running Migrate must be idempotent.
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("idempotent Migrate failed: %v", err)
	}
}

func TestSchemaConstraintsAndEncryptedSecretRoundTrip(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "maekom-roundtrip.db")

	store, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

	cipher, err := crypto.NewCipherFromMasterKey("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewCipherFromMasterKey failed: %v", err)
	}

	sqlDB := store.SQL()

	if _, err := sqlDB.ExecContext(ctx,
		`INSERT INTO projects (id, name, description) VALUES (?, ?, ?)`,
		"proj_1", "maekom", "test project",
	); err != nil {
		t.Fatalf("insert project failed: %v", err)
	}

	if _, err := sqlDB.ExecContext(ctx,
		`INSERT INTO environments (id, project_id, name) VALUES (?, ?, ?)`,
		"env_1", "proj_1", "prod",
	); err != nil {
		t.Fatalf("insert environment failed: %v", err)
	}

	ciphertext, nonce, err := cipher.EncryptString("postgres://secret-pass")
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}

	if _, err := sqlDB.ExecContext(ctx,
		`INSERT INTO secrets (id, env_id, key, encrypted_value, nonce) VALUES (?, ?, ?, ?, ?)`,
		"sec_1", "env_1", "DATABASE_URL", ciphertext, nonce,
	); err != nil {
		t.Fatalf("insert secret failed: %v", err)
	}

	var storedCipher, storedNonce []byte
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT encrypted_value, nonce FROM secrets WHERE id = ?`,
		"sec_1",
	).Scan(&storedCipher, &storedNonce); err != nil {
		t.Fatalf("select secret failed: %v", err)
	}

	decrypted, err := cipher.DecryptString(storedCipher, storedNonce)
	if err != nil {
		t.Fatalf("DecryptString failed: %v", err)
	}
	if decrypted != "postgres://secret-pass" {
		t.Fatalf("got %q, want %q", decrypted, "postgres://secret-pass")
	}

	// Verify CHECK constraint on service_tokens.scope.
	if _, err := sqlDB.ExecContext(ctx,
		`INSERT INTO service_tokens (id, project_id, env_id, name, token_hash, scope) VALUES (?, ?, ?, ?, ?, ?)`,
		"tok_1", "proj_1", "env_1", "ci", crypto.HashToken("mkv_secret"), "admin",
	); err == nil {
		t.Fatal("expected CHECK constraint error for invalid token scope 'admin'")
	}

	// Verify CHECK constraint on webhooks.type.
	if _, err := sqlDB.ExecContext(ctx,
		`INSERT INTO webhooks (id, project_id, env_id, type, target_url) VALUES (?, ?, ?, ?, ?)`,
		"wh_1", "proj_1", "env_1", "sms", "https://example.com/hook",
	); err == nil {
		t.Fatal("expected CHECK constraint error for invalid webhook type 'sms'")
	}

	// Verify ON DELETE CASCADE removes child environments and secrets.
	if _, err := sqlDB.ExecContext(ctx, `DELETE FROM projects WHERE id = ?`, "proj_1"); err != nil {
		t.Fatalf("delete project failed: %v", err)
	}

	var secretCount int
	if err := sqlDB.QueryRowContext(ctx, `SELECT COUNT(1) FROM secrets`).Scan(&secretCount); err != nil {
		t.Fatalf("count secrets failed: %v", err)
	}
	if secretCount != 0 {
		t.Fatalf("expected 0 secrets after cascade delete, got %d", secretCount)
	}
}

func tableColumns(t *testing.T, ctx context.Context, store *DB, table string) map[string]bool {
	t.Helper()

	rows, err := store.SQL().QueryContext(ctx, "PRAGMA table_info("+table+");")
	if err != nil {
		t.Fatalf("PRAGMA table_info(%s) failed: %v", table, err)
	}
	defer func() {
		_ = rows.Close()
	}()

	cols := make(map[string]bool)
	for rows.Next() {
		var (
			cid       int
			name      string
			colType   string
			notNull   int
			dfltValue any
			pk        int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan table_info(%s): %v", table, err)
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows error table_info(%s): %v", table, err)
	}
	return cols
}
