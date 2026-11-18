package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

const (
	// DefaultBusyTimeoutMs is the SQLite busy timeout in milliseconds.
	DefaultBusyTimeoutMs = 5000

	// DefaultJournalMode is the SQLite journal mode used for concurrency.
	DefaultJournalMode = "WAL"
)

// DB wraps a SQLite database connection pool configured for concurrent WAL access.
type DB struct {
	sqlDB *sql.DB
}

// Open opens a SQLite database using the pure-Go modernc.org/sqlite driver,
// applies WAL mode and busy_timeout PRAGMAs, and runs automatic schema migrations.
func Open(ctx context.Context, dsn string) (*DB, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("db: dsn must not be empty")
	}

	configuredDSN := withDefaultPragmas(dsn)
	sqlDB, err := sql.Open("sqlite", configuredDSN)
	if err != nil {
		return nil, fmt.Errorf("db: open sqlite: %w", err)
	}

	// Keep a single connection or bounded pool; DSN pragmas apply to every connection opened.
	sqlDB.SetMaxOpenConns(1)

	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("db: ping sqlite: %w", err)
	}

	// Explicitly execute PRAGMAs as required so WAL and busy_timeout are guaranteed active.
	if _, err := sqlDB.ExecContext(ctx, "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;"); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("db: apply pragmas: %w", err)
	}

	store := &DB{sqlDB: sqlDB}
	if err := store.Migrate(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}

	return store, nil
}

// SQL returns the underlying *sql.DB handle.
func (d *DB) SQL() *sql.DB {
	return d.sqlDB
}

// Close closes the underlying database connection pool.
func (d *DB) Close() error {
	if d == nil || d.sqlDB == nil {
		return nil
	}
	return d.sqlDB.Close()
}

// JournalMode queries the active SQLite journal_mode PRAGMA.
func (d *DB) JournalMode(ctx context.Context) (string, error) {
	var mode string
	if err := d.sqlDB.QueryRowContext(ctx, "PRAGMA journal_mode;").Scan(&mode); err != nil {
		return "", fmt.Errorf("db: query journal_mode: %w", err)
	}
	return mode, nil
}

// BusyTimeout queries the active SQLite busy_timeout PRAGMA in milliseconds.
func (d *DB) BusyTimeout(ctx context.Context) (int, error) {
	var timeout int
	if err := d.sqlDB.QueryRowContext(ctx, "PRAGMA busy_timeout;").Scan(&timeout); err != nil {
		return 0, fmt.Errorf("db: query busy_timeout: %w", err)
	}
	return timeout, nil
}

func withDefaultPragmas(dsn string) string {
	pragmas := []string{
		"_pragma=journal_mode(WAL)",
		"_pragma=busy_timeout(5000)",
		"_pragma=foreign_keys(ON)",
	}

	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}

	return dsn + sep + strings.Join(pragmas, "&")
}
