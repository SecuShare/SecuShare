package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func Initialize(dbPath string) (*sql.DB, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	// SQLite handles concurrency differently, but we still set reasonable limits
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(10 * time.Minute)

	const maxPingAttempts = 5
	pingDelay := 200 * time.Millisecond
	var pingErr error
	for attempt := 1; attempt <= maxPingAttempts; attempt++ {
		pingErr = db.Ping()
		if pingErr == nil {
			break
		}
		if attempt < maxPingAttempts {
			time.Sleep(pingDelay)
			if pingDelay < 2*time.Second {
				pingDelay *= 2
			}
		}
	}
	if pingErr != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database after %d attempts: %w", maxPingAttempts, pingErr)
	}

	// Enable foreign key enforcement (SQLite has this off by default)
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Enable WAL mode for better concurrent read/write performance
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	// Wait up to 5 seconds when the database is locked by another writer
	// instead of failing immediately with SQLITE_BUSY.
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		return nil, fmt.Errorf("failed to set busy_timeout: %w", err)
	}

	return db, nil
}

// InitSchema creates all tables and indexes. Safe to call on every startup
// because every statement uses IF NOT EXISTS.
func InitSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			opaque_record BLOB NOT NULL,
			storage_quota_bytes INTEGER DEFAULT 1073741824,
			storage_used_bytes INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			is_email_verified INTEGER DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS guest_sessions (
			id TEXT PRIMARY KEY,
			storage_quota_bytes INTEGER DEFAULT 10485760,
			storage_used_bytes INTEGER DEFAULT 0,
			expires_at DATETIME NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			ip_address TEXT
		);

		CREATE TABLE IF NOT EXISTS pending_registrations (
			email TEXT PRIMARY KEY,
			registration_record BLOB NOT NULL,
			verification_code_hash TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			resend_after DATETIME NOT NULL,
			attempts INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS files (
			id TEXT PRIMARY KEY,
			owner_id TEXT,
			guest_session_id TEXT,
			original_filename TEXT NOT NULL,
			encrypted_filename TEXT NOT NULL,
			mime_type TEXT NOT NULL,
			file_size_bytes INTEGER NOT NULL,
			encrypted_size_bytes INTEGER NOT NULL,
			iv_base64 TEXT NOT NULL,
			checksum_sha256 TEXT NOT NULL,
			expires_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (guest_session_id) REFERENCES guest_sessions(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS shares (
			id TEXT PRIMARY KEY,
			file_id TEXT NOT NULL,
			password_hash TEXT,
			max_downloads INTEGER,
			download_count INTEGER DEFAULT 0,
			requires_email_verification INTEGER DEFAULT 0,
			notify_on_download INTEGER DEFAULT 0,
			notify_email TEXT,
			expires_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			is_active INTEGER DEFAULT 1,
			FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS share_allowed_emails (
			share_id TEXT NOT NULL,
			email TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (share_id, email),
			FOREIGN KEY (share_id) REFERENCES shares(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS pending_share_download_verifications (
			share_id TEXT NOT NULL,
			email TEXT NOT NULL,
			verification_code_hash TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			resend_after DATETIME NOT NULL,
			attempts INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (share_id, email),
			FOREIGN KEY (share_id) REFERENCES shares(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS rate_limit_counters (
			scope_key TEXT PRIMARY KEY,
			count INTEGER NOT NULL,
			window_end DATETIME NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_files_owner_id ON files(owner_id);
		CREATE INDEX IF NOT EXISTS idx_files_guest_session_id ON files(guest_session_id);
		CREATE INDEX IF NOT EXISTS idx_shares_file_id ON shares(file_id);
		CREATE INDEX IF NOT EXISTS idx_share_allowed_emails_share_id ON share_allowed_emails(share_id);
		CREATE INDEX IF NOT EXISTS idx_pending_share_download_verifications_expires_at ON pending_share_download_verifications(expires_at);
		CREATE INDEX IF NOT EXISTS idx_guest_sessions_expires_at ON guest_sessions(expires_at);
		CREATE INDEX IF NOT EXISTS idx_guest_sessions_ip_address ON guest_sessions(ip_address);
		CREATE INDEX IF NOT EXISTS idx_pending_registrations_expires_at ON pending_registrations(expires_at);
		CREATE INDEX IF NOT EXISTS idx_rate_limit_counters_window_end ON rate_limit_counters(window_end);

		CREATE TABLE IF NOT EXISTS app_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}

	// Add is_admin column to users table if it doesn't exist.
	if err := addColumnIfNotExists(db, "users", "is_admin", "INTEGER DEFAULT 0"); err != nil {
		return fmt.Errorf("failed to add is_admin column: %w", err)
	}
	if err := addColumnIfNotExists(db, "shares", "requires_email_verification", "INTEGER DEFAULT 0"); err != nil {
		return fmt.Errorf("failed to add requires_email_verification column: %w", err)
	}

	// Seed default settings.
	defaults := map[string]string{
		"max_file_size_guest":          "10485760",   // 10MB
		"max_file_size_user":           "104857600",  // 100MB
		"storage_quota_guest":          "10485760",   // 10MB
		"storage_quota_user":           "1073741824", // 1GB
		"allowed_email_domains":        "",
		"setup_completed":              "false",
		"guest_session_duration_hours": "24",
	}
	for k, v := range defaults {
		if _, err := db.Exec(`INSERT OR IGNORE INTO app_settings (key, value) VALUES (?, ?)`, k, v); err != nil {
			return fmt.Errorf("failed to seed default setting %s: %w", k, err)
		}
	}

	return nil
}

// addColumnIfNotExists adds a column to a table only if it doesn't already exist.
func addColumnIfNotExists(db *sql.DB, table, column, colDef string) error {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dfltValue *string
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if strings.EqualFold(name, column) {
			return nil // column already exists
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	_, err = db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, colDef))
	return err
}
