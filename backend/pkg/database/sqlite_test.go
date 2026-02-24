package database

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitializeCreatesDatabasePath(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "nested", "secushare.db")

	db, err := Initialize(dbPath)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	defer db.Close()

	if _, err := os.Stat(filepath.Dir(dbPath)); err != nil {
		t.Fatalf("expected database directory to exist: %v", err)
	}
}

func TestInitSchemaCreatesAndSeedsTables(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "schema.db")

	db, err := Initialize(dbPath)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	defer db.Close()

	if err := InitSchema(db); err != nil {
		t.Fatalf("InitSchema first run failed: %v", err)
	}
	// Ensure idempotency and exercise the "column already exists" branch.
	if err := InitSchema(db); err != nil {
		t.Fatalf("InitSchema second run failed: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		t.Fatalf("expected users table to exist: %v", err)
	}

	var setupCompleted string
	if err := db.QueryRow(`SELECT value FROM app_settings WHERE key = 'setup_completed'`).Scan(&setupCompleted); err != nil {
		t.Fatalf("expected seeded setup_completed setting: %v", err)
	}
	if setupCompleted != "false" {
		t.Fatalf("unexpected setup_completed default: %q", setupCompleted)
	}
}
