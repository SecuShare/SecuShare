package testutil

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/SecuShare/SecuShare/backend/pkg/database"
	_ "github.com/mattn/go-sqlite3"
)

// TestConfig holds test configuration
type TestConfig struct {
	DBPath      string
	StoragePath string
}

// SetupTest creates a test environment with temporary database and storage
func SetupTest(t *testing.T) (*sql.DB, *TestConfig, func()) {
	t.Helper()

	// Create temporary directory for test data
	tmpDir, err := os.MkdirTemp("", "secushare-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	cfg := &TestConfig{
		DBPath:      filepath.Join(tmpDir, "test.db"),
		StoragePath: filepath.Join(tmpDir, "storage"),
	}

	// Create test database
	db, err := database.Initialize(cfg.DBPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Initialize schema using the same logic as runtime startup.
	if err := database.InitSchema(db); err != nil {
		db.Close()
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to initialize test schema: %v", err)
	}

	// Create storage directory
	if err := os.MkdirAll(cfg.StoragePath, 0755); err != nil {
		db.Close()
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create storage directory: %v", err)
	}

	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}

	return db, cfg, cleanup
}
