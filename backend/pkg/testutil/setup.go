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
	cleanupTmpDir := func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Logf("Failed to remove temp directory %q: %v", tmpDir, err)
		}
	}

	// Create test database
	db, err := database.Initialize(cfg.DBPath)
	if err != nil {
		cleanupTmpDir()
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Initialize schema using the same logic as runtime startup.
	if err := database.InitSchema(db); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			t.Logf("Failed to close test database after schema init error: %v", closeErr)
		}
		cleanupTmpDir()
		t.Fatalf("Failed to initialize test schema: %v", err)
	}

	// Create storage directory
	if err := os.MkdirAll(cfg.StoragePath, 0750); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			t.Logf("Failed to close test database after storage init error: %v", closeErr)
		}
		cleanupTmpDir()
		t.Fatalf("Failed to create storage directory: %v", err)
	}

	cleanup := func() {
		if err := db.Close(); err != nil {
			t.Logf("Failed to close test database: %v", err)
		}
		cleanupTmpDir()
	}

	return db, cfg, cleanup
}
