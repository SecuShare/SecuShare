package handler

import (
	"database/sql"
	"os"
	"path/filepath"

	"github.com/gofiber/fiber/v2"
)

// HealthHandler handles health check endpoints
type HealthHandler struct {
	db          *sql.DB
	storagePath string
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(db *sql.DB, storagePath string) *HealthHandler {
	return &HealthHandler{
		db:          db,
		storagePath: storagePath,
	}
}

// Liveness returns basic liveness status (is the server running?)
func (h *HealthHandler) Liveness(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "ok",
	})
}

// Readiness returns readiness status (can the server handle requests?)
func (h *HealthHandler) Readiness(c *fiber.Ctx) error {
	checks := make(map[string]interface{})
	allHealthy := true

	// Check database connection
	if err := h.checkDatabase(); err != nil {
		checks["database"] = fiber.Map{
			"status": "unhealthy",
			"error":  err.Error(),
		}
		allHealthy = false
	} else {
		checks["database"] = fiber.Map{
			"status": "healthy",
		}
	}

	// Check storage accessibility
	if err := h.checkStorage(); err != nil {
		checks["storage"] = fiber.Map{
			"status": "unhealthy",
			"error":  err.Error(),
		}
		allHealthy = false
	} else {
		checks["storage"] = fiber.Map{
			"status": "healthy",
		}
	}

	status := "ok"
	statusCode := fiber.StatusOK
	if !allHealthy {
		status = "degraded"
		statusCode = fiber.StatusServiceUnavailable
	}

	return c.Status(statusCode).JSON(fiber.Map{
		"status": status,
		"checks": checks,
	})
}

// checkDatabase verifies database connectivity
func (h *HealthHandler) checkDatabase() error {
	if h.db == nil {
		return ErrDatabaseNotInitialized
	}
	return h.db.Ping()
}

// checkStorage verifies storage directory is accessible and writable
func (h *HealthHandler) checkStorage() error {
	// Ensure storage directory exists
	if err := os.MkdirAll(h.storagePath, 0755); err != nil {
		return err
	}

	// Try to create a test file to verify write permissions
	testFile := filepath.Join(h.storagePath, ".healthcheck")
	f, err := os.Create(testFile)
	if err != nil {
		return err
	}
	f.Close()

	// Clean up the test file
	os.Remove(testFile)
	return nil
}
