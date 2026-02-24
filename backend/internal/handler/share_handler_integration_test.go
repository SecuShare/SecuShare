package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/config"
	"github.com/SecuShare/SecuShare/backend/internal/models"
	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/SecuShare/SecuShare/backend/internal/service"
	"github.com/SecuShare/SecuShare/backend/pkg/testutil"
	"github.com/gofiber/fiber/v2"
)

type shareHandlerTestResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   string          `json:"error"`
}

func TestShareHandler_DownloadFile_InternalErrorReturns500(t *testing.T) {
	db, cfg, cleanup := testutil.SetupTest(t)
	defer cleanup()

	userRepo := repository.NewUserRepository(db)
	guestRepo := repository.NewGuestSessionRepository(db)
	fileRepo := repository.NewFileRepository(db)
	shareRepo := repository.NewShareRepository(db)

	fileSvc := service.NewFileService(fileRepo, userRepo, guestRepo, cfg.StoragePath)
	shareSvc := service.NewShareService(shareRepo, fileRepo, fileSvc, &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:              "share-handler-test-secret",
			DownloadCodeHMACSecret: "share-handler-download-code-secret",
		},
	})
	t.Cleanup(shareSvc.Stop)
	shareHandler := NewShareHandler(shareSvc, fileSvc)

	app := fiber.New()
	app.Post("/api/v1/shares/:id/file", shareHandler.DownloadFile)

	// Force repository operations to fail with an internal DB error.
	if err := db.Close(); err != nil {
		t.Fatalf("close test database: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/shares/any/file", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 for internal download failure, got %d", resp.StatusCode)
	}

	var parsed shareHandlerTestResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if parsed.Success {
		t.Fatal("expected success=false for internal error response")
	}
	if parsed.Error != "failed to process download" {
		t.Fatalf("expected generic internal error message, got %q", parsed.Error)
	}
}

func TestShareHandler_DownloadFile_InternalVerificationValidationReturns500(t *testing.T) {
	db, cfg, cleanup := testutil.SetupTest(t)
	defer cleanup()

	userRepo := repository.NewUserRepository(db)
	guestRepo := repository.NewGuestSessionRepository(db)
	fileRepo := repository.NewFileRepository(db)
	shareRepo := repository.NewShareRepository(db)

	fileSvc := service.NewFileService(fileRepo, userRepo, guestRepo, cfg.StoragePath)
	shareSvc := service.NewShareService(shareRepo, fileRepo, fileSvc, &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:              "share-handler-test-secret",
			DownloadCodeHMACSecret: "share-handler-download-code-secret",
		},
	})
	t.Cleanup(shareSvc.Stop)
	shareHandler := NewShareHandler(shareSvc, fileSvc)

	app := fiber.New()
	app.Post("/api/v1/shares/:id/file", shareHandler.DownloadFile)

	userID := "share-handler-test-user"
	if err := userRepo.Create(&models.User{
		ID:              userID,
		Email:           "owner@example.com",
		OpaqueRecord:    []byte("opaque-record"),
		StorageQuota:    1024 * 1024,
		StorageUsed:     0,
		CreatedAt:       time.Now(),
		IsEmailVerified: true,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	if err := fileRepo.Create(&models.File{
		ID:                "share-handler-test-file",
		OwnerID:           &userID,
		OriginalFilename:  "document.txt",
		EncryptedFilename: "document.txt.enc",
		MimeType:          "text/plain",
		FileSize:          128,
		EncryptedSize:     256,
		IVBase64:          "AAAAAAAAAAAAAAAA",
		ChecksumSHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CreatedAt:         time.Now(),
	}); err != nil {
		t.Fatalf("create file: %v", err)
	}

	share, err := shareSvc.Create(&service.CreateShareRequest{
		FileID:        "share-handler-test-file",
		AllowedEmails: []string{"allowed@example.com"},
	})
	if err != nil {
		t.Fatalf("create restricted share: %v", err)
	}

	// Force internal verification validation failure while leaving share lookup available.
	if _, err := db.Exec(`DROP TABLE share_allowed_emails`); err != nil {
		t.Fatalf("drop share_allowed_emails table: %v", err)
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/shares/"+share.ID+"/file",
		bytes.NewBufferString(`{"email":"allowed@example.com","verification_code":"123456"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 for internal verification failure, got %d", resp.StatusCode)
	}

	var parsed shareHandlerTestResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if parsed.Success {
		t.Fatal("expected success=false for internal error response")
	}
	if parsed.Error != "failed to process download" {
		t.Fatalf("expected generic internal error message, got %q", parsed.Error)
	}
}

func TestShareHandler_ListByFile_ReturnsAllowedEmailsForOwner(t *testing.T) {
	db, cfg, cleanup := testutil.SetupTest(t)
	defer cleanup()

	userRepo := repository.NewUserRepository(db)
	guestRepo := repository.NewGuestSessionRepository(db)
	fileRepo := repository.NewFileRepository(db)
	shareRepo := repository.NewShareRepository(db)

	fileSvc := service.NewFileService(fileRepo, userRepo, guestRepo, cfg.StoragePath)
	shareSvc := service.NewShareService(shareRepo, fileRepo, fileSvc, &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:              "share-handler-test-secret",
			DownloadCodeHMACSecret: "share-handler-download-code-secret",
		},
	})
	t.Cleanup(shareSvc.Stop)
	shareHandler := NewShareHandler(shareSvc, fileSvc)

	userID := "share-owner-user"
	if err := userRepo.Create(&models.User{
		ID:              userID,
		Email:           "owner@example.com",
		OpaqueRecord:    []byte("opaque-record"),
		StorageQuota:    1024 * 1024,
		StorageUsed:     0,
		CreatedAt:       time.Now(),
		IsEmailVerified: true,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	fileID := "share-owner-file"
	if err := fileRepo.Create(&models.File{
		ID:                fileID,
		OwnerID:           &userID,
		OriginalFilename:  "notes.txt",
		EncryptedFilename: "notes.txt.enc",
		MimeType:          "text/plain",
		FileSize:          128,
		EncryptedSize:     256,
		IVBase64:          "AAAAAAAAAAAAAAAA",
		ChecksumSHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CreatedAt:         time.Now(),
	}); err != nil {
		t.Fatalf("create file: %v", err)
	}

	allowedEmails := []string{"alice@example.com", "bob@example.com"}
	if _, err := shareSvc.Create(&service.CreateShareRequest{
		FileID:        fileID,
		AllowedEmails: allowedEmails,
	}); err != nil {
		t.Fatalf("create restricted share: %v", err)
	}

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("user_id", userID)
		c.Locals("is_guest", false)
		return c.Next()
	})
	app.Get("/api/v1/files/:id/shares", shareHandler.ListByFile)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/files/"+fileID+"/shares", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 for owner share listing, got %d", resp.StatusCode)
	}

	var parsed shareHandlerTestResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !parsed.Success {
		t.Fatalf("expected success=true, got error %q", parsed.Error)
	}

	var payload []struct {
		AllowedEmails []string `json:"allowed_emails"`
	}
	if err := json.Unmarshal(parsed.Data, &payload); err != nil {
		t.Fatalf("decode shares payload: %v", err)
	}
	if len(payload) != 1 {
		t.Fatalf("expected exactly one share, got %d", len(payload))
	}
	if len(payload[0].AllowedEmails) != len(allowedEmails) {
		t.Fatalf("expected %d allowed emails, got %d", len(allowedEmails), len(payload[0].AllowedEmails))
	}

	seen := make(map[string]struct{}, len(payload[0].AllowedEmails))
	for _, email := range payload[0].AllowedEmails {
		seen[email] = struct{}{}
	}
	for _, expected := range allowedEmails {
		if _, ok := seen[expected]; !ok {
			t.Fatalf("expected allowed email %q in response", expected)
		}
	}
}
