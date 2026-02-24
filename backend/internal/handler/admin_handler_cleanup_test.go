package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/models"
	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/SecuShare/SecuShare/backend/internal/service"
	"github.com/SecuShare/SecuShare/backend/pkg/testutil"
	"github.com/gofiber/fiber/v2"
)

func TestAdminHandler_TriggerCleanup_RemovesExpiredPendingShareDownloadVerifications(t *testing.T) {
	db, cfg, cleanup := testutil.SetupTest(t)
	defer cleanup()

	userRepo := repository.NewUserRepository(db)
	guestRepo := repository.NewGuestSessionRepository(db)
	pendingRepo := repository.NewPendingRegistrationRepository(db)
	fileRepo := repository.NewFileRepository(db)
	shareRepo := repository.NewShareRepository(db)
	fileSvc := service.NewFileService(fileRepo, userRepo, guestRepo, cfg.StoragePath)

	adminHandler := NewAdminHandler(nil, nil, fileSvc, shareRepo, guestRepo, pendingRepo)

	ownerID := "cleanup-owner"
	if err := userRepo.Create(&models.User{
		ID:              ownerID,
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
		ID:                "cleanup-file",
		OwnerID:           &ownerID,
		OriginalFilename:  "cleanup.txt",
		EncryptedFilename: "cleanup.txt.enc",
		MimeType:          "text/plain",
		FileSize:          1,
		EncryptedSize:     1,
		IVBase64:          "AAAAAAAAAAAAAAAA",
		ChecksumSHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CreatedAt:         time.Now(),
	}); err != nil {
		t.Fatalf("create file: %v", err)
	}

	share := &models.Share{
		ID:                        "cleanup-share",
		FileID:                    "cleanup-file",
		DownloadCount:             0,
		RequiresEmailVerification: true,
		CreatedAt:                 time.Now(),
		IsActive:                  true,
	}
	if err := shareRepo.Create(share, []string{"allowed@example.com"}); err != nil {
		t.Fatalf("create share: %v", err)
	}

	expired := time.Now().Add(-1 * time.Minute)
	if err := shareRepo.UpsertPendingDownloadVerification(&models.PendingShareDownloadVerification{
		ShareID:              share.ID,
		Email:                "allowed@example.com",
		VerificationCodeHash: "expired-hash",
		ExpiresAt:            expired,
		ResendAfter:          expired,
		Attempts:             0,
	}); err != nil {
		t.Fatalf("create pending share verification: %v", err)
	}

	app := fiber.New()
	app.Post("/cleanup", adminHandler.TriggerCleanup)

	req := httptest.NewRequest(http.MethodPost, "/cleanup", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test cleanup: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var parsed struct {
		Success bool              `json:"success"`
		Data    map[string]string `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !parsed.Success {
		t.Fatal("expected success response")
	}
	if parsed.Data["pending_share_download_verifications"] != "cleaned" {
		t.Fatalf(
			"expected pending_share_download_verifications=cleaned, got %q",
			parsed.Data["pending_share_download_verifications"],
		)
	}

	if _, err := shareRepo.GetPendingDownloadVerification(share.ID, "allowed@example.com"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected expired pending verification to be removed, got %v", err)
	}
}
