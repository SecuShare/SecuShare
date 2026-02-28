package service

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/models"
	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/SecuShare/SecuShare/backend/pkg/testutil"
)

func createUploadTestUser(t *testing.T, userRepo *repository.UserRepository, userID string) {
	t.Helper()
	if err := userRepo.Create(&models.User{
		ID:           userID,
		Email:        "upload-test@example.com",
		OpaqueRecord: []byte("opaque"),
		StorageQuota: 1024 * 1024,
		StorageUsed:  0,
		CreatedAt:    time.Now(),
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
}

func TestFileService_Upload_RejectsNonPositiveDeclaredSizes(t *testing.T) {
	db, cfg, cleanup := testutil.SetupTest(t)
	defer cleanup()

	userRepo := repository.NewUserRepository(db)
	guestRepo := repository.NewGuestSessionRepository(db)
	fileRepo := repository.NewFileRepository(db)
	fileSvc := NewFileService(fileRepo, userRepo, guestRepo, cfg.StoragePath)

	userID := "upload-user-1"
	createUploadTestUser(t, userRepo, userID)

	ivBase64 := base64.StdEncoding.EncodeToString(make([]byte, 12))
	checksum := strings.Repeat("a", 64)

	_, err := fileSvc.Upload(&UploadRequest{
		OriginalFilename: "invalid.bin",
		MimeType:         "application/octet-stream",
		FileSize:         1,
		EncryptedSize:    0,
		IVBase64:         ivBase64,
		ChecksumSHA256:   checksum,
		EncryptedData:    bytes.NewReader([]byte{0x00}),
		OwnerID:          &userID,
	})
	if err == nil || !strings.Contains(err.Error(), "greater than zero") {
		t.Fatalf("expected non-positive encrypted size error, got %v", err)
	}

	user, err := userRepo.GetByID(userID)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if user.StorageUsed != 0 {
		t.Fatalf("expected storage_used=0, got %d", user.StorageUsed)
	}
}

func TestFileService_Upload_RejectsDeclaredActualSizeMismatch(t *testing.T) {
	db, cfg, cleanup := testutil.SetupTest(t)
	defer cleanup()

	userRepo := repository.NewUserRepository(db)
	guestRepo := repository.NewGuestSessionRepository(db)
	fileRepo := repository.NewFileRepository(db)
	fileSvc := NewFileService(fileRepo, userRepo, guestRepo, cfg.StoragePath)

	userID := "upload-user-2"
	createUploadTestUser(t, userRepo, userID)

	blob := make([]byte, 64)
	if _, err := rand.Read(blob); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	ivBase64 := base64.StdEncoding.EncodeToString(make([]byte, 12))
	checksum := strings.Repeat("b", 64)

	_, err := fileSvc.Upload(&UploadRequest{
		OriginalFilename: "mismatch.bin",
		MimeType:         "application/octet-stream",
		FileSize:         int64(len(blob)),
		EncryptedSize:    int64(len(blob) - 1),
		IVBase64:         ivBase64,
		ChecksumSHA256:   checksum,
		EncryptedData:    bytes.NewReader(blob),
		OwnerID:          &userID,
	})
	if err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("expected declared/actual size mismatch error, got %v", err)
	}

	user, err := userRepo.GetByID(userID)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if user.StorageUsed != 0 {
		t.Fatalf("expected storage_used=0 after rejected upload, got %d", user.StorageUsed)
	}

	files, err := fileRepo.GetByOwnerID(userID)
	if err != nil {
		t.Fatalf("GetByOwnerID: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected no persisted files, got %d", len(files))
	}
}
