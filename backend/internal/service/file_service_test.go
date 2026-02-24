package service

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/models"
	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/SecuShare/SecuShare/backend/pkg/testutil"
)

func TestFileService_DeleteExpired_ReleasesUserQuotaAndRemovesBlob(t *testing.T) {
	db, cfg, cleanup := testutil.SetupTest(t)
	defer cleanup()

	userRepo := repository.NewUserRepository(db)
	guestRepo := repository.NewGuestSessionRepository(db)
	fileRepo := repository.NewFileRepository(db)
	fileSvc := NewFileService(fileRepo, userRepo, guestRepo, cfg.StoragePath)

	userID := "user-1"
	if err := userRepo.Create(&models.User{
		ID:           userID,
		Email:        "user1@example.com",
		OpaqueRecord: []byte("opaque"),
		StorageQuota: 1024 * 1024,
		StorageUsed:  128,
		CreatedAt:    time.Now(),
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	expiresAt := time.Now().Add(-1 * time.Hour)
	file := &models.File{
		ID:                "expired-file-1",
		OwnerID:           &userID,
		OriginalFilename:  "a.txt",
		EncryptedFilename: "expired-file-1.enc",
		MimeType:          "text/plain",
		FileSize:          64,
		EncryptedSize:     128,
		IVBase64:          "AAAAAAAAAAAAAAAA",
		ChecksumSHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ExpiresAt:         &expiresAt,
		CreatedAt:         time.Now(),
	}
	if err := fileRepo.Create(file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	blobPath := filepath.Join(cfg.StoragePath, file.EncryptedFilename)
	if err := os.WriteFile(blobPath, []byte("encrypted"), 0644); err != nil {
		t.Fatalf("write test blob: %v", err)
	}

	if err := fileSvc.DeleteExpired(time.Now()); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	if _, err := fileRepo.GetByID(file.ID); err == nil {
		t.Fatalf("expected expired file to be deleted from database")
	}

	user, err := userRepo.GetByID(userID)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if user.StorageUsed != 0 {
		t.Fatalf("expected storage_used to be 0 after cleanup, got %d", user.StorageUsed)
	}

	if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
		t.Fatalf("expected blob to be removed, stat err=%v", err)
	}
}

func TestFileService_DeleteExpired_ReleasesGuestQuotaAndKeepsActiveFiles(t *testing.T) {
	db, cfg, cleanup := testutil.SetupTest(t)
	defer cleanup()

	userRepo := repository.NewUserRepository(db)
	guestRepo := repository.NewGuestSessionRepository(db)
	fileRepo := repository.NewFileRepository(db)
	fileSvc := NewFileService(fileRepo, userRepo, guestRepo, cfg.StoragePath)

	guestID := "guest-1"
	ip := "203.0.113.42"
	if err := guestRepo.Create(&models.GuestSession{
		ID:           guestID,
		IPAddress:    &ip,
		StorageQuota: 10 * 1024 * 1024,
		StorageUsed:  250,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}); err != nil {
		t.Fatalf("create guest session: %v", err)
	}

	expiredAt := time.Now().Add(-1 * time.Hour)
	activeAt := time.Now().Add(24 * time.Hour)

	expired := &models.File{
		ID:                "expired-guest-file",
		GuestSessionID:    &guestID,
		OriginalFilename:  "old.bin",
		EncryptedFilename: "expired-guest-file.enc",
		MimeType:          "application/octet-stream",
		FileSize:          200,
		EncryptedSize:     200,
		IVBase64:          "AAAAAAAAAAAAAAAA",
		ChecksumSHA256:    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		ExpiresAt:         &expiredAt,
		CreatedAt:         time.Now(),
	}
	active := &models.File{
		ID:                "active-guest-file",
		GuestSessionID:    &guestID,
		OriginalFilename:  "new.bin",
		EncryptedFilename: "active-guest-file.enc",
		MimeType:          "application/octet-stream",
		FileSize:          50,
		EncryptedSize:     50,
		IVBase64:          "AAAAAAAAAAAAAAAA",
		ChecksumSHA256:    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
		ExpiresAt:         &activeAt,
		CreatedAt:         time.Now(),
	}
	if err := fileRepo.Create(expired); err != nil {
		t.Fatalf("create expired file: %v", err)
	}
	if err := fileRepo.Create(active); err != nil {
		t.Fatalf("create active file: %v", err)
	}

	expiredBlob := filepath.Join(cfg.StoragePath, expired.EncryptedFilename)
	activeBlob := filepath.Join(cfg.StoragePath, active.EncryptedFilename)
	if err := os.WriteFile(expiredBlob, []byte("expired"), 0644); err != nil {
		t.Fatalf("write expired blob: %v", err)
	}
	if err := os.WriteFile(activeBlob, []byte("active"), 0644); err != nil {
		t.Fatalf("write active blob: %v", err)
	}

	if err := fileSvc.DeleteExpired(time.Now()); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	if _, err := fileRepo.GetByID(expired.ID); err == nil {
		t.Fatalf("expected expired file to be deleted")
	}
	if _, err := fileRepo.GetByID(active.ID); err != nil {
		t.Fatalf("expected non-expired file to remain: %v", err)
	}

	session, err := guestRepo.GetByID(guestID)
	if err != nil {
		t.Fatalf("reload guest session: %v", err)
	}
	if session.StorageUsed != 50 {
		t.Fatalf("expected storage_used to be 50 after cleanup, got %d", session.StorageUsed)
	}

	if _, err := os.Stat(expiredBlob); !os.IsNotExist(err) {
		t.Fatalf("expected expired blob to be removed, stat err=%v", err)
	}
	if _, err := os.Stat(activeBlob); err != nil {
		t.Fatalf("expected active blob to remain, stat err=%v", err)
	}
}

func TestFileService_DeleteByExpiredGuestSessions_RemovesFilesWithoutFileExpiry(t *testing.T) {
	db, cfg, cleanup := testutil.SetupTest(t)
	defer cleanup()

	userRepo := repository.NewUserRepository(db)
	guestRepo := repository.NewGuestSessionRepository(db)
	fileRepo := repository.NewFileRepository(db)
	fileSvc := NewFileService(fileRepo, userRepo, guestRepo, cfg.StoragePath)

	expiredGuestID := "guest-expired"
	expiredIP := "203.0.113.10"
	if err := guestRepo.Create(&models.GuestSession{
		ID:           expiredGuestID,
		IPAddress:    &expiredIP,
		StorageQuota: 10 * 1024 * 1024,
		StorageUsed:  120,
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
		CreatedAt:    time.Now().Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("create expired guest session: %v", err)
	}

	activeGuestID := "guest-active"
	activeIP := "203.0.113.11"
	if err := guestRepo.Create(&models.GuestSession{
		ID:           activeGuestID,
		IPAddress:    &activeIP,
		StorageQuota: 10 * 1024 * 1024,
		StorageUsed:  80,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}); err != nil {
		t.Fatalf("create active guest session: %v", err)
	}

	expiredGuestFile := &models.File{
		ID:                "expired-guest-no-file-expiry",
		GuestSessionID:    &expiredGuestID,
		OriginalFilename:  "old.bin",
		EncryptedFilename: "expired-guest-no-file-expiry.enc",
		MimeType:          "application/octet-stream",
		FileSize:          100,
		EncryptedSize:     120,
		IVBase64:          "AAAAAAAAAAAAAAAA",
		ChecksumSHA256:    "1111111111111111111111111111111111111111111111111111111111111111",
		ExpiresAt:         nil,
		CreatedAt:         time.Now().Add(-90 * time.Minute),
	}
	activeGuestFile := &models.File{
		ID:                "active-guest-no-file-expiry",
		GuestSessionID:    &activeGuestID,
		OriginalFilename:  "new.bin",
		EncryptedFilename: "active-guest-no-file-expiry.enc",
		MimeType:          "application/octet-stream",
		FileSize:          70,
		EncryptedSize:     80,
		IVBase64:          "AAAAAAAAAAAAAAAA",
		ChecksumSHA256:    "2222222222222222222222222222222222222222222222222222222222222222",
		ExpiresAt:         nil,
		CreatedAt:         time.Now(),
	}

	if err := fileRepo.Create(expiredGuestFile); err != nil {
		t.Fatalf("create expired guest file: %v", err)
	}
	if err := fileRepo.Create(activeGuestFile); err != nil {
		t.Fatalf("create active guest file: %v", err)
	}

	expiredBlob := filepath.Join(cfg.StoragePath, expiredGuestFile.EncryptedFilename)
	activeBlob := filepath.Join(cfg.StoragePath, activeGuestFile.EncryptedFilename)
	if err := os.WriteFile(expiredBlob, []byte("expired"), 0644); err != nil {
		t.Fatalf("write expired blob: %v", err)
	}
	if err := os.WriteFile(activeBlob, []byte("active"), 0644); err != nil {
		t.Fatalf("write active blob: %v", err)
	}

	if err := fileSvc.DeleteByExpiredGuestSessions(time.Now()); err != nil {
		t.Fatalf("DeleteByExpiredGuestSessions: %v", err)
	}

	if _, err := fileRepo.GetByID(expiredGuestFile.ID); err == nil {
		t.Fatalf("expected file owned by expired guest session to be deleted")
	}
	if _, err := fileRepo.GetByID(activeGuestFile.ID); err != nil {
		t.Fatalf("expected file owned by active guest session to remain: %v", err)
	}

	expiredSession, err := guestRepo.GetByID(expiredGuestID)
	if err != nil {
		t.Fatalf("reload expired guest session: %v", err)
	}
	if expiredSession.StorageUsed != 0 {
		t.Fatalf("expected expired session storage_used to be released to 0, got %d", expiredSession.StorageUsed)
	}

	activeSession, err := guestRepo.GetByID(activeGuestID)
	if err != nil {
		t.Fatalf("reload active guest session: %v", err)
	}
	if activeSession.StorageUsed != 80 {
		t.Fatalf("expected active session storage_used to remain 80, got %d", activeSession.StorageUsed)
	}

	if _, err := os.Stat(expiredBlob); !os.IsNotExist(err) {
		t.Fatalf("expected expired guest blob to be removed, stat err=%v", err)
	}
	if _, err := os.Stat(activeBlob); err != nil {
		t.Fatalf("expected active guest blob to remain, stat err=%v", err)
	}
}
