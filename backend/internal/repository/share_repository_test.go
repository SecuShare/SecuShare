package repository

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/models"
	"github.com/SecuShare/SecuShare/backend/pkg/testutil"
	"github.com/google/uuid"
)

func setupPendingVerificationRepoTest(
	t *testing.T,
) (*ShareRepository, string, string, func()) {
	t.Helper()

	db, _, cleanup := testutil.SetupTest(t)

	userRepo := NewUserRepository(db)
	fileRepo := NewFileRepository(db)
	shareRepo := NewShareRepository(db)

	userID := uuid.New().String()
	if err := userRepo.Create(&models.User{
		ID:              userID,
		Email:           "owner@example.com",
		OpaqueRecord:    []byte("opaque-record"),
		StorageQuota:    1024 * 1024,
		StorageUsed:     0,
		CreatedAt:       time.Now(),
		IsEmailVerified: true,
	}); err != nil {
		cleanup()
		t.Fatalf("create user: %v", err)
	}

	fileID := uuid.New().String()
	if err := fileRepo.Create(&models.File{
		ID:                fileID,
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
		cleanup()
		t.Fatalf("create file: %v", err)
	}

	shareID := uuid.New().String()
	if err := shareRepo.Create(&models.Share{
		ID:                        shareID,
		FileID:                    fileID,
		MaxDownloads:              nil,
		DownloadCount:             0,
		RequiresEmailVerification: true,
		ExpiresAt:                 nil,
		CreatedAt:                 time.Now(),
		IsActive:                  true,
	}, nil); err != nil {
		cleanup()
		t.Fatalf("create share: %v", err)
	}

	return shareRepo, shareID, "allowed@example.com", cleanup
}

func TestShareRepository_UpsertPendingDownloadVerificationIfResendAllowed_EnforcesWindow(t *testing.T) {
	repo, shareID, email, cleanup := setupPendingVerificationRepoTest(t)
	defer cleanup()

	now := time.Now()
	initial := &models.PendingShareDownloadVerification{
		ShareID:              shareID,
		Email:                email,
		VerificationCodeHash: "hash-initial",
		ExpiresAt:            now.Add(10 * time.Minute),
		ResendAfter:          now.Add(1 * time.Minute),
		Attempts:             0,
	}

	stored, err := repo.UpsertPendingDownloadVerificationIfResendAllowed(initial, now)
	if err != nil {
		t.Fatalf("store initial pending verification: %v", err)
	}
	if !stored {
		t.Fatal("expected initial upsert to store pending verification")
	}

	blocked := &models.PendingShareDownloadVerification{
		ShareID:              shareID,
		Email:                email,
		VerificationCodeHash: "hash-blocked",
		ExpiresAt:            now.Add(20 * time.Minute),
		ResendAfter:          now.Add(2 * time.Minute),
		Attempts:             0,
	}

	stored, err = repo.UpsertPendingDownloadVerificationIfResendAllowed(blocked, now.Add(10*time.Second))
	if err != nil {
		t.Fatalf("attempt blocked upsert: %v", err)
	}
	if stored {
		t.Fatal("expected upsert to be blocked inside resend window")
	}

	pending, err := repo.GetPendingDownloadVerification(shareID, email)
	if err != nil {
		t.Fatalf("load pending verification after blocked upsert: %v", err)
	}
	if pending.VerificationCodeHash != initial.VerificationCodeHash {
		t.Fatalf(
			"expected hash %q to remain during resend window, got %q",
			initial.VerificationCodeHash,
			pending.VerificationCodeHash,
		)
	}

	stored, err = repo.UpsertPendingDownloadVerificationIfResendAllowed(blocked, initial.ResendAfter)
	if err != nil {
		t.Fatalf("attempt allowed upsert after resend window: %v", err)
	}
	if !stored {
		t.Fatal("expected upsert to rotate code after resend window elapsed")
	}

	rotated, err := repo.GetPendingDownloadVerification(shareID, email)
	if err != nil {
		t.Fatalf("load rotated pending verification: %v", err)
	}
	if rotated.VerificationCodeHash != blocked.VerificationCodeHash {
		t.Fatalf(
			"expected rotated hash %q, got %q",
			blocked.VerificationCodeHash,
			rotated.VerificationCodeHash,
		)
	}
}

func TestShareRepository_DeletePendingDownloadVerificationIfExpired_GuardsFreshRow(t *testing.T) {
	repo, shareID, email, cleanup := setupPendingVerificationRepoTest(t)
	defer cleanup()

	now := time.Now()
	expired := &models.PendingShareDownloadVerification{
		ShareID:              shareID,
		Email:                email,
		VerificationCodeHash: "hash-expired",
		ExpiresAt:            now.Add(-1 * time.Minute),
		ResendAfter:          now,
		Attempts:             0,
	}
	if err := repo.UpsertPendingDownloadVerification(expired); err != nil {
		t.Fatalf("store expired pending verification: %v", err)
	}

	if err := repo.DeletePendingDownloadVerificationIfExpired(shareID, email, now); err != nil {
		t.Fatalf("delete expired pending verification: %v", err)
	}

	if _, err := repo.GetPendingDownloadVerification(shareID, email); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected expired pending verification to be deleted, got %v", err)
	}

	fresh := &models.PendingShareDownloadVerification{
		ShareID:              shareID,
		Email:                email,
		VerificationCodeHash: "hash-fresh",
		ExpiresAt:            now.Add(10 * time.Minute),
		ResendAfter:          now,
		Attempts:             0,
	}
	if err := repo.UpsertPendingDownloadVerification(fresh); err != nil {
		t.Fatalf("store fresh pending verification: %v", err)
	}

	if err := repo.DeletePendingDownloadVerificationIfExpired(shareID, email, now); err != nil {
		t.Fatalf("attempt delete for fresh pending verification: %v", err)
	}

	pending, err := repo.GetPendingDownloadVerification(shareID, email)
	if err != nil {
		t.Fatalf("load fresh pending verification: %v", err)
	}
	if pending.VerificationCodeHash != fresh.VerificationCodeHash {
		t.Fatalf(
			"expected fresh hash %q to remain, got %q",
			fresh.VerificationCodeHash,
			pending.VerificationCodeHash,
		)
	}
}

func TestShareRepository_GetAllowedEmails_ReturnsSortedEmails(t *testing.T) {
	db, _, cleanup := testutil.SetupTest(t)
	defer cleanup()

	userRepo := NewUserRepository(db)
	fileRepo := NewFileRepository(db)
	shareRepo := NewShareRepository(db)

	userID := uuid.New().String()
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

	fileID := uuid.New().String()
	if err := fileRepo.Create(&models.File{
		ID:                fileID,
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

	shareID := uuid.New().String()
	if err := shareRepo.Create(&models.Share{
		ID:                        shareID,
		FileID:                    fileID,
		MaxDownloads:              nil,
		DownloadCount:             0,
		RequiresEmailVerification: true,
		ExpiresAt:                 nil,
		CreatedAt:                 time.Now(),
		IsActive:                  true,
	}, []string{"zeta@example.com", "alpha@example.com"}); err != nil {
		t.Fatalf("create share: %v", err)
	}

	emails, err := shareRepo.GetAllowedEmails(shareID)
	if err != nil {
		t.Fatalf("get allowed emails: %v", err)
	}
	if len(emails) != 2 {
		t.Fatalf("expected 2 allowed emails, got %d", len(emails))
	}
	if emails[0] != "alpha@example.com" || emails[1] != "zeta@example.com" {
		t.Fatalf("expected sorted allowed emails, got %v", emails)
	}

	emptyShareID := uuid.New().String()
	if err := shareRepo.Create(&models.Share{
		ID:                        emptyShareID,
		FileID:                    fileID,
		MaxDownloads:              nil,
		DownloadCount:             0,
		RequiresEmailVerification: false,
		ExpiresAt:                 nil,
		CreatedAt:                 time.Now(),
		IsActive:                  true,
	}, nil); err != nil {
		t.Fatalf("create unrestricted share: %v", err)
	}

	emptyEmails, err := shareRepo.GetAllowedEmails(emptyShareID)
	if err != nil {
		t.Fatalf("get allowed emails for unrestricted share: %v", err)
	}
	if len(emptyEmails) != 0 {
		t.Fatalf("expected no allowed emails for unrestricted share, got %v", emptyEmails)
	}
}
