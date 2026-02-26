package handler

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/config"
	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/SecuShare/SecuShare/backend/internal/service"
	"github.com/SecuShare/SecuShare/backend/pkg/testutil"
	"github.com/gofiber/fiber/v2"
)

func TestGuestCleanup_RemovesBlobAndInvalidatesGuestAccess(t *testing.T) {
	db, cfg, cleanup := testutil.SetupTest(t)
	defer cleanup()

	userRepo := repository.NewUserRepository(db)
	guestRepo := repository.NewGuestSessionRepository(db)
	pendingRepo := repository.NewPendingRegistrationRepository(db)
	fileRepo := repository.NewFileRepository(db)

	authSvc, err := service.NewAuthService(
		userRepo,
		guestRepo,
		pendingRepo,
		&config.Config{
			Auth: config.AuthConfig{
				JWTSecret:         "cleanup-integration-secret-key-32-plus",
				GuestDuration:     24,
				OPAQUEServerSetup: buildTestOPAQUEServerSetup(t),
			},
		},
	)
	if err != nil {
		t.Fatalf("NewAuthService: %v", err)
	}
	defer authSvc.Stop()

	fileSvc := service.NewFileService(fileRepo, userRepo, guestRepo, cfg.StoragePath)
	fileHandler := NewFileHandler(fileSvc)

	app := fiber.New()
	files := app.Group("/api/v1/files")
	files.Get("/", AuthMiddleware(authSvc), fileHandler.List)

	session, token, err := authSvc.CreateGuestSession("203.0.113.77")
	if err != nil {
		t.Fatalf("CreateGuestSession: %v", err)
	}

	// Use random bytes so the MIME sniff sees application/octet-stream
	// (matching what real AES-GCM ciphertext looks like).
	blob := make([]byte, 64)
	if _, err := rand.Read(blob); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	ivBase64 := base64.StdEncoding.EncodeToString(make([]byte, 12))
	checksum := strings.Repeat("a", 64)

	uploaded, err := fileSvc.Upload(&service.UploadRequest{
		OriginalFilename: "guest-secret.txt",
		MimeType:         "text/plain",
		FileSize:         int64(len(blob)),
		EncryptedSize:    int64(len(blob)),
		IVBase64:         ivBase64,
		ChecksumSHA256:   checksum,
		EncryptedData:    bytes.NewReader(blob),
		GuestSessionID:   &session.ID,
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}

	blobPath := fileSvc.GetFilePath(uploaded)
	if _, err := os.Stat(blobPath); err != nil {
		t.Fatalf("expected uploaded blob on disk: %v", err)
	}

	beforeReq := httptest.NewRequest(http.MethodGet, "/api/v1/files/", nil)
	beforeReq.Header.Set("Authorization", "Bearer "+token)
	beforeResp, err := app.Test(beforeReq, -1)
	if err != nil {
		t.Fatalf("app.Test before cleanup: %v", err)
	}
	if beforeResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 before cleanup, got %d", beforeResp.StatusCode)
	}
	_ = beforeResp.Body.Close()

	expiredAt := time.Now().Add(-1 * time.Hour)
	if _, err := db.Exec(`UPDATE guest_sessions SET expires_at = ? WHERE id = ?`, expiredAt, session.ID); err != nil {
		t.Fatalf("expire guest session: %v", err)
	}

	now := time.Now()
	if err := fileSvc.DeleteByExpiredGuestSessions(now); err != nil {
		t.Fatalf("DeleteByExpiredGuestSessions: %v", err)
	}
	if err := guestRepo.DeleteExpired(); err != nil {
		t.Fatalf("DeleteExpired guest sessions: %v", err)
	}

	if _, err := fileRepo.GetByID(uploaded.ID); err == nil {
		t.Fatalf("expected file metadata to be deleted after cleanup")
	}
	if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
		t.Fatalf("expected blob to be removed after cleanup, got err=%v", err)
	}

	afterReq := httptest.NewRequest(http.MethodGet, "/api/v1/files/", nil)
	afterReq.Header.Set("Authorization", "Bearer "+token)
	afterResp, err := app.Test(afterReq, -1)
	if err != nil {
		t.Fatalf("app.Test after cleanup: %v", err)
	}
	defer afterResp.Body.Close()
	if afterResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after cleanup, got %d", afterResp.StatusCode)
	}
}
