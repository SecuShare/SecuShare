package handler

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/models"
	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/SecuShare/SecuShare/backend/internal/service"
	"github.com/SecuShare/SecuShare/backend/pkg/testutil"
	"github.com/gofiber/fiber/v2"
)

type fileHandlerUploadTestResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   string          `json:"error"`
}

func newFileUploadIntegrationTestApp(t *testing.T) (*fiber.App, *repository.FileRepository, string, func()) {
	t.Helper()

	db, cfg, cleanup := testutil.SetupTest(t)
	userRepo := repository.NewUserRepository(db)
	guestRepo := repository.NewGuestSessionRepository(db)
	fileRepo := repository.NewFileRepository(db)
	fileSvc := service.NewFileService(fileRepo, userRepo, guestRepo, cfg.StoragePath)
	fileHandler := NewFileHandler(fileSvc)

	ownerID := "file-upload-handler-owner"
	if err := userRepo.Create(&models.User{
		ID:              ownerID,
		Email:           "file-upload-handler-owner@example.com",
		OpaqueRecord:    []byte("opaque-record"),
		StorageQuota:    1024 * 1024,
		StorageUsed:     0,
		CreatedAt:       time.Now(),
		IsEmailVerified: true,
	}); err != nil {
		cleanup()
		t.Fatalf("create upload owner: %v", err)
	}

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("user_id", ownerID)
		c.Locals("is_guest", false)
		return c.Next()
	})
	app.Post("/api/v1/files/", fileHandler.Upload)

	return app, fileRepo, ownerID, cleanup
}

func newUploadRequest(
	t *testing.T,
	target string,
	fileBytes []byte,
	fileSize int64,
	encryptedSize int64,
) *http.Request {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	fileWriter, err := writer.CreateFormFile("file", "ciphertext.bin")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fileWriter.Write(fileBytes); err != nil {
		t.Fatalf("write multipart file: %v", err)
	}

	fields := map[string]string{
		"original_filename":    "secret.txt",
		"mime_type":            "text/plain",
		"file_size_bytes":      strconv.FormatInt(fileSize, 10),
		"encrypted_size_bytes": strconv.FormatInt(encryptedSize, 10),
		"iv_base64":            base64.StdEncoding.EncodeToString(make([]byte, 12)),
		"checksum_sha256":      strings.Repeat("a", 64),
	}
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatalf("WriteField %s: %v", key, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, target, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func performUploadRequest(t *testing.T, app *fiber.App, req *http.Request) (int, fileHandlerUploadTestResponse) {
	t.Helper()

	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test upload: %v", err)
	}
	defer resp.Body.Close()

	var parsed fileHandlerUploadTestResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}

	return resp.StatusCode, parsed
}

func assertNoOwnerFiles(
	t *testing.T,
	fileRepo *repository.FileRepository,
	ownerID string,
) {
	t.Helper()

	files, err := fileRepo.GetByOwnerID(ownerID)
	if err != nil {
		t.Fatalf("GetByOwnerID: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected no stored files, got %d", len(files))
	}
}

func TestFileHandler_Upload_RejectsNonPositiveEncryptedSize(t *testing.T) {
	app, fileRepo, ownerID, cleanup := newFileUploadIntegrationTestApp(t)
	defer cleanup()

	fileBytes := []byte{0x11, 0x22, 0x33, 0x44}
	req := newUploadRequest(t, "/api/v1/files/", fileBytes, int64(len(fileBytes)), 0)
	statusCode, parsed := performUploadRequest(t, app, req)

	if statusCode != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", statusCode)
	}
	if parsed.Success {
		t.Fatal("expected success=false for invalid encrypted size")
	}
	if parsed.Error != "encrypted_size_bytes must be greater than 0" {
		t.Fatalf("unexpected error message: %q", parsed.Error)
	}

	assertNoOwnerFiles(t, fileRepo, ownerID)
}

func TestFileHandler_Upload_RejectsNonPositiveFileSize(t *testing.T) {
	app, fileRepo, ownerID, cleanup := newFileUploadIntegrationTestApp(t)
	defer cleanup()

	fileBytes := []byte{0x11, 0x22, 0x33, 0x44}
	req := newUploadRequest(t, "/api/v1/files/", fileBytes, 0, int64(len(fileBytes)))
	statusCode, parsed := performUploadRequest(t, app, req)

	if statusCode != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", statusCode)
	}
	if parsed.Success {
		t.Fatal("expected success=false for invalid file size")
	}
	if parsed.Error != "file_size_bytes must be greater than 0" {
		t.Fatalf("unexpected error message: %q", parsed.Error)
	}

	assertNoOwnerFiles(t, fileRepo, ownerID)
}

func TestFileHandler_Upload_RejectsDeclaredEncryptedSizeMismatch(t *testing.T) {
	app, fileRepo, ownerID, cleanup := newFileUploadIntegrationTestApp(t)
	defer cleanup()

	fileBytes := []byte{0x11, 0x22, 0x33, 0x44}
	req := newUploadRequest(t, "/api/v1/files/", fileBytes, int64(len(fileBytes)), int64(len(fileBytes)-1))
	statusCode, parsed := performUploadRequest(t, app, req)

	if statusCode != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", statusCode)
	}
	if parsed.Success {
		t.Fatal("expected success=false for mismatched encrypted size")
	}
	if parsed.Error != "encrypted_size_bytes must match uploaded file size" {
		t.Fatalf("unexpected error message: %q", parsed.Error)
	}

	assertNoOwnerFiles(t, fileRepo, ownerID)
}
