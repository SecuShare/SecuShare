package handler

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/service"
	"github.com/SecuShare/SecuShare/backend/pkg/logger"
	"github.com/SecuShare/SecuShare/backend/pkg/response"
	"github.com/SecuShare/SecuShare/backend/pkg/sanitize"
	"github.com/gofiber/fiber/v2"
)

type FileHandler struct {
	fileSvc *service.FileService
}

func NewFileHandler(fileSvc *service.FileService) *FileHandler {
	return &FileHandler{fileSvc: fileSvc}
}

func (h *FileHandler) Upload(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return response.Unauthorized(c, "authentication required")
	}
	isGuest, ok := c.Locals("is_guest").(bool)
	if !ok {
		return response.Unauthorized(c, "authentication required")
	}

	// Get form file
	fileHeader, err := c.FormFile("file")
	if err != nil {
		return response.BadRequest(c, "file is required")
	}

	// Get metadata
	originalFilename := c.FormValue("original_filename", fileHeader.Filename)
	mimeType := c.FormValue("mime_type", "application/octet-stream")
	fileSizeStr := c.FormValue("file_size_bytes", "0")
	encryptedSizeStr := c.FormValue("encrypted_size_bytes", "0")
	ivBase64 := c.FormValue("iv_base64")
	checksum := c.FormValue("checksum_sha256")

	if ivBase64 == "" || checksum == "" {
		return response.BadRequest(c, "iv_base64 and checksum_sha256 are required")
	}

	// Validate IV is valid base64 and correct length (12 bytes for AES-GCM)
	ivBytes, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil || len(ivBytes) != 12 {
		return response.BadRequest(c, "iv_base64 must be valid base64 encoding of 12 bytes")
	}

	// Validate checksum is valid hex SHA-256 (64 hex characters)
	if len(checksum) != 64 {
		return response.BadRequest(c, "checksum_sha256 must be a 64-character hex string")
	}
	if _, err := hex.DecodeString(checksum); err != nil {
		return response.BadRequest(c, "checksum_sha256 must be valid hexadecimal")
	}

	// Validate MIME type against server-side allowlist
	if !service.AllowedMIMETypes[mimeType] {
		return response.BadRequest(c, "unsupported file type")
	}

	fileSize, err := strconv.ParseInt(fileSizeStr, 10, 64)
	if err != nil {
		return response.BadRequest(c, "invalid file_size_bytes")
	}
	if fileSize <= 0 {
		return response.BadRequest(c, "file_size_bytes must be greater than 0")
	}
	encryptedSize, err := strconv.ParseInt(encryptedSizeStr, 10, 64)
	if err != nil {
		return response.BadRequest(c, "invalid encrypted_size_bytes")
	}
	if encryptedSize <= 0 {
		return response.BadRequest(c, "encrypted_size_bytes must be greater than 0")
	}
	if fileHeader.Size > 0 && encryptedSize != fileHeader.Size {
		return response.BadRequest(c, "encrypted_size_bytes must match uploaded file size")
	}

	// Open uploaded file
	file, err := fileHeader.Open()
	if err != nil {
		return response.InternalError(c, "failed to read file")
	}
	defer file.Close()

	// Create upload request
	var ownerID *string
	var guestSessionID *string
	if isGuest {
		guestSessionID = &userID
	} else {
		ownerID = &userID
	}

	req := &service.UploadRequest{
		OriginalFilename: originalFilename,
		MimeType:         mimeType,
		FileSize:         fileSize,
		EncryptedSize:    encryptedSize,
		IVBase64:         ivBase64,
		ChecksumSHA256:   checksum,
		EncryptedData:    file,
		OwnerID:          ownerID,
		GuestSessionID:   guestSessionID,
	}

	// Handle expiration if provided
	expiresAtStr := c.FormValue("expires_at")
	if expiresAtStr != "" {
		expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
		if err == nil {
			req.ExpiresAt = &expiresAt
		}
	}

	uploadedFile, err := h.fileSvc.Upload(req)
	if err != nil {
		if strings.Contains(err.Error(), "quota") {
			return response.Error(c, fiber.StatusPaymentRequired, err.Error())
		}
		return response.InternalError(c, err.Error())
	}

	return response.Success(c, uploadedFile)
}

func (h *FileHandler) List(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return response.Unauthorized(c, "authentication required")
	}
	isGuest, ok := c.Locals("is_guest").(bool)
	if !ok {
		return response.Unauthorized(c, "authentication required")
	}

	var files interface{}
	var err error

	if isGuest {
		files, err = h.fileSvc.GetByGuestSessionID(userID)
	} else {
		files, err = h.fileSvc.GetByOwnerID(userID)
	}

	if err != nil {
		return response.InternalError(c, "failed to retrieve files")
	}

	return response.Success(c, files)
}

func (h *FileHandler) Delete(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return response.Unauthorized(c, "authentication required")
	}
	isGuest, ok := c.Locals("is_guest").(bool)
	if !ok {
		return response.Unauthorized(c, "authentication required")
	}
	fileID := c.Params("id")

	if fileID == "" {
		return response.BadRequest(c, "file id is required")
	}

	if err := h.fileSvc.Delete(fileID, userID, isGuest); err != nil {
		if strings.Contains(err.Error(), "unauthorized") {
			return response.Forbidden(c, "unauthorized")
		}
		return response.InternalError(c, err.Error())
	}

	logger.Audit("file_deleted", userID, map[string]string{
		"file_id":  fileID,
		"is_guest": strconv.FormatBool(isGuest),
	})

	return response.Success(c, map[string]string{"message": "file deleted"})
}

func (h *FileHandler) Download(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return response.Unauthorized(c, "authentication required")
	}
	isGuest, ok := c.Locals("is_guest").(bool)
	if !ok {
		return response.Unauthorized(c, "authentication required")
	}
	fileID := c.Params("id")

	file, err := h.fileSvc.GetByID(fileID)
	if err != nil {
		return response.NotFound(c, "file not found")
	}

	// Verify ownership
	if isGuest {
		if file.GuestSessionID == nil || *file.GuestSessionID != userID {
			return response.Forbidden(c, "unauthorized")
		}
	} else {
		if file.OwnerID == nil || *file.OwnerID != userID {
			return response.Forbidden(c, "unauthorized")
		}
	}

	filePath := h.fileSvc.GetFilePath(file)

	// Sanitize filenames for headers
	safeFilename := sanitize.SanitizeForHeader(file.EncryptedFilename)
	safeOriginalName := sanitize.SanitizeForHeader(file.OriginalFilename)

	c.Set("Content-Disposition", "attachment; filename=\""+safeFilename+"\"")
	c.Set("Content-Type", "application/octet-stream")
	c.Set("X-Original-Filename", safeOriginalName)
	c.Set("X-Mime-Type", file.MimeType)
	c.Set("X-File-Size", strconv.FormatInt(file.FileSize, 10))
	c.Set("X-IV-Base64", file.IVBase64)
	c.Set("X-Checksum-Sha256", file.ChecksumSHA256)

	return c.SendFile(filePath)
}
