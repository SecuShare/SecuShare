package handler

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/service"
	"github.com/SecuShare/SecuShare/backend/pkg/logger"
	"github.com/SecuShare/SecuShare/backend/pkg/response"
	"github.com/SecuShare/SecuShare/backend/pkg/sanitize"
	"github.com/gofiber/fiber/v2"
)

// sharePasswordAttempts tracks failed password attempts per share+IP key.
type sharePasswordAttempts struct {
	mu       sync.Mutex
	attempts map[string]*attemptInfo
}

type attemptInfo struct {
	count    int
	lockedAt time.Time
}

var shareAttempts = &sharePasswordAttempts{
	attempts: make(map[string]*attemptInfo),
}

const maxSharePasswordAttempts = 5
const sharePasswordLockDuration = 15 * time.Minute

func (s *sharePasswordAttempts) check(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, exists := s.attempts[key]
	if !exists {
		return true
	}
	if info.count >= maxSharePasswordAttempts {
		if time.Since(info.lockedAt) < sharePasswordLockDuration {
			return false
		}
		// Reset after lock duration
		delete(s.attempts, key)
		return true
	}
	return true
}

func (s *sharePasswordAttempts) recordFailure(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, exists := s.attempts[key]
	if !exists {
		s.attempts[key] = &attemptInfo{count: 1, lockedAt: time.Now()}
		return
	}
	info.count++
	info.lockedAt = time.Now()
}

func (s *sharePasswordAttempts) reset(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.attempts, key)
}

// mimeToDisplayName returns a generic display name based on MIME type,
// avoiding exposure of the original filename in public share info.
func mimeToDisplayName(mimeType string) string {
	category := strings.SplitN(mimeType, "/", 2)[0]
	switch category {
	case "image":
		return "Image file"
	case "video":
		return "Video file"
	case "audio":
		return "Audio file"
	case "text":
		return "Text file"
	default:
		return "Shared file"
	}
}

type ShareHandler struct {
	shareSvc *service.ShareService
	fileSvc  *service.FileService
}

func NewShareHandler(shareSvc *service.ShareService, fileSvc *service.FileService) *ShareHandler {
	return &ShareHandler{shareSvc: shareSvc, fileSvc: fileSvc}
}

type CreateShareRequest struct {
	FileID       string  `json:"file_id"`
	Password     *string `json:"password"`
	MaxDownloads *int    `json:"max_downloads"`
	ExpiresAt    *string `json:"expires_at"`
}

func (h *ShareHandler) Create(c *fiber.Ctx) error {
	var req CreateShareRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "invalid request body")
	}

	if req.FileID == "" {
		return response.BadRequest(c, "file_id is required")
	}

	// Verify file ownership
	userID := c.Locals("user_id").(string)
	isGuest := c.Locals("is_guest").(bool)

	file, err := h.fileSvc.GetByID(req.FileID)
	if err != nil {
		return response.NotFound(c, "file not found")
	}

	// Check ownership
	if isGuest {
		if file.GuestSessionID == nil || *file.GuestSessionID != userID {
			return response.Forbidden(c, "unauthorized")
		}
	} else {
		if file.OwnerID == nil || *file.OwnerID != userID {
			return response.Forbidden(c, "unauthorized")
		}
	}

	// Parse expiration time
	var expiresAt *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			return response.BadRequest(c, "invalid expires_at format")
		}
		expiresAt = &t
	}

	shareReq := &service.CreateShareRequest{
		FileID:       req.FileID,
		Password:     req.Password,
		MaxDownloads: req.MaxDownloads,
		ExpiresAt:    expiresAt,
	}

	share, err := h.shareSvc.Create(shareReq)
	if err != nil {
		return response.InternalError(c, err.Error())
	}

	return response.Success(c, share)
}

type GetShareRequest struct {
	Password *string `json:"password"`
}

func (h *ShareHandler) GetShare(c *fiber.Ctx) error {
	shareID := c.Params("id")

	share, err := h.shareSvc.GetByID(shareID)
	if err != nil {
		return response.NotFound(c, "share not found")
	}

	// Get file info
	file, err := h.fileSvc.GetByID(share.FileID)
	if err != nil {
		return response.NotFound(c, "file not found")
	}

	// Don't expose the original filename in the public share info response.
	// Use a generic display name derived from the MIME type.
	displayName := mimeToDisplayName(file.MimeType)

	return response.Success(c, map[string]interface{}{
		"id":              share.ID,
		"file_name":       displayName,
		"file_size_bytes": file.FileSize,
		"mime_type":       file.MimeType,
		"has_password":    share.PasswordHash != nil,
		"expires_at":      share.ExpiresAt,
		"download_count":  share.DownloadCount,
		"max_downloads":   share.MaxDownloads,
	})
}

func (h *ShareHandler) DownloadFile(c *fiber.Ctx) error {
	shareID := c.Params("id")
	attemptKey := shareID + ":" + c.IP()

	// Check brute-force lockout by share+IP to avoid global share lockout.
	if !shareAttempts.check(attemptKey) {
		return response.Error(c, fiber.StatusTooManyRequests, "too many failed attempts, please try again later")
	}

	var req GetShareRequest
	if err := c.BodyParser(&req); err != nil {
		// Body is optional for non-password-protected shares
		req.Password = nil
	}

	file, err := h.shareSvc.GetFile(shareID, req.Password)
	if err != nil {
		if strings.Contains(err.Error(), "password") {
			shareAttempts.recordFailure(attemptKey)
			return response.Error(c, fiber.StatusUnauthorized, err.Error())
		}
		if strings.Contains(err.Error(), "expired") || strings.Contains(err.Error(), "limit") || strings.Contains(err.Error(), "active") {
			return response.Error(c, fiber.StatusGone, err.Error())
		}
		return response.NotFound(c, err.Error())
	}

	// Successful access — reset brute-force counter
	shareAttempts.reset(attemptKey)

	filePath := h.fileSvc.GetFilePath(file)

	// Sanitize filenames for headers
	safeFilename := sanitize.SanitizeForHeader(file.EncryptedFilename)
	safeOriginalName := sanitize.SanitizeForHeader(file.OriginalFilename)

	c.Set("Content-Disposition", "attachment; filename=\""+safeFilename+"\"")
	c.Set("Content-Type", "application/octet-stream")
	c.Set("Content-Length", strconv.FormatInt(file.EncryptedSize, 10))
	c.Set("X-Original-Filename", safeOriginalName)
	c.Set("X-Mime-Type", file.MimeType)
	c.Set("X-File-Size", strconv.FormatInt(file.FileSize, 10))
	c.Set("X-IV-Base64", file.IVBase64)
	c.Set("X-Checksum-Sha256", file.ChecksumSHA256)

	return c.SendFile(filePath)
}

func (h *ShareHandler) ListByFile(c *fiber.Ctx) error {
	fileID := c.Params("id")
	userID := c.Locals("user_id").(string)
	isGuest := c.Locals("is_guest").(bool)

	// Verify file ownership
	file, err := h.fileSvc.GetByID(fileID)
	if err != nil {
		return response.NotFound(c, "file not found")
	}

	if isGuest {
		if file.GuestSessionID == nil || *file.GuestSessionID != userID {
			return response.Forbidden(c, "unauthorized")
		}
	} else {
		if file.OwnerID == nil || *file.OwnerID != userID {
			return response.Forbidden(c, "unauthorized")
		}
	}

	shares, err := h.shareSvc.GetByFileID(fileID)
	if err != nil {
		return response.InternalError(c, "failed to get shares")
	}

	result := make([]map[string]interface{}, 0, len(shares))
	for _, share := range shares {
		result = append(result, map[string]interface{}{
			"id":             share.ID,
			"file_id":        share.FileID,
			"has_password":   share.PasswordHash != nil,
			"max_downloads":  share.MaxDownloads,
			"download_count": share.DownloadCount,
			"expires_at":     share.ExpiresAt,
			"created_at":     share.CreatedAt,
			"is_active":      share.IsActive,
		})
	}

	return response.Success(c, result)
}

func (h *ShareHandler) Deactivate(c *fiber.Ctx) error {
	shareID := c.Params("id")
	userID := c.Locals("user_id").(string)
	isGuest := c.Locals("is_guest").(bool)

	if err := h.shareSvc.Deactivate(shareID, userID, isGuest); err != nil {
		if strings.Contains(err.Error(), "unauthorized") {
			return response.Forbidden(c, "unauthorized")
		}
		return response.InternalError(c, "failed to deactivate share")
	}

	logger.Audit("share_deactivated", userID, map[string]string{
		"share_id": shareID,
		"is_guest": strconv.FormatBool(isGuest),
	})

	return response.Success(c, map[string]string{"message": "share deactivated"})
}
