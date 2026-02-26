package service

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/models"
	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/gabriel-vasile/mimetype"
	"github.com/google/uuid"
)

// AllowedMIMETypes defines the MIME types allowed for upload
var AllowedMIMETypes = map[string]bool{
	// Documents
	"application/pdf":    true,
	"application/msword": true,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": true,
	"application/vnd.ms-excel": true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         true,
	"application/vnd.ms-powerpoint":                                             true,
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": true,
	"text/plain":      true,
	"text/csv":        true,
	"application/rtf": true,

	// Images
	"image/jpeg":    true,
	"image/png":     true,
	"image/gif":     true,
	"image/webp":    true,
	"image/svg+xml": true,
	"image/bmp":     true,
	"image/tiff":    true,

	// Audio
	"audio/mpeg": true,
	"audio/wav":  true,
	"audio/ogg":  true,
	"audio/aac":  true,
	"audio/flac": true,

	// Video
	"video/mp4":       true,
	"video/webm":      true,
	"video/ogg":       true,
	"video/quicktime": true,
	"video/x-msvideo": true,

	// Archives
	"application/zip":              true,
	"application/x-rar-compressed": true,
	"application/x-7z-compressed":  true,
	"application/x-tar":            true,
	"application/gzip":             true,

	// Other
	"application/json": true,
	"application/xml":  true,
}

type FileService struct {
	fileRepo    *repository.FileRepository
	userRepo    *repository.UserRepository
	guestRepo   *repository.GuestSessionRepository
	storagePath string
	settings    SettingsProvider
}

func NewFileService(fileRepo *repository.FileRepository, userRepo *repository.UserRepository, guestRepo *repository.GuestSessionRepository, storagePath string) *FileService {
	return &FileService{
		fileRepo:    fileRepo,
		userRepo:    userRepo,
		guestRepo:   guestRepo,
		storagePath: storagePath,
	}
}

type UploadRequest struct {
	OriginalFilename string
	MimeType         string
	FileSize         int64
	EncryptedSize    int64
	IVBase64         string
	ChecksumSHA256   string
	EncryptedData    io.Reader
	OwnerID          *string
	GuestSessionID   *string
	ExpiresAt        *time.Time
}

func (s *FileService) SetSettingsProvider(sp SettingsProvider) {
	s.settings = sp
}

// ReconcileStorageUsage repairs quota drift by recalculating usage from file
// metadata. This is used at startup and periodic maintenance.
func (s *FileService) ReconcileStorageUsage() error {
	if err := s.userRepo.ReconcileStorageUsage(); err != nil {
		return err
	}
	if err := s.guestRepo.ReconcileStorageUsage(); err != nil {
		return err
	}
	return nil
}

func (s *FileService) Upload(req *UploadRequest) (*models.File, error) {
	// Check max file size from settings
	if s.settings != nil {
		isGuest := req.GuestSessionID != nil
		maxSize := s.settings.GetMaxFileSize(isGuest)
		if req.EncryptedSize > maxSize {
			return nil, fmt.Errorf("file exceeds maximum allowed size of %d bytes", maxSize)
		}
	}

	// Atomically reserve storage quota before writing file
	var ownerID string
	var isGuest bool
	if req.OwnerID != nil {
		ownerID = *req.OwnerID
		reserved, err := s.userRepo.ReserveStorage(ownerID, req.EncryptedSize)
		if err != nil {
			return nil, err
		}
		if !reserved {
			return nil, errors.New("storage quota exceeded")
		}
	} else if req.GuestSessionID != nil {
		ownerID = *req.GuestSessionID
		isGuest = true
		reserved, err := s.guestRepo.ReserveStorage(ownerID, req.EncryptedSize)
		if err != nil {
			return nil, err
		}
		if !reserved {
			return nil, errors.New("storage quota exceeded")
		}
	}

	// releaseQuota rolls back the reservation on failure
	releaseQuota := func() {
		if isGuest {
			s.guestRepo.ReleaseStorage(ownerID, req.EncryptedSize)
		} else if ownerID != "" {
			s.userRepo.ReleaseStorage(ownerID, req.EncryptedSize)
		}
	}

	fileID := uuid.New().String()
	encryptedFilename := fileID + ".enc"
	filePath := filepath.Join(s.storagePath, encryptedFilename)

	// Ensure storage directory exists
	if err := os.MkdirAll(s.storagePath, 0750); err != nil {
		releaseQuota()
		return nil, err
	}

	// Write encrypted file to disk
	// #nosec G304 -- filePath is built from trusted storagePath and a server-generated UUID filename.
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		releaseQuota()
		return nil, err
	}
	defer file.Close()

	written, err := io.Copy(file, req.EncryptedData)
	if err != nil {
		removeErr := removeFileIfExists(filePath)
		releaseQuota()
		if removeErr != nil {
			return nil, fmt.Errorf("write encrypted file: %w (cleanup failed: %v)", err, removeErr)
		}
		return nil, err
	}

	// Adjust reservation if actual written size differs from declared size
	if written != req.EncryptedSize {
		diff := req.EncryptedSize - written
		if isGuest {
			s.guestRepo.ReleaseStorage(ownerID, diff)
		} else if ownerID != "" {
			s.userRepo.ReleaseStorage(ownerID, diff)
		}
	}

	// Create file record
	fileRecord := &models.File{
		ID:                fileID,
		OwnerID:           req.OwnerID,
		GuestSessionID:    req.GuestSessionID,
		OriginalFilename:  req.OriginalFilename,
		EncryptedFilename: encryptedFilename,
		MimeType:          req.MimeType,
		FileSize:          req.FileSize,
		EncryptedSize:     written,
		IVBase64:          req.IVBase64,
		ChecksumSHA256:    req.ChecksumSHA256,
		ExpiresAt:         req.ExpiresAt,
		CreatedAt:         time.Now(),
	}

	if err := s.fileRepo.Create(fileRecord); err != nil {
		removeErr := removeFileIfExists(filePath)
		// Release exact written amount since we already adjusted
		if isGuest {
			s.guestRepo.ReleaseStorage(ownerID, written)
		} else if ownerID != "" {
			s.userRepo.ReleaseStorage(ownerID, written)
		}
		if removeErr != nil {
			return nil, fmt.Errorf("persist file metadata: %w (cleanup failed: %v)", err, removeErr)
		}
		return nil, err
	}

	return fileRecord, nil
}

// ValidateMIMEType checks if the detected MIME type matches the claimed type
// and if it's in the allowed list
func ValidateMIMEType(data []byte, claimedType string) error {
	detectedType := mimetype.Detect(data)
	if detectedType == nil {
		return errors.New("unable to detect MIME type")
	}

	// Check if the claimed type is in the allowed list
	if !AllowedMIMETypes[claimedType] {
		// Also check if the detected type is in the allowed list (for aliases)
		if !AllowedMIMETypes[detectedType.String()] {
			return errors.New("MIME type not allowed")
		}
	}

	return nil
}

func (s *FileService) GetByID(id string) (*models.File, error) {
	return s.fileRepo.GetByID(id)
}

func (s *FileService) GetByOwnerID(ownerID string) ([]*models.File, error) {
	return s.fileRepo.GetByOwnerID(ownerID)
}

func (s *FileService) GetByGuestSessionID(sessionID string) ([]*models.File, error) {
	return s.fileRepo.GetByGuestSessionID(sessionID)
}

func (s *FileService) GetFilePath(file *models.File) string {
	return filepath.Join(s.storagePath, file.EncryptedFilename)
}

func (s *FileService) Delete(id string, ownerID string, isGuest bool) error {
	file, err := s.fileRepo.GetByID(id)
	if err != nil {
		return err
	}

	// Verify ownership
	if isGuest {
		if file.GuestSessionID == nil || *file.GuestSessionID != ownerID {
			return errors.New("unauthorized")
		}
	} else {
		if file.OwnerID == nil || *file.OwnerID != ownerID {
			return errors.New("unauthorized")
		}
	}

	// Delete from database first (authoritative state), then clean up disk
	if err := s.fileRepo.Delete(id); err != nil {
		return err
	}

	// Release storage quota
	if file.OwnerID != nil {
		s.userRepo.ReleaseStorage(*file.OwnerID, file.EncryptedSize)
	} else if file.GuestSessionID != nil {
		s.guestRepo.ReleaseStorage(*file.GuestSessionID, file.EncryptedSize)
	}

	// Remove file from disk (best-effort; orphaned files cleaned up by background job)
	filePath := s.GetFilePath(file)
	if err := removeFileIfExists(filePath); err != nil {
		return fmt.Errorf("remove file blob: %w", err)
	}

	return nil
}

// DeleteExpired removes expired file metadata and encrypted blobs, and releases
// reserved storage from the corresponding user/guest quotas.
func (s *FileService) DeleteExpired(now time.Time) error {
	expiredFiles, err := s.fileRepo.GetExpired(now)
	if err != nil {
		return err
	}

	var cleanupErrors []string
	for _, file := range expiredFiles {
		if err := s.fileRepo.Delete(file.ID); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("delete metadata for file %s: %v", file.ID, err))
			continue
		}

		if file.OwnerID != nil {
			s.userRepo.ReleaseStorage(*file.OwnerID, file.EncryptedSize)
		} else if file.GuestSessionID != nil {
			s.guestRepo.ReleaseStorage(*file.GuestSessionID, file.EncryptedSize)
		}

		filePath := s.GetFilePath(file)
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("remove blob for file %s: %v", file.ID, err))
		}
	}

	if len(cleanupErrors) > 0 {
		return errors.New(strings.Join(cleanupErrors, "; "))
	}

	return nil
}

// DeleteByExpiredGuestSessions removes files owned by guest sessions that have
// already expired. This prevents orphaned encrypted blobs when guest sessions
// are later deleted with ON DELETE CASCADE.
func (s *FileService) DeleteByExpiredGuestSessions(now time.Time) error {
	expiredGuestFiles, err := s.fileRepo.GetByExpiredGuestSessions(now)
	if err != nil {
		return err
	}

	var cleanupErrors []string
	for _, file := range expiredGuestFiles {
		if err := s.fileRepo.Delete(file.ID); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("delete metadata for expired guest file %s: %v", file.ID, err))
			continue
		}

		if file.GuestSessionID != nil {
			s.guestRepo.ReleaseStorage(*file.GuestSessionID, file.EncryptedSize)
		}

		filePath := s.GetFilePath(file)
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("remove blob for expired guest file %s: %v", file.ID, err))
		}
	}

	if len(cleanupErrors) > 0 {
		return errors.New(strings.Join(cleanupErrors, "; "))
	}

	return nil
}

// DeleteAsAdmin removes a file without ownership checks (admin-only).
func (s *FileService) DeleteAsAdmin(fileID string) error {
	file, err := s.fileRepo.GetByID(fileID)
	if err != nil {
		return err
	}

	if err := s.fileRepo.Delete(fileID); err != nil {
		return err
	}

	if file.OwnerID != nil {
		s.userRepo.ReleaseStorage(*file.OwnerID, file.EncryptedSize)
	} else if file.GuestSessionID != nil {
		s.guestRepo.ReleaseStorage(*file.GuestSessionID, file.EncryptedSize)
	}

	filePath := s.GetFilePath(file)
	if err := removeFileIfExists(filePath); err != nil {
		return fmt.Errorf("remove file blob: %w", err)
	}

	return nil
}

func removeFileIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
