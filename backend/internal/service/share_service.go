package service

import (
	"errors"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/models"
	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type ShareService struct {
	shareRepo *repository.ShareRepository
	fileRepo  *repository.FileRepository
	fileSvc   *FileService
}

func NewShareService(shareRepo *repository.ShareRepository, fileRepo *repository.FileRepository, fileSvc *FileService) *ShareService {
	return &ShareService{
		shareRepo: shareRepo,
		fileRepo:  fileRepo,
		fileSvc:   fileSvc,
	}
}

type CreateShareRequest struct {
	FileID       string
	Password     *string
	MaxDownloads *int
	ExpiresAt    *time.Time
}

func (s *ShareService) Create(req *CreateShareRequest) (*models.Share, error) {
	// Verify file exists
	_, err := s.fileRepo.GetByID(req.FileID)
	if err != nil {
		return nil, errors.New("file not found")
	}

	share := &models.Share{
		ID:            uuid.New().String(),
		FileID:        req.FileID,
		MaxDownloads:  req.MaxDownloads,
		DownloadCount: 0,
		ExpiresAt:     req.ExpiresAt,
		CreatedAt:     time.Now(),
		IsActive:      true,
	}

	// Hash password if provided
	if req.Password != nil && *req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		hashedStr := string(hashedPassword)
		share.PasswordHash = &hashedStr
	}

	if err := s.shareRepo.Create(share); err != nil {
		return nil, err
	}

	return share, nil
}

func (s *ShareService) GetByID(id string) (*models.Share, error) {
	return s.shareRepo.GetByID(id)
}

func (s *ShareService) GetFile(shareID string, password *string) (*models.File, error) {
	share, err := s.shareRepo.GetByID(shareID)
	if err != nil {
		return nil, err
	}

	// Check if share is active
	if !share.IsActive {
		return nil, errors.New("share is no longer active")
	}

	// Check expiration
	if share.ExpiresAt != nil && share.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("share has expired")
	}

	// Check download limit
	if share.MaxDownloads != nil && share.DownloadCount >= *share.MaxDownloads {
		return nil, errors.New("download limit reached")
	}

	// Verify password if required
	if share.PasswordHash != nil {
		if password == nil {
			return nil, errors.New("password required")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(*share.PasswordHash), []byte(*password)); err != nil {
			return nil, errors.New("invalid password")
		}
	}

	// Atomically increment download count and re-verify limits
	allowed, err := s.shareRepo.IncrementDownloadCountAtomic(shareID)
	if err != nil {
		return nil, errors.New("failed to process download")
	}
	if !allowed {
		return nil, errors.New("download limit reached")
	}

	// Get file
	file, err := s.fileRepo.GetByID(share.FileID)
	if err != nil {
		return nil, err
	}

	return file, nil
}

func (s *ShareService) Deactivate(id string, userID string, isGuest bool) error {
	// Get the share
	share, err := s.shareRepo.GetByID(id)
	if err != nil {
		return err
	}

	// Get the file to verify ownership
	file, err := s.fileRepo.GetByID(share.FileID)
	if err != nil {
		return errors.New("file not found")
	}

	// Verify ownership
	if isGuest {
		if file.GuestSessionID == nil || *file.GuestSessionID != userID {
			return errors.New("unauthorized")
		}
	} else {
		if file.OwnerID == nil || *file.OwnerID != userID {
			return errors.New("unauthorized")
		}
	}

	return s.shareRepo.Deactivate(id)
}

func (s *ShareService) GetByFileID(fileID string) ([]*models.Share, error) {
	return s.shareRepo.GetByFileID(fileID)
}
