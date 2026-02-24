package service

import (
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/SecuShare/SecuShare/backend/internal/models"
	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/SecuShare/SecuShare/backend/pkg/logger"
)

type AdminService struct {
	settingsRepo *repository.SettingsRepository
	userRepo     *repository.UserRepository
	cache        map[string]string
	mu           sync.RWMutex
}

func NewAdminService(settingsRepo *repository.SettingsRepository, userRepo *repository.UserRepository) *AdminService {
	svc := &AdminService{
		settingsRepo: settingsRepo,
		userRepo:     userRepo,
		cache:        make(map[string]string),
	}
	svc.RefreshCache()
	return svc
}

func (s *AdminService) RefreshCache() {
	settings, err := s.settingsRepo.GetAll()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to refresh settings cache")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, setting := range settings {
		s.cache[setting.Key] = setting.Value
	}
}

func (s *AdminService) GetCachedSetting(key string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cache[key]
}

func (s *AdminService) GetCachedSettingInt(key string, fallback int64) int64 {
	val := s.GetCachedSetting(key)
	if val == "" {
		return fallback
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

// SettingsProvider implementation

func (s *AdminService) GetDefaultStorageQuota(isGuest bool) int64 {
	if isGuest {
		return s.GetCachedSettingInt("storage_quota_guest", 10485760)
	}
	return s.GetCachedSettingInt("storage_quota_user", 1073741824)
}

func (s *AdminService) GetMaxFileSize(isGuest bool) int64 {
	if isGuest {
		return s.GetCachedSettingInt("max_file_size_guest", 10485760)
	}
	return s.GetCachedSettingInt("max_file_size_user", 104857600)
}

func (s *AdminService) IsEmailDomainAllowed(email string) bool {
	allowed := s.GetCachedSetting("allowed_email_domains")
	if allowed == "" {
		return true // empty = all domains allowed
	}

	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return false
	}
	domain := strings.ToLower(parts[1])

	for _, d := range strings.Split(allowed, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && d == domain {
			return true
		}
	}
	return false
}

func (s *AdminService) IsSetupCompleted() bool {
	return s.GetCachedSetting("setup_completed") == "true"
}

// Admin operations

func (s *AdminService) GetAllSettings() ([]*models.AppSetting, error) {
	return s.settingsRepo.GetAll()
}

func (s *AdminService) UpdateSettings(updates map[string]string) error {
	// Prevent modifying setup_completed via the settings API
	delete(updates, "setup_completed")

	for k, v := range updates {
		if err := s.settingsRepo.Set(k, v); err != nil {
			return err
		}
	}
	s.RefreshCache()
	return nil
}

func (s *AdminService) CompleteSetup() error {
	if err := s.settingsRepo.Set("setup_completed", "true"); err != nil {
		return err
	}
	s.RefreshCache()
	return nil
}

func (s *AdminService) GetUsageStats() (*models.UsageStats, error) {
	return s.userRepo.GetUsageStats()
}

func (s *AdminService) ListUsers() ([]*models.AdminUserInfo, error) {
	return s.userRepo.ListAll()
}

func (s *AdminService) DeleteUser(userID, adminID string) error {
	if userID == adminID {
		return errors.New("cannot delete your own account")
	}

	// Protect the last admin
	target, err := s.userRepo.GetByID(userID)
	if err != nil {
		return errors.New("user not found")
	}

	if target.IsAdmin {
		count, err := s.userRepo.CountAdmins()
		if err != nil {
			return err
		}
		if count <= 1 {
			return errors.New("cannot delete the last admin")
		}
	}

	return s.userRepo.Delete(userID)
}
