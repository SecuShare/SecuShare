package service

import (
	"errors"
	"fmt"
	"regexp"
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

const (
	defaultGuestStorageQuota  int64 = 10485760   // 10MB
	defaultUserStorageQuota   int64 = 1073741824 // 1GB
	defaultGuestMaxFileSize   int64 = 10485760   // 10MB
	defaultUserMaxFileSize    int64 = 104857600  // 100MB
	defaultGuestDurationHours       = 24

	minStorageBytes     int64 = 1
	maxStorageBytes     int64 = 1099511627776 // 1TB
	minGuestDurationHrs       = 1
	maxGuestDurationHrs       = 720 // 30 days
)

var allowedDomainPattern = regexp.MustCompile(
	`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`,
)

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
		quota := s.GetCachedSettingInt("storage_quota_guest", defaultGuestStorageQuota)
		if quota <= 0 {
			return defaultGuestStorageQuota
		}
		return quota
	}
	quota := s.GetCachedSettingInt("storage_quota_user", defaultUserStorageQuota)
	if quota <= 0 {
		return defaultUserStorageQuota
	}
	return quota
}

func (s *AdminService) GetMaxFileSize(isGuest bool) int64 {
	if isGuest {
		maxSize := s.GetCachedSettingInt("max_file_size_guest", defaultGuestMaxFileSize)
		if maxSize <= 0 {
			return defaultGuestMaxFileSize
		}
		return maxSize
	}
	maxSize := s.GetCachedSettingInt("max_file_size_user", defaultUserMaxFileSize)
	if maxSize <= 0 {
		return defaultUserMaxFileSize
	}
	return maxSize
}

func (s *AdminService) GetGuestSessionDurationHours() int {
	hours := s.GetCachedSettingInt("guest_session_duration_hours", defaultGuestDurationHours)
	if hours <= 0 {
		return defaultGuestDurationHours
	}
	return int(hours)
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
		normalizedValue, err := normalizeSetting(k, v)
		if err != nil {
			return err
		}
		if err := s.settingsRepo.Set(k, normalizedValue); err != nil {
			return err
		}
	}
	s.RefreshCache()
	return nil
}

func normalizeSetting(key, value string) (string, error) {
	trimmed := strings.TrimSpace(value)

	switch key {
	case "max_file_size_guest", "max_file_size_user", "storage_quota_guest", "storage_quota_user":
		if _, err := parseIntInRange(trimmed, minStorageBytes, maxStorageBytes); err != nil {
			return "", fmt.Errorf("invalid value for %s: %w", key, err)
		}
		return trimmed, nil
	case "guest_session_duration_hours":
		if _, err := parseIntInRange(trimmed, minGuestDurationHrs, maxGuestDurationHrs); err != nil {
			return "", fmt.Errorf("invalid value for %s: %w", key, err)
		}
		return trimmed, nil
	case "allowed_email_domains":
		normalized, err := normalizeAllowedEmailDomains(trimmed)
		if err != nil {
			return "", fmt.Errorf("invalid value for %s: %w", key, err)
		}
		return normalized, nil
	default:
		return "", fmt.Errorf("unknown setting key %q", key)
	}
}

func parseIntInRange(value string, min, max int64) (int64, error) {
	if value == "" {
		return 0, errors.New("value is required")
	}

	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, errors.New("must be an integer")
	}
	if n < min || n > max {
		return 0, fmt.Errorf("must be between %d and %d", min, max)
	}
	return n, nil
}

func normalizeAllowedEmailDomains(value string) (string, error) {
	if value == "" {
		return "", nil
	}

	seen := make(map[string]struct{})
	normalized := make([]string, 0)

	for _, raw := range strings.Split(value, ",") {
		domain := strings.ToLower(strings.TrimSpace(raw))
		if domain == "" {
			continue
		}
		if !allowedDomainPattern.MatchString(domain) {
			return "", fmt.Errorf("invalid domain %q", raw)
		}
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		normalized = append(normalized, domain)
	}

	return strings.Join(normalized, ","), nil
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
