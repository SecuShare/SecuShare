package service

// SettingsProvider provides runtime-configurable settings.
type SettingsProvider interface {
	GetDefaultStorageQuota(isGuest bool) int64
	GetMaxFileSize(isGuest bool) int64
	GetGuestSessionDurationHours() int
	IsEmailDomainAllowed(email string) bool
	IsSetupCompleted() bool
}
