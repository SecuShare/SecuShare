package service

// SettingsProvider provides runtime-configurable settings.
type SettingsProvider interface {
	GetDefaultStorageQuota(isGuest bool) int64
	GetMaxFileSize(isGuest bool) int64
	IsEmailDomainAllowed(email string) bool
	IsSetupCompleted() bool
}
