package models

import "time"

type User struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	OpaqueRecord    []byte    `json:"-"`
	StorageQuota    int64     `json:"storage_quota_bytes"`
	StorageUsed     int64     `json:"storage_used_bytes"`
	CreatedAt       time.Time `json:"created_at"`
	IsEmailVerified bool      `json:"is_email_verified"`
	IsAdmin         bool      `json:"is_admin"`
}

type PendingRegistration struct {
	Email                string
	RegistrationRecord   []byte
	VerificationCodeHash string
	ExpiresAt            time.Time
	ResendAfter          time.Time
	Attempts             int
	CreatedAt            time.Time
}

type GuestSession struct {
	ID           string    `json:"id"`
	IPAddress    *string   `json:"ip_address,omitempty"`
	StorageQuota int64     `json:"storage_quota_bytes"`
	StorageUsed  int64     `json:"storage_used_bytes"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

type File struct {
	ID                string     `json:"id"`
	OwnerID           *string    `json:"owner_id"`
	GuestSessionID    *string    `json:"guest_session_id"`
	OriginalFilename  string     `json:"original_filename"`
	EncryptedFilename string     `json:"encrypted_filename"`
	MimeType          string     `json:"mime_type"`
	FileSize          int64      `json:"file_size_bytes"`
	EncryptedSize     int64      `json:"encrypted_size_bytes"`
	IVBase64          string     `json:"iv_base64"`
	ChecksumSHA256    string     `json:"checksum_sha256"`
	ExpiresAt         *time.Time `json:"expires_at"`
	CreatedAt         time.Time  `json:"created_at"`
}

type Share struct {
	ID            string     `json:"id"`
	FileID        string     `json:"file_id"`
	PasswordHash  *string    `json:"-"`
	MaxDownloads  *int       `json:"max_downloads"`
	DownloadCount int        `json:"download_count"`
	ExpiresAt     *time.Time `json:"expires_at"`
	CreatedAt     time.Time  `json:"created_at"`
	IsActive      bool       `json:"is_active"`
}

type StorageInfo struct {
	Quota int64 `json:"quota"`
	Used  int64 `json:"used"`
	Free  int64 `json:"free"`
}

type AppSetting struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

type UsageStats struct {
	TotalUsers          int   `json:"total_users"`
	TotalFiles          int   `json:"total_files"`
	TotalStorageUsed    int64 `json:"total_storage_used"`
	TotalShares         int   `json:"total_shares"`
	ActiveGuestSessions int   `json:"active_guest_sessions"`
}

type AdminUserInfo struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	StorageQuota    int64     `json:"storage_quota_bytes"`
	StorageUsed     int64     `json:"storage_used_bytes"`
	FileCount       int       `json:"file_count"`
	IsAdmin         bool      `json:"is_admin"`
	IsEmailVerified bool      `json:"is_email_verified"`
	CreatedAt       time.Time `json:"created_at"`
}
