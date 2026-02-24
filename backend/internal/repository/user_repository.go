package repository

import (
	"database/sql"

	"github.com/SecuShare/SecuShare/backend/internal/models"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(user *models.User) error {
	isAdmin := 0
	if user.IsAdmin {
		isAdmin = 1
	}
	_, err := r.db.Exec(`
		INSERT INTO users (id, email, opaque_record, storage_quota_bytes, storage_used_bytes, created_at, is_email_verified, is_admin)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, user.ID, user.Email, user.OpaqueRecord, user.StorageQuota, user.StorageUsed, user.CreatedAt, user.IsEmailVerified, isAdmin)
	return err
}

func (r *UserRepository) GetByID(id string) (*models.User, error) {
	user := &models.User{}
	var isEmailVerified, isAdmin int
	err := r.db.QueryRow(`
		SELECT id, email, opaque_record, storage_quota_bytes, storage_used_bytes, created_at, is_email_verified, is_admin
		FROM users WHERE id = ?
	`, id).Scan(&user.ID, &user.Email, &user.OpaqueRecord, &user.StorageQuota, &user.StorageUsed, &user.CreatedAt, &isEmailVerified, &isAdmin)
	if err != nil {
		return nil, err
	}
	user.IsEmailVerified = isEmailVerified == 1
	user.IsAdmin = isAdmin == 1
	return user, nil
}

func (r *UserRepository) GetByEmail(email string) (*models.User, error) {
	user := &models.User{}
	var isEmailVerified, isAdmin int
	err := r.db.QueryRow(`
		SELECT id, email, opaque_record, storage_quota_bytes, storage_used_bytes, created_at, is_email_verified, is_admin
		FROM users WHERE email = ? COLLATE NOCASE
	`, email).Scan(&user.ID, &user.Email, &user.OpaqueRecord, &user.StorageQuota, &user.StorageUsed, &user.CreatedAt, &isEmailVerified, &isAdmin)
	if err != nil {
		return nil, err
	}
	user.IsEmailVerified = isEmailVerified == 1
	user.IsAdmin = isAdmin == 1
	return user, nil
}

func (r *UserRepository) UpdateStorageUsed(id string, delta int64) error {
	_, err := r.db.Exec(`
		UPDATE users SET storage_used_bytes = storage_used_bytes + ? WHERE id = ?
	`, delta, id)
	return err
}

// ReserveStorage atomically checks quota and reserves space. Returns true if reserved.
func (r *UserRepository) ReserveStorage(id string, size int64) (bool, error) {
	result, err := r.db.Exec(`
		UPDATE users SET storage_used_bytes = storage_used_bytes + ?
		WHERE id = ? AND (storage_quota_bytes - storage_used_bytes) >= ?
	`, size, id, size)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

// ReleaseStorage returns reserved space back to available quota.
func (r *UserRepository) ReleaseStorage(id string, size int64) {
	r.db.Exec(`UPDATE users SET storage_used_bytes = MAX(0, storage_used_bytes - ?) WHERE id = ?`, size, id)
}

func (r *UserRepository) GetStorageInfo(id string) (*models.StorageInfo, error) {
	info := &models.StorageInfo{}
	err := r.db.QueryRow(`
		SELECT storage_quota_bytes, storage_used_bytes FROM users WHERE id = ?
	`, id).Scan(&info.Quota, &info.Used)
	if err != nil {
		return nil, err
	}
	info.Free = info.Quota - info.Used
	return info, nil
}

func (r *UserRepository) SetEmailVerified(id string, verified bool) error {
	value := 0
	if verified {
		value = 1
	}
	_, err := r.db.Exec(`
		UPDATE users
		SET is_email_verified = ?
		WHERE id = ?
	`, value, id)
	return err
}

func (r *UserRepository) SetAdmin(id string, isAdmin bool) error {
	value := 0
	if isAdmin {
		value = 1
	}
	_, err := r.db.Exec(`UPDATE users SET is_admin = ? WHERE id = ?`, value, id)
	return err
}

func (r *UserRepository) CountAdmins() (int, error) {
	var count int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM users WHERE is_admin = 1`).Scan(&count)
	return count, err
}

func (r *UserRepository) Delete(id string) error {
	_, err := r.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	return err
}

func (r *UserRepository) ListAll() ([]*models.AdminUserInfo, error) {
	rows, err := r.db.Query(`
		SELECT u.id, u.email, u.storage_quota_bytes, u.storage_used_bytes,
		       u.is_admin, u.is_email_verified, u.created_at,
		       COUNT(f.id) as file_count
		FROM users u
		LEFT JOIN files f ON f.owner_id = u.id
		GROUP BY u.id
		ORDER BY u.created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*models.AdminUserInfo
	for rows.Next() {
		u := &models.AdminUserInfo{}
		var isAdmin, isVerified int
		if err := rows.Scan(&u.ID, &u.Email, &u.StorageQuota, &u.StorageUsed,
			&isAdmin, &isVerified, &u.CreatedAt, &u.FileCount); err != nil {
			return nil, err
		}
		u.IsAdmin = isAdmin == 1
		u.IsEmailVerified = isVerified == 1
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *UserRepository) GetUsageStats() (*models.UsageStats, error) {
	stats := &models.UsageStats{}

	if err := r.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&stats.TotalUsers); err != nil {
		return nil, err
	}
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM files`).Scan(&stats.TotalFiles); err != nil {
		return nil, err
	}
	if err := r.db.QueryRow(`SELECT COALESCE(SUM(encrypted_size_bytes), 0) FROM files`).Scan(&stats.TotalStorageUsed); err != nil {
		return nil, err
	}
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM shares WHERE is_active = 1`).Scan(&stats.TotalShares); err != nil {
		return nil, err
	}
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM guest_sessions WHERE expires_at > datetime('now')`).Scan(&stats.ActiveGuestSessions); err != nil {
		return nil, err
	}

	return stats, nil
}
