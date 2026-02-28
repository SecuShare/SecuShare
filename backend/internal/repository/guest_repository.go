package repository

import (
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/models"
)

type GuestSessionRepository struct {
	db      *sql.DB
	quotaMu sync.Mutex
}

func NewGuestSessionRepository(db *sql.DB) *GuestSessionRepository {
	return &GuestSessionRepository{db: db}
}

func (r *GuestSessionRepository) Create(session *models.GuestSession) error {
	_, err := r.db.Exec(`
		INSERT INTO guest_sessions (id, storage_quota_bytes, storage_used_bytes, expires_at, created_at, ip_address)
		VALUES (?, ?, ?, ?, ?, ?)
	`, session.ID, session.StorageQuota, session.StorageUsed, session.ExpiresAt, session.CreatedAt, session.IPAddress)
	return err
}

func (r *GuestSessionRepository) GetByID(id string) (*models.GuestSession, error) {
	session := &models.GuestSession{}
	err := r.db.QueryRow(`
		SELECT id, storage_quota_bytes, storage_used_bytes, expires_at, created_at, ip_address
		FROM guest_sessions WHERE id = ?
	`, id).Scan(&session.ID, &session.StorageQuota, &session.StorageUsed, &session.ExpiresAt, &session.CreatedAt, &session.IPAddress)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// GetIPStorageInfo returns aggregate storage usage across all active sessions
// sharing the same IP as the given session. Used for quota display so the UI
// reflects the true remaining capacity regardless of how many sessions an IP has.
func (r *GuestSessionRepository) GetIPStorageInfo(sessionID string) (*models.StorageInfo, error) {
	var ip sql.NullString
	var quota int64
	err := r.db.QueryRow(`
		SELECT ip_address, storage_quota_bytes FROM guest_sessions WHERE id = ?
	`, sessionID).Scan(&ip, &quota)
	if err != nil {
		return nil, err
	}

	var used int64
	if ip.Valid && ip.String != "" {
		err = r.db.QueryRow(`
			SELECT COALESCE(SUM(storage_used_bytes), 0)
			FROM guest_sessions
			WHERE ip_address = ? AND expires_at > ?
		`, ip.String, time.Now()).Scan(&used)
	} else {
		err = r.db.QueryRow(`
			SELECT storage_used_bytes FROM guest_sessions WHERE id = ?
		`, sessionID).Scan(&used)
	}
	if err != nil {
		return nil, err
	}

	return &models.StorageInfo{
		Quota: quota,
		Used:  used,
		Free:  quota - used,
	}, nil
}

func (r *GuestSessionRepository) UpdateStorageUsed(id string, delta int64) error {
	_, err := r.db.Exec(`
		UPDATE guest_sessions SET storage_used_bytes = storage_used_bytes + ? WHERE id = ?
	`, delta, id)
	return err
}

// ReserveStorage atomically checks the per-IP aggregate quota and reserves
// space on the specific session. The mutex ensures the aggregate read and the
// session write are not interleaved with concurrent requests from the same IP.
func (r *GuestSessionRepository) ReserveStorage(id string, size int64) (bool, error) {
	if size <= 0 {
		return false, errors.New("invalid storage reservation size")
	}

	r.quotaMu.Lock()
	defer r.quotaMu.Unlock()

	var ip sql.NullString
	var quota int64
	err := r.db.QueryRow(`
		SELECT ip_address, storage_quota_bytes FROM guest_sessions WHERE id = ?
	`, id).Scan(&ip, &quota)
	if err != nil {
		return false, err
	}

	var currentUsed int64
	if ip.Valid && ip.String != "" {
		// IP-level check: sum storage across all active sessions from this IP.
		err = r.db.QueryRow(`
			SELECT COALESCE(SUM(storage_used_bytes), 0)
			FROM guest_sessions
			WHERE ip_address = ? AND expires_at > ?
		`, ip.String, time.Now()).Scan(&currentUsed)
	} else {
		// Fallback for sessions without an IP: per-session check.
		err = r.db.QueryRow(`
			SELECT storage_used_bytes FROM guest_sessions WHERE id = ?
		`, id).Scan(&currentUsed)
	}
	if err != nil {
		return false, err
	}

	if currentUsed+size > quota {
		return false, nil
	}

	_, err = r.db.Exec(`
		UPDATE guest_sessions SET storage_used_bytes = storage_used_bytes + ? WHERE id = ?
	`, size, id)
	return err == nil, err
}

// ReleaseStorage returns reserved space back to available quota.
func (r *GuestSessionRepository) ReleaseStorage(id string, size int64) {
	if _, err := r.db.Exec(`UPDATE guest_sessions SET storage_used_bytes = MAX(0, storage_used_bytes - ?) WHERE id = ?`, size, id); err != nil {
		return
	}
}

// ReconcileStorageUsage recalculates storage_used_bytes from authoritative file
// metadata, repairing leaked quota reservations after unexpected crashes.
func (r *GuestSessionRepository) ReconcileStorageUsage() error {
	_, err := r.db.Exec(`
		UPDATE guest_sessions
		SET storage_used_bytes = COALESCE((
			SELECT SUM(f.encrypted_size_bytes)
			FROM files f
			WHERE f.guest_session_id = guest_sessions.id
		), 0)
	`)
	return err
}

func (r *GuestSessionRepository) DeleteExpired() error {
	_, err := r.db.Exec(`DELETE FROM guest_sessions WHERE expires_at < ?`, time.Now())
	return err
}
