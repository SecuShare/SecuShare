package repository

import (
	"database/sql"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/models"
)

type ShareRepository struct {
	db *sql.DB
}

func NewShareRepository(db *sql.DB) *ShareRepository {
	return &ShareRepository{db: db}
}

func (r *ShareRepository) Create(share *models.Share) error {
	var isActive int
	if share.IsActive {
		isActive = 1
	}
	_, err := r.db.Exec(`
		INSERT INTO shares (id, file_id, password_hash, max_downloads, download_count, expires_at, created_at, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, share.ID, share.FileID, share.PasswordHash, share.MaxDownloads, share.DownloadCount, share.ExpiresAt, share.CreatedAt, isActive)
	return err
}

func (r *ShareRepository) GetByID(id string) (*models.Share, error) {
	share := &models.Share{}
	var isActive int
	err := r.db.QueryRow(`
		SELECT id, file_id, password_hash, max_downloads, download_count, expires_at, created_at, is_active
		FROM shares WHERE id = ?
	`, id).Scan(&share.ID, &share.FileID, &share.PasswordHash, &share.MaxDownloads, &share.DownloadCount, &share.ExpiresAt, &share.CreatedAt, &isActive)
	if err != nil {
		return nil, err
	}
	share.IsActive = isActive == 1
	return share, nil
}

func (r *ShareRepository) IncrementDownloadCount(id string) error {
	_, err := r.db.Exec(`UPDATE shares SET download_count = download_count + 1 WHERE id = ?`, id)
	return err
}

// IncrementDownloadCountAtomic atomically checks the download limit and increments the count.
// Returns true if the download was allowed, false if the limit was reached.
func (r *ShareRepository) IncrementDownloadCountAtomic(id string) (bool, error) {
	result, err := r.db.Exec(`
		UPDATE shares SET download_count = download_count + 1
		WHERE id = ? AND is_active = 1
		AND (max_downloads IS NULL OR download_count < max_downloads)
		AND (expires_at IS NULL OR expires_at > datetime('now'))
	`, id)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

func (r *ShareRepository) Deactivate(id string) error {
	_, err := r.db.Exec(`UPDATE shares SET is_active = 0 WHERE id = ?`, id)
	return err
}

func (r *ShareRepository) GetByFileID(fileID string) ([]*models.Share, error) {
	rows, err := r.db.Query(`
		SELECT id, file_id, password_hash, max_downloads, download_count, expires_at, created_at, is_active
		FROM shares WHERE file_id = ? ORDER BY created_at DESC
	`, fileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var shares []*models.Share
	for rows.Next() {
		share := &models.Share{}
		var isActive int
		err := rows.Scan(&share.ID, &share.FileID, &share.PasswordHash, &share.MaxDownloads, &share.DownloadCount, &share.ExpiresAt, &share.CreatedAt, &isActive)
		if err != nil {
			return nil, err
		}
		share.IsActive = isActive == 1
		shares = append(shares, share)
	}
	return shares, nil
}

func (r *ShareRepository) DeleteExpired() error {
	_, err := r.db.Exec(`UPDATE shares SET is_active = 0 WHERE expires_at IS NOT NULL AND expires_at < ?`, time.Now())
	return err
}
