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

func (r *ShareRepository) Create(share *models.Share, allowedEmails []string) (err error) {
	var isActive int
	if share.IsActive {
		isActive = 1
	}
	var requiresEmailVerification int
	if share.RequiresEmailVerification {
		requiresEmailVerification = 1
	}

	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && rollbackErr != sql.ErrTxDone && err == nil {
			err = rollbackErr
		}
	}()

	if _, err := tx.Exec(`
		INSERT INTO shares (id, file_id, password_hash, max_downloads, download_count, requires_email_verification, expires_at, created_at, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, share.ID, share.FileID, share.PasswordHash, share.MaxDownloads, share.DownloadCount, requiresEmailVerification, share.ExpiresAt, share.CreatedAt, isActive); err != nil {
		return err
	}

	if len(allowedEmails) > 0 {
		stmt, err := tx.Prepare(`
			INSERT INTO share_allowed_emails (share_id, email)
			VALUES (?, ?)
		`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for _, email := range allowedEmails {
			if _, err := stmt.Exec(share.ID, email); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (r *ShareRepository) GetByID(id string) (*models.Share, error) {
	share := &models.Share{}
	var isActive, requiresEmailVerification int
	err := r.db.QueryRow(`
		SELECT id, file_id, password_hash, max_downloads, download_count, requires_email_verification, expires_at, created_at, is_active
		FROM shares WHERE id = ?
	`, id).Scan(
		&share.ID,
		&share.FileID,
		&share.PasswordHash,
		&share.MaxDownloads,
		&share.DownloadCount,
		&requiresEmailVerification,
		&share.ExpiresAt,
		&share.CreatedAt,
		&isActive,
	)
	if err != nil {
		return nil, err
	}
	share.IsActive = isActive == 1
	share.RequiresEmailVerification = requiresEmailVerification == 1
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
		SELECT id, file_id, password_hash, max_downloads, download_count, requires_email_verification, expires_at, created_at, is_active
		FROM shares WHERE file_id = ? ORDER BY created_at DESC
	`, fileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var shares []*models.Share
	for rows.Next() {
		share := &models.Share{}
		var isActive, requiresEmailVerification int
		err := rows.Scan(
			&share.ID,
			&share.FileID,
			&share.PasswordHash,
			&share.MaxDownloads,
			&share.DownloadCount,
			&requiresEmailVerification,
			&share.ExpiresAt,
			&share.CreatedAt,
			&isActive,
		)
		if err != nil {
			return nil, err
		}
		share.IsActive = isActive == 1
		share.RequiresEmailVerification = requiresEmailVerification == 1
		shares = append(shares, share)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return shares, nil
}

func (r *ShareRepository) DeleteExpired() error {
	_, err := r.db.Exec(`UPDATE shares SET is_active = 0 WHERE expires_at IS NOT NULL AND expires_at < ?`, time.Now())
	return err
}

func (r *ShareRepository) IsEmailAllowed(shareID, email string) (bool, error) {
	var exists int
	err := r.db.QueryRow(`
		SELECT 1
		FROM share_allowed_emails
		WHERE share_id = ? AND email = ? COLLATE NOCASE
		LIMIT 1
	`, shareID, email).Scan(&exists)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (r *ShareRepository) GetAllowedEmails(shareID string) ([]string, error) {
	rows, err := r.db.Query(`
		SELECT email
		FROM share_allowed_emails
		WHERE share_id = ?
		ORDER BY email ASC
	`, shareID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	emails := make([]string, 0)
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return nil, err
		}
		emails = append(emails, email)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return emails, nil
}

func (r *ShareRepository) UpsertPendingDownloadVerification(p *models.PendingShareDownloadVerification) error {
	_, err := r.db.Exec(`
		INSERT INTO pending_share_download_verifications (
			share_id, email, verification_code_hash, expires_at, resend_after, attempts
		)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(share_id, email) DO UPDATE SET
			verification_code_hash = excluded.verification_code_hash,
			expires_at = excluded.expires_at,
			resend_after = excluded.resend_after,
			attempts = excluded.attempts
	`, p.ShareID, p.Email, p.VerificationCodeHash, p.ExpiresAt, p.ResendAfter, p.Attempts)
	return err
}

func (r *ShareRepository) UpsertPendingDownloadVerificationIfResendAllowed(
	p *models.PendingShareDownloadVerification,
	now time.Time,
) (bool, error) {
	result, err := r.db.Exec(`
		INSERT INTO pending_share_download_verifications (
			share_id, email, verification_code_hash, expires_at, resend_after, attempts
		)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(share_id, email) DO UPDATE SET
			verification_code_hash = excluded.verification_code_hash,
			expires_at = excluded.expires_at,
			resend_after = excluded.resend_after,
			attempts = excluded.attempts
		WHERE pending_share_download_verifications.resend_after <= ?
	`, p.ShareID, p.Email, p.VerificationCodeHash, p.ExpiresAt, p.ResendAfter, p.Attempts, now)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

func (r *ShareRepository) GetPendingDownloadVerification(shareID, email string) (*models.PendingShareDownloadVerification, error) {
	p := &models.PendingShareDownloadVerification{}
	err := r.db.QueryRow(`
		SELECT share_id, email, verification_code_hash, expires_at, resend_after, attempts, created_at
		FROM pending_share_download_verifications
		WHERE share_id = ? AND email = ? COLLATE NOCASE
	`, shareID, email).Scan(
		&p.ShareID,
		&p.Email,
		&p.VerificationCodeHash,
		&p.ExpiresAt,
		&p.ResendAfter,
		&p.Attempts,
		&p.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (r *ShareRepository) ConsumePendingDownloadVerification(
	shareID, email, verificationCodeHash string,
	now time.Time,
	maxAttempts int,
) (bool, error) {
	result, err := r.db.Exec(`
		DELETE FROM pending_share_download_verifications
		WHERE share_id = ?
		AND email = ? COLLATE NOCASE
		AND verification_code_hash = ?
		AND expires_at > ?
		AND attempts < ?
	`, shareID, email, verificationCodeHash, now, maxAttempts)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

func (r *ShareRepository) IncrementPendingDownloadVerificationAttempts(
	shareID, email string,
	now time.Time,
	maxAttempts int,
) (bool, error) {
	result, err := r.db.Exec(`
		UPDATE pending_share_download_verifications
		SET attempts = attempts + 1
		WHERE share_id = ? AND email = ? COLLATE NOCASE
		AND expires_at > ?
		AND attempts < ?
	`, shareID, email, now, maxAttempts)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

func (r *ShareRepository) DeletePendingDownloadVerification(shareID, email string) error {
	_, err := r.db.Exec(`
		DELETE FROM pending_share_download_verifications
		WHERE share_id = ? AND email = ? COLLATE NOCASE
	`, shareID, email)
	return err
}

func (r *ShareRepository) DeletePendingDownloadVerificationIfExpired(
	shareID, email string,
	now time.Time,
) error {
	_, err := r.db.Exec(`
		DELETE FROM pending_share_download_verifications
		WHERE share_id = ? AND email = ? COLLATE NOCASE
		AND expires_at <= ?
	`, shareID, email, now)
	return err
}

func (r *ShareRepository) DeletePendingDownloadVerificationByCodeHash(
	shareID, email, verificationCodeHash string,
) error {
	_, err := r.db.Exec(`
		DELETE FROM pending_share_download_verifications
		WHERE share_id = ? AND email = ? COLLATE NOCASE
		AND verification_code_hash = ?
	`, shareID, email, verificationCodeHash)
	return err
}

func (r *ShareRepository) DeletePendingDownloadVerificationIfAttemptsAtLeast(
	shareID, email string,
	minAttempts int,
) error {
	_, err := r.db.Exec(`
		DELETE FROM pending_share_download_verifications
		WHERE share_id = ? AND email = ? COLLATE NOCASE
		AND attempts >= ?
	`, shareID, email, minAttempts)
	return err
}

func (r *ShareRepository) DeleteExpiredPendingDownloadVerifications(now time.Time) error {
	_, err := r.db.Exec(`
		DELETE FROM pending_share_download_verifications
		WHERE expires_at <= ?
	`, now)
	return err
}
