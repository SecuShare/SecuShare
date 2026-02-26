package repository

import (
	"database/sql"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/models"
)

type PendingRegistrationRepository struct {
	db *sql.DB
}

func NewPendingRegistrationRepository(db *sql.DB) *PendingRegistrationRepository {
	return &PendingRegistrationRepository{db: db}
}

func (r *PendingRegistrationRepository) Upsert(p *models.PendingRegistration) error {
	_, err := r.db.Exec(`
		INSERT INTO pending_registrations (email, registration_record, verification_code_hash, expires_at, resend_after, attempts)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(email) DO UPDATE SET
			registration_record = excluded.registration_record,
			verification_code_hash = excluded.verification_code_hash,
			expires_at = excluded.expires_at,
			resend_after = excluded.resend_after,
			attempts = excluded.attempts
	`, p.Email, p.RegistrationRecord, p.VerificationCodeHash, p.ExpiresAt, p.ResendAfter, p.Attempts)
	return err
}

func (r *PendingRegistrationRepository) GetByEmail(email string) (*models.PendingRegistration, error) {
	p := &models.PendingRegistration{}
	err := r.db.QueryRow(`
		SELECT email, registration_record, verification_code_hash, expires_at, resend_after, attempts, created_at
		FROM pending_registrations
		WHERE email = ? COLLATE NOCASE
	`, email).Scan(
		&p.Email,
		&p.RegistrationRecord,
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

// IncrementAttempts atomically increments the attempt counter for the given
// email only if the current count is below maxAttempts. It returns true if the
// increment succeeded (i.e. the caller is within the attempt budget) or false
// if the limit has been reached.
func (r *PendingRegistrationRepository) IncrementAttempts(email string, maxAttempts int) (bool, error) {
	result, err := r.db.Exec(`
		UPDATE pending_registrations
		SET attempts = attempts + 1
		WHERE email = ? COLLATE NOCASE AND attempts < ?
	`, email, maxAttempts)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (r *PendingRegistrationRepository) DeleteByEmail(email string) error {
	_, err := r.db.Exec(`
		DELETE FROM pending_registrations
		WHERE email = ? COLLATE NOCASE
	`, email)
	return err
}

func (r *PendingRegistrationRepository) DeleteExpired(now time.Time) error {
	_, err := r.db.Exec(`
		DELETE FROM pending_registrations
		WHERE expires_at <= ?
	`, now)
	return err
}
