package repository

import (
	"database/sql"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/models"
)

type FileRepository struct {
	db *sql.DB
}

func NewFileRepository(db *sql.DB) *FileRepository {
	return &FileRepository{db: db}
}

func (r *FileRepository) Create(file *models.File) error {
	_, err := r.db.Exec(`
		INSERT INTO files (id, owner_id, guest_session_id, original_filename, encrypted_filename, mime_type, file_size_bytes, encrypted_size_bytes, iv_base64, checksum_sha256, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, file.ID, file.OwnerID, file.GuestSessionID, file.OriginalFilename, file.EncryptedFilename, file.MimeType, file.FileSize, file.EncryptedSize, file.IVBase64, file.ChecksumSHA256, file.ExpiresAt, file.CreatedAt)
	return err
}

func (r *FileRepository) GetByID(id string) (*models.File, error) {
	file := &models.File{}
	err := r.db.QueryRow(`
		SELECT id, owner_id, guest_session_id, original_filename, encrypted_filename, mime_type, file_size_bytes, encrypted_size_bytes, iv_base64, checksum_sha256, expires_at, created_at
		FROM files WHERE id = ?
	`, id).Scan(&file.ID, &file.OwnerID, &file.GuestSessionID, &file.OriginalFilename, &file.EncryptedFilename, &file.MimeType, &file.FileSize, &file.EncryptedSize, &file.IVBase64, &file.ChecksumSHA256, &file.ExpiresAt, &file.CreatedAt)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (r *FileRepository) GetByOwnerID(ownerID string) ([]*models.File, error) {
	rows, err := r.db.Query(`
		SELECT id, owner_id, guest_session_id, original_filename, encrypted_filename, mime_type, file_size_bytes, encrypted_size_bytes, iv_base64, checksum_sha256, expires_at, created_at
		FROM files WHERE owner_id = ? ORDER BY created_at DESC
	`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*models.File
	for rows.Next() {
		file := &models.File{}
		err := rows.Scan(&file.ID, &file.OwnerID, &file.GuestSessionID, &file.OriginalFilename, &file.EncryptedFilename, &file.MimeType, &file.FileSize, &file.EncryptedSize, &file.IVBase64, &file.ChecksumSHA256, &file.ExpiresAt, &file.CreatedAt)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return files, nil
}

func (r *FileRepository) GetByGuestSessionID(sessionID string) ([]*models.File, error) {
	rows, err := r.db.Query(`
		SELECT id, owner_id, guest_session_id, original_filename, encrypted_filename, mime_type, file_size_bytes, encrypted_size_bytes, iv_base64, checksum_sha256, expires_at, created_at
		FROM files WHERE guest_session_id = ? ORDER BY created_at DESC
	`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*models.File
	for rows.Next() {
		file := &models.File{}
		err := rows.Scan(&file.ID, &file.OwnerID, &file.GuestSessionID, &file.OriginalFilename, &file.EncryptedFilename, &file.MimeType, &file.FileSize, &file.EncryptedSize, &file.IVBase64, &file.ChecksumSHA256, &file.ExpiresAt, &file.CreatedAt)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return files, nil
}

func (r *FileRepository) Delete(id string) error {
	_, err := r.db.Exec(`DELETE FROM files WHERE id = ?`, id)
	return err
}

func (r *FileRepository) GetExpired(now time.Time) ([]*models.File, error) {
	rows, err := r.db.Query(`
		SELECT id, owner_id, guest_session_id, original_filename, encrypted_filename, mime_type, file_size_bytes, encrypted_size_bytes, iv_base64, checksum_sha256, expires_at, created_at
		FROM files
		WHERE expires_at IS NOT NULL AND expires_at < ?
	`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*models.File
	for rows.Next() {
		file := &models.File{}
		err := rows.Scan(&file.ID, &file.OwnerID, &file.GuestSessionID, &file.OriginalFilename, &file.EncryptedFilename, &file.MimeType, &file.FileSize, &file.EncryptedSize, &file.IVBase64, &file.ChecksumSHA256, &file.ExpiresAt, &file.CreatedAt)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return files, nil
}

// GetByExpiredGuestSessions returns files whose owning guest session has expired.
func (r *FileRepository) GetByExpiredGuestSessions(now time.Time) ([]*models.File, error) {
	rows, err := r.db.Query(`
		SELECT f.id, f.owner_id, f.guest_session_id, f.original_filename, f.encrypted_filename, f.mime_type, f.file_size_bytes, f.encrypted_size_bytes, f.iv_base64, f.checksum_sha256, f.expires_at, f.created_at
		FROM files f
		INNER JOIN guest_sessions gs ON gs.id = f.guest_session_id
		WHERE gs.expires_at < ?
	`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*models.File
	for rows.Next() {
		file := &models.File{}
		err := rows.Scan(&file.ID, &file.OwnerID, &file.GuestSessionID, &file.OriginalFilename, &file.EncryptedFilename, &file.MimeType, &file.FileSize, &file.EncryptedSize, &file.IVBase64, &file.ChecksumSHA256, &file.ExpiresAt, &file.CreatedAt)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return files, nil
}

func (r *FileRepository) DeleteExpired() error {
	_, err := r.db.Exec(`DELETE FROM files WHERE expires_at IS NOT NULL AND expires_at < ?`, time.Now())
	return err
}
