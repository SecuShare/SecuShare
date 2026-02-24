package repository

import (
	"database/sql"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/models"
)

type SettingsRepository struct {
	db *sql.DB
}

func NewSettingsRepository(db *sql.DB) *SettingsRepository {
	return &SettingsRepository{db: db}
}

func (r *SettingsRepository) Get(key string) (string, error) {
	var value string
	err := r.db.QueryRow(`SELECT value FROM app_settings WHERE key = ?`, key).Scan(&value)
	return value, err
}

func (r *SettingsRepository) Set(key, value string) error {
	_, err := r.db.Exec(`
		INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, key, value, time.Now())
	return err
}

func (r *SettingsRepository) GetAll() ([]*models.AppSetting, error) {
	rows, err := r.db.Query(`SELECT key, value, updated_at FROM app_settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var settings []*models.AppSetting
	for rows.Next() {
		s := &models.AppSetting{}
		if err := rows.Scan(&s.Key, &s.Value, &s.UpdatedAt); err != nil {
			return nil, err
		}
		settings = append(settings, s)
	}
	return settings, rows.Err()
}
