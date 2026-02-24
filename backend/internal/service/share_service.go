package service

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/config"
	"github.com/SecuShare/SecuShare/backend/internal/models"
	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/SecuShare/SecuShare/backend/pkg/logger"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type ShareService struct {
	shareRepo *repository.ShareRepository
	fileRepo  *repository.FileRepository
	fileSvc   *FileService
	config    *config.Config

	downloadVerificationEmailJobs       chan downloadVerificationEmailJob
	downloadVerificationSendTTL         time.Duration
	sendDownloadVerificationEmailFn     func(email, code string) error
	downloadVerificationEmailWorkerStop chan struct{}
	downloadVerificationEmailWorkerWG   sync.WaitGroup
	downloadVerificationEmailStopOnce   sync.Once
}

const (
	shareVerificationCodeLength  = 6
	shareVerificationCodeTTL     = 10 * time.Minute
	shareVerificationResendDelay = 60 * time.Second
	shareVerificationMaxAttempts = 5
	shareVerificationInvalidCode = "invalid verification code"

	shareVerificationEmailWorkerCount = 4
	shareVerificationEmailQueueSize   = 128
	shareVerificationEmailSendTTL     = 10 * time.Second
)

var (
	ErrShareNotFound                     = errors.New("share not found")
	ErrFileNotFound                      = errors.New("file not found")
	ErrShareInactive                     = errors.New("share is no longer active")
	ErrShareExpired                      = errors.New("share has expired")
	ErrDownloadLimitReached              = errors.New("download limit reached")
	ErrPasswordRequired                  = errors.New("password required")
	ErrInvalidPassword                   = errors.New("invalid password")
	ErrInvalidEmailFormat                = errors.New("invalid email format")
	ErrShareEmailVerificationNotRequired = errors.New("share does not require email verification")
	ErrEmailRequired                     = errors.New("email required")
	ErrVerificationCodeRequired          = errors.New("verification code required")
	ErrInvalidVerificationCode           = errors.New(shareVerificationInvalidCode)
	ErrUnauthorized                      = errors.New("unauthorized")
	ErrDownloadProcessing                = errors.New("failed to process download")
	ErrDownloadVerificationValidation    = errors.New("failed to validate verification code")
)

type downloadVerificationEmailJob struct {
	shareID              string
	email                string
	code                 string
	verificationCodeHash string
}

func wrapDownloadVerificationValidationError(err error) error {
	if err == nil {
		return ErrDownloadVerificationValidation
	}
	return fmt.Errorf("%w: %v", ErrDownloadVerificationValidation, err)
}

func canonicalizeShareEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func isValidShareEmail(email string) bool {
	if len(email) > 254 {
		return false
	}
	addr, err := mail.ParseAddress(email)
	return err == nil && strings.EqualFold(strings.TrimSpace(addr.Address), strings.TrimSpace(email))
}

func NewShareService(
	shareRepo *repository.ShareRepository,
	fileRepo *repository.FileRepository,
	fileSvc *FileService,
	cfg *config.Config,
) *ShareService {
	svc := &ShareService{
		shareRepo: shareRepo,
		fileRepo:  fileRepo,
		fileSvc:   fileSvc,
		config:    cfg,
		downloadVerificationEmailJobs: make(
			chan downloadVerificationEmailJob,
			shareVerificationEmailQueueSize,
		),
		downloadVerificationSendTTL:         shareVerificationEmailSendTTL,
		downloadVerificationEmailWorkerStop: make(chan struct{}),
	}
	svc.startDownloadVerificationEmailWorkers()
	return svc
}

func (s *ShareService) startDownloadVerificationEmailWorkers() {
	for i := 0; i < shareVerificationEmailWorkerCount; i++ {
		s.downloadVerificationEmailWorkerWG.Add(1)
		go func() {
			defer s.downloadVerificationEmailWorkerWG.Done()
			s.downloadVerificationEmailWorker()
		}()
	}
}

func (s *ShareService) downloadVerificationEmailWorker() {
	for {
		select {
		case <-s.downloadVerificationEmailWorkerStop:
			return
		case job, ok := <-s.downloadVerificationEmailJobs:
			if !ok {
				return
			}
			if !s.shouldSendDownloadVerificationEmailJob(job) {
				continue
			}

			if err := s.sendDownloadVerificationEmailWithOverride(job.email, job.code); err != nil {
				logger.Warn().
					Err(err).
					Str("component", "share_download_verification").
					Str("share_id", job.shareID).
					Str("email", job.email).
					Msg("Failed to send download verification email")

				s.cleanupPendingDownloadVerificationAfterSendFailure(
					job.shareID,
					job.email,
					job.verificationCodeHash,
				)
			}
		}
	}
}

// Stop terminates async download verification email workers.
func (s *ShareService) Stop() {
	s.downloadVerificationEmailStopOnce.Do(func() {
		close(s.downloadVerificationEmailWorkerStop)
		s.downloadVerificationEmailWorkerWG.Wait()
	})
}

func (s *ShareService) sendDownloadVerificationEmailWithOverride(email, code string) error {
	if s.sendDownloadVerificationEmailFn != nil {
		return s.sendDownloadVerificationEmailFn(email, code)
	}
	return s.sendDownloadVerificationEmail(email, code)
}

func (s *ShareService) shouldSendDownloadVerificationEmailJob(job downloadVerificationEmailJob) bool {
	pending, err := s.shareRepo.GetPendingDownloadVerification(job.shareID, job.email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false
		}

		logger.Warn().
			Err(err).
			Str("component", "share_download_verification").
			Str("share_id", job.shareID).
			Str("email", job.email).
			Msg("Failed to verify pending download verification before email send")
		return false
	}

	return pending.VerificationCodeHash == job.verificationCodeHash
}

type CreateShareRequest struct {
	FileID        string
	Password      *string
	MaxDownloads  *int
	ExpiresAt     *time.Time
	AllowedEmails []string
}

func (s *ShareService) Create(req *CreateShareRequest) (*models.Share, error) {
	// Verify file exists
	_, err := s.fileRepo.GetByID(req.FileID)
	if err != nil {
		return nil, errors.New("file not found")
	}

	share := &models.Share{
		ID:                        uuid.New().String(),
		FileID:                    req.FileID,
		MaxDownloads:              req.MaxDownloads,
		DownloadCount:             0,
		RequiresEmailVerification: len(req.AllowedEmails) > 0,
		ExpiresAt:                 req.ExpiresAt,
		CreatedAt:                 time.Now(),
		IsActive:                  true,
	}

	// Hash password if provided
	if req.Password != nil && *req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		hashedStr := string(hashedPassword)
		share.PasswordHash = &hashedStr
	}

	if err := s.shareRepo.Create(share, req.AllowedEmails); err != nil {
		return nil, err
	}

	return share, nil
}

func (s *ShareService) GetByID(id string) (*models.Share, error) {
	return s.shareRepo.GetByID(id)
}

func (s *ShareService) GetFile(
	shareID string,
	password *string,
	requesterEmail *string,
	verificationCode *string,
) (*models.File, error) {
	share, err := s.shareRepo.GetByID(shareID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrShareNotFound
		}
		return nil, err
	}

	if err := validateShareDownloadAvailability(share); err != nil {
		return nil, err
	}

	// Verify password if required
	if share.PasswordHash != nil {
		if password == nil {
			return nil, ErrPasswordRequired
		}
		if err := bcrypt.CompareHashAndPassword([]byte(*share.PasswordHash), []byte(*password)); err != nil {
			return nil, ErrInvalidPassword
		}
	}

	if share.RequiresEmailVerification {
		if err := s.consumeDownloadVerificationCode(shareID, requesterEmail, verificationCode); err != nil {
			return nil, err
		}
	}

	// Atomically increment download count and re-verify limits
	allowed, err := s.shareRepo.IncrementDownloadCountAtomic(shareID)
	if err != nil {
		return nil, ErrDownloadProcessing
	}
	if !allowed {
		return nil, ErrDownloadLimitReached
	}

	// Get file
	file, err := s.fileRepo.GetByID(share.FileID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFileNotFound
		}
		return nil, err
	}

	return file, nil
}

func validateShareDownloadAvailability(share *models.Share) error {
	// Check if share is active
	if !share.IsActive {
		return ErrShareInactive
	}

	// Check expiration
	if share.ExpiresAt != nil && share.ExpiresAt.Before(time.Now()) {
		return ErrShareExpired
	}

	// Check download limit
	if share.MaxDownloads != nil && share.DownloadCount >= *share.MaxDownloads {
		return ErrDownloadLimitReached
	}

	return nil
}

func generateShareVerificationCode() (string, error) {
	var b strings.Builder
	b.Grow(shareVerificationCodeLength)

	max := big.NewInt(10)
	for i := 0; i < shareVerificationCodeLength; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(byte('0' + n.Int64()))
	}

	return b.String(), nil
}

func (s *ShareService) hashDownloadVerificationCode(shareID, email, code string) string {
	secret := ""
	if s.config != nil {
		secret = s.config.Auth.DownloadCodeHMACSecret
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(shareID))
	mac.Write([]byte(":"))
	mac.Write([]byte(canonicalizeShareEmail(email)))
	mac.Write([]byte(":"))
	mac.Write([]byte(strings.TrimSpace(code)))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *ShareService) sendDownloadVerificationEmail(email, code string) error {
	host := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	if host == "" {
		if s.config != nil && s.config.IsProduction {
			return errors.New("SMTP_HOST is required in production")
		}
		// Development fallback: keep share verification testable without SMTP.
		logger.Info().
			Str("component", "share_download_verification").
			Str("email", email).
			Str("verification_code", strings.TrimSpace(code)).
			Msg("Download verification code (SMTP_HOST not configured)")
		return nil
	}

	port := strings.TrimSpace(os.Getenv("SMTP_PORT"))
	if port == "" {
		port = "587"
	}

	from := strings.TrimSpace(os.Getenv("SMTP_FROM"))
	if from == "" {
		from = "no-reply@secushare.local"
	}

	username := strings.TrimSpace(os.Getenv("SMTP_USERNAME"))
	password := os.Getenv("SMTP_PASSWORD")

	subject := "SecuShare download verification code"
	body := fmt.Sprintf(
		"Your SecuShare download verification code is: %s\n\nThis code expires in %d minutes.",
		code,
		int(shareVerificationCodeTTL.Minutes()),
	)
	msg := []byte("From: " + from + "\r\n" +
		"To: " + email + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" + body + "\r\n")

	addr := net.JoinHostPort(host, port)
	var auth smtp.Auth
	if username != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}

	if err := sendSMTPMailWithTimeout(
		addr,
		host,
		auth,
		from,
		[]string{email},
		msg,
		s.downloadVerificationSendTTL,
	); err != nil {
		return fmt.Errorf("send download verification email: %w", err)
	}

	return nil
}

func sendSMTPMailWithTimeout(
	addr, host string,
	auth smtp.Auth,
	from string,
	to []string,
	msg []byte,
	timeout time.Duration,
) error {
	if timeout <= 0 {
		timeout = shareVerificationEmailSendTTL
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}

	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return err
	}

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return err
		}
	}

	if auth != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(auth); err != nil {
				return err
			}
		}
	}

	if err := c.Mail(from); err != nil {
		return err
	}
	for _, recipient := range to {
		if err := c.Rcpt(recipient); err != nil {
			return err
		}
	}

	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	return c.Quit()
}

func (s *ShareService) cleanupPendingDownloadVerificationAfterSendFailure(
	shareID, email, verificationCodeHash string,
) {
	if cleanupErr := s.shareRepo.DeletePendingDownloadVerificationByCodeHash(
		shareID,
		email,
		verificationCodeHash,
	); cleanupErr != nil {
		logger.Warn().
			Err(cleanupErr).
			Str("component", "share_download_verification").
			Str("share_id", shareID).
			Str("email", email).
			Msg("Failed to cleanup pending download verification after email send failure")
	}
}

func (s *ShareService) sendDownloadVerificationEmailAsync(
	shareID, email, code, verificationCodeHash string,
) {
	if s.downloadVerificationEmailJobs == nil {
		logger.Warn().
			Str("component", "share_download_verification").
			Str("share_id", shareID).
			Str("email", email).
			Msg("Download verification email queue is unavailable")
		s.cleanupPendingDownloadVerificationAfterSendFailure(shareID, email, verificationCodeHash)
		return
	}

	job := downloadVerificationEmailJob{
		shareID:              shareID,
		email:                email,
		code:                 code,
		verificationCodeHash: verificationCodeHash,
	}

	select {
	case <-s.downloadVerificationEmailWorkerStop:
		logger.Warn().
			Str("component", "share_download_verification").
			Str("share_id", shareID).
			Str("email", email).
			Msg("Download verification email workers are stopped; dropping send request")
		s.cleanupPendingDownloadVerificationAfterSendFailure(shareID, email, verificationCodeHash)
		return
	default:
	}

	select {
	case <-s.downloadVerificationEmailWorkerStop:
		logger.Warn().
			Str("component", "share_download_verification").
			Str("share_id", shareID).
			Str("email", email).
			Msg("Download verification email workers are stopped; dropping send request")
		s.cleanupPendingDownloadVerificationAfterSendFailure(shareID, email, verificationCodeHash)
	case s.downloadVerificationEmailJobs <- job:
	default:
		logger.Warn().
			Str("component", "share_download_verification").
			Str("share_id", shareID).
			Str("email", email).
			Msg("Download verification email queue is full; dropping send request")
		s.cleanupPendingDownloadVerificationAfterSendFailure(shareID, email, verificationCodeHash)
	}
}

func (s *ShareService) RequestDownloadVerificationCode(shareID, email string) error {
	email = canonicalizeShareEmail(email)
	if !isValidShareEmail(email) {
		return ErrInvalidEmailFormat
	}

	share, err := s.shareRepo.GetByID(shareID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrShareNotFound
		}
		return err
	}
	if err := validateShareDownloadAvailability(share); err != nil {
		return err
	}
	if !share.RequiresEmailVerification {
		return ErrShareEmailVerificationNotRequired
	}

	isAllowed, err := s.shareRepo.IsEmailAllowed(shareID, email)
	if err != nil {
		return fmt.Errorf("failed to check allowed emails: %w", err)
	}
	if !isAllowed {
		// Deliberately return success without sending email to avoid exposing allowlist membership.
		return nil
	}

	now := time.Now()
	code, err := generateShareVerificationCode()
	if err != nil {
		logger.Error().
			Err(err).
			Str("component", "share_download_verification").
			Str("share_id", shareID).
			Str("email", email).
			Msg("Failed to generate download verification code")
		return nil
	}

	pending := &models.PendingShareDownloadVerification{
		ShareID:              shareID,
		Email:                email,
		VerificationCodeHash: s.hashDownloadVerificationCode(shareID, email, code),
		ExpiresAt:            now.Add(shareVerificationCodeTTL),
		ResendAfter:          now.Add(shareVerificationResendDelay),
		Attempts:             0,
	}

	stored, err := s.shareRepo.UpsertPendingDownloadVerificationIfResendAllowed(pending, now)
	if err != nil {
		logger.Warn().
			Err(err).
			Str("component", "share_download_verification").
			Str("share_id", shareID).
			Str("email", email).
			Msg("Failed to store pending download verification")
		return nil
	}
	if !stored {
		// Keep response generic to avoid side-channel leaks about allowlist entries.
		return nil
	}

	// Dispatch in the background so request timing and outcome stay generic.
	s.sendDownloadVerificationEmailAsync(shareID, email, code, pending.VerificationCodeHash)

	return nil
}

func (s *ShareService) consumeDownloadVerificationCode(shareID string, requesterEmail *string, verificationCode *string) error {
	if requesterEmail == nil || strings.TrimSpace(*requesterEmail) == "" {
		return ErrEmailRequired
	}
	if verificationCode == nil || strings.TrimSpace(*verificationCode) == "" {
		return ErrVerificationCodeRequired
	}

	email := canonicalizeShareEmail(*requesterEmail)
	if !isValidShareEmail(email) {
		return ErrInvalidEmailFormat
	}
	code := strings.TrimSpace(*verificationCode)

	isAllowed, err := s.shareRepo.IsEmailAllowed(shareID, email)
	if err != nil {
		return wrapDownloadVerificationValidationError(err)
	}
	if !isAllowed {
		return ErrInvalidVerificationCode
	}

	now := time.Now()
	expected := s.hashDownloadVerificationCode(shareID, email, code)
	consumed, err := s.shareRepo.ConsumePendingDownloadVerification(
		shareID,
		email,
		expected,
		now,
		shareVerificationMaxAttempts,
	)
	if err != nil {
		return wrapDownloadVerificationValidationError(err)
	}
	if consumed {
		return nil
	}

	pending, err := s.shareRepo.GetPendingDownloadVerification(shareID, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidVerificationCode
		}
		return wrapDownloadVerificationValidationError(err)
	}

	if now.After(pending.ExpiresAt) {
		_ = s.shareRepo.DeletePendingDownloadVerificationIfExpired(shareID, email, now)
		return ErrInvalidVerificationCode
	}

	if pending.Attempts >= shareVerificationMaxAttempts {
		_ = s.shareRepo.DeletePendingDownloadVerificationIfAttemptsAtLeast(
			shareID,
			email,
			shareVerificationMaxAttempts,
		)
		return ErrInvalidVerificationCode
	}

	// We know the code is wrong here because a matching atomic consume failed.
	incremented, err := s.shareRepo.IncrementPendingDownloadVerificationAttempts(
		shareID,
		email,
		now,
		shareVerificationMaxAttempts,
	)
	if err != nil {
		return wrapDownloadVerificationValidationError(err)
	}
	if incremented {
		_ = s.shareRepo.DeletePendingDownloadVerificationIfAttemptsAtLeast(
			shareID,
			email,
			shareVerificationMaxAttempts,
		)
	}

	return ErrInvalidVerificationCode
}

func (s *ShareService) Deactivate(id string, userID string, isGuest bool) error {
	// Get the share
	share, err := s.shareRepo.GetByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrShareNotFound
		}
		return err
	}

	// Get the file to verify ownership
	file, err := s.fileRepo.GetByID(share.FileID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrFileNotFound
		}
		return err
	}

	// Verify ownership
	if isGuest {
		if file.GuestSessionID == nil || *file.GuestSessionID != userID {
			return ErrUnauthorized
		}
	} else {
		if file.OwnerID == nil || *file.OwnerID != userID {
			return ErrUnauthorized
		}
	}

	return s.shareRepo.Deactivate(id)
}

func (s *ShareService) GetByFileID(fileID string) ([]*models.Share, error) {
	return s.shareRepo.GetByFileID(fileID)
}

func (s *ShareService) GetAllowedEmails(shareID string) ([]string, error) {
	return s.shareRepo.GetAllowedEmails(shareID)
}
