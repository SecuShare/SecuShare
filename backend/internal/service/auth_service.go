package service

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/config"
	"github.com/SecuShare/SecuShare/backend/internal/models"
	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/SecuShare/SecuShare/backend/pkg/logger"
	"github.com/bytemare/opaque"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// opaqueServerSetup holds the serialized server key material.
type opaqueServerSetup struct {
	PrivateKey []byte `json:"private_key"`
	PublicKey  []byte `json:"public_key"`
	OPRFSeed   []byte `json:"oprf_seed"`
}

// loginState holds ephemeral server-side state between LoginInit and LoginFinish.
type loginState struct {
	akeState []byte
	userID   string
	isFake   bool
	expires  time.Time
}

type AuthService struct {
	userRepo    *repository.UserRepository
	guestRepo   *repository.GuestSessionRepository
	pendingRepo *repository.PendingRegistrationRepository
	config      *config.Config
	settings    SettingsProvider
	opaqueConf  *opaque.Configuration
	privateKey  []byte
	publicKey   []byte
	oprfSeed    []byte
	serverID    []byte
	traceAuth   bool
	loginStates sync.Map // map[string]*loginState
	loginStopCh chan struct{}
	loginStopMu sync.Once
}

type Claims struct {
	UserID  string `json:"user_id"`
	IsGuest bool   `json:"is_guest"`
	jwt.RegisteredClaims
}

const (
	opaqueEnvPath            = ".env"
	verificationCodeLength   = 6
	verificationCodeTTL      = 10 * time.Minute
	verificationResendDelay  = 60 * time.Second
	verificationMaxAttempts  = 5
	verificationEmailSendTTL = 10 * time.Second
	loginStateTTL            = 5 * time.Minute
	verificationFailureMsg   = "invalid or expired verification code"
)

func canonicalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func NewAuthService(
	userRepo *repository.UserRepository,
	guestRepo *repository.GuestSessionRepository,
	pendingRepo *repository.PendingRegistrationRepository,
	cfg *config.Config,
) (*AuthService, error) {
	conf := opaque.DefaultConfiguration()

	var privateKey, publicKey, oprfSeed []byte
	serverID := []byte(os.Getenv("OPAQUE_SERVER_IDENTIFIER"))
	if len(serverID) == 0 {
		serverID = nil
	}

	if cfg.Auth.OPAQUEServerSetup == "" {
		oprfSeed = conf.GenerateOPRFSeed()
		privateKey, publicKey = conf.KeyGen()

		setup := opaqueServerSetup{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
			OPRFSeed:   oprfSeed,
		}
		setupJSON, err := json.Marshal(setup)
		if err != nil {
			return nil, fmt.Errorf("failed to encode OPAQUE_SERVER_SETUP: %w", err)
		}
		encoded := base64.StdEncoding.EncodeToString(setupJSON)

		if err := appendOPAQUESetupToEnv(encoded); err != nil {
			logger.Warn().Err(err).Msg("Failed to auto-persist OPAQUE_SERVER_SETUP to .env. Login will break on restart.")
		} else {
			logger.Info().Msg("OPAQUE_SERVER_SETUP auto-generated and persisted to .env for development.")
		}
	} else {
		raw, err := base64.StdEncoding.DecodeString(cfg.Auth.OPAQUEServerSetup)
		if err != nil {
			return nil, fmt.Errorf("invalid OPAQUE_SERVER_SETUP (base64 decode): %w", err)
		}
		var setup opaqueServerSetup
		if err := json.Unmarshal(raw, &setup); err != nil {
			return nil, fmt.Errorf("invalid OPAQUE_SERVER_SETUP (JSON decode): %w", err)
		}
		privateKey = setup.PrivateKey
		publicKey = setup.PublicKey
		oprfSeed = setup.OPRFSeed
	}

	// Validate key material by creating a test server instance.
	testServer, err := conf.Server()
	if err != nil {
		return nil, fmt.Errorf("failed to create OPAQUE server: %w", err)
	}
	if err := testServer.SetKeyMaterial(serverID, privateKey, publicKey, oprfSeed); err != nil {
		return nil, fmt.Errorf("invalid OPAQUE server key material: %w", err)
	}

	svc := &AuthService{
		userRepo:    userRepo,
		guestRepo:   guestRepo,
		pendingRepo: pendingRepo,
		config:      cfg,
		opaqueConf:  conf,
		privateKey:  privateKey,
		publicKey:   publicKey,
		oprfSeed:    oprfSeed,
		serverID:    serverID,
		traceAuth:   os.Getenv("AUTH_TRACE") == "1",
		loginStopCh: make(chan struct{}),
	}

	go svc.cleanupLoginStates()

	return svc, nil
}

func shortHash(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:8])
}

func (s *AuthService) trace(msg string, fields map[string]string) {
	if !s.traceAuth {
		return
	}

	e := logger.Info().Str("component", "auth_trace").Str("msg", msg)
	for k, v := range fields {
		e = e.Str(k, v)
	}
	e.Msg("opaque-debug")
}

func appendOPAQUESetupToEnv(encodedSetup string) error {
	// #nosec G304 -- fixed application-controlled path used for local development bootstrap.
	content, err := os.ReadFile(opaqueEnvPath)
	if err != nil {
		if os.IsNotExist(err) {
			return os.WriteFile(opaqueEnvPath, []byte("OPAQUE_SERVER_SETUP="+encodedSetup+"\n"), 0600)
		}
		return err
	}

	lines := strings.Split(string(content), "\n")
	existingIdx := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "OPAQUE_SERVER_SETUP=") {
			existingIdx = i
			break
		}
	}

	if existingIdx >= 0 {
		parts := strings.SplitN(lines[existingIdx], "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
			return nil
		}
		lines[existingIdx] = "OPAQUE_SERVER_SETUP=" + encodedSetup
		return os.WriteFile(opaqueEnvPath, []byte(strings.Join(lines, "\n")), 0600)
	}

	// #nosec G304 -- fixed application-controlled path used for local development bootstrap.
	f, err := os.OpenFile(opaqueEnvPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString("\n# OPAQUE server keys (auto-generated for development)\nOPAQUE_SERVER_SETUP=" + encodedSetup + "\n")
	return err
}

func (s *AuthService) cleanupLoginStates() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.loginStates.Range(func(key, value interface{}) bool {
				state, ok := value.(*loginState)
				if !ok || now.After(state.expires) {
					s.loginStates.Delete(key)
				}
				return true
			})
		case <-s.loginStopCh:
			return
		}
	}
}

// newServer creates a fresh Server instance with key material loaded.
func (s *AuthService) newServer() (*opaque.Server, error) {
	server, err := s.opaqueConf.Server()
	if err != nil {
		return nil, err
	}
	if err := server.SetKeyMaterial(s.serverID, s.privateKey, s.publicKey, s.oprfSeed); err != nil {
		return nil, err
	}
	return server, nil
}

func (s *AuthService) prepareRegistrationRecord(email, password string) ([]byte, error) {
	client, err := s.opaqueConf.Client()
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	regReq := client.RegistrationInit([]byte(password))
	regRespBytes, err := s.RegisterInit(email, regReq.Serialize())
	if err != nil {
		return nil, err
	}

	regResp, err := client.Deserialize.RegistrationResponse(regRespBytes)
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	record, _ := client.RegistrationFinalize(regResp, opaque.ClientRegistrationFinalizeOptions{})
	return record.Serialize(), nil
}

func generateVerificationCode() (string, error) {
	var b strings.Builder
	b.Grow(verificationCodeLength)

	max := big.NewInt(10)
	for i := 0; i < verificationCodeLength; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(byte('0' + n.Int64()))
	}

	return b.String(), nil
}

func (s *AuthService) hashVerificationCode(email, code string) string {
	mac := hmac.New(sha256.New, []byte(s.config.Auth.JWTSecret))
	mac.Write([]byte(canonicalizeEmail(email)))
	mac.Write([]byte(":"))
	mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *AuthService) sendVerificationEmail(email, code string) error {
	host := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	if host == "" {
		if s.config != nil && s.config.IsProduction {
			return errors.New("SMTP_HOST is required in production")
		}
		// Development fallback: keep flow testable without SMTP.
		logger.Info().
			Str("component", "email_verification").
			Str("email", email).
			Str("verification_code", code).
			Msg("Verification code (SMTP_HOST not configured)")
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

	subject := "SecuShare verification code"
	body := fmt.Sprintf("Your SecuShare verification code is: %s\n\nThis code expires in %d minutes.", code, int(verificationCodeTTL.Minutes()))
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
		verificationEmailSendTTL,
	); err != nil {
		return fmt.Errorf("send verification email: %w", err)
	}

	return nil
}

func (s *AuthService) RequestRegistrationVerification(email, password string) error {
	email = canonicalizeEmail(email)

	// Check email domain restriction before any OPAQUE work
	if s.settings != nil && !s.settings.IsEmailDomainAllowed(email) {
		return errors.New("registration is not allowed for this email domain")
	}

	existing, err := s.userRepo.GetByEmail(email)
	if err == nil && existing != nil {
		return errors.New("email already registered")
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to read existing user: %w", err)
	}

	now := time.Now()
	if pending, err := s.pendingRepo.GetByEmail(email); err == nil {
		if pending.ResendAfter.After(now) {
			return errors.New("please wait before requesting another verification code")
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to read pending registration: %w", err)
	}

	registrationRecord, err := s.prepareRegistrationRecord(email, password)
	if err != nil {
		return err
	}

	code, err := generateVerificationCode()
	if err != nil {
		return fmt.Errorf("failed to generate verification code: %w", err)
	}

	pending := &models.PendingRegistration{
		Email:                email,
		RegistrationRecord:   registrationRecord,
		VerificationCodeHash: s.hashVerificationCode(email, code),
		ExpiresAt:            now.Add(verificationCodeTTL),
		ResendAfter:          now.Add(verificationResendDelay),
		Attempts:             0,
	}

	if err := s.pendingRepo.Upsert(pending); err != nil {
		return fmt.Errorf("failed to store pending registration: %w", err)
	}

	if err := s.sendVerificationEmail(email, code); err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	return nil
}

func (s *AuthService) VerifyRegistrationCode(email, code string) (*models.User, string, error) {
	email = canonicalizeEmail(email)

	pending, err := s.pendingRepo.GetByEmail(email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", errors.New(verificationFailureMsg)
		}
		return nil, "", fmt.Errorf("failed to read pending registration: %w", err)
	}

	now := time.Now()
	if now.After(pending.ExpiresAt) {
		if err := s.pendingRepo.DeleteByEmail(email); err != nil {
			logger.Warn().Err(err).Str("email", email).Msg("Failed to delete expired pending registration")
		}
		return nil, "", errors.New(verificationFailureMsg)
	}

	expected := s.hashVerificationCode(email, code)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(pending.VerificationCodeHash)) != 1 {
		// Atomically increment the attempt counter and check the limit in
		// a single UPDATE … WHERE attempts < max.  This prevents concurrent
		// requests from both reading the same counter value and bypassing
		// the brute-force limit.
		allowed, err := s.pendingRepo.IncrementAttempts(email, verificationMaxAttempts)
		if err != nil {
			logger.Warn().Err(err).Str("email", email).Msg("Failed to increment pending registration attempts")
		}
		if !allowed {
			// Limit reached — clean up the pending record.
			if err := s.pendingRepo.DeleteByEmail(email); err != nil {
				logger.Warn().Err(err).Str("email", email).Msg("Failed to delete locked pending registration")
			}
			return nil, "", errors.New("too many verification attempts")
		}
		return nil, "", errors.New(verificationFailureMsg)
	}

	user, token, err := s.registerFinishWithVerification(email, pending.RegistrationRecord, true)
	if err != nil {
		return nil, "", err
	}

	if err := s.pendingRepo.DeleteByEmail(email); err != nil {
		logger.Warn().Err(err).Str("email", email).Msg("Failed to cleanup pending registration after success")
	}
	return user, token, nil
}

// RegisterInit handles the first registration round.
// Returns the serialized RegistrationResponse bytes.
func (s *AuthService) RegisterInit(email string, registrationRequestBytes []byte) ([]byte, error) {
	email = canonicalizeEmail(email)
	s.trace("register_init_start", map[string]string{
		"email":           email,
		"email_hash":      shortHash([]byte(email)),
		"public_key_hash": shortHash(s.publicKey),
		"oprf_seed_hash":  shortHash(s.oprfSeed),
	})

	// Check email uniqueness early to give a fast failure.
	existing, err := s.userRepo.GetByEmail(email)
	if err == nil && existing != nil {
		return nil, errors.New("email already registered")
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("failed to read existing user: %w", err)
	}

	server, err := s.newServer()
	if err != nil {
		return nil, err
	}

	req, err := server.Deserialize.RegistrationRequest(registrationRequestBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid registration request: %w", err)
	}

	// Use email as the stable credential identifier.
	credID := []byte(email)

	pks, err := server.Deserialize.DecodeAkePublicKey(s.publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server public key: %w", err)
	}

	resp := server.RegistrationResponse(req, pks, credID, s.oprfSeed)
	return resp.Serialize(), nil
}

// RegisterFinish handles the second registration round.
// Creates the user account and returns the user + JWT.
func (s *AuthService) RegisterFinish(email string, registrationRecordBytes []byte) (*models.User, string, error) {
	return s.registerFinishWithVerification(email, registrationRecordBytes, false)
}

func (s *AuthService) registerFinishWithVerification(
	email string,
	registrationRecordBytes []byte,
	isEmailVerified bool,
) (*models.User, string, error) {
	email = canonicalizeEmail(email)
	s.trace("register_finish_start", map[string]string{
		"email":                   email,
		"registration_record_sha": shortHash(registrationRecordBytes),
	})

	// Re-check email uniqueness (race condition protection).
	existing, err := s.userRepo.GetByEmail(email)
	if err == nil && existing != nil {
		return nil, "", errors.New("email already registered")
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, "", fmt.Errorf("failed to read existing user: %w", err)
	}

	server, err := s.newServer()
	if err != nil {
		return nil, "", err
	}

	regRecord, err := server.Deserialize.RegistrationRecord(registrationRecordBytes)
	if err != nil {
		return nil, "", fmt.Errorf("invalid registration record: %w", err)
	}

	quota := int64(1073741824) // 1GB default
	if s.settings != nil {
		quota = s.settings.GetDefaultStorageQuota(false)
	}
	user := &models.User{
		ID:              uuid.New().String(),
		Email:           email,
		OpaqueRecord:    regRecord.Serialize(),
		StorageQuota:    quota,
		StorageUsed:     0,
		CreatedAt:       time.Now(),
		IsEmailVerified: isEmailVerified,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, "", fmt.Errorf("failed to create user: %w", err)
	}

	token, err := s.GenerateToken(user.ID, false)
	if err != nil {
		return nil, "", err
	}

	return user, token, nil
}

// LoginInit handles the first login round.
// Returns (loginID, ke2Bytes, error). Unknown users get a fake KE2 to prevent enumeration.
func (s *AuthService) LoginInit(email string, ke1Bytes []byte) (string, []byte, error) {
	email = canonicalizeEmail(email)
	s.trace("login_init_start", map[string]string{
		"email":           email,
		"email_hash":      shortHash([]byte(email)),
		"ke1_hash":        shortHash(ke1Bytes),
		"public_key_hash": shortHash(s.publicKey),
		"oprf_seed_hash":  shortHash(s.oprfSeed),
	})

	server, err := s.newServer()
	if err != nil {
		return "", nil, err
	}

	ke1, err := server.Deserialize.KE1(ke1Bytes)
	if err != nil {
		return "", nil, fmt.Errorf("invalid KE1 message: %w", err)
	}

	var record *opaque.ClientRecord
	var userID string
	isFake := false

	user, lookupErr := s.userRepo.GetByEmail(email)
	if lookupErr != nil {
		if !errors.Is(lookupErr, sql.ErrNoRows) {
			return "", nil, fmt.Errorf("failed to lookup user by email: %w", lookupErr)
		}
		s.trace("login_init_lookup", map[string]string{
			"email":        email,
			"user_found":   "false",
			"lookup_error": lookupErr.Error(),
		})
		// User not found — use fake record to prevent enumeration.
		fakeRecord, err := s.opaqueConf.GetFakeRecord([]byte(email))
		if err != nil {
			return "", nil, fmt.Errorf("failed to create fake record: %w", err)
		}
		record = fakeRecord
		isFake = true
	} else {
		s.trace("login_init_lookup", map[string]string{
			"email":              email,
			"user_found":         "true",
			"stored_email":       user.Email,
			"stored_email_hash":  shortHash([]byte(user.Email)),
			"opaque_record_hash": shortHash(user.OpaqueRecord),
		})
		regRecord, err := server.Deserialize.RegistrationRecord(user.OpaqueRecord)
		if err != nil {
			return "", nil, fmt.Errorf("corrupt user record: %w", err)
		}
		record = &opaque.ClientRecord{
			// Use the stored email as credential identifier to support records
			// created before canonicalization (mixed-case legacy accounts).
			CredentialIdentifier: []byte(user.Email),
			// Keep nil for compatibility with records that default to client public key identity.
			ClientIdentity:     nil,
			RegistrationRecord: regRecord,
		}
		s.trace("login_init_record", map[string]string{
			"credential_identifier_hash": shortHash(record.CredentialIdentifier),
			"client_identity_set":        fmt.Sprintf("%t", len(record.ClientIdentity) > 0),
		})
		userID = user.ID
	}

	ke2, err := server.LoginInit(ke1, record)
	if err != nil {
		return "", nil, fmt.Errorf("login init failed: %w", err)
	}

	loginID := uuid.New().String()
	s.loginStates.Store(loginID, &loginState{
		akeState: server.SerializeState(),
		userID:   userID,
		isFake:   isFake,
		expires:  time.Now().Add(loginStateTTL),
	})
	s.trace("login_init_done", map[string]string{
		"login_id": loginID,
		"is_fake":  fmt.Sprintf("%t", isFake),
		"ke2_hash": shortHash(ke2.Serialize()),
	})

	return loginID, ke2.Serialize(), nil
}

// LoginFinish handles the second login round.
// Returns the authenticated user + JWT, or error on failure.
func (s *AuthService) LoginFinish(loginID string, ke3Bytes []byte) (*models.User, string, error) {
	raw, ok := s.loginStates.LoadAndDelete(loginID)
	if !ok {
		return nil, "", errors.New("invalid or expired login session")
	}

	state, ok := raw.(*loginState)
	if !ok {
		return nil, "", errors.New("invalid login session state")
	}
	if time.Now().After(state.expires) {
		return nil, "", errors.New("login session expired")
	}

	// Fake states always fail — user didn't exist.
	if state.isFake {
		return nil, "", errors.New("invalid credentials")
	}

	server, err := s.newServer()
	if err != nil {
		return nil, "", err
	}

	if err := server.SetAKEState(state.akeState); err != nil {
		return nil, "", fmt.Errorf("failed to restore login state: %w", err)
	}

	ke3, err := server.Deserialize.KE3(ke3Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("invalid KE3 message: %w", err)
	}

	if err := server.LoginFinish(ke3); err != nil {
		return nil, "", errors.New("invalid credentials")
	}

	user, err := s.userRepo.GetByID(state.userID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load user: %w", err)
	}

	token, err := s.GenerateToken(user.ID, false)
	if err != nil {
		return nil, "", err
	}

	return user, token, nil
}

// RegisterWithPassword runs a complete OPAQUE registration server-side.
// This is used by frontend clients that don't implement a compatible OPAQUE stack.
func (s *AuthService) RegisterWithPassword(email, password string) (*models.User, string, error) {
	email = canonicalizeEmail(email)

	record, err := s.prepareRegistrationRecord(email, password)
	if err != nil {
		return nil, "", err
	}

	return s.RegisterFinish(email, record)
}

// LoginWithPassword runs a complete OPAQUE login server-side.
// Passwords are never persisted and are only used in-memory for the protocol roundtrip.
func (s *AuthService) LoginWithPassword(email, password string) (*models.User, string, error) {
	email = canonicalizeEmail(email)

	client, err := s.opaqueConf.Client()
	if err != nil {
		return nil, "", fmt.Errorf("login failed: %w", err)
	}

	ke1 := client.LoginInit([]byte(password))
	loginID, ke2Bytes, err := s.LoginInit(email, ke1.Serialize())
	if err != nil {
		return nil, "", err
	}

	ke2, err := client.Deserialize.KE2(ke2Bytes)
	if err != nil {
		s.loginStates.Delete(loginID)
		return nil, "", errors.New("invalid credentials")
	}

	ke3, _, err := client.LoginFinish(ke2, opaque.ClientLoginFinishOptions{})
	if err != nil {
		s.loginStates.Delete(loginID)
		return nil, "", errors.New("invalid credentials")
	}

	user, token, err := s.LoginFinish(loginID, ke3.Serialize())
	if err != nil {
		return nil, "", err
	}

	return user, token, nil
}

func (s *AuthService) CreateGuestSession(ip string) (*models.GuestSession, string, error) {
	ip = strings.TrimSpace(ip)

	quota := int64(10485760) // 10MB default
	if s.settings != nil {
		quota = s.settings.GetDefaultStorageQuota(true)
	}
	expiresAt := time.Now().Add(s.guestSessionDuration())

	// Reuse latest active empty session for this IP to reduce session table bloat
	// while preserving isolation for sessions that already contain files.
	if ip != "" {
		reusable, err := s.guestRepo.GetReusableActiveByIP(ip)
		switch {
		case err == nil:
			if err := s.guestRepo.RefreshSession(reusable.ID, quota, expiresAt); err != nil {
				return nil, "", err
			}
			reusable.StorageQuota = quota
			reusable.ExpiresAt = expiresAt

			token, err := s.GenerateToken(reusable.ID, true)
			if err != nil {
				return nil, "", err
			}
			return reusable, token, nil
		case !errors.Is(err, sql.ErrNoRows):
			return nil, "", err
		}
	}

	session := &models.GuestSession{
		ID:           uuid.New().String(),
		IPAddress:    &ip,
		StorageQuota: quota,
		StorageUsed:  0,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
	}

	if err := s.guestRepo.Create(session); err != nil {
		return nil, "", err
	}

	token, err := s.GenerateToken(session.ID, true)
	if err != nil {
		return nil, "", err
	}

	return session, token, nil
}

func (s *AuthService) GetGuestStorageInfo(sessionID string) (*models.StorageInfo, error) {
	return s.guestRepo.GetIPStorageInfo(sessionID)
}

func (s *AuthService) GenerateToken(userID string, isGuest bool) (string, error) {
	// Guest tokens expire to match guest session duration; registered user tokens expire in 24h
	var expiry time.Duration
	if isGuest {
		expiry = s.guestSessionDuration()
	} else {
		expiry = 24 * time.Hour
	}

	claims := &Claims{
		UserID:  userID,
		IsGuest: isGuest,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.Auth.JWTSecret))
}

func (s *AuthService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing algorithm is HS256
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing algorithm: %v, expected HS256", token.Method.Alg())
		}
		return []byte(s.config.Auth.JWTSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (s *AuthService) GetUserByID(userID string) (*models.User, error) {
	return s.userRepo.GetByID(userID)
}

func (s *AuthService) GetGuestSessionByID(sessionID string) (*models.GuestSession, error) {
	return s.guestRepo.GetByID(sessionID)
}

func (s *AuthService) SetSettingsProvider(sp SettingsProvider) {
	s.settings = sp
}

func (s *AuthService) SetAdmin(id string, isAdmin bool) error {
	return s.userRepo.SetAdmin(id, isAdmin)
}

func (s *AuthService) SetEmailVerified(id string, verified bool) error {
	return s.userRepo.SetEmailVerified(id, verified)
}

func (s *AuthService) guestSessionDuration() time.Duration {
	hours := s.config.Auth.GuestDuration
	if s.settings != nil {
		if configured := s.settings.GetGuestSessionDurationHours(); configured > 0 {
			hours = configured
		}
	}
	if hours <= 0 {
		hours = 24
	}
	return time.Duration(hours) * time.Hour
}

// Stop terminates background cleanup loops used by AuthService.
func (s *AuthService) Stop() {
	s.loginStopMu.Do(func() {
		close(s.loginStopCh)
	})
}
