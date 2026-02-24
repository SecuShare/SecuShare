package handler

import (
	"encoding/base64"
	"net/mail"
	"regexp"
	"strings"

	"github.com/SecuShare/SecuShare/backend/internal/service"
	"github.com/SecuShare/SecuShare/backend/pkg/logger"
	"github.com/SecuShare/SecuShare/backend/pkg/response"
	"github.com/gofiber/fiber/v2"
)

// emailRegex provides additional validation beyond net/mail
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
var verificationCodeRegex = regexp.MustCompile(`^\d{6}$`)

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func isValidEmail(email string) bool {
	if len(email) > 254 {
		return false
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return false
	}
	return emailRegex.MatchString(email)
}

func isValidPasswordLength(password string) bool {
	n := len(password)
	return n >= 8 && n <= 128
}

type AuthHandler struct {
	authSvc *service.AuthService
}

func NewAuthHandler(authSvc *service.AuthService) *AuthHandler {
	return &AuthHandler{authSvc: authSvc}
}

// setCSRFCookie generates and sets a CSRF token cookie on the response.
func setCSRFCookie(c *fiber.Ctx) string {
	token := GenerateCSRFToken()
	c.Cookie(&fiber.Cookie{
		Name:     "csrf_token",
		Value:    token,
		HTTPOnly: false, // Must be readable by JS
		Secure:   true,
		SameSite: "Strict",
		Path:     "/",
		MaxAge:   86400, // 24 hours
	})
	return token
}

type AuthResponse struct {
	Token     string      `json:"token"`
	CSRFToken string      `json:"csrf_token,omitempty"`
	User      interface{} `json:"user,omitempty"`
}

// RegisterRequest handles one-shot registration with email + password.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest handles one-shot login with email + password.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterVerifyRequest struct {
	Email            string `json:"email"`
	VerificationCode string `json:"verification_code"`
}

// RegisterInitRequest is sent by the client to start registration.
type RegisterInitRequest struct {
	Email               string `json:"email"`
	RegistrationRequest string `json:"registration_request"` // base64
}

// RegisterInitResponse is the server's response to the first registration round.
type RegisterInitResponse struct {
	RegistrationResponse string `json:"registration_response"` // base64
}

// RegisterFinishRequest completes registration.
type RegisterFinishRequest struct {
	Email              string `json:"email"`
	RegistrationRecord string `json:"registration_record"` // base64
}

// LoginInitRequest starts a login attempt.
type LoginInitRequest struct {
	Email             string `json:"email"`
	StartLoginRequest string `json:"start_login_request"` // base64
}

// LoginInitResponse carries the server's KE2 and a session ID.
type LoginInitResponse struct {
	LoginID       string `json:"login_id"`
	LoginResponse string `json:"login_response"` // base64
}

// LoginFinishRequest completes login.
type LoginFinishRequest struct {
	LoginID            string `json:"login_id"`
	FinishLoginRequest string `json:"finish_login_request"` // base64
}

// RegisterPassword handles POST /auth/register using a one-shot password flow.
func (h *AuthHandler) RegisterPassword(c *fiber.Ctx) error {
	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "invalid request body")
	}

	req.Email = normalizeEmail(req.Email)

	if req.Email == "" || req.Password == "" {
		return response.BadRequest(c, "email and password are required")
	}

	if !isValidEmail(req.Email) {
		return response.BadRequest(c, "invalid email format")
	}

	if !isValidPasswordLength(req.Password) {
		return response.BadRequest(c, "password must be between 8 and 128 characters")
	}

	err := h.authSvc.RequestRegistrationVerification(req.Email, req.Password)
	if err != nil {
		if err.Error() == "email already registered" {
			return response.Error(c, fiber.StatusConflict, "email already registered")
		}
		if err.Error() == "please wait before requesting another verification code" {
			return response.Error(c, fiber.StatusTooManyRequests, err.Error())
		}
		logger.Error().Err(err).Str("email", req.Email).Msg("RegisterPassword failed")
		return response.InternalError(c, "registration failed")
	}

	logger.Audit("registration_verification_sent", "", map[string]string{
		"email": req.Email,
	})

	return response.Success(c, map[string]string{
		"message": "verification code sent to your email",
	})
}

// VerifyRegistration handles POST /auth/register/verify and creates the account only after email ownership verification.
func (h *AuthHandler) VerifyRegistration(c *fiber.Ctx) error {
	var req RegisterVerifyRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "invalid request body")
	}

	req.Email = normalizeEmail(req.Email)

	if req.Email == "" || req.VerificationCode == "" {
		return response.BadRequest(c, "email and verification_code are required")
	}

	if !isValidEmail(req.Email) {
		return response.BadRequest(c, "invalid email format")
	}

	if !verificationCodeRegex.MatchString(req.VerificationCode) {
		return response.BadRequest(c, "invalid verification code")
	}

	user, token, err := h.authSvc.VerifyRegistrationCode(req.Email, req.VerificationCode)
	if err != nil {
		switch err.Error() {
		case "invalid verification code", "invalid or expired verification code", "verification code expired":
			return response.Unauthorized(c, err.Error())
		case "too many verification attempts":
			return response.Error(c, fiber.StatusTooManyRequests, err.Error())
		case "email already registered":
			return response.Error(c, fiber.StatusConflict, err.Error())
		default:
			logger.Error().Err(err).Str("email", req.Email).Msg("VerifyRegistration failed")
			return response.InternalError(c, "verification failed")
		}
	}

	csrfToken := setCSRFCookie(c)

	logger.Audit("user_registered", user.ID, map[string]string{
		"email": req.Email,
		"mode":  "email_verification",
	})

	return response.Success(c, AuthResponse{
		Token:     token,
		CSRFToken: csrfToken,
		User:      user,
	})
}

// LoginPassword handles POST /auth/login using a one-shot password flow.
func (h *AuthHandler) LoginPassword(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "invalid request body")
	}

	req.Email = normalizeEmail(req.Email)

	if req.Email == "" || req.Password == "" {
		return response.BadRequest(c, "email and password are required")
	}

	if !isValidEmail(req.Email) {
		return response.BadRequest(c, "invalid email format")
	}

	if len(req.Password) > 128 {
		return response.BadRequest(c, "password is too long")
	}

	user, token, err := h.authSvc.LoginWithPassword(req.Email, req.Password)
	if err != nil {
		RecordAuthFailure("invalid_credentials")
		logger.Audit("login_failed", "", map[string]string{
			"ip": c.IP(),
		})
		return response.Unauthorized(c, "invalid credentials")
	}

	logger.Audit("login_success", user.ID, map[string]string{
		"email": user.Email,
		"mode":  "password",
	})

	csrfToken := setCSRFCookie(c)

	return response.Success(c, AuthResponse{
		Token:     token,
		CSRFToken: csrfToken,
		User:      user,
	})
}

// RegisterInit handles POST /auth/register/init.
// This endpoint is intentionally disabled so account creation always requires email ownership verification.
func (h *AuthHandler) RegisterInit(c *fiber.Ctx) error {
	return response.Error(c, fiber.StatusGone, "registration via /auth/register/init is disabled; use /auth/register then /auth/register/verify")
}

// RegisterFinish handles POST /auth/register/finish.
// This endpoint is intentionally disabled so account creation always requires email ownership verification.
func (h *AuthHandler) RegisterFinish(c *fiber.Ctx) error {
	return response.Error(c, fiber.StatusGone, "registration via /auth/register/finish is disabled; use /auth/register then /auth/register/verify")
}

// LoginInit handles POST /auth/login/init — round 1 of OPAQUE login.
func (h *AuthHandler) LoginInit(c *fiber.Ctx) error {
	var req LoginInitRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "invalid request body")
	}

	req.Email = normalizeEmail(req.Email)

	if req.Email == "" || req.StartLoginRequest == "" {
		return response.BadRequest(c, "email and start_login_request are required")
	}

	ke1Bytes, err := base64.RawURLEncoding.DecodeString(req.StartLoginRequest)
	if err != nil {
		return response.BadRequest(c, "invalid start_login_request encoding")
	}

	loginID, ke2Bytes, err := h.authSvc.LoginInit(req.Email, ke1Bytes)
	if err != nil {
		logger.Error().Err(err).Str("email", req.Email).Msg("LoginInit failed")
		return response.InternalError(c, "login failed")
	}

	return response.Success(c, LoginInitResponse{
		LoginID:       loginID,
		LoginResponse: base64.RawURLEncoding.EncodeToString(ke2Bytes),
	})
}

// LoginFinish handles POST /auth/login/finish — round 2 of OPAQUE login.
func (h *AuthHandler) LoginFinish(c *fiber.Ctx) error {
	var req LoginFinishRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "invalid request body")
	}

	if req.LoginID == "" || req.FinishLoginRequest == "" {
		return response.BadRequest(c, "login_id and finish_login_request are required")
	}

	ke3Bytes, err := base64.RawURLEncoding.DecodeString(req.FinishLoginRequest)
	if err != nil {
		return response.BadRequest(c, "invalid finish_login_request encoding")
	}

	user, token, err := h.authSvc.LoginFinish(req.LoginID, ke3Bytes)
	if err != nil {
		RecordAuthFailure("invalid_credentials")
		logger.Audit("login_failed", "", map[string]string{
			"ip": c.IP(),
		})
		return response.Unauthorized(c, "invalid credentials")
	}

	logger.Audit("login_success", user.ID, map[string]string{
		"email": user.Email,
	})

	csrfToken := setCSRFCookie(c)

	return response.Success(c, AuthResponse{
		Token:     token,
		CSRFToken: csrfToken,
		User:      user,
	})
}

func (h *AuthHandler) CreateGuestSession(c *fiber.Ctx) error {
	session, token, err := h.authSvc.CreateGuestSession(c.IP())
	if err != nil {
		return response.InternalError(c, "failed to create guest session")
	}

	csrfToken := setCSRFCookie(c)

	return response.Success(c, AuthResponse{
		Token:     token,
		CSRFToken: csrfToken,
		User: map[string]interface{}{
			"id":                  session.ID,
			"storage_quota_bytes": session.StorageQuota,
			"storage_used_bytes":  session.StorageUsed,
			"expires_at":          session.ExpiresAt,
			"is_guest":            true,
		},
	})
}

func (h *AuthHandler) GetMe(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return response.Unauthorized(c, "authentication required")
	}
	isGuest, ok := c.Locals("is_guest").(bool)
	if !ok {
		return response.Unauthorized(c, "authentication required")
	}

	if isGuest {
		session, err := h.authSvc.GetGuestSessionByID(userID)
		if err != nil {
			return response.NotFound(c, "session not found")
		}
		storageInfo, err := h.authSvc.GetGuestStorageInfo(userID)
		if err != nil {
			return response.InternalError(c, "failed to get storage info")
		}
		return response.Success(c, map[string]interface{}{
			"id":                  session.ID,
			"storage_quota_bytes": storageInfo.Quota,
			"storage_used_bytes":  storageInfo.Used,
			"expires_at":          session.ExpiresAt,
			"is_guest":            true,
		})
	}

	user, err := h.authSvc.GetUserByID(userID)
	if err != nil {
		return response.NotFound(c, "user not found")
	}

	return response.Success(c, user)
}

func (h *AuthHandler) GetStorageInfo(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return response.Unauthorized(c, "authentication required")
	}
	isGuest, ok := c.Locals("is_guest").(bool)
	if !ok {
		return response.Unauthorized(c, "authentication required")
	}
	var quota int64
	var used int64

	if isGuest {
		storageInfo, err := h.authSvc.GetGuestStorageInfo(userID)
		if err != nil {
			return response.NotFound(c, "session not found")
		}
		quota = storageInfo.Quota
		used = storageInfo.Used
	} else {
		user, err := h.authSvc.GetUserByID(userID)
		if err != nil {
			return response.NotFound(c, "user not found")
		}
		quota = user.StorageQuota
		used = user.StorageUsed
	}

	return response.Success(c, map[string]interface{}{
		"quota": quota,
		"used":  used,
		"free":  quota - used,
	})
}
