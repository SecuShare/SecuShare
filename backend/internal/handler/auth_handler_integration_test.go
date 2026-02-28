package handler

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/config"
	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/SecuShare/SecuShare/backend/internal/service"
	"github.com/SecuShare/SecuShare/backend/pkg/testutil"
	"github.com/bytemare/opaque"
	"github.com/gofiber/fiber/v2"
)

type authHandlerTestResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   string          `json:"error"`
}

type testOPAQUEServerSetup struct {
	PrivateKey []byte `json:"private_key"`
	PublicKey  []byte `json:"public_key"`
	OPRFSeed   []byte `json:"oprf_seed"`
}

func buildTestOPAQUEServerSetup(t *testing.T) string {
	t.Helper()

	conf := opaque.DefaultConfiguration()
	privateKey, publicKey := conf.KeyGen()
	oprfSeed := conf.GenerateOPRFSeed()

	setupJSON, err := json.Marshal(testOPAQUEServerSetup{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		OPRFSeed:   oprfSeed,
	})
	if err != nil {
		t.Fatalf("marshal OPAQUE setup: %v", err)
	}

	return base64.StdEncoding.EncodeToString(setupJSON)
}

func newAuthHandlerTestApp(t *testing.T) (*fiber.App, *repository.PendingRegistrationRepository, string, func()) {
	t.Helper()

	db, _, cleanup := testutil.SetupTest(t)
	userRepo := repository.NewUserRepository(db)
	guestRepo := repository.NewGuestSessionRepository(db)
	pendingRepo := repository.NewPendingRegistrationRepository(db)

	jwtSecret := "test-secret-key-for-auth-handler-tests"
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:         jwtSecret,
			GuestDuration:     24,
			OPAQUEServerSetup: buildTestOPAQUEServerSetup(t),
		},
	}

	authSvc, err := service.NewAuthService(userRepo, guestRepo, pendingRepo, cfg)
	if err != nil {
		cleanup()
		t.Fatalf("NewAuthService failed: %v", err)
	}

	authHandler := NewAuthHandler(authSvc)
	app := fiber.New()
	auth := app.Group("/api/v1/auth")
	auth.Post("/register", authHandler.RegisterPassword)
	auth.Post("/register/verify", authHandler.VerifyRegistration)
	auth.Post("/register/init", authHandler.RegisterInit)
	auth.Post("/register/finish", authHandler.RegisterFinish)
	auth.Post("/login", authHandler.LoginPassword)

	return app, pendingRepo, jwtSecret, func() {
		authSvc.Stop()
		cleanup()
	}
}

func performJSONRequest(
	t *testing.T,
	app *fiber.App,
	method, path string,
	payload interface{},
) (int, authHandlerTestResponse) {
	t.Helper()

	var body io.Reader = http.NoBody
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		body = bytes.NewReader(raw)
	}

	req := httptest.NewRequest(method, path, body)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test failed: %v", err)
	}
	statusCode := resp.StatusCode
	defer resp.Body.Close()

	rawResp, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	var parsed authHandlerTestResponse
	if err := json.Unmarshal(rawResp, &parsed); err != nil {
		t.Fatalf("unmarshal response body: %v, body=%s", err, string(rawResp))
	}

	return statusCode, parsed
}

func computeVerificationCodeHash(jwtSecret, email, code string) string {
	mac := hmac.New(sha256.New, []byte(jwtSecret))
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(email))))
	mac.Write([]byte(":"))
	mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}

func setPendingVerificationCode(
	t *testing.T,
	pendingRepo *repository.PendingRegistrationRepository,
	jwtSecret, email, code string,
) {
	t.Helper()

	pending, err := pendingRepo.GetByEmail(email)
	if err != nil {
		t.Fatalf("GetByEmail pending registration: %v", err)
	}

	pending.VerificationCodeHash = computeVerificationCodeHash(jwtSecret, email, code)
	pending.Attempts = 0
	pending.ExpiresAt = time.Now().Add(10 * time.Minute)
	pending.ResendAfter = time.Now()

	if err := pendingRepo.Upsert(pending); err != nil {
		t.Fatalf("Upsert pending registration: %v", err)
	}
}

func TestAuthHandler_RegisterPassword_SendsVerificationRequest(t *testing.T) {
	app, pendingRepo, _, cleanup := newAuthHandlerTestApp(t)
	defer cleanup()

	email := "register@example.com"
	password := "Passw0rd!123"

	statusCode, parsed := performJSONRequest(t, app, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"email":    email,
		"password": password,
	})

	if statusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d (error=%q)", statusCode, parsed.Error)
	}
	if !parsed.Success {
		t.Fatalf("expected success=true, got false (error=%q)", parsed.Error)
	}

	var data struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(parsed.Data, &data); err != nil {
		t.Fatalf("unmarshal register data: %v", err)
	}
	if data.Message != registrationAcknowledgementMessage {
		t.Fatalf("unexpected message: %q", data.Message)
	}

	if _, err := pendingRepo.GetByEmail(email); err != nil {
		t.Fatalf("expected pending registration to exist: %v", err)
	}
}

func TestAuthHandler_RegisterPassword_DoesNotEnumerateExistingEmail(t *testing.T) {
	app, pendingRepo, jwtSecret, cleanup := newAuthHandlerTestApp(t)
	defer cleanup()

	email := "already-registered@example.com"
	password := "Passw0rd!123"
	code := "654321"

	firstStatus, firstParsed := performJSONRequest(t, app, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"email":    email,
		"password": password,
	})
	if firstStatus != http.StatusOK || !firstParsed.Success {
		t.Fatalf("initial register failed: status=%d success=%v error=%q", firstStatus, firstParsed.Success, firstParsed.Error)
	}

	setPendingVerificationCode(t, pendingRepo, jwtSecret, email, code)

	verifyStatus, verifyParsed := performJSONRequest(t, app, http.MethodPost, "/api/v1/auth/register/verify", map[string]string{
		"email":             email,
		"verification_code": code,
	})
	if verifyStatus != http.StatusOK || !verifyParsed.Success {
		t.Fatalf("verification failed: status=%d success=%v error=%q", verifyStatus, verifyParsed.Success, verifyParsed.Error)
	}

	secondStatus, secondParsed := performJSONRequest(t, app, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"email":    email,
		"password": password,
	})
	if secondStatus != http.StatusOK {
		t.Fatalf("expected status=200 for re-register request, got %d", secondStatus)
	}
	if !secondParsed.Success {
		t.Fatalf("expected success=true for re-register request, got error=%q", secondParsed.Error)
	}

	var data struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(secondParsed.Data, &data); err != nil {
		t.Fatalf("unmarshal response data: %v", err)
	}
	if data.Message != registrationAcknowledgementMessage {
		t.Fatalf("unexpected message: %q", data.Message)
	}
}

func TestAuthHandler_VerifyRegistration_Success(t *testing.T) {
	app, pendingRepo, jwtSecret, cleanup := newAuthHandlerTestApp(t)
	defer cleanup()

	email := "verify-success@example.com"
	password := "Passw0rd!123"
	code := "123456"

	registerStatusCode, registerParsed := performJSONRequest(t, app, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"email":    email,
		"password": password,
	})
	if registerStatusCode != http.StatusOK || !registerParsed.Success {
		t.Fatalf("register failed: status=%d success=%v error=%q", registerStatusCode, registerParsed.Success, registerParsed.Error)
	}

	setPendingVerificationCode(t, pendingRepo, jwtSecret, email, code)

	verifyStatusCode, verifyParsed := performJSONRequest(t, app, http.MethodPost, "/api/v1/auth/register/verify", map[string]string{
		"email":             email,
		"verification_code": code,
	})

	if verifyStatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d (error=%q)", verifyStatusCode, verifyParsed.Error)
	}
	if !verifyParsed.Success {
		t.Fatalf("expected success=true, got false (error=%q)", verifyParsed.Error)
	}

	var data struct {
		Token string `json:"token"`
		User  struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.Unmarshal(verifyParsed.Data, &data); err != nil {
		t.Fatalf("unmarshal verify data: %v", err)
	}
	if data.Token == "" {
		t.Fatal("expected non-empty token after verification")
	}
	if data.User.Email != email {
		t.Fatalf("expected user email %q, got %q", email, data.User.Email)
	}
}

func TestAuthHandler_VerifyRegistration_FailsOnWrongCode(t *testing.T) {
	app, pendingRepo, jwtSecret, cleanup := newAuthHandlerTestApp(t)
	defer cleanup()

	email := "verify-fail@example.com"
	password := "Passw0rd!123"

	registerStatusCode, registerParsed := performJSONRequest(t, app, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"email":    email,
		"password": password,
	})
	if registerStatusCode != http.StatusOK || !registerParsed.Success {
		t.Fatalf("register failed: status=%d success=%v error=%q", registerStatusCode, registerParsed.Success, registerParsed.Error)
	}

	setPendingVerificationCode(t, pendingRepo, jwtSecret, email, "123456")

	verifyStatusCode, verifyParsed := performJSONRequest(t, app, http.MethodPost, "/api/v1/auth/register/verify", map[string]string{
		"email":             email,
		"verification_code": "000000",
	})

	if verifyStatusCode != http.StatusUnauthorized {
		t.Fatalf("expected HTTP 401, got %d (error=%q)", verifyStatusCode, verifyParsed.Error)
	}
	if verifyParsed.Success {
		t.Fatal("expected success=false for wrong verification code")
	}
	if verifyParsed.Error != "invalid or expired verification code" {
		t.Fatalf("expected invalid or expired verification code error, got %q", verifyParsed.Error)
	}
}

func TestAuthHandler_LegacyRegistrationEndpoints_ReturnGone(t *testing.T) {
	app, _, _, cleanup := newAuthHandlerTestApp(t)
	defer cleanup()

	initStatusCode, initParsed := performJSONRequest(t, app, http.MethodPost, "/api/v1/auth/register/init", map[string]string{})
	if initStatusCode != http.StatusGone {
		t.Fatalf("expected /register/init status 410, got %d", initStatusCode)
	}
	if initParsed.Success {
		t.Fatal("expected /register/init success=false")
	}

	finishStatusCode, finishParsed := performJSONRequest(t, app, http.MethodPost, "/api/v1/auth/register/finish", map[string]string{})
	if finishStatusCode != http.StatusGone {
		t.Fatalf("expected /register/finish status 410, got %d", finishStatusCode)
	}
	if finishParsed.Success {
		t.Fatal("expected /register/finish success=false")
	}
}
