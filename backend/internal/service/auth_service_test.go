package service

import (
	"strings"
	"testing"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/config"
	"github.com/SecuShare/SecuShare/backend/internal/models"
	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/SecuShare/SecuShare/backend/pkg/testutil"
	"github.com/bytemare/opaque"
	"github.com/google/uuid"
)

func newTestAuthService(t *testing.T) (*AuthService, func()) {
	t.Helper()
	db, _, cleanup := testutil.SetupTest(t)
	userRepo := repository.NewUserRepository(db)
	guestRepo := repository.NewGuestSessionRepository(db)
	pendingRepo := repository.NewPendingRegistrationRepository(db)
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:     "test-secret-key-for-testing",
			GuestDuration: 24,
			// OPAQUEServerSetup is empty → auto-generate in dev mode
		},
	}
	svc, err := NewAuthService(userRepo, guestRepo, pendingRepo, cfg)
	if err != nil {
		cleanup()
		t.Fatalf("NewAuthService failed: %v", err)
	}
	return svc, func() {
		svc.Stop()
		cleanup()
	}
}

// runOPAQUERegistration performs a full OPAQUE registration using the bytemare Go client.
// Returns the user's email and password for subsequent login tests.
func runOPAQUERegistration(t *testing.T, svc *AuthService, email, password string) {
	t.Helper()
	conf := opaque.DefaultConfiguration()

	client, err := conf.Client()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// Round 1: client → server
	ke1 := client.RegistrationInit([]byte(password))
	regRespBytes, err := svc.RegisterInit(email, ke1.Serialize())
	if err != nil {
		t.Fatalf("RegisterInit: %v", err)
	}

	// Round 2: server → client → server
	regResp, err := client.Deserialize.RegistrationResponse(regRespBytes)
	if err != nil {
		t.Fatalf("deserialize registration response: %v", err)
	}
	record, _ := client.RegistrationFinalize(regResp, opaque.ClientRegistrationFinalizeOptions{})
	_, _, err = svc.RegisterFinish(email, record.Serialize())
	if err != nil {
		t.Fatalf("RegisterFinish: %v", err)
	}
}

// runOPAQUELogin performs a full OPAQUE login and returns the JWT token.
func runOPAQUELogin(t *testing.T, svc *AuthService, email, password string) string {
	t.Helper()
	conf := opaque.DefaultConfiguration()

	client, err := conf.Client()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// Round 1: client → server
	ke1 := client.LoginInit([]byte(password))
	loginID, ke2Bytes, err := svc.LoginInit(email, ke1.Serialize())
	if err != nil {
		t.Fatalf("LoginInit: %v", err)
	}

	// Round 2: server → client → server
	ke2, err := client.Deserialize.KE2(ke2Bytes)
	if err != nil {
		t.Fatalf("deserialize KE2: %v", err)
	}
	ke3, _, err := client.LoginFinish(ke2, opaque.ClientLoginFinishOptions{})
	if err != nil {
		t.Fatalf("client LoginFinish: %v", err)
	}

	user, token, err := svc.LoginFinish(loginID, ke3.Serialize())
	if err != nil {
		t.Fatalf("LoginFinish: %v", err)
	}
	if user == nil || token == "" {
		t.Fatal("expected non-nil user and token")
	}
	return token
}

// runLegacyOPAQUERegistrationWithRawEmail simulates records created before
// email canonicalization by using the raw email as credential identifier.
func runLegacyOPAQUERegistrationWithRawEmail(t *testing.T, svc *AuthService, email, password string) {
	t.Helper()
	conf := opaque.DefaultConfiguration()

	client, err := conf.Client()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	server, err := svc.newServer()
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	regReq := client.RegistrationInit([]byte(password))
	deserReq, err := server.Deserialize.RegistrationRequest(regReq.Serialize())
	if err != nil {
		t.Fatalf("deserialize registration request: %v", err)
	}

	pks, err := server.Deserialize.DecodeAkePublicKey(svc.publicKey)
	if err != nil {
		t.Fatalf("decode server public key: %v", err)
	}

	regResp := server.RegistrationResponse(deserReq, pks, []byte(email), svc.oprfSeed)
	deserResp, err := client.Deserialize.RegistrationResponse(regResp.Serialize())
	if err != nil {
		t.Fatalf("deserialize registration response: %v", err)
	}

	record, _ := client.RegistrationFinalize(deserResp, opaque.ClientRegistrationFinalizeOptions{})

	user := &models.User{
		ID:              uuid.New().String(),
		Email:           email,
		OpaqueRecord:    record.Serialize(),
		StorageQuota:    1073741824,
		StorageUsed:     0,
		CreatedAt:       time.Now(),
		IsEmailVerified: false,
	}
	if err := svc.userRepo.Create(user); err != nil {
		t.Fatalf("create legacy user: %v", err)
	}
}

func TestAuthService_OPAQUE_RegisterAndLogin(t *testing.T) {
	svc, cleanup := newTestAuthService(t)
	defer cleanup()

	email := "test@example.com"
	password := "securePassword123"

	runOPAQUERegistration(t, svc, email, password)
	token := runOPAQUELogin(t, svc, email, password)

	claims, err := svc.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.IsGuest {
		t.Error("expected non-guest token")
	}
}

func TestAuthService_OPAQUE_WrongPassword(t *testing.T) {
	svc, cleanup := newTestAuthService(t)
	defer cleanup()

	email := "test@example.com"
	runOPAQUERegistration(t, svc, email, "correctPassword")

	conf := opaque.DefaultConfiguration()
	client, _ := conf.Client()

	ke1 := client.LoginInit([]byte("wrongPassword"))
	loginID, ke2Bytes, err := svc.LoginInit(email, ke1.Serialize())
	if err != nil {
		t.Fatalf("LoginInit: %v", err)
	}

	ke2, err := client.Deserialize.KE2(ke2Bytes)
	if err != nil {
		t.Fatalf("deserialize KE2: %v", err)
	}

	// client.LoginFinish should fail with wrong password
	ke3, _, err := client.LoginFinish(ke2, opaque.ClientLoginFinishOptions{})
	if err == nil && ke3 != nil {
		// Client accepted the KE2 — but server should reject the KE3.
		_, _, finishErr := svc.LoginFinish(loginID, ke3.Serialize())
		if finishErr == nil {
			t.Error("expected LoginFinish to fail with wrong password")
		}
	}
	// If client.LoginFinish itself errored, that's also correct — wrong password detected client-side.
}

func TestAuthService_OPAQUE_UnknownUser(t *testing.T) {
	svc, cleanup := newTestAuthService(t)
	defer cleanup()

	conf := opaque.DefaultConfiguration()
	client, _ := conf.Client()

	// Login for a user that doesn't exist — server must return a valid KE2 (no enumeration).
	ke1 := client.LoginInit([]byte("anyPassword"))
	loginID, ke2Bytes, err := svc.LoginInit("ghost@example.com", ke1.Serialize())
	if err != nil {
		t.Fatalf("LoginInit for unknown user must not error: %v", err)
	}
	if loginID == "" || len(ke2Bytes) == 0 {
		t.Fatal("expected non-empty loginID and ke2 for unknown user")
	}

	// Attempt to finish — must fail with invalid credentials, not panic.
	ke2, err := client.Deserialize.KE2(ke2Bytes)
	if err != nil {
		// KE2 deserialization may fail due to fake record — that's acceptable.
		return
	}

	ke3, _, clientErr := client.LoginFinish(ke2, opaque.ClientLoginFinishOptions{})
	if clientErr != nil {
		// Client detected wrong password client-side — enumeration protection worked.
		return
	}

	_, _, err = svc.LoginFinish(loginID, ke3.Serialize())
	if err == nil {
		t.Error("expected LoginFinish to fail for unknown user")
	}
}

func TestAuthService_OPAQUE_DuplicateEmail(t *testing.T) {
	svc, cleanup := newTestAuthService(t)
	defer cleanup()

	email := "dup@example.com"
	runOPAQUERegistration(t, svc, email, "password1")

	conf := opaque.DefaultConfiguration()
	client, _ := conf.Client()

	ke1 := client.RegistrationInit([]byte("password2"))
	_, err := svc.RegisterInit(email, ke1.Serialize())
	if err == nil {
		t.Error("expected RegisterInit to reject duplicate email")
	}
}

func TestAuthService_OPAQUE_LoginWithDifferentEmailCase(t *testing.T) {
	svc, cleanup := newTestAuthService(t)
	defer cleanup()

	email := "Case.User+tag@Example.COM"
	password := "securePassword123"

	runOPAQUERegistration(t, svc, email, password)

	token := runOPAQUELogin(t, svc, strings.ToLower(email), password)
	if token == "" {
		t.Fatal("expected non-empty token for case-insensitive email login")
	}
}

func TestAuthService_OPAQUE_LegacyMixedCaseRecord_LoginWithLowercase(t *testing.T) {
	svc, cleanup := newTestAuthService(t)
	defer cleanup()

	legacyEmail := "Case.User+tag@Example.COM"
	password := "securePassword123"

	runLegacyOPAQUERegistrationWithRawEmail(t, svc, legacyEmail, password)

	token := runOPAQUELogin(t, svc, strings.ToLower(legacyEmail), password)
	if token == "" {
		t.Fatal("expected non-empty token for legacy mixed-case OPAQUE records")
	}
}

func TestAuthService_PasswordFlow_RegisterAndLogin(t *testing.T) {
	svc, cleanup := newTestAuthService(t)
	defer cleanup()

	email := "Case.User+tag@Example.COM"
	password := "securePassword123"

	registeredUser, registerToken, err := svc.RegisterWithPassword(email, password)
	if err != nil {
		t.Fatalf("RegisterWithPassword failed: %v", err)
	}
	if registeredUser == nil || registerToken == "" {
		t.Fatal("expected registered user and non-empty token")
	}

	user, token, err := svc.LoginWithPassword(strings.ToLower(email), password)
	if err != nil {
		t.Fatalf("LoginWithPassword failed: %v", err)
	}
	if user == nil || token == "" {
		t.Fatal("expected user and non-empty token")
	}
}

func TestAuthService_PasswordFlow_WrongPassword(t *testing.T) {
	svc, cleanup := newTestAuthService(t)
	defer cleanup()

	email := "test@example.com"
	password := "correctPassword123"

	if _, _, err := svc.RegisterWithPassword(email, password); err != nil {
		t.Fatalf("RegisterWithPassword failed: %v", err)
	}

	_, _, err := svc.LoginWithPassword(email, "wrongPassword123")
	if err == nil {
		t.Fatal("expected LoginWithPassword to fail with wrong password")
	}
}

func TestAuthService_GenerateAndValidateToken(t *testing.T) {
	svc, cleanup := newTestAuthService(t)
	defer cleanup()

	tests := []struct {
		name    string
		userID  string
		isGuest bool
	}{
		{"user token", "user-123", false},
		{"guest token", "guest-456", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := svc.GenerateToken(tt.userID, tt.isGuest)
			if err != nil {
				t.Fatalf("Failed to generate token: %v", err)
			}

			if token == "" {
				t.Fatal("Expected non-empty token")
			}

			claims, err := svc.ValidateToken(token)
			if err != nil {
				t.Fatalf("Failed to validate token: %v", err)
			}

			if claims.UserID != tt.userID {
				t.Errorf("Expected UserID %s, got %s", tt.userID, claims.UserID)
			}
			if claims.IsGuest != tt.isGuest {
				t.Errorf("Expected IsGuest %v, got %v", tt.isGuest, claims.IsGuest)
			}
		})
	}
}

func TestAuthService_ValidateToken_Invalid(t *testing.T) {
	svc, cleanup := newTestAuthService(t)
	defer cleanup()

	tests := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"invalid token format", "not-a-valid-token"},
		{
			"token signed with wrong secret",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzIiwiaXNfZ3Vlc3QiOmZhbHNlfQ.wrong-signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.ValidateToken(tt.token)
			if err == nil {
				t.Error("Expected error for invalid token")
			}
		})
	}
}

func TestAuthService_CreateGuestSession(t *testing.T) {
	svc, cleanup := newTestAuthService(t)
	defer cleanup()

	session, token, err := svc.CreateGuestSession("203.0.113.1")
	if err != nil {
		t.Fatalf("Failed to create guest session: %v", err)
	}

	if session == nil {
		t.Fatal("Expected non-nil session")
	}
	if token == "" {
		t.Fatal("Expected non-empty token")
	}
	if session.StorageQuota != 10485760 {
		t.Errorf("Expected storage quota 10485760, got %d", session.StorageQuota)
	}
	if session.ExpiresAt.Before(time.Now()) {
		t.Error("Expected expires_at to be in the future")
	}

	// Validate the token
	claims, err := svc.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate guest token: %v", err)
	}
	if !claims.IsGuest {
		t.Error("Expected IsGuest to be true")
	}
}

func TestAuthService_CreateGuestSession_UniqueSessionsPerCall(t *testing.T) {
	svc, cleanup := newTestAuthService(t)
	defer cleanup()

	ip := "203.0.113.42"

	// Every call must produce a distinct session so each user has a private file list.
	session1, _, err := svc.CreateGuestSession(ip)
	if err != nil {
		t.Fatalf("First CreateGuestSession failed: %v", err)
	}
	session2, _, err := svc.CreateGuestSession(ip)
	if err != nil {
		t.Fatalf("Second CreateGuestSession failed: %v", err)
	}

	if session1.ID == session2.ID {
		t.Error("Expected distinct session IDs for separate calls from the same IP")
	}
}
