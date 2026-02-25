package service

import (
	"bytes"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/config"
	"github.com/SecuShare/SecuShare/backend/internal/models"
	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/SecuShare/SecuShare/backend/pkg/logger"
	"github.com/SecuShare/SecuShare/backend/pkg/testutil"
)

type shareServiceTestEnv struct {
	shareSvc  *ShareService
	shareRepo *repository.ShareRepository
	fileID    string
}

func setupShareServiceTest(t *testing.T) (*shareServiceTestEnv, func()) {
	return setupShareServiceTestWithWorkerState(t, true)
}

func setupShareServiceTestWithoutWorkers(t *testing.T) (*shareServiceTestEnv, func()) {
	return setupShareServiceTestWithWorkerState(t, false)
}

func setupShareServiceTestWithWorkerState(
	t *testing.T,
	startEmailWorkers bool,
) (*shareServiceTestEnv, func()) {
	t.Helper()

	db, cfg, cleanup := testutil.SetupTest(t)

	userRepo := repository.NewUserRepository(db)
	guestRepo := repository.NewGuestSessionRepository(db)
	fileRepo := repository.NewFileRepository(db)
	shareRepo := repository.NewShareRepository(db)
	fileSvc := NewFileService(fileRepo, userRepo, guestRepo, cfg.StoragePath)
	shareSvc := NewShareService(shareRepo, fileRepo, fileSvc, &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:              "share-service-test-secret",
			DownloadCodeHMACSecret: "share-service-download-code-secret",
		},
	})
	if !startEmailWorkers {
		shareSvc.Stop()
		shareSvc.downloadVerificationEmailWorkerStop = make(chan struct{})
		shareSvc.downloadVerificationEmailStopOnce = sync.Once{}
	}

	userID := "share-test-user"
	if err := userRepo.Create(&models.User{
		ID:              userID,
		Email:           "owner@example.com",
		OpaqueRecord:    []byte("opaque-record"),
		StorageQuota:    1024 * 1024,
		StorageUsed:     0,
		CreatedAt:       time.Now(),
		IsEmailVerified: true,
	}); err != nil {
		shareSvc.Stop()
		cleanup()
		t.Fatalf("create user: %v", err)
	}

	if err := fileRepo.Create(&models.File{
		ID:                "share-test-file",
		OwnerID:           &userID,
		OriginalFilename:  "document.txt",
		EncryptedFilename: "document.txt.enc",
		MimeType:          "text/plain",
		FileSize:          128,
		EncryptedSize:     256,
		IVBase64:          "AAAAAAAAAAAAAAAA",
		ChecksumSHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CreatedAt:         time.Now(),
	}); err != nil {
		shareSvc.Stop()
		cleanup()
		t.Fatalf("create file: %v", err)
	}

	wrappedCleanup := func() {
		shareSvc.Stop()
		cleanup()
	}

	return &shareServiceTestEnv{
		shareSvc:  shareSvc,
		shareRepo: shareRepo,
		fileID:    "share-test-file",
	}, wrappedCleanup
}

func createRestrictedShareWithKnownCode(
	t *testing.T,
	env *shareServiceTestEnv,
	email string,
	knownCode string,
) *models.Share {
	t.Helper()

	share, err := env.shareSvc.Create(&CreateShareRequest{
		FileID:        env.fileID,
		AllowedEmails: []string{email},
	})
	if err != nil {
		t.Fatalf("create restricted share: %v", err)
	}

	if err := env.shareSvc.RequestDownloadVerificationCode(share.ID, email); err != nil {
		t.Fatalf("request download verification code: %v", err)
	}

	pending, err := env.shareRepo.GetPendingDownloadVerification(share.ID, email)
	if err != nil {
		t.Fatalf("load pending download verification: %v", err)
	}

	pending.VerificationCodeHash = env.shareSvc.hashDownloadVerificationCode(share.ID, email, knownCode)
	pending.Attempts = 0
	pending.ExpiresAt = time.Now().Add(10 * time.Minute)
	pending.ResendAfter = time.Now()
	if err := env.shareRepo.UpsertPendingDownloadVerification(pending); err != nil {
		t.Fatalf("update pending download verification: %v", err)
	}

	return share
}

func runDownloadVerificationWorkerForJobs(
	t *testing.T,
	svc *ShareService,
	jobs ...downloadVerificationEmailJob,
) {
	t.Helper()

	svc.downloadVerificationEmailJobs = make(chan downloadVerificationEmailJob, len(jobs))

	done := make(chan struct{})
	go func() {
		svc.downloadVerificationEmailWorker()
		close(done)
	}()

	for _, job := range jobs {
		svc.downloadVerificationEmailJobs <- job
	}
	close(svc.downloadVerificationEmailJobs)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("download verification email worker did not stop")
	}
}

func TestShareService_DownloadVerificationCode_IsSingleUseUnderConcurrency(t *testing.T) {
	env, cleanup := setupShareServiceTest(t)
	defer cleanup()

	email := "allowed@example.com"
	code := "123456"
	share := createRestrictedShareWithKnownCode(t, env, email, code)

	const parallelDownloads = 2
	start := make(chan struct{})
	errCh := make(chan error, parallelDownloads)
	var wg sync.WaitGroup

	for i := 0; i < parallelDownloads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := env.shareSvc.GetFile(share.ID, nil, &email, &code)
			errCh <- err
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)

	successCount := 0
	failureCount := 0
	for err := range errCh {
		if err == nil {
			successCount++
			continue
		}
		failureCount++
		if !strings.Contains(err.Error(), "verification code") &&
			!strings.Contains(err.Error(), "invalid or expired") {
			t.Fatalf("unexpected concurrent download error: %v", err)
		}
	}

	if successCount != 1 {
		t.Fatalf("expected exactly one successful download, got %d", successCount)
	}
	if failureCount != 1 {
		t.Fatalf("expected exactly one failed download, got %d", failureCount)
	}

	refreshedShare, err := env.shareRepo.GetByID(share.ID)
	if err != nil {
		t.Fatalf("reload share: %v", err)
	}
	if refreshedShare.DownloadCount != 1 {
		t.Fatalf("expected download_count=1 after replay attempt, got %d", refreshedShare.DownloadCount)
	}
}

func TestShareService_DownloadVerificationCode_ConcurrentInvalidAttemptsCannotBypassLimit(t *testing.T) {
	env, cleanup := setupShareServiceTest(t)
	defer cleanup()

	email := "allowed@example.com"
	correctCode := "654321"
	share := createRestrictedShareWithKnownCode(t, env, email, correctCode)

	wrongCode := "000000"
	const extraAttempts = 3
	totalAttempts := shareVerificationMaxAttempts + extraAttempts

	start := make(chan struct{})
	errCh := make(chan error, totalAttempts)
	var wg sync.WaitGroup

	for i := 0; i < totalAttempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := env.shareSvc.GetFile(share.ID, nil, &email, &wrongCode)
			errCh <- err
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err == nil {
			t.Fatal("expected all wrong-code attempts to fail")
		}
	}

	_, err := env.shareSvc.GetFile(share.ID, nil, &email, &correctCode)
	if err == nil {
		t.Fatal("expected correct code to be rejected after concurrent invalid attempts")
	}
	if !strings.Contains(err.Error(), "verification") && !strings.Contains(err.Error(), "invalid or expired") {
		t.Fatalf("unexpected error after lockout: %v", err)
	}

	refreshedShare, err := env.shareRepo.GetByID(share.ID)
	if err != nil {
		t.Fatalf("reload share: %v", err)
	}
	if refreshedShare.DownloadCount != 0 {
		t.Fatalf("expected no successful downloads after invalid attempts, got %d", refreshedShare.DownloadCount)
	}
}

func TestShareService_DownloadVerificationCode_FailureMessageIsUniform(t *testing.T) {
	env, cleanup := setupShareServiceTest(t)
	defer cleanup()

	allowedEmail := "allowed@example.com"
	disallowedEmail := "blocked@example.com"
	wrongCode := "000000"

	share, err := env.shareSvc.Create(&CreateShareRequest{
		FileID:        env.fileID,
		AllowedEmails: []string{allowedEmail},
	})
	if err != nil {
		t.Fatalf("create restricted share: %v", err)
	}

	assertInvalidCodeError := func(email string) {
		t.Helper()

		_, err := env.shareSvc.GetFile(share.ID, nil, &email, &wrongCode)
		if err == nil {
			t.Fatalf("expected verification failure for %q", email)
		}
		if err.Error() != shareVerificationInvalidCode {
			t.Fatalf("expected %q, got %q", shareVerificationInvalidCode, err.Error())
		}
	}

	// Disallowed email and allowlisted email without pending state must be indistinguishable.
	assertInvalidCodeError(disallowedEmail)
	assertInvalidCodeError(allowedEmail)

	if err := env.shareSvc.RequestDownloadVerificationCode(share.ID, allowedEmail); err != nil {
		t.Fatalf("request download verification code for expiry case: %v", err)
	}

	expiredPending, err := env.shareRepo.GetPendingDownloadVerification(share.ID, allowedEmail)
	if err != nil {
		t.Fatalf("load pending verification for expiry case: %v", err)
	}
	expiredPending.ExpiresAt = time.Now().Add(-1 * time.Minute)
	if err := env.shareRepo.UpsertPendingDownloadVerification(expiredPending); err != nil {
		t.Fatalf("persist expired pending verification: %v", err)
	}

	assertInvalidCodeError(allowedEmail)

	if err := env.shareSvc.RequestDownloadVerificationCode(share.ID, allowedEmail); err != nil {
		t.Fatalf("request download verification code for lockout case: %v", err)
	}

	lockedPending, err := env.shareRepo.GetPendingDownloadVerification(share.ID, allowedEmail)
	if err != nil {
		t.Fatalf("load pending verification for lockout case: %v", err)
	}
	lockedPending.Attempts = shareVerificationMaxAttempts
	lockedPending.ExpiresAt = time.Now().Add(10 * time.Minute)
	if err := env.shareRepo.UpsertPendingDownloadVerification(lockedPending); err != nil {
		t.Fatalf("persist lockout pending verification: %v", err)
	}

	assertInvalidCodeError(allowedEmail)
}

func TestShareService_RequestDownloadVerificationCode_ResendDelayDoesNotRotateCode(t *testing.T) {
	env, cleanup := setupShareServiceTest(t)
	defer cleanup()

	email := "allowed@example.com"
	share, err := env.shareSvc.Create(&CreateShareRequest{
		FileID:        env.fileID,
		AllowedEmails: []string{email},
	})
	if err != nil {
		t.Fatalf("create restricted share: %v", err)
	}

	if err := env.shareSvc.RequestDownloadVerificationCode(share.ID, email); err != nil {
		t.Fatalf("first code request: %v", err)
	}

	firstPending, err := env.shareRepo.GetPendingDownloadVerification(share.ID, email)
	if err != nil {
		t.Fatalf("load pending after first request: %v", err)
	}

	if err := env.shareSvc.RequestDownloadVerificationCode(share.ID, email); err != nil {
		t.Fatalf("second code request during resend window: %v", err)
	}

	secondPending, err := env.shareRepo.GetPendingDownloadVerification(share.ID, email)
	if err != nil {
		t.Fatalf("load pending after second request: %v", err)
	}

	if firstPending.VerificationCodeHash != secondPending.VerificationCodeHash {
		t.Fatal("expected verification code hash to remain unchanged within resend delay window")
	}
}

func TestShareService_RequestDownloadVerificationCode_ConcurrentRotateQueuesSingleEmail(t *testing.T) {
	env, cleanup := setupShareServiceTestWithoutWorkers(t)
	defer cleanup()

	email := "allowed@example.com"
	share, err := env.shareSvc.Create(&CreateShareRequest{
		FileID:        env.fileID,
		AllowedEmails: []string{email},
	})
	if err != nil {
		t.Fatalf("create restricted share: %v", err)
	}

	now := time.Now()
	if err := env.shareRepo.UpsertPendingDownloadVerification(&models.PendingShareDownloadVerification{
		ShareID:              share.ID,
		Email:                email,
		VerificationCodeHash: env.shareSvc.hashDownloadVerificationCode(share.ID, email, "000000"),
		ExpiresAt:            now.Add(10 * time.Minute),
		ResendAfter:          now.Add(-1 * time.Minute),
		Attempts:             0,
	}); err != nil {
		t.Fatalf("seed pending verification: %v", err)
	}

	const parallelRequests = 8
	env.shareSvc.downloadVerificationEmailJobs = make(chan downloadVerificationEmailJob, parallelRequests)

	start := make(chan struct{})
	errCh := make(chan error, parallelRequests)
	var wg sync.WaitGroup
	for i := 0; i < parallelRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errCh <- env.shareSvc.RequestDownloadVerificationCode(share.ID, email)
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)

	for reqErr := range errCh {
		if reqErr != nil {
			t.Fatalf("concurrent code request failed: %v", reqErr)
		}
	}

	if queued := len(env.shareSvc.downloadVerificationEmailJobs); queued != 1 {
		t.Fatalf("expected exactly one queued email job after concurrent rotate, got %d", queued)
	}

	job := <-env.shareSvc.downloadVerificationEmailJobs
	pending, err := env.shareRepo.GetPendingDownloadVerification(share.ID, email)
	if err != nil {
		t.Fatalf("load pending verification: %v", err)
	}
	if pending.VerificationCodeHash != job.verificationCodeHash {
		t.Fatalf(
			"expected stored hash %q to match queued job hash %q",
			pending.VerificationCodeHash,
			job.verificationCodeHash,
		)
	}
}

func TestShareService_SendDownloadVerificationEmail_NoSMTPInNonProductionLogsFallbackCode(t *testing.T) {
	env, cleanup := setupShareServiceTest(t)
	defer cleanup()

	t.Setenv("SMTP_HOST", "")
	env.shareSvc.config.IsProduction = false

	var logOutput bytes.Buffer
	logger.Init(logger.Config{
		Level:  "info",
		Format: "json",
		Output: &logOutput,
	})
	t.Cleanup(func() {
		logger.Init(logger.Config{
			Level:  "info",
			Format: "json",
		})
	})

	const (
		email = "allowed@example.com"
		code  = "123456"
	)
	if err := env.shareSvc.sendDownloadVerificationEmail(email, code); err != nil {
		t.Fatalf("send download verification email with SMTP fallback: %v", err)
	}

	logged := logOutput.String()
	if !strings.Contains(logged, `"component":"share_download_verification"`) {
		t.Fatalf("expected fallback log to include share component, got logs: %s", logged)
	}
	if !strings.Contains(logged, `"email":"`+email+`"`) {
		t.Fatalf("expected fallback log to include email %q, got logs: %s", email, logged)
	}
	if !strings.Contains(logged, `"verification_code":"`+code+`"`) {
		t.Fatalf("expected fallback log to include verification code %q, got logs: %s", code, logged)
	}
	if !strings.Contains(logged, "Download verification code (SMTP_HOST not configured)") {
		t.Fatalf("expected fallback log message, got logs: %s", logged)
	}
}

func TestShareService_RequestDownloadVerificationCode_SendFailureDoesNotPersistPending(t *testing.T) {
	env, cleanup := setupShareServiceTest(t)
	defer cleanup()

	email := "allowed@example.com"
	share, err := env.shareSvc.Create(&CreateShareRequest{
		FileID:        env.fileID,
		AllowedEmails: []string{email},
	})
	if err != nil {
		t.Fatalf("create restricted share: %v", err)
	}

	t.Setenv("SMTP_HOST", "")
	env.shareSvc.config.IsProduction = true

	waitForNoPending := func(message string) {
		t.Helper()

		deadline := time.Now().Add(2 * time.Second)
		for {
			_, err := env.shareRepo.GetPendingDownloadVerification(share.ID, email)
			if errors.Is(err, sql.ErrNoRows) {
				return
			}
			if err != nil {
				t.Fatalf("unexpected pending verification lookup error: %v", err)
			}

			if time.Now().After(deadline) {
				t.Fatal(message)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	if err := env.shareSvc.RequestDownloadVerificationCode(share.ID, email); err != nil {
		t.Fatalf("expected generic success for first code request when SMTP is unavailable, got %v", err)
	}
	waitForNoPending("expected no pending verification after first async send failure")

	if err := env.shareSvc.RequestDownloadVerificationCode(share.ID, email); err != nil {
		t.Fatalf("expected generic success for second code request when SMTP is unavailable, got %v", err)
	}
	waitForNoPending("expected no pending verification after second async send failure")
}

func TestShareService_RequestDownloadVerificationCode_AsyncFailureCleanupTargetsFailedCodeOnly(t *testing.T) {
	env, cleanup := setupShareServiceTest(t)
	defer cleanup()

	email := "allowed@example.com"
	share, err := env.shareSvc.Create(&CreateShareRequest{
		FileID:        env.fileID,
		AllowedEmails: []string{email},
	})
	if err != nil {
		t.Fatalf("create restricted share: %v", err)
	}

	now := time.Now()
	firstCodeHash := env.shareSvc.hashDownloadVerificationCode(share.ID, email, "111111")
	if err := env.shareRepo.UpsertPendingDownloadVerification(&models.PendingShareDownloadVerification{
		ShareID:              share.ID,
		Email:                email,
		VerificationCodeHash: firstCodeHash,
		ExpiresAt:            now.Add(10 * time.Minute),
		ResendAfter:          now,
		Attempts:             0,
	}); err != nil {
		t.Fatalf("store first pending verification: %v", err)
	}

	secondCodeHash := env.shareSvc.hashDownloadVerificationCode(share.ID, email, "222222")
	if err := env.shareRepo.UpsertPendingDownloadVerification(&models.PendingShareDownloadVerification{
		ShareID:              share.ID,
		Email:                email,
		VerificationCodeHash: secondCodeHash,
		ExpiresAt:            now.Add(10 * time.Minute),
		ResendAfter:          now,
		Attempts:             0,
	}); err != nil {
		t.Fatalf("store second pending verification: %v", err)
	}

	env.shareSvc.cleanupPendingDownloadVerificationAfterSendFailure(share.ID, email, firstCodeHash)

	pending, err := env.shareRepo.GetPendingDownloadVerification(share.ID, email)
	if err != nil {
		t.Fatalf("expected newer pending verification to remain: %v", err)
	}
	if pending.VerificationCodeHash != secondCodeHash {
		t.Fatalf("expected newer code hash %q to remain, got %q", secondCodeHash, pending.VerificationCodeHash)
	}

	env.shareSvc.cleanupPendingDownloadVerificationAfterSendFailure(share.ID, email, secondCodeHash)

	_, err = env.shareRepo.GetPendingDownloadVerification(share.ID, email)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected pending verification to be deleted for matching failed code hash, got %v", err)
	}
}

func TestShareService_DownloadVerificationEmailWorker_DropsStaleQueuedJob(t *testing.T) {
	env, cleanup := setupShareServiceTestWithoutWorkers(t)
	defer cleanup()

	email := "allowed@example.com"
	share, err := env.shareSvc.Create(&CreateShareRequest{
		FileID:        env.fileID,
		AllowedEmails: []string{email},
	})
	if err != nil {
		t.Fatalf("create restricted share: %v", err)
	}

	currentCode := "222222"
	currentHash := env.shareSvc.hashDownloadVerificationCode(share.ID, email, currentCode)
	if err := env.shareRepo.UpsertPendingDownloadVerification(&models.PendingShareDownloadVerification{
		ShareID:              share.ID,
		Email:                email,
		VerificationCodeHash: currentHash,
		ExpiresAt:            time.Now().Add(10 * time.Minute),
		ResendAfter:          time.Now(),
		Attempts:             0,
	}); err != nil {
		t.Fatalf("store current pending verification: %v", err)
	}

	sendCount := 0
	env.shareSvc.sendDownloadVerificationEmailFn = func(_ string, _ string) error {
		sendCount++
		return nil
	}

	staleCode := "111111"
	staleHash := env.shareSvc.hashDownloadVerificationCode(share.ID, email, staleCode)
	runDownloadVerificationWorkerForJobs(t, env.shareSvc, downloadVerificationEmailJob{
		shareID:              share.ID,
		email:                email,
		code:                 staleCode,
		verificationCodeHash: staleHash,
	})

	if sendCount != 0 {
		t.Fatalf("expected stale queued job to be skipped, got %d send calls", sendCount)
	}

	pending, err := env.shareRepo.GetPendingDownloadVerification(share.ID, email)
	if err != nil {
		t.Fatalf("load pending verification after stale job: %v", err)
	}
	if pending.VerificationCodeHash != currentHash {
		t.Fatalf("expected current hash %q to remain, got %q", currentHash, pending.VerificationCodeHash)
	}
}

func TestShareService_DownloadVerificationEmailWorker_SendsCurrentQueuedJob(t *testing.T) {
	env, cleanup := setupShareServiceTestWithoutWorkers(t)
	defer cleanup()

	email := "allowed@example.com"
	share, err := env.shareSvc.Create(&CreateShareRequest{
		FileID:        env.fileID,
		AllowedEmails: []string{email},
	})
	if err != nil {
		t.Fatalf("create restricted share: %v", err)
	}

	currentCode := "333333"
	currentHash := env.shareSvc.hashDownloadVerificationCode(share.ID, email, currentCode)
	if err := env.shareRepo.UpsertPendingDownloadVerification(&models.PendingShareDownloadVerification{
		ShareID:              share.ID,
		Email:                email,
		VerificationCodeHash: currentHash,
		ExpiresAt:            time.Now().Add(10 * time.Minute),
		ResendAfter:          time.Now(),
		Attempts:             0,
	}); err != nil {
		t.Fatalf("store current pending verification: %v", err)
	}

	sendCount := 0
	sentEmail := ""
	sentCode := ""
	env.shareSvc.sendDownloadVerificationEmailFn = func(jobEmail, jobCode string) error {
		sendCount++
		sentEmail = jobEmail
		sentCode = jobCode
		return nil
	}

	runDownloadVerificationWorkerForJobs(t, env.shareSvc, downloadVerificationEmailJob{
		shareID:              share.ID,
		email:                email,
		code:                 currentCode,
		verificationCodeHash: currentHash,
	})

	if sendCount != 1 {
		t.Fatalf("expected current queued job to be sent once, got %d send calls", sendCount)
	}
	if sentEmail != email {
		t.Fatalf("expected sent email %q, got %q", email, sentEmail)
	}
	if sentCode != currentCode {
		t.Fatalf("expected sent code %q, got %q", currentCode, sentCode)
	}
}

func TestShareService_RequestDownloadVerificationCode_QueueFullCleansPending(t *testing.T) {
	env, cleanup := setupShareServiceTestWithoutWorkers(t)
	defer cleanup()

	email := "allowed@example.com"
	share, err := env.shareSvc.Create(&CreateShareRequest{
		FileID:        env.fileID,
		AllowedEmails: []string{email},
	})
	if err != nil {
		t.Fatalf("create restricted share: %v", err)
	}

	// Replace queue with a full local buffer to force the bounded async path to drop work.
	env.shareSvc.downloadVerificationEmailJobs = make(chan downloadVerificationEmailJob, 1)
	env.shareSvc.downloadVerificationEmailJobs <- downloadVerificationEmailJob{
		shareID:              "saturated-share",
		email:                "saturated@example.com",
		code:                 "000000",
		verificationCodeHash: "saturated-hash",
	}

	if err := env.shareSvc.RequestDownloadVerificationCode(share.ID, email); err != nil {
		t.Fatalf("expected generic success when queue is full, got %v", err)
	}

	if _, err := env.shareRepo.GetPendingDownloadVerification(share.ID, email); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected pending verification to be deleted when queue is full, got %v", err)
	}
}

func TestShareService_DownloadVerificationCode_CanBeUsedOnlyOnceSequentially(t *testing.T) {
	env, cleanup := setupShareServiceTest(t)
	defer cleanup()

	email := "allowed@example.com"
	code := "111111"
	share := createRestrictedShareWithKnownCode(t, env, email, code)

	if _, err := env.shareSvc.GetFile(share.ID, nil, &email, &code); err != nil {
		t.Fatalf("first download with valid code failed: %v", err)
	}

	if _, err := env.shareSvc.GetFile(share.ID, nil, &email, &code); err == nil {
		t.Fatal("expected second download with same code to fail")
	}

	if _, err := env.shareRepo.GetPendingDownloadVerification(share.ID, email); err == nil {
		t.Fatal("expected pending verification entry to be consumed")
	} else if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows after code consumption, got %v", err)
	}
}
