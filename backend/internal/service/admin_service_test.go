package service

import (
	"strings"
	"testing"

	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/SecuShare/SecuShare/backend/pkg/testutil"
)

func newAdminServiceForTest(t *testing.T) (*AdminService, func()) {
	t.Helper()

	db, _, cleanup := testutil.SetupTest(t)
	settingsRepo := repository.NewSettingsRepository(db)
	userRepo := repository.NewUserRepository(db)
	adminSvc := NewAdminService(settingsRepo, userRepo)

	return adminSvc, cleanup
}

func TestAdminService_UpdateSettings_RejectsUnknownSettingKey(t *testing.T) {
	adminSvc, cleanup := newAdminServiceForTest(t)
	defer cleanup()

	err := adminSvc.UpdateSettings(map[string]string{
		"unknown_setting": "1",
	})
	if err == nil {
		t.Fatal("expected unknown setting key to be rejected")
	}
	if !strings.Contains(err.Error(), "unknown setting key") {
		t.Fatalf("expected unknown key error, got %v", err)
	}
}

func TestAdminService_UpdateSettings_RejectsInvalidValues(t *testing.T) {
	adminSvc, cleanup := newAdminServiceForTest(t)
	defer cleanup()

	testCases := []struct {
		name string
		key  string
		val  string
	}{
		{
			name: "non-positive max file size",
			key:  "max_file_size_guest",
			val:  "0",
		},
		{
			name: "non-positive duration",
			key:  "guest_session_duration_hours",
			val:  "-1",
		},
		{
			name: "invalid domain",
			key:  "allowed_email_domains",
			val:  "example.com, bad domain",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := adminSvc.UpdateSettings(map[string]string{
				tc.key: tc.val,
			})
			if err == nil {
				t.Fatalf("expected invalid %s to be rejected", tc.key)
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("expected error to mention key %s, got %v", tc.key, err)
			}
		})
	}
}

func TestAdminService_UpdateSettings_NormalizesDomainsAndDuration(t *testing.T) {
	adminSvc, cleanup := newAdminServiceForTest(t)
	defer cleanup()

	err := adminSvc.UpdateSettings(map[string]string{
		"allowed_email_domains":        "Example.COM, company.org, example.com",
		"guest_session_duration_hours": "48",
	})
	if err != nil {
		t.Fatalf("UpdateSettings failed: %v", err)
	}

	if got := adminSvc.GetCachedSetting("allowed_email_domains"); got != "example.com,company.org" {
		t.Fatalf("expected normalized domains example.com,company.org, got %q", got)
	}
	if got := adminSvc.GetGuestSessionDurationHours(); got != 48 {
		t.Fatalf("expected guest session duration to be 48, got %d", got)
	}
}
