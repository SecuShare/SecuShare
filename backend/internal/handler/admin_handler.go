package handler

import (
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/SecuShare/SecuShare/backend/internal/service"
	"github.com/SecuShare/SecuShare/backend/pkg/logger"
	"github.com/SecuShare/SecuShare/backend/pkg/response"
	"github.com/gofiber/fiber/v2"
)

type AdminHandler struct {
	adminSvc  *service.AdminService
	authSvc   *service.AuthService
	fileSvc   *service.FileService
	shareRepo *repository.ShareRepository
	guestRepo *repository.GuestSessionRepository
	pendRepo  *repository.PendingRegistrationRepository
}

func NewAdminHandler(
	adminSvc *service.AdminService,
	authSvc *service.AuthService,
	fileSvc *service.FileService,
	shareRepo *repository.ShareRepository,
	guestRepo *repository.GuestSessionRepository,
	pendRepo *repository.PendingRegistrationRepository,
) *AdminHandler {
	return &AdminHandler{
		adminSvc:  adminSvc,
		authSvc:   authSvc,
		fileSvc:   fileSvc,
		shareRepo: shareRepo,
		guestRepo: guestRepo,
		pendRepo:  pendRepo,
	}
}

func localUserID(c *fiber.Ctx) string {
	userID, ok := c.Locals("user_id").(string)
	if !ok {
		return ""
	}
	return userID
}

// CheckSetupStatus returns whether setup has been completed.
func (h *AdminHandler) CheckSetupStatus(c *fiber.Ctx) error {
	return response.Success(c, map[string]bool{
		"setup_completed": h.adminSvc.IsSetupCompleted(),
	})
}

// CompleteSetup creates the first admin account. Self-disabling after first use.
func (h *AdminHandler) CompleteSetup(c *fiber.Ctx) error {
	if h.adminSvc.IsSetupCompleted() {
		return response.Forbidden(c, "setup already completed")
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
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

	user, token, err := h.authSvc.RegisterWithPassword(req.Email, req.Password)
	if err != nil {
		logger.Error().Err(err).Str("email", req.Email).Msg("Setup registration failed")
		return response.InternalError(c, "failed to create admin account")
	}

	if err := h.authSvc.SetAdmin(user.ID, true); err != nil {
		logger.Error().Err(err).Str("user_id", user.ID).Msg("Failed to set admin flag")
		return response.InternalError(c, "failed to set admin privileges")
	}

	// Mark email as verified for setup account
	if err := h.authSvc.SetEmailVerified(user.ID, true); err != nil {
		logger.Error().Err(err).Str("user_id", user.ID).Msg("Failed to verify email for setup admin")
	}

	if err := h.adminSvc.CompleteSetup(); err != nil {
		logger.Error().Err(err).Msg("Failed to mark setup as completed")
		return response.InternalError(c, "failed to complete setup")
	}

	user.IsAdmin = true
	user.IsEmailVerified = true

	csrfToken := setCSRFCookie(c)
	setAuthCookie(c, token)

	logger.Audit("setup_completed", user.ID, map[string]string{
		"email": req.Email,
	})

	return response.Success(c, AuthResponse{
		Token:     token,
		CSRFToken: csrfToken,
		User:      user,
	})
}

// GetSettings returns all app settings.
func (h *AdminHandler) GetSettings(c *fiber.Ctx) error {
	settings, err := h.adminSvc.GetAllSettings()
	if err != nil {
		return response.InternalError(c, "failed to load settings")
	}
	return response.Success(c, settings)
}

// UpdateSettings modifies app settings.
func (h *AdminHandler) UpdateSettings(c *fiber.Ctx) error {
	var req struct {
		Settings map[string]string `json:"settings"`
	}
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "invalid request body")
	}
	if len(req.Settings) == 0 {
		return response.BadRequest(c, "no settings provided")
	}

	if err := h.adminSvc.UpdateSettings(req.Settings); err != nil {
		return response.InternalError(c, "failed to update settings")
	}

	userID := localUserID(c)
	logger.Audit("settings_updated", userID, nil)

	return response.Success(c, map[string]string{"message": "settings updated"})
}

// GetStats returns usage statistics.
func (h *AdminHandler) GetStats(c *fiber.Ctx) error {
	stats, err := h.adminSvc.GetUsageStats()
	if err != nil {
		return response.InternalError(c, "failed to load stats")
	}
	return response.Success(c, stats)
}

// ListUsers returns all users with usage info.
func (h *AdminHandler) ListUsers(c *fiber.Ctx) error {
	users, err := h.adminSvc.ListUsers()
	if err != nil {
		return response.InternalError(c, "failed to list users")
	}
	return response.Success(c, users)
}

// DeleteUser removes a user and their files.
func (h *AdminHandler) DeleteUser(c *fiber.Ctx) error {
	targetID := c.Params("id")
	if targetID == "" {
		return response.BadRequest(c, "user ID is required")
	}

	adminID := localUserID(c)

	if err := h.adminSvc.DeleteUser(targetID, adminID); err != nil {
		switch err.Error() {
		case "cannot delete your own account":
			return response.BadRequest(c, err.Error())
		case "cannot delete the last admin":
			return response.BadRequest(c, err.Error())
		case "user not found":
			return response.NotFound(c, err.Error())
		default:
			return response.InternalError(c, "failed to delete user")
		}
	}

	logger.Audit("user_deleted", adminID, map[string]string{
		"deleted_user_id": targetID,
	})

	return response.Success(c, map[string]string{"message": "user deleted"})
}

// TriggerCleanup runs the same cleanup as the hourly background job.
func (h *AdminHandler) TriggerCleanup(c *fiber.Ctx) error {
	now := time.Now()
	results := map[string]string{}

	if err := h.shareRepo.DeleteExpired(); err != nil {
		results["shares"] = "error: " + err.Error()
	} else {
		results["shares"] = "cleaned"
	}

	if err := h.fileSvc.DeleteExpired(now); err != nil {
		results["expired_files"] = "error: " + err.Error()
	} else {
		results["expired_files"] = "cleaned"
	}

	if err := h.fileSvc.DeleteByExpiredGuestSessions(now); err != nil {
		results["guest_files"] = "error: " + err.Error()
	} else {
		results["guest_files"] = "cleaned"
	}

	if err := h.guestRepo.DeleteExpired(); err != nil {
		results["guest_sessions"] = "error: " + err.Error()
	} else {
		results["guest_sessions"] = "cleaned"
	}

	if err := h.pendRepo.DeleteExpired(now); err != nil {
		results["pending_registrations"] = "error: " + err.Error()
	} else {
		results["pending_registrations"] = "cleaned"
	}
	if err := h.shareRepo.DeleteExpiredPendingDownloadVerifications(now); err != nil {
		results["pending_share_download_verifications"] = "error: " + err.Error()
	} else {
		results["pending_share_download_verifications"] = "cleaned"
	}

	if err := h.fileSvc.ReconcileStorageUsage(); err != nil {
		results["storage_reconciliation"] = "error: " + err.Error()
	} else {
		results["storage_reconciliation"] = "cleaned"
	}

	userID := localUserID(c)
	logger.Audit("manual_cleanup", userID, nil)

	return response.Success(c, results)
}

// GetPublicSettings returns file size limits visible to all users.
func (h *AdminHandler) GetPublicSettings(c *fiber.Ctx) error {
	return response.Success(c, map[string]int64{
		"max_file_size_guest": h.adminSvc.GetMaxFileSize(true),
		"max_file_size_user":  h.adminSvc.GetMaxFileSize(false),
	})
}
