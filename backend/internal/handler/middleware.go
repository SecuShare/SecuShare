package handler

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/service"
	"github.com/SecuShare/SecuShare/backend/pkg/response"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// SecurityHeadersMiddleware adds security-related headers to all responses
func SecurityHeadersMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Prevent MIME type sniffing
		c.Set("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking
		c.Set("X-Frame-Options", "DENY")

		// Enable XSS protection in browsers
		c.Set("X-XSS-Protection", "1; mode=block")

		// Control referrer information
		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Content Security Policy - restrictive for API
		c.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		// Prevent caching of sensitive API responses
		c.Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		c.Set("Pragma", "no-cache")
		c.Set("Expires", "0")

		return c.Next()
	}
}

// RequestIDMiddleware adds a unique request ID to each request
func RequestIDMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Check if request ID already exists in headers
		requestID := c.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Set request ID in response headers and locals
		c.Set("X-Request-ID", requestID)
		c.Locals("request_id", requestID)

		return c.Next()
	}
}

func AuthMiddleware(authSvc *service.AuthService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var token string
		authHeader := strings.TrimSpace(c.Get("Authorization"))
		if authHeader != "" {
			parts := strings.Fields(authHeader)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || strings.TrimSpace(parts[1]) == "" {
				return response.Unauthorized(c, "invalid authorization header format")
			}
			token = parts[1]
		} else {
			token = strings.TrimSpace(c.Cookies(authTokenCookieName))
			if token == "" {
				return response.Unauthorized(c, "missing authorization token")
			}
		}

		claims, err := authSvc.ValidateToken(token)
		if err != nil {
			RecordAuthFailure("invalid_token")
			return response.Unauthorized(c, "invalid or expired token")
		}

		// Validate guest session expiry from the database
		if claims.IsGuest {
			session, err := authSvc.GetGuestSessionByID(claims.UserID)
			if err != nil {
				RecordAuthFailure("guest_session_not_found")
				return response.Unauthorized(c, "guest session not found")
			}
			if session.ExpiresAt.Before(time.Now()) {
				RecordAuthFailure("guest_session_expired")
				return response.Unauthorized(c, "guest session has expired")
			}
		}

		c.Locals("user_id", claims.UserID)
		c.Locals("is_guest", claims.IsGuest)

		return c.Next()
	}
}

func OptionalAuthMiddleware(authSvc *service.AuthService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var token string
		authHeader := strings.TrimSpace(c.Get("Authorization"))
		if authHeader != "" {
			parts := strings.Fields(authHeader)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || strings.TrimSpace(parts[1]) == "" {
				c.Locals("user_id", "")
				c.Locals("is_guest", false)
				return c.Next()
			}
			token = parts[1]
		} else {
			token = strings.TrimSpace(c.Cookies(authTokenCookieName))
			if token == "" {
				c.Locals("user_id", "")
				c.Locals("is_guest", false)
				return c.Next()
			}
		}

		claims, err := authSvc.ValidateToken(token)
		if err != nil {
			c.Locals("user_id", "")
			c.Locals("is_guest", false)
			return c.Next()
		}

		// Validate guest session expiry from the database
		if claims.IsGuest {
			session, err := authSvc.GetGuestSessionByID(claims.UserID)
			if err != nil || session.ExpiresAt.Before(time.Now()) {
				c.Locals("user_id", "")
				c.Locals("is_guest", false)
				return c.Next()
			}
		}

		c.Locals("user_id", claims.UserID)
		c.Locals("is_guest", claims.IsGuest)

		return c.Next()
	}
}

// AdminMiddleware checks that the authenticated user has admin privileges.
// Must be chained after AuthMiddleware.
func AdminMiddleware(authSvc *service.AuthService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		isGuest, ok := c.Locals("is_guest").(bool)
		if !ok {
			return response.Unauthorized(c, "authentication required")
		}
		if isGuest {
			return response.Forbidden(c, "admin access required")
		}

		userID, ok := c.Locals("user_id").(string)
		if !ok || userID == "" {
			return response.Unauthorized(c, "authentication required")
		}

		user, err := authSvc.GetUserByID(userID)
		if err != nil {
			return response.Unauthorized(c, "user not found")
		}

		if !user.IsAdmin {
			return response.Forbidden(c, "admin access required")
		}

		return c.Next()
	}
}

// CSRFMiddleware validates CSRF tokens for state-changing requests.
// The token is generated per-session and must be sent in the X-CSRF-Token header.
func CSRFMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Only validate on state-changing methods
		method := c.Method()
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			return c.Next()
		}

		csrfToken := c.Get("X-CSRF-Token")
		if csrfToken == "" {
			return response.Forbidden(c, "missing CSRF token")
		}

		// Validate the token matches the one stored for this session
		expectedToken := c.Cookies("csrf_token")
		if expectedToken == "" || csrfToken != expectedToken {
			return response.Forbidden(c, "invalid CSRF token")
		}

		return c.Next()
	}
}

// BodyLimitMiddleware enforces a per-route body size limit.
func BodyLimitMiddleware(maxBytes int) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if len(c.Body()) > maxBytes {
			return response.Error(c, fiber.StatusRequestEntityTooLarge, "request body too large")
		}
		return c.Next()
	}
}

// GenerateCSRFToken generates a new CSRF token and sets it as a cookie.
func GenerateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
