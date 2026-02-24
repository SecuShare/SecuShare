package handler

import (
	"crypto/subtle"
	"strings"

	"github.com/SecuShare/SecuShare/backend/pkg/response"
	"github.com/gofiber/fiber/v2"
)

// BearerTokenMiddleware protects an endpoint with a static bearer token.
func BearerTokenMiddleware(expectedToken string) fiber.Handler {
	expected := strings.TrimSpace(expectedToken)

	return func(c *fiber.Ctx) error {
		if expected == "" {
			return response.Forbidden(c, "endpoint is disabled")
		}

		authHeader := strings.TrimSpace(c.Get("Authorization"))
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return response.Unauthorized(c, "missing or invalid authorization header")
		}

		provided := strings.TrimSpace(parts[1])
		if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			return response.Unauthorized(c, "invalid authorization token")
		}

		return c.Next()
	}
}
