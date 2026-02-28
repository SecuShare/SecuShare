package handler

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SecuShare/SecuShare/backend/pkg/testutil"
	"github.com/gofiber/fiber/v2"
)

func newRateLimitTestApp(t *testing.T, limiter *RateLimiter, keyHeader string) *fiber.App {
	t.Helper()

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		if keyHeader != "" {
			c.Request().Header.Set("X-Rate-Key", keyHeader)
		}
		return c.Next()
	})
	app.Use(limiter.Middleware())
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	return app
}

func requestStatus(t *testing.T, app *fiber.App) int {
	t.Helper()

	req := httptest.NewRequest("GET", "/", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestRateLimiterPersistent_PersistsAcrossInstances(t *testing.T) {
	db, _, cleanup := testutil.SetupTest(t)
	defer cleanup()

	keyFunc := func(c *fiber.Ctx) string { return c.Get("X-Rate-Key") }

	limiter1 := NewPersistentRateLimiterWithKey(db, "auth-test", 2, time.Minute, keyFunc)
	defer limiter1.Stop()
	app1 := newRateLimitTestApp(t, limiter1, "k1")

	if got := requestStatus(t, app1); got != fiber.StatusOK {
		t.Fatalf("request 1 status=%d, want %d", got, fiber.StatusOK)
	}
	if got := requestStatus(t, app1); got != fiber.StatusOK {
		t.Fatalf("request 2 status=%d, want %d", got, fiber.StatusOK)
	}
	if got := requestStatus(t, app1); got != fiber.StatusTooManyRequests {
		t.Fatalf("request 3 status=%d, want %d", got, fiber.StatusTooManyRequests)
	}

	limiter2 := NewPersistentRateLimiterWithKey(db, "auth-test", 2, time.Minute, keyFunc)
	defer limiter2.Stop()
	app2 := newRateLimitTestApp(t, limiter2, "k1")

	if got := requestStatus(t, app2); got != fiber.StatusTooManyRequests {
		t.Fatalf("request after limiter restart status=%d, want %d", got, fiber.StatusTooManyRequests)
	}
}

func TestRateLimiterPersistent_ResetsAfterWindow(t *testing.T) {
	db, _, cleanup := testutil.SetupTest(t)
	defer cleanup()

	keyFunc := func(c *fiber.Ctx) string { return c.Get("X-Rate-Key") }
	limiter := NewPersistentRateLimiterWithKey(db, "setup-test", 1, 100*time.Millisecond, keyFunc)
	defer limiter.Stop()

	app := newRateLimitTestApp(t, limiter, "k2")

	if got := requestStatus(t, app); got != fiber.StatusOK {
		t.Fatalf("request 1 status=%d, want %d", got, fiber.StatusOK)
	}
	if got := requestStatus(t, app); got != fiber.StatusTooManyRequests {
		t.Fatalf("request 2 status=%d, want %d", got, fiber.StatusTooManyRequests)
	}

	time.Sleep(130 * time.Millisecond)

	if got := requestStatus(t, app); got != fiber.StatusOK {
		t.Fatalf("request after window status=%d, want %d", got, fiber.StatusOK)
	}
}
