package logger

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

type testCtxKey string

func TestInitNewAndContextHelpers(t *testing.T) {
	previous := DefaultLogger
	defer func() { DefaultLogger = previous }()

	var buf bytes.Buffer
	Init(Config{
		Level:  "debug",
		Format: "json",
		Output: &buf,
	})

	l := New(Config{
		Level:  "info",
		Format: "json",
		Output: &buf,
	})
	if l == nil {
		t.Fatal("expected logger instance")
	}

	l.Debug().Msg("debug")
	l.Info().Msg("info")
	l.Warn().Msg("warn")
	l.Error().Msg("error")
	_ = l.With()

	ctx := context.WithValue(context.Background(), testCtxKey("request_id"), "req-1")
	ctx = context.WithValue(ctx, testCtxKey("user_id"), "user-1")
	withCtx := l.WithContext(ctx)
	withCtx.Info().Msg("with context")

	ctxWithLogger := ContextWithLogger(context.Background(), l)
	if got := FromContext(ctxWithLogger); got != l {
		t.Fatal("expected logger from context")
	}
}

func TestPackageFunctionsAndMiddleware(t *testing.T) {
	previous := DefaultLogger
	defer func() { DefaultLogger = previous }()
	DefaultLogger = nil

	Debug().Msg("debug")
	Info().Msg("info")
	Warn().Msg("warn")
	Error().Msg("error")
	Audit("action", "user-123", map[string]string{"k": "v"})

	app := fiber.New()
	app.Use(Middleware())
	app.Get("/ok", func(c *fiber.Ctx) error {
		c.Locals("request_id", "rid-1")
		return c.SendStatus(fiber.StatusAccepted)
	})
	app.Get("/fail", func(c *fiber.Ctx) error {
		return fiber.ErrBadRequest
	})

	okReq := httptest.NewRequest(http.MethodGet, "/ok", nil)
	okResp, err := app.Test(okReq, -1)
	if err != nil {
		t.Fatalf("app.Test /ok: %v", err)
	}
	defer okResp.Body.Close()
	if okResp.StatusCode != fiber.StatusAccepted {
		t.Fatalf("expected %d, got %d", fiber.StatusAccepted, okResp.StatusCode)
	}

	failReq := httptest.NewRequest(http.MethodGet, "/fail", nil)
	failResp, err := app.Test(failReq, -1)
	if err != nil {
		t.Fatalf("app.Test /fail: %v", err)
	}
	defer failResp.Body.Close()
	if failResp.StatusCode == fiber.StatusAccepted {
		t.Fatal("expected non-success status for failing route")
	}
}
