package response

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestSuccess(t *testing.T) {
	app := fiber.New()
	app.Get("/ok", func(c *fiber.Ctx) error {
		return Success(c, map[string]string{"message": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected status %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	var payload APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !payload.Success {
		t.Fatal("expected success=true")
	}
	if payload.Error != "" {
		t.Fatalf("expected empty error, got %q", payload.Error)
	}
}

func TestErrorHelpers(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantStatus   int
		wantErrorMsg string
		handler      func(c *fiber.Ctx) error
	}{
		{
			name:         "error",
			path:         "/error",
			wantStatus:   fiber.StatusTeapot,
			wantErrorMsg: "teapot",
			handler: func(c *fiber.Ctx) error {
				return Error(c, fiber.StatusTeapot, "teapot")
			},
		},
		{
			name:         "bad_request",
			path:         "/bad_request",
			wantStatus:   fiber.StatusBadRequest,
			wantErrorMsg: "bad request",
			handler: func(c *fiber.Ctx) error {
				return BadRequest(c, "bad request")
			},
		},
		{
			name:         "unauthorized",
			path:         "/unauthorized",
			wantStatus:   fiber.StatusUnauthorized,
			wantErrorMsg: "unauthorized",
			handler: func(c *fiber.Ctx) error {
				return Unauthorized(c, "unauthorized")
			},
		},
		{
			name:         "forbidden",
			path:         "/forbidden",
			wantStatus:   fiber.StatusForbidden,
			wantErrorMsg: "forbidden",
			handler: func(c *fiber.Ctx) error {
				return Forbidden(c, "forbidden")
			},
		},
		{
			name:         "not_found",
			path:         "/not_found",
			wantStatus:   fiber.StatusNotFound,
			wantErrorMsg: "missing",
			handler: func(c *fiber.Ctx) error {
				return NotFound(c, "missing")
			},
		},
		{
			name:         "internal_error",
			path:         "/internal",
			wantStatus:   fiber.StatusInternalServerError,
			wantErrorMsg: "internal",
			handler: func(c *fiber.Ctx) error {
				return InternalError(c, "internal")
			},
		},
	}

	app := fiber.New()
	for _, tt := range tests {
		tt := tt
		app.Get(tt.path, tt.handler)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			resp, err := app.Test(req, -1)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}

			var payload APIResponse
			if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if payload.Success {
				t.Fatal("expected success=false")
			}
			if payload.Error != tt.wantErrorMsg {
				t.Fatalf("expected error %q, got %q", tt.wantErrorMsg, payload.Error)
			}
		})
	}
}
