package config

import (
	"strings"
	"testing"
)

func baseProdConfig() *Config {
	return &Config{
		IsProduction: true,
		Server: ServerConfig{
			BindAddress:  "127.0.0.1",
			Port:         "8080",
			AllowOrigins: "https://secushare.example.com",
		},
		Auth: AuthConfig{
			JWTSecret:              strings.Repeat("x", 32),
			DownloadCodeHMACSecret: strings.Repeat("y", 32),
			OPAQUEServerSetup:      "opaque-setup",
		},
		Observability: ObservabilityConfig{
			MetricsEnabled: false,
		},
	}
}

func TestValidate_ProductionMetricsRequireTokenWhenEnabled(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")

	cfg := baseProdConfig()
	cfg.Observability.MetricsEnabled = true
	cfg.Observability.MetricsToken = ""

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "METRICS_TOKEN") {
		t.Fatalf("expected METRICS_TOKEN validation error, got: %v", err)
	}
}

func TestValidate_ProductionMetricsEnabledWithTokenPasses(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")

	cfg := baseProdConfig()
	cfg.Observability.MetricsEnabled = true
	cfg.Observability.MetricsToken = "metrics-secret"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected config to validate, got: %v", err)
	}
}

func TestValidate_RejectsEmptyBindAddress(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")

	cfg := baseProdConfig()
	cfg.Server.BindAddress = ""

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "SERVER_BIND_ADDRESS") {
		t.Fatalf("expected SERVER_BIND_ADDRESS validation error, got: %v", err)
	}
}

func TestValidate_ProductionRequiresDedicatedDownloadCodeHMACSecret(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")

	cfg := baseProdConfig()
	cfg.Auth.DownloadCodeHMACSecret = ""

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "DOWNLOAD_CODE_HMAC_SECRET") {
		t.Fatalf("expected DOWNLOAD_CODE_HMAC_SECRET validation error, got: %v", err)
	}
}

func TestValidate_ProductionRejectsSharedJWTAndDownloadCodeSecrets(t *testing.T) {
	t.Setenv("SMTP_HOST", "smtp.example.com")

	cfg := baseProdConfig()
	cfg.Auth.DownloadCodeHMACSecret = cfg.Auth.JWTSecret

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must be different") {
		t.Fatalf("expected dedicated secret validation error, got: %v", err)
	}
}

func TestLoad_NonProductionDerivesDownloadCodeHMACSecretWhenMissing(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("JWT_SECRET", "dev-jwt-secret")
	t.Setenv("DOWNLOAD_CODE_HMAC_SECRET", "")

	cfg := Load()

	if cfg.Auth.JWTSecret != "dev-jwt-secret" {
		t.Fatalf("expected JWT secret from env, got %q", cfg.Auth.JWTSecret)
	}
	if cfg.Auth.DownloadCodeHMACSecret == "" {
		t.Fatal("expected derived download code secret in non-production")
	}
	if cfg.Auth.DownloadCodeHMACSecret == cfg.Auth.JWTSecret {
		t.Fatal("expected derived download code secret to differ from JWT secret")
	}
	if cfg.Auth.DownloadCodeHMACSecret != deriveDevDownloadCodeHMACSecret(cfg.Auth.JWTSecret) {
		t.Fatal("expected derived download code secret to match derivation function")
	}
}

func TestLoad_ProductionDoesNotDeriveDownloadCodeHMACSecret(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("DOWNLOAD_CODE_HMAC_SECRET", "")

	cfg := Load()
	if cfg.Auth.DownloadCodeHMACSecret != "" {
		t.Fatalf("expected empty download code secret in production when unset, got %q", cfg.Auth.DownloadCodeHMACSecret)
	}
}
