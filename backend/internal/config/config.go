package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Server        ServerConfig
	Database      DatabaseConfig
	Storage       StorageConfig
	Auth          AuthConfig
	Observability ObservabilityConfig
	IsProduction  bool
}

type ServerConfig struct {
	BindAddress    string
	Port           string
	AllowOrigins   string
	TrustedProxies []string
}

type DatabaseConfig struct {
	Path string
}

type StorageConfig struct {
	Path string
}

type AuthConfig struct {
	JWTSecret              string
	DownloadCodeHMACSecret string
	GuestDuration          int // hours
	OPAQUEServerSetup      string
}

type ObservabilityConfig struct {
	MetricsEnabled bool
	MetricsToken   string
}

func Load() *Config {
	loadDotEnvIfPresent()

	isProd := getEnv("ENVIRONMENT", "development") == "production"
	defaultSecret := ""
	if !isProd {
		defaultSecret = "dev-secret-change-in-production"
	}
	defaultDownloadCodeHMACSecret := ""
	jwtSecret := strings.TrimSpace(getEnv("JWT_SECRET", defaultSecret))
	downloadCodeHMACSecret := strings.TrimSpace(getEnv("DOWNLOAD_CODE_HMAC_SECRET", defaultDownloadCodeHMACSecret))
	if !isProd && downloadCodeHMACSecret == "" {
		downloadCodeHMACSecret = deriveDevDownloadCodeHMACSecret(jwtSecret)
	}
	defaultBindAddress := "0.0.0.0"
	if isProd {
		// In production we default to loopback and rely on a reverse proxy.
		defaultBindAddress = "127.0.0.1"
	}
	defaultTrustedProxies := "127.0.0.1,::1"
	defaultMetricsEnabled := !isProd

	return &Config{
		IsProduction: isProd,
		Server: ServerConfig{
			BindAddress:    getEnv("SERVER_BIND_ADDRESS", defaultBindAddress),
			Port:           getEnv("SERVER_PORT", "8080"),
			AllowOrigins:   getEnv("ALLOW_ORIGINS", "http://localhost:5173"),
			TrustedProxies: splitCSV(getEnv("TRUSTED_PROXIES", defaultTrustedProxies)),
		},
		Database: DatabaseConfig{
			Path: getEnv("DATABASE_PATH", "./storage/secushare.db"),
		},
		Storage: StorageConfig{
			Path: getEnv("STORAGE_PATH", "./storage/files"),
		},
		Auth: AuthConfig{
			JWTSecret:              jwtSecret,
			DownloadCodeHMACSecret: downloadCodeHMACSecret,
			GuestDuration:          getEnvIntAny(24, "GUEST_DURATION_HOURS", "GUEST_DURATION"),
			OPAQUEServerSetup:      getEnv("OPAQUE_SERVER_SETUP", ""),
		},
		Observability: ObservabilityConfig{
			MetricsEnabled: getEnvBool("METRICS_ENABLED", defaultMetricsEnabled),
			MetricsToken:   strings.TrimSpace(getEnv("METRICS_TOKEN", "")),
		},
	}
}

func deriveDevDownloadCodeHMACSecret(jwtSecret string) string {
	sum := sha256.Sum256([]byte("secushare-dev-download-code:" + jwtSecret))
	return hex.EncodeToString(sum[:])
}

// Validate checks that the configuration is valid for the current environment.
// In production, it enforces stricter requirements.
func (c *Config) Validate() error {
	if c.IsProduction {
		if c.Auth.JWTSecret == "" {
			return errors.New("JWT_SECRET environment variable is required in production")
		}
		if len(c.Auth.JWTSecret) < 32 {
			return errors.New("JWT_SECRET must be at least 32 characters in production")
		}
		if c.Auth.DownloadCodeHMACSecret == "" {
			return errors.New("DOWNLOAD_CODE_HMAC_SECRET environment variable is required in production")
		}
		if len(c.Auth.DownloadCodeHMACSecret) < 32 {
			return errors.New("DOWNLOAD_CODE_HMAC_SECRET must be at least 32 characters in production")
		}
		if c.Auth.DownloadCodeHMACSecret == c.Auth.JWTSecret {
			return errors.New("DOWNLOAD_CODE_HMAC_SECRET must be different from JWT_SECRET in production")
		}
		if c.Auth.OPAQUEServerSetup == "" {
			return errors.New("OPAQUE_SERVER_SETUP environment variable is required in production")
		}
		if c.Server.AllowOrigins == "http://localhost:5173" {
			return errors.New("ALLOW_ORIGINS must be configured for production (localhost not allowed)")
		}
		if c.Server.AllowOrigins == "*" {
			return errors.New("ALLOW_ORIGINS must not be wildcard (*) in production")
		}
		if strings.TrimSpace(os.Getenv("SMTP_HOST")) == "" {
			return errors.New("SMTP_HOST environment variable is required in production for email verification")
		}
		if c.Observability.MetricsEnabled && c.Observability.MetricsToken == "" {
			return errors.New("METRICS_TOKEN is required in production when METRICS_ENABLED=true")
		}
	}

	if strings.TrimSpace(c.Server.BindAddress) == "" {
		return errors.New("SERVER_BIND_ADDRESS must not be empty")
	}

	port, err := strconv.Atoi(c.Server.Port)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("SERVER_PORT must be a valid port number (1-65535)")
	}

	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntAny(defaultValue int, keys ...string) int {
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			if intVal, err := strconv.Atoi(value); err == nil {
				return intVal
			}
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	value, ok := os.LookupEnv(key)
	if !ok {
		return defaultValue
	}

	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultValue
	}
}

func splitCSV(value string) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}

	parts := strings.Split(trimmed, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		v := strings.TrimSpace(part)
		if v == "" {
			continue
		}
		out = append(out, v)
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

func loadDotEnvIfPresent() {
	for _, path := range []string{".env", "backend/.env"} {
		// #nosec G304 -- paths are hardcoded application dotenv locations.
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		for _, rawLine := range strings.Split(string(content), "\n") {
			line := strings.TrimSpace(rawLine)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "export ") {
				line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
			}

			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if key == "" {
				continue
			}

			if len(value) >= 2 {
				if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
					value = value[1 : len(value)-1]
				}
			}

			if _, exists := os.LookupEnv(key); exists {
				continue
			}
			_ = os.Setenv(key, value)
		}
	}
}
