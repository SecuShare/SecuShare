package logger

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// Logger wraps zerolog with our application-specific configuration
type Logger struct {
	zl zerolog.Logger
}

// ctxKey is the context key for the logger
type ctxKey struct{}

// loggerCtxKey is the context key for storing the logger
var loggerCtxKey = ctxKey{}

var (
	// DefaultLogger is the global logger instance
	DefaultLogger *Logger
)

// Config holds logger configuration
type Config struct {
	// Level sets the minimum log level (debug, info, warn, error)
	Level string
	// Format sets the output format (json, console)
	Format string
	// Output sets the output destination (defaults to stdout)
	Output io.Writer
}

// Init initializes the default logger with the given configuration
func Init(cfg Config) {
	if cfg.Output == nil {
		cfg.Output = os.Stdout
	}

	var zl zerolog.Logger
	if cfg.Format == "console" {
		// Console format with colors for development
		zl = zerolog.New(zerolog.ConsoleWriter{
			Out:        cfg.Output,
			TimeFormat: time.RFC3339,
		}).With().Timestamp().Logger()
	} else {
		// JSON format for production
		zl = zerolog.New(cfg.Output).With().Timestamp().Logger()
	}

	// Set log level
	switch cfg.Level {
	case "debug":
		zl = zl.Level(zerolog.DebugLevel)
	case "info":
		zl = zl.Level(zerolog.InfoLevel)
	case "warn":
		zl = zl.Level(zerolog.WarnLevel)
	case "error":
		zl = zl.Level(zerolog.ErrorLevel)
	default:
		zl = zl.Level(zerolog.InfoLevel)
	}

	DefaultLogger = &Logger{zl: zl}
	zerolog.TimeFieldFormat = time.RFC3339
}

// New creates a new logger instance
func New(cfg Config) *Logger {
	if DefaultLogger == nil {
		Init(cfg)
	}
	return DefaultLogger
}

// WithContext returns a logger with context values
func (l *Logger) WithContext(ctx context.Context) *zerolog.Logger {
	logger := l.zl.With()

	// Add request ID if present
	if requestID, ok := ctx.Value("request_id").(string); ok && requestID != "" {
		logger = logger.Str("request_id", requestID)
	}

	// Add user ID if present
	if userID, ok := ctx.Value("user_id").(string); ok && userID != "" {
		logger = logger.Str("user_id", userID)
	}

	l2 := logger.Logger()
	return &l2
}

// Debug logs a debug message
func (l *Logger) Debug() *zerolog.Event {
	return l.zl.Debug()
}

// Info logs an info message
func (l *Logger) Info() *zerolog.Event {
	return l.zl.Info()
}

// Warn logs a warning message
func (l *Logger) Warn() *zerolog.Event {
	return l.zl.Warn()
}

// Error logs an error message
func (l *Logger) Error() *zerolog.Event {
	return l.zl.Error()
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal() *zerolog.Event {
	return l.zl.Fatal()
}

// With returns a sub-logger with additional fields
func (l *Logger) With() zerolog.Context {
	return l.zl.With()
}

// Package-level convenience functions

func Debug() *zerolog.Event {
	if DefaultLogger == nil {
		Init(Config{Level: "info", Format: "json"})
	}
	return DefaultLogger.Debug()
}

func Info() *zerolog.Event {
	if DefaultLogger == nil {
		Init(Config{Level: "info", Format: "json"})
	}
	return DefaultLogger.Info()
}

func Warn() *zerolog.Event {
	if DefaultLogger == nil {
		Init(Config{Level: "info", Format: "json"})
	}
	return DefaultLogger.Warn()
}

func Error() *zerolog.Event {
	if DefaultLogger == nil {
		Init(Config{Level: "info", Format: "json"})
	}
	return DefaultLogger.Error()
}

func Fatal() *zerolog.Event {
	if DefaultLogger == nil {
		Init(Config{Level: "info", Format: "json"})
	}
	return DefaultLogger.Fatal()
}

// ContextWithLogger returns a new context with the logger attached
func ContextWithLogger(ctx context.Context, logger *Logger) context.Context {
	return context.WithValue(ctx, loggerCtxKey, logger)
}

// FromContext retrieves the logger from context
func FromContext(ctx context.Context) *Logger {
	if logger, ok := ctx.Value(loggerCtxKey).(*Logger); ok {
		return logger
	}
	if DefaultLogger == nil {
		Init(Config{Level: "info", Format: "json"})
	}
	return DefaultLogger
}

// Audit logs a security-sensitive operation at info level with a distinct "audit" tag.
// Use this for file deletions, share deactivations, auth events, etc.
func Audit(action string, userID string, fields map[string]string) {
	if DefaultLogger == nil {
		Init(Config{Level: "info", Format: "json"})
	}
	event := DefaultLogger.Info().
		Str("log_type", "audit").
		Str("action", action).
		Str("user_id", userID)
	for k, v := range fields {
		event = event.Str(k, v)
	}
	event.Msg("audit event")
}

// Middleware returns a Fiber middleware that logs requests
func Middleware() fiber.Handler {
	if DefaultLogger == nil {
		Init(Config{Level: "info", Format: "json"})
	}

	return func(c *fiber.Ctx) error {
		start := time.Now()

		err := c.Next()

		// Log request details
		event := DefaultLogger.Info()
		if err != nil {
			event = DefaultLogger.Error().Err(err)
		}

		requestID := ""
		if rid, ok := c.Locals("request_id").(string); ok {
			requestID = rid
		}

		event.
			Str("method", c.Method()).
			Str("path", c.Path()).
			Int("status", c.Response().StatusCode()).
			Int("bytes_sent", len(c.Response().Body())).
			Str("ip", c.IP()).
			Dur("latency", time.Since(start)).
			Str("request_id", requestID).
			Msg("HTTP request")

		return err
	}
}
