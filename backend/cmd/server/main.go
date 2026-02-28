package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/config"
	"github.com/SecuShare/SecuShare/backend/internal/handler"
	"github.com/SecuShare/SecuShare/backend/internal/repository"
	"github.com/SecuShare/SecuShare/backend/internal/service"
	"github.com/SecuShare/SecuShare/backend/pkg/database"
	"github.com/SecuShare/SecuShare/backend/pkg/logger"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func main() {
	// Initialize structured logger
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}
	logFormat := os.Getenv("LOG_FORMAT")
	if logFormat == "" {
		logFormat = "json"
	}
	logger.Init(logger.Config{
		Level:  logLevel,
		Format: logFormat,
		Output: os.Stdout,
	})

	// Load configuration
	cfg := config.Load()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		logger.Fatal().Err(err).Msg("Configuration error")
	}

	logger.Info().
		Str("bind_address", cfg.Server.BindAddress).
		Str("port", cfg.Server.Port).
		Str("log_level", logLevel).
		Msg("Starting SecuShare server")

	// Initialize database
	db, err := database.Initialize(cfg.Database.Path)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize database")
	}
	logger.Info().Str("path", cfg.Database.Path).Msg("Database initialized")

	// Initialize schema
	if err := database.InitSchema(db); err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize schema")
	}
	logger.Info().Msg("Database schema initialized")

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	guestRepo := repository.NewGuestSessionRepository(db)
	pendingRepo := repository.NewPendingRegistrationRepository(db)
	fileRepo := repository.NewFileRepository(db)
	shareRepo := repository.NewShareRepository(db)

	// Initialize settings repository
	settingsRepo := repository.NewSettingsRepository(db)

	// Initialize services
	authSvc, err := service.NewAuthService(userRepo, guestRepo, pendingRepo, cfg)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize auth service")
	}
	fileSvc := service.NewFileService(fileRepo, userRepo, guestRepo, cfg.Storage.Path)
	shareSvc := service.NewShareService(shareRepo, fileRepo, fileSvc, cfg)

	// Initialize admin service and wire up settings provider
	adminSvc := service.NewAdminService(settingsRepo, userRepo)
	authSvc.SetSettingsProvider(adminSvc)
	fileSvc.SetSettingsProvider(adminSvc)
	if err := fileSvc.ReconcileStorageUsage(); err != nil {
		logger.Warn().Err(err).Msg("Failed to reconcile storage usage at startup")
	}

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authSvc)
	fileHandler := handler.NewFileHandler(fileSvc)
	shareHandler := handler.NewShareHandler(shareSvc, fileSvc)
	adminHandler := handler.NewAdminHandler(adminSvc, authSvc, fileSvc, shareRepo, guestRepo, pendingRepo)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		BodyLimit:               100 * 1024 * 1024, // 100MB limit
		DisableKeepalive:        false,
		ReadTimeout:             10 * time.Second,
		WriteTimeout:            30 * time.Second,
		IdleTimeout:             60 * time.Second,
		ProxyHeader:             fiber.HeaderXForwardedFor,
		EnableTrustedProxyCheck: true,
		TrustedProxies:          cfg.Server.TrustedProxies,
		EnableIPValidation:      true,
	})

	logger.Info().
		Strs("trusted_proxies", cfg.Server.TrustedProxies).
		Msg("Trusted proxy configuration loaded")

	// Middleware
	app.Use(recover.New())
	app.Use(compress.New(compress.Config{
		Level: compress.LevelDefault,
	}))
	app.Use(handler.SecurityHeadersMiddleware())
	app.Use(handler.RequestIDMiddleware())
	app.Use(handler.MetricsMiddleware())
	app.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.Server.AllowOrigins,
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, X-Request-ID, X-CSRF-Token",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
		AllowCredentials: true,
		MaxAge:           3600, // Cache preflight responses for 1 hour
	}))
	app.Use(logger.Middleware())

	// Routes
	api := app.Group("/api/v1")

	// Rate limiters: auth uses IP-only (runs before auth), file uses IP+UserID.
	// Backed by DB to persist counters across restarts and shared replicas.
	authRateLimiter := handler.NewPersistentRateLimiter(db, "auth", 10, 1*time.Minute)
	fileRateLimiter := handler.NewPersistentRateLimiterWithKey(db, "file", 30, 1*time.Minute, handler.IPAndUserKey)

	// Body limit middleware: 1MB for JSON API routes, 100MB for file uploads
	jsonBodyLimit := handler.BodyLimitMiddleware(1 * 1024 * 1024) // 1MB

	// Auth routes
	auth := api.Group("/auth")
	auth.Post("/register", jsonBodyLimit, authRateLimiter.Middleware(), authHandler.RegisterPassword)
	auth.Post("/register/verify", jsonBodyLimit, authRateLimiter.Middleware(), authHandler.VerifyRegistration)
	auth.Post("/login", jsonBodyLimit, authRateLimiter.Middleware(), authHandler.LoginPassword)
	auth.Post("/register/init", jsonBodyLimit, authRateLimiter.Middleware(), authHandler.RegisterInit)
	auth.Post("/register/finish", jsonBodyLimit, authRateLimiter.Middleware(), authHandler.RegisterFinish)
	auth.Post("/login/init", jsonBodyLimit, authRateLimiter.Middleware(), authHandler.LoginInit)
	auth.Post("/login/finish", jsonBodyLimit, authRateLimiter.Middleware(), authHandler.LoginFinish)
	auth.Post("/guest", jsonBodyLimit, authRateLimiter.Middleware(), authHandler.CreateGuestSession)
	auth.Post("/logout", jsonBodyLimit, handler.CSRFMiddleware(), authHandler.Logout)
	auth.Get("/me", handler.AuthMiddleware(authSvc), authHandler.GetMe)
	auth.Get("/storage/quota", handler.AuthMiddleware(authSvc), authHandler.GetStorageInfo)

	// File routes (CSRF-protected; upload uses app-level 100MB limit)
	files := api.Group("/files")
	files.Post("/", handler.AuthMiddleware(authSvc), handler.CSRFMiddleware(), fileRateLimiter.Middleware(), fileHandler.Upload)
	files.Get("/", handler.AuthMiddleware(authSvc), fileHandler.List)
	files.Delete("/:id", handler.AuthMiddleware(authSvc), handler.CSRFMiddleware(), fileHandler.Delete)
	files.Get("/:id", handler.AuthMiddleware(authSvc), fileRateLimiter.Middleware(), fileHandler.Download)
	files.Get("/:id/shares", handler.AuthMiddleware(authSvc), shareHandler.ListByFile)

	// Share routes (CSRF-protected for state-changing operations)
	shares := api.Group("/shares")
	shares.Post("/", jsonBodyLimit, handler.AuthMiddleware(authSvc), handler.CSRFMiddleware(), shareHandler.Create)
	shares.Get("/:id", shareHandler.GetShare)
	shares.Post("/:id/request-code", jsonBodyLimit, fileRateLimiter.Middleware(), shareHandler.RequestDownloadCode)
	shares.Post("/:id/file", jsonBodyLimit, fileRateLimiter.Middleware(), shareHandler.DownloadFile)
	shares.Delete("/:id", handler.AuthMiddleware(authSvc), handler.CSRFMiddleware(), shareHandler.Deactivate)

	// Setup routes (unauthenticated, rate-limited)
	setup := api.Group("/setup")
	setup.Get("/status", adminHandler.CheckSetupStatus)
	setup.Post("/complete", jsonBodyLimit, authRateLimiter.Middleware(), adminHandler.CompleteSetup)

	// Admin routes (authenticated + admin + CSRF for mutations)
	admin := api.Group("/admin", handler.AuthMiddleware(authSvc), handler.AdminMiddleware(authSvc))
	admin.Get("/settings", adminHandler.GetSettings)
	admin.Put("/settings", jsonBodyLimit, handler.CSRFMiddleware(), adminHandler.UpdateSettings)
	admin.Get("/stats", adminHandler.GetStats)
	admin.Get("/users", adminHandler.ListUsers)
	admin.Delete("/users/:id", handler.CSRFMiddleware(), adminHandler.DeleteUser)
	admin.Post("/cleanup", handler.CSRFMiddleware(), adminHandler.TriggerCleanup)

	// Public settings (max file sizes)
	auth.Get("/settings", adminHandler.GetPublicSettings)

	// Health check handler
	healthHandler := handler.NewHealthHandler(db, cfg.Storage.Path)
	app.Get("/health", healthHandler.Liveness)
	app.Get("/health/ready", healthHandler.Readiness)

	// Metrics endpoint
	metricsHandler := handler.NewMetricsHandler()
	if cfg.Observability.MetricsEnabled {
		if cfg.IsProduction {
			app.Get("/metrics", handler.BearerTokenMiddleware(cfg.Observability.MetricsToken), metricsHandler.Handler())
		} else {
			app.Get("/metrics", metricsHandler.Handler())
		}
	} else {
		logger.Info().Msg("Metrics endpoint disabled")
	}

	// Start background cleanup job for expired files, shares, and guest sessions
	cleanupStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				logger.Info().Msg("Running expired data cleanup...")
				now := time.Now()
				if err := shareRepo.DeleteExpired(); err != nil {
					logger.Error().Err(err).Msg("Failed to clean up expired shares")
				}
				if err := fileSvc.DeleteExpired(now); err != nil {
					logger.Error().Err(err).Msg("Failed to clean up expired files")
				}
				if err := fileSvc.DeleteByExpiredGuestSessions(now); err != nil {
					logger.Error().Err(err).Msg("Failed to clean up files from expired guest sessions")
				}
				if err := guestRepo.DeleteExpired(); err != nil {
					logger.Error().Err(err).Msg("Failed to clean up expired guest sessions")
				}
				if err := pendingRepo.DeleteExpired(now); err != nil {
					logger.Error().Err(err).Msg("Failed to clean up expired pending registrations")
				}
				if err := shareRepo.DeleteExpiredPendingDownloadVerifications(now); err != nil {
					logger.Error().Err(err).Msg("Failed to clean up expired pending share download verifications")
				}
				if err := fileSvc.ReconcileStorageUsage(); err != nil {
					logger.Error().Err(err).Msg("Failed to reconcile storage usage")
				}
				logger.Info().Msg("Expired data cleanup completed")
			case <-cleanupStop:
				return
			}
		}
	}()

	// Start server in goroutine
	go func() {
		addr := net.JoinHostPort(cfg.Server.BindAddress, cfg.Server.Port)
		logger.Info().
			Str("address", addr).
			Bool("metrics_enabled", cfg.Observability.MetricsEnabled).
			Msg("HTTP server listening")
		if err := app.Listen(addr); err != nil {
			logger.Error().Err(err).Msg("Server stopped")
		}
	}()

	// Graceful shutdown setup
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	sig := <-quit
	logger.Info().Str("signal", sig.String()).Msg("Received shutdown signal")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop background jobs
	logger.Info().Msg("Stopping background jobs...")
	close(cleanupStop)
	authSvc.Stop()
	authRateLimiter.Stop()
	fileRateLimiter.Stop()

	// Shutdown Fiber app
	logger.Info().Msg("Shutting down HTTP server...")
	if err := app.ShutdownWithContext(ctx); err != nil {
		logger.Error().Err(err).Msg("Error during shutdown")
	}

	// Stop share service background workers after HTTP shutdown drains requests.
	shareSvc.Stop()

	// Close database connection
	logger.Info().Msg("Closing database connection...")
	if err := db.Close(); err != nil {
		logger.Error().Err(err).Msg("Error closing database")
	}

	logger.Info().Msg("Server stopped gracefully")
}
