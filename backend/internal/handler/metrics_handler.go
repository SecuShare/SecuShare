package handler

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/expfmt"
)

// MetricsHandler handles Prometheus metrics endpoint
type MetricsHandler struct {
}

var (
	// HTTP request duration histogram
	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "secushare_http_request_duration_seconds",
		Help:    "Duration of HTTP requests in seconds",
		Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
	}, []string{"method", "path", "status"})

	// Active connections gauge
	activeConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "secushare_active_connections",
		Help: "Number of active connections",
	})

	// Total requests counter
	totalRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "secushare_http_requests_total",
		Help: "Total number of HTTP requests",
	}, []string{"method", "path", "status"})

	// File upload size histogram
	fileUploadSize = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "secushare_file_upload_size_bytes",
		Help:    "Size of uploaded files in bytes",
		Buckets: []float64{1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024, 100 * 1024 * 1024},
	})

	// Total files uploaded
	filesUploaded = promauto.NewCounter(prometheus.CounterOpts{
		Name: "secushare_files_uploaded_total",
		Help: "Total number of files uploaded",
	})

	// Total shares created
	sharesCreated = promauto.NewCounter(prometheus.CounterOpts{
		Name: "secushare_shares_created_total",
		Help: "Total number of shares created",
	})

	// Database query duration
	dbQueryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "secushare_db_query_duration_seconds",
		Help:    "Duration of database queries in seconds",
		Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
	}, []string{"query"})

	// Storage used gauge
	storageUsed = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "secushare_storage_used_bytes",
		Help: "Total storage used in bytes",
	})

	// Failed authentication attempts counter
	authFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "secushare_auth_failures_total",
		Help: "Total number of failed authentication attempts",
	}, []string{"reason"})
)

// NewMetricsHandler creates a new metrics handler
func NewMetricsHandler() *MetricsHandler {
	return &MetricsHandler{}
}

// Handler returns the Prometheus metrics handler for Fiber
func (h *MetricsHandler) Handler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Gather metrics from the default registry
		mfs, err := prometheus.DefaultGatherer.Gather()
		if err != nil {
			return c.Status(500).SendString("Failed to gather metrics")
		}

		// Format as Prometheus text format
		var sb strings.Builder
		for _, mf := range mfs {
			if _, err := expfmt.MetricFamilyToText(&sb, mf); err != nil {
				return c.Status(500).SendString("Failed to format metrics")
			}
		}

		c.Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		return c.SendString(sb.String())
	}
}

// MetricsMiddleware records HTTP metrics for each request
func MetricsMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Increment active connections
		activeConnections.Inc()
		defer activeConnections.Dec()
		start := time.Now()

		// Continue request processing
		err := c.Next()

		// Record metrics
		status := c.Response().StatusCode()
		path := c.Route().Path
		if path == "" {
			path = "__unmatched__"
		}

		statusStr := "200"
		if status >= 200 && status < 300 {
			statusStr = "2xx"
		} else if status >= 300 && status < 400 {
			statusStr = "3xx"
		} else if status >= 400 && status < 500 {
			statusStr = "4xx"
		} else if status >= 500 {
			statusStr = "5xx"
		}

		totalRequests.WithLabelValues(c.Method(), path, statusStr).Inc()
		httpDuration.WithLabelValues(c.Method(), path, statusStr).Observe(time.Since(start).Seconds())

		return err
	}
}

// RecordFileUpload records metrics for file uploads
func RecordFileUpload(size float64) {
	fileUploadSize.Observe(size)
	filesUploaded.Inc()
}

// RecordShareCreated records metrics for share creation
func RecordShareCreated() {
	sharesCreated.Inc()
}

// RecordDBQuery records metrics for database queries
func RecordDBQuery(query string, duration float64) {
	dbQueryDuration.WithLabelValues(query).Observe(duration)
}

// UpdateStorageUsed updates the storage used gauge
func UpdateStorageUsed(bytes float64) {
	storageUsed.Set(bytes)
}

// RecordAuthFailure increments the failed auth counter with a reason label.
func RecordAuthFailure(reason string) {
	authFailures.WithLabelValues(reason).Inc()
}
