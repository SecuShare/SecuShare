package handler

import (
	"context"
	"sync"
	"time"

	"github.com/SecuShare/SecuShare/backend/pkg/response"
	"github.com/gofiber/fiber/v2"
)

// KeyFunc extracts a rate-limiting key from a request.
type KeyFunc func(c *fiber.Ctx) string

type RateLimiter struct {
	requests map[string]*clientInfo
	mu       sync.RWMutex
	limit    int           // max requests
	window   time.Duration // time window
	stopCh   chan struct{} // channel to stop cleanup goroutine
	keyFunc  KeyFunc       // custom key extractor
}

type clientInfo struct {
	count     int
	windowEnd time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string]*clientInfo),
		limit:    limit,
		window:   window,
		stopCh:   make(chan struct{}),
		keyFunc:  defaultKeyFunc,
	}
	// Start cleanup goroutine
	go rl.cleanup()
	return rl
}

// NewRateLimiterWithKey creates a rate limiter with a custom key extraction function.
func NewRateLimiterWithKey(limit int, window time.Duration, keyFunc KeyFunc) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string]*clientInfo),
		limit:    limit,
		window:   window,
		stopCh:   make(chan struct{}),
		keyFunc:  keyFunc,
	}
	go rl.cleanup()
	return rl
}

// IPAndUserKey combines IP address with authenticated user ID for rate limiting.
// This prevents a single authenticated user from bypassing IP-based limits via
// multiple IPs, and prevents shared IPs from unfairly limiting distinct users.
func IPAndUserKey(c *fiber.Ctx) string {
	ip := c.IP()
	userID, ok := c.Locals("user_id").(string)
	if !ok {
		return ip
	}
	if userID != "" {
		return ip + ":" + userID
	}
	return ip
}

func defaultKeyFunc(c *fiber.Ctx) string {
	return c.IP()
}

// Middleware returns the rate limiting middleware
func (rl *RateLimiter) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		key := rl.keyFunc(c)

		rl.mu.Lock()
		defer rl.mu.Unlock()

		now := time.Now()
		info, exists := rl.requests[key]

		if !exists || now.After(info.windowEnd) {
			// New window
			rl.requests[key] = &clientInfo{
				count:     1,
				windowEnd: now.Add(rl.window),
			}
			return c.Next()
		}

		// Existing window
		if info.count >= rl.limit {
			return response.Error(c, fiber.StatusTooManyRequests, "too many requests, please try again later")
		}

		info.count++
		return c.Next()
	}
}

// cleanup periodically removes expired entries
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, info := range rl.requests {
				if now.After(info.windowEnd) {
					delete(rl.requests, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}

// Stop gracefully stops the cleanup goroutine
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
}

// StopWithContext gracefully stops the cleanup goroutine with context support
func (rl *RateLimiter) StopWithContext(ctx context.Context) error {
	select {
	case <-rl.stopCh:
		// Already closed
	default:
		close(rl.stopCh)
	}
	return nil
}
