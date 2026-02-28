package handler

import (
	"context"
	"database/sql"
	"strings"
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
	db       *sql.DB
	scope    string
	stopOnce sync.Once
}

type clientInfo struct {
	count     int
	windowEnd time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return newRateLimiter(limit, window, defaultKeyFunc, nil, "")
}

// NewRateLimiterWithKey creates a rate limiter with a custom key extraction function.
func NewRateLimiterWithKey(limit int, window time.Duration, keyFunc KeyFunc) *RateLimiter {
	return newRateLimiter(limit, window, keyFunc, nil, "")
}

// NewPersistentRateLimiter creates a rate limiter backed by the shared SQL database.
// This preserves counters across process restarts and across replicas that share the DB.
func NewPersistentRateLimiter(db *sql.DB, scope string, limit int, window time.Duration) *RateLimiter {
	return newRateLimiter(limit, window, defaultKeyFunc, db, scope)
}

// NewPersistentRateLimiterWithKey creates a DB-backed rate limiter with a custom key function.
func NewPersistentRateLimiterWithKey(
	db *sql.DB,
	scope string,
	limit int,
	window time.Duration,
	keyFunc KeyFunc,
) *RateLimiter {
	return newRateLimiter(limit, window, keyFunc, db, scope)
}

func newRateLimiter(
	limit int,
	window time.Duration,
	keyFunc KeyFunc,
	db *sql.DB,
	scope string,
) *RateLimiter {
	if keyFunc == nil {
		keyFunc = defaultKeyFunc
	}
	scope = strings.TrimSpace(scope)
	if scope == "" {
		scope = "default"
	}

	rl := &RateLimiter{
		requests: make(map[string]*clientInfo),
		limit:    limit,
		window:   window,
		stopCh:   make(chan struct{}),
		keyFunc:  keyFunc,
		db:       db,
		scope:    scope,
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
		now := time.Now()

		if rl.db != nil {
			allowed, err := rl.allowPersistent(key, now)
			if err == nil {
				if !allowed {
					return response.Error(c, fiber.StatusTooManyRequests, "too many requests, please try again later")
				}
				return c.Next()
			}
			// Fall back to in-memory limiter if persistent storage fails.
		}

		if !rl.allowInMemory(key, now) {
			return response.Error(c, fiber.StatusTooManyRequests, "too many requests, please try again later")
		}
		return c.Next()
	}
}

func (rl *RateLimiter) scopedKey(key string) string {
	return rl.scope + ":" + key
}

func (rl *RateLimiter) allowPersistent(key string, now time.Time) (bool, error) {
	scopedKey := rl.scopedKey(key)
	windowEnd := now.Add(rl.window)

	_, err := rl.db.Exec(`
		INSERT INTO rate_limit_counters (scope_key, count, window_end, updated_at)
		VALUES (?, 1, ?, ?)
		ON CONFLICT(scope_key) DO UPDATE SET
			count = CASE
				WHEN rate_limit_counters.window_end <= excluded.updated_at THEN 1
				ELSE rate_limit_counters.count + 1
			END,
			window_end = CASE
				WHEN rate_limit_counters.window_end <= excluded.updated_at THEN excluded.window_end
				ELSE rate_limit_counters.window_end
			END,
			updated_at = excluded.updated_at
	`, scopedKey, windowEnd, now)
	if err != nil {
		return false, err
	}

	var count int
	if err := rl.db.QueryRow(`SELECT count FROM rate_limit_counters WHERE scope_key = ?`, scopedKey).Scan(&count); err != nil {
		return false, err
	}
	return count <= rl.limit, nil
}

func (rl *RateLimiter) allowInMemory(key string, now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	info, exists := rl.requests[key]
	if !exists || now.After(info.windowEnd) {
		rl.requests[key] = &clientInfo{
			count:     1,
			windowEnd: now.Add(rl.window),
		}
		return true
	}

	if info.count >= rl.limit {
		return false
	}

	info.count++
	return true
}

// cleanup periodically removes expired entries
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			rl.cleanupInMemory(now)
			rl.cleanupPersistent(now)
		case <-rl.stopCh:
			return
		}
	}
}

func (rl *RateLimiter) cleanupInMemory(now time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	for key, info := range rl.requests {
		if now.After(info.windowEnd) {
			delete(rl.requests, key)
		}
	}
}

func (rl *RateLimiter) cleanupPersistent(now time.Time) {
	if rl.db == nil {
		return
	}
	if _, err := rl.db.Exec(`DELETE FROM rate_limit_counters WHERE window_end <= ?`, now); err != nil {
		return
	}
}

// Stop gracefully stops the cleanup goroutine
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.stopCh)
	})
}

// StopWithContext gracefully stops the cleanup goroutine with context support
func (rl *RateLimiter) StopWithContext(ctx context.Context) error {
	rl.Stop()
	return nil
}
