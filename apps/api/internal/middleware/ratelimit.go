package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/sbomhub/sbomhub/internal/model"
)

// RateLimitByAPIKey creates a rate limiting middleware based on API key
// SECURITY FIX: Window bucket key now correctly uses the configured duration
func RateLimitByAPIKey(rdb *redis.Client, limit int, window time.Duration) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			key, ok := c.Get(ContextKeyAPI).(*model.APIKey)
			if !ok || key == nil {
				return next(c)
			}

			now := time.Now().UTC()
			// SECURITY FIX: Calculate window bucket based on actual window duration
			// Previously always used minute granularity regardless of window setting
			windowKey := calculateWindowKey(now, window)
			redisKey := "mcp:ratelimit:" + key.ID.String() + ":" + windowKey

			count, err := rdb.Incr(c.Request().Context(), redisKey).Result()
			if err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "rate limit error"})
			}
			if count == 1 {
				// Set expiry slightly longer than window to handle edge cases
				_ = rdb.Expire(c.Request().Context(), redisKey, window+time.Second).Err()
			}
			if count > int64(limit) {
				c.Response().Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
				c.Response().Header().Set("X-RateLimit-Remaining", "0")
				c.Response().Header().Set("Retry-After", fmt.Sprintf("%d", int(window.Seconds())))
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error":       "rate limit exceeded",
					"retry_after": fmt.Sprintf("%ds", int(window.Seconds())),
				})
			}

			// Add rate limit headers for successful requests
			c.Response().Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
			c.Response().Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", limit-int(count)))

			return next(c)
		}
	}
}

// calculateWindowKey generates a bucket key based on the window duration
// This ensures rate limits are tracked correctly for different time windows
func calculateWindowKey(t time.Time, window time.Duration) string {
	switch {
	case window <= time.Minute:
		// Per-minute buckets
		return t.Format("200601021504")
	case window <= time.Hour:
		// Per-hour buckets (truncate to hour)
		return t.Format("2006010215")
	case window <= 24*time.Hour:
		// Per-day buckets (truncate to day)
		return t.Format("20060102")
	default:
		// For longer windows, use Unix timestamp divided by window seconds
		windowSeconds := int64(window.Seconds())
		bucket := t.Unix() / windowSeconds
		return fmt.Sprintf("w%d", bucket)
	}
}
