package middleware

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/sbomhub/sbomhub/internal/model"
)

func RateLimitByAPIKey(rdb *redis.Client, limit int, window time.Duration) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			key, ok := c.Get(ContextKeyAPI).(*model.APIKey)
			if !ok || key == nil {
				return next(c)
			}

			now := time.Now().UTC()
			windowKey := now.Format("200601021504")
			redisKey := "mcp:ratelimit:" + key.ID.String() + ":" + windowKey

			count, err := rdb.Incr(c.Request().Context(), redisKey).Result()
			if err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "rate limit error"})
			}
			if count == 1 {
				_ = rdb.Expire(c.Request().Context(), redisKey, window).Err()
			}
			if count > int64(limit) {
				return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
			}

			return next(c)
		}
	}
}
