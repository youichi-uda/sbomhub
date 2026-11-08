package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	goredis "github.com/redis/go-redis/v9"

	"github.com/sbomhub/sbomhub/internal/model"
	sbomredis "github.com/sbomhub/sbomhub/internal/redis"
	"github.com/sbomhub/sbomhub/internal/redis/redistest"
)

// A Redis that accepts connections and never answers must not hang API
// requests. Both limiters fail closed by design — the API-key limiter with
// 500, the public-link limiter with 503 — and these pin that they do so
// within a bounded time rather than after go-redis's default read timeout
// multiplied by its retries (or, on the API-key path, never: it used the
// request context, which has no deadline).

func blackHoledClient(t *testing.T) *goredis.Client {
	t.Helper()
	opts, err := sbomredis.Options(redistest.BlackHole(t))
	if err != nil {
		t.Fatal(err)
	}
	c := goredis.NewClient(opts)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// failFastBound is how long one request may take against the black hole:
// the bounded Redis phase plus scheduling slack.
const failFastBound = sbomredis.CommandTimeout + time.Second

func TestRateLimitByAPIKey_BlackHoledRedisFailsFast(t *testing.T) {
	rdb := blackHoledClient(t)
	e := echo.New()
	handlerRan := false
	e.GET("/x", func(c echo.Context) error {
		handlerRan = true
		return c.NoContent(http.StatusOK)
	}, func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set(ContextKeyAPI, &model.APIKey{ID: uuid.New()})
			return next(c)
		}
	}, RateLimitByAPIKey(rdb, BudgetStandard))

	start := time.Now()
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	elapsed := time.Since(start)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (fail closed)", rec.Code)
	}
	if handlerRan {
		t.Fatal("handler ran although the limiter could not count")
	}
	if elapsed > failFastBound {
		t.Fatalf("request took %v against a hung Redis (bound %v)", elapsed, failFastBound)
	}
}

func TestRateLimitPublicLink_BlackHoledRedisFailsFast(t *testing.T) {
	rdb := blackHoledClient(t)
	e := echo.New()
	handlerRan := false
	e.GET("/api/v1/public/:token", func(c echo.Context) error {
		handlerRan = true
		return c.NoContent(http.StatusOK)
	}, RateLimitPublicLink(rdb, PublicLinkFailuresPerToken, PublicLinkFailuresPerIP, PublicLinkWindow))

	start := time.Now()
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/public/tok", nil))
	elapsed := time.Since(start)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (fail closed)", rec.Code)
	}
	if handlerRan {
		t.Fatal("handler ran although the limiter could not reserve")
	}
	if elapsed > failFastBound {
		t.Fatalf("request took %v against a hung Redis (bound %v)", elapsed, failFastBound)
	}
}
