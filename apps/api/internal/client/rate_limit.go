// Package client provides HTTP clients for external integrations (Jira, Backlog,
// GHSA, etc.). This file houses shared rate-limit hardening helpers used by the
// Jira and Backlog clients.
//
// F277 (M19-1): promoted from the F269 alternative (b) ADR (ticket_sync HTTP
// under-tx defer). Prior to F277 the Jira/Backlog clients had zero backoff and
// zero rate-limit awareness — a 429 status was surfaced verbatim as
// "Jira API error: 429 - ..." with no retry attempt. The ticket_sync scheduler
// runs every 15 minutes across all tenant connections; without client-side
// hardening any provider-side rate-limit event cascades into a burst of
// permanent failures.
//
// The helpers in this file are transport-agnostic on purpose — they only reason
// about the pieces of an HTTP response that matter for backoff decisions
// (status code, Retry-After header, X-RateLimit-Reset header) and never touch
// the request body or auth wiring. Each client remains responsible for its own
// auth / body encoding.
package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ErrRateLimitExhausted is the sentinel returned when a rate-limited request
// exceeds MaxRetries. Callers can use errors.Is to detect it — the individual
// client wrappers wrap this with their own prefix (e.g.
// "jira: rate limit exhausted after 3 retries: ...").
var ErrRateLimitExhausted = errors.New("rate limit exhausted")

// BackoffPolicy describes the retry cadence for a rate-limit-aware HTTP client.
// Zero values are unsafe — callers should always construct via
// DefaultBackoffPolicy() or a test helper. The exponential backoff formula is
// InitialDelay * 2^attempt (attempt is 0-indexed), capped at MaxDelay, with a
// full-jitter perturbation when Jitter is true.
//
// The default policy targets conservative production behaviour: three retries
// starting at 1s and capping at 30s. Tests should override with tiny delays to
// keep runtime under 100ms.
type BackoffPolicy struct {
	// MaxRetries is the number of retry attempts after the initial request.
	// A value of 3 means up to 4 total attempts (1 initial + 3 retries).
	MaxRetries int
	// InitialDelay is the base wait before the first retry.
	InitialDelay time.Duration
	// MaxDelay caps any single computed delay (before jitter).
	MaxDelay time.Duration
	// Jitter enables full-jitter (delay = random in [0, computed]). Disable
	// in tests that want deterministic timing.
	Jitter bool
}

// DefaultBackoffPolicy returns the production-safe defaults documented on
// BackoffPolicy. Callers should copy the struct and mutate fields locally
// rather than mutating the returned value in place — the return is a value
// type, so this pattern is naturally safe today, but the convention keeps
// intent obvious.
func DefaultBackoffPolicy() BackoffPolicy {
	return BackoffPolicy{
		MaxRetries:   3,
		InitialDelay: 1 * time.Second,
		MaxDelay:     30 * time.Second,
		Jitter:       true,
	}
}

// Delay computes the wait duration before the (attempt+1)-th retry. attempt is
// 0-indexed, so Delay(0) is the delay before the first retry.
//
// The unjittered value is InitialDelay * 2^attempt clamped at MaxDelay. When
// Jitter is true the returned value is uniformly random in [0, unjittered].
// InitialDelay <= 0 short-circuits to a zero delay (test convenience).
func (p BackoffPolicy) Delay(attempt int) time.Duration {
	if p.InitialDelay <= 0 {
		return 0
	}
	if attempt < 0 {
		attempt = 0
	}
	// Guard against int overflow when attempt is unreasonably large.
	shift := attempt
	if shift > 30 {
		shift = 30
	}
	multiplier := int64(1) << uint(shift)
	unjittered := time.Duration(int64(p.InitialDelay) * multiplier)
	if unjittered <= 0 || (p.MaxDelay > 0 && unjittered > p.MaxDelay) {
		unjittered = p.MaxDelay
	}
	if unjittered <= 0 {
		return 0
	}
	if !p.Jitter {
		return unjittered
	}
	return time.Duration(cryptoRandFloat64() * float64(unjittered))
}

// cryptoRandFloat64 returns a value in [0.0, 1.0) using crypto/rand to avoid
// pulling math/rand into the client. Falls back to 0.5 on the vanishingly
// unlikely case that the random source fails, so jitter degrades gracefully
// rather than panicking.
func cryptoRandFloat64() float64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0.5
	}
	// Mask to 53 bits (float64 mantissa) then normalise into [0, 1).
	u := binary.BigEndian.Uint64(buf[:]) >> 11
	return float64(u) / float64(uint64(1)<<53)
}

// RespectRetryAfter parses a Retry-After header value per RFC 7231 §7.1.3.
// The header may be either delta-seconds (e.g. "5") or an HTTP-date
// (e.g. "Wed, 21 Oct 2015 07:28:00 GMT"). Malformed / empty values fall back
// to the supplied fallback duration. Values that resolve to a past time are
// clamped to zero.
func RespectRetryAfter(header string, fallback time.Duration) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return fallback
	}
	// delta-seconds form.
	if secs, err := strconv.Atoi(header); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	// HTTP-date form (RFC 1123 preferred, but net/http accepts common formats).
	if t, err := http.ParseTime(header); err == nil {
		delta := time.Until(t)
		if delta < 0 {
			return 0
		}
		return delta
	}
	return fallback
}

// RespectRateLimitReset parses an epoch-seconds header value. Backlog uses
// X-RateLimit-Reset (documented in the Nulab Backlog API docs) — that is the
// only consumer today. GitHub's REST API exposes the same header shape
// (X-RateLimit-Reset as an epoch-seconds integer), so the helper is
// transport-agnostic on purpose: a future GHSA-client hardening pass (see
// client/ghsa.go, currently minimal — no 429 retry) can reuse this helper
// as-is without a rewrite. Returns the delta between now and the reset
// instant, clamped to zero if the reset has already passed. Malformed /
// empty values return the fallback.
func RespectRateLimitReset(header string, fallback time.Duration) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return fallback
	}
	epoch, err := strconv.ParseInt(header, 10, 64)
	if err != nil {
		return fallback
	}
	delta := time.Until(time.Unix(epoch, 0))
	if delta < 0 {
		return 0
	}
	return delta
}

// waitOrDone blocks for d, returning nil on completion or ctx.Err() when the
// context is cancelled first. A non-positive d returns immediately (respecting
// context cancellation semantics — the caller may still observe a cancelled
// context by checking ctx.Err() after this returns nil).
func waitOrDone(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		// Even for zero delay, yield to context cancellation so callers see
		// prompt aborts when the context is already done.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

