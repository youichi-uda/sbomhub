package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
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

// Public-link budgets (M48 FO-6). Two limits with different jobs, because the
// route carries two different risks:
//
//   - a CUMULATIVE budget of FAILED attempts per window, which bounds password
//     guessing. Successes never advance it, so a link being viewed normally is
//     not throttled by its own popularity.
//   - a cap on ADMISSIONS HOLDING A LIVE LEASE, which bounds how many requests
//     a burst can get through at once. (Not "executing": a handler that
//     outlives the two-minute lease keeps running while its lease ages out —
//     see RateLimitPublicLink.) The cumulative budget alone cannot do this: it
//     is read before the handler runs and written after, so a simultaneous
//     burst all reads the same pre-burst value. Measured on this repo's Redis
//     (2026-07-29) with only the cumulative check in place, 300 concurrent
//     attempts against a budget of 10 put 101 requests through to the handler.
const (
	// PublicLinkFailuresPerToken bounds guesses against ONE link. This is the
	// load-bearing number: the token is the thing being attacked and it cannot
	// be spoofed away.
	PublicLinkFailuresPerToken = 10
	// PublicLinkFailuresPerIP bounds one source sweeping MANY links, which is
	// what token enumeration looks like. Weaker by construction — see the
	// RateLimitPublicLink doc comment.
	PublicLinkFailuresPerIP = 60

	// PublicLinkInFlightPerToken caps concurrent ADMISSIONS for one token. It
	// is deliberately HIGHER than the failure budget: it is not a second
	// brute-force limit, it exists so a parallel burst cannot convert the
	// attacker's connection count into bcrypt work. Legitimate use is nowhere
	// near it — these are links mailed to an auditor or a customer, and 16
	// simultaneous requests for one link is far more than that.
	//
	// Codex rounds 2 and 3 both had to correct claims made here. It does NOT
	// bound the cumulative overshoot by a constant (see RateLimitPublicLink),
	// and "concurrent" means "holding an unexpired lease", not "executing" —
	// a handler that outlives publicLinkInFlightTTL keeps running while its
	// lease ages out.
	PublicLinkInFlightPerToken = 16
	// PublicLinkInFlightPerIP is the same idea across tokens.
	PublicLinkInFlightPerIP = 64

	// PublicLinkWindow is the counting window for the cumulative budget. One
	// hour is chosen so the buckets line up exactly with calculateWindowKey's
	// hour granularity rather than silently rounding up to it.
	PublicLinkWindow = time.Hour
	// publicLinkInFlightTTL bounds how long ONE leaked reservation can occupy
	// a slot. Reservations are released in a defer, so a leak needs the
	// release itself to fail — process death between reserve and release, or a
	// Redis error on the release. Without an expiry either would permanently
	// shrink the link's concurrency.
	//
	// Since Codex round 2 the expiry is PER LEASE (a score in a sorted set),
	// not per key, so a request that outruns it loses only its own slot and
	// cannot disturb anyone else's — see inFlightReserve. A request that takes
	// longer than this therefore stops being counted against the cap while it
	// is still running; that is the honest cost of not having a hard request
	// deadline on the server (see the residuals).
	publicLinkInFlightTTL = 2 * time.Minute
	// publicLinkRedisTimeout bounds the bookkeeping round trips, which run on
	// a context detached from the client's (see RateLimitPublicLink).
	publicLinkRedisTimeout = 3 * time.Second
)

// RateLimitPublicLink throttles failed attempts against the anonymous public
// share routes (GET /api/v1/public/:token and .../download).
//
// M48 (FO-6). Those two routes are the only unauthenticated endpoints that
// take a caller-supplied credential and do expensive work with it: a
// password-protected link verifies the supplied password with
// bcrypt.CompareHashAndPassword at DefaultCost. (/api/v1/health is anonymous
// too, but answers a constant; /api/webhooks/* is anonymous but verifies an
// HMAC.) With no limiter that gave an anonymous caller two things at once:
// unlimited guesses against the password, and an unlimited supply of
// deliberately-expensive hash computations aimed at the API's CPU.
//
// # Why it counts failures rather than requests
//
// Every brute-force guess is a failure, so a failure counter bounds the attack
// exactly, while leaving a legitimately popular link — which returns 200 — at
// full speed. A link with no password never reaches bcrypt at all.
//
// The handlers collapse "bad password", "expired", "revoked" and "no such
// token" into one generic 403 (F442), so that single status is what this
// middleware counts. That is coarser than counting password failures alone: a
// caller hammering an expired link burns the same budget. Since the answer in
// both cases is "this link will not serve you", the conflation costs a
// legitimate caller nothing.
//
// # Why the concurrency cap is a separate mechanism
//
// The cumulative counter is READ before the handler and WRITTEN after it, so a
// simultaneous burst all reads the same pre-burst value and all of it gets
// through. That is not a theoretical gap: measured on this repo's Redis
// (2026-07-29), 300 concurrent attempts against a budget of 10 put 101
// requests — 101 bcrypt verifications — through to the handler.
//
// Making the cumulative counter itself atomic (INCR on entry, refund on
// success) would fix the burst but would also cap simultaneous SUCCESSFUL
// viewers at the same small number as the failure budget, which is the one
// property this limiter must not have. So concurrency gets its own,
// deliberately looser cap, and the two limits stay independent.
//
// # What that does and does not guarantee
//
// The cap is on ADMISSIONS HOLDING A LIVE LEASE, not on goroutines executing.
// At most `in-flight cap` requests for one token hold an unexpired lease at
// any instant.
//
// That is deliberately all this says (Codex round 4, Low): the obvious next
// sentence — "so a burst cannot become simultaneous bcrypt work" — does not
// follow, because a handler whose lease ages out keeps running while the next
// wave is admitted. Under CPU starvation bcrypt itself can outlive a
// two-minute lease. What the cap does is bound how many requests are ADMITTED
// per lease period; the bound on work executing at one instant follows only
// for handlers that finish inside the lease, which is every realistic one but
// not a guarantee.
//
// Two things it does NOT guarantee, both corrected after review claimed
// otherwise:
//
//   - An exact cumulative total (round 2). Leases are released as requests
//     finish, so a burst drains in waves and a request admitted early in the
//     drain can still read a cumulative count predating the previous wave's
//     charges. Running the burst test under `-race` produced 28 against a
//     nominal 10 + 16 = 26 and falsified the "budget + cap" claim.
//   - A hard ceiling on RUNNING handlers (round 3). A request that outlives
//     publicLinkInFlightTTL has its lease aged out while it is still
//     executing, and the next wave is admitted alongside it. Without a server
//     write deadline a slow /public/:token/download can do this repeatedly.
//     The lease is therefore an admission lease with a two-minute horizon, not
//     an instantaneous concurrency guarantee. Fixing it properly needs either
//     lease renewal from inside the handler or a request deadline shorter than
//     the lease; neither is in this wave.
//
// What can honestly be said, and only as measurement rather than proof: with
// accounting succeeding, the overshoot is a small multiple of the cap rather
// than a function of the attacker's connection count. On this repo's Redis,
// 300 concurrent attempts against a budget of 10 reached the handler 101 times
// with no cap and 17-28 times with it.
//
// # Honest limits
//
//   - The per-token buckets are the real defence and cannot be evaded: the
//     token IS the target.
//   - The per-IP buckets are derived from c.RealIP(), which trusts
//     X-Forwarded-For. Behind a proxy that does not overwrite it, an attacker
//     can rotate the header and reset their own IP buckets. They are a speed
//     bump against enumeration from one host, not a boundary.
//   - The cumulative window is FIXED, not sliding (matching
//     RateLimitByAPIKey): a caller can spend one bucket at the end of an hour
//     and the next at the start of the following one.
//   - While a link is being brute-forced, its legitimate viewers are locked
//     out too for the rest of the window, and a burst of more than
//     PublicLinkInFlightPerToken simultaneous SUCCESSFUL views is throttled as
//     well. Both answer 429; recovery from the first is to reissue the link.
//   - A Redis failure on the post-response INCR is logged and lost, so
//     failures during a Redis outage do not advance the counter. Every
//     pre-response step fails CLOSED (503), so an outage denies rather than
//     admits.
//   - A panic inside the handler unwinds past the charging step (Echo's
//     Recover middleware is installed with e.Use, i.e. OUTSIDE this one). The
//     in-flight reservation is still released, because that is a defer. A
//     panic produces a 500 rather than a 403, so no charge would be due
//     anyway; the residual is that a panic-inducing request is free.
func RateLimitPublicLink(rdb *redis.Client, perToken, perIP int, window time.Duration) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Security accounting must NOT ride on the request context.
			// Codex round 1 (Medium): an attacker who lets bcrypt start and
			// then closes the connection cancels that context — Go cancels it
			// on disconnect, but the handler's bcrypt keeps running — so both
			// the post-handler INCR and the deferred DECR would fail. The
			// cumulative counter would stay at zero while the work was
			// happening, turning "10 guesses per hour" into "one in-flight
			// cap's worth every lease period, forever".
			//
			// WithoutCancel keeps the context's values (tracing, etc.) and
			// drops only the cancellation.
			//
			// The deadline is applied PER PHASE rather than once for the whole
			// middleware. A single shared deadline started here would expire
			// during any handler that runs longer than it — a large SBOM
			// download on /public/:token/download is the obvious one — and the
			// release in the defer would then fail on an already-expired
			// context, leaking the reservation until its TTL. That would let
			// slow legitimate downloads throttle the link they belong to.
			base := context.WithoutCancel(c.Request().Context())
			redisCtx := func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(base, publicLinkRedisTimeout)
			}

			windowKey := calculateWindowKey(time.Now().UTC(), window)

			// The token is a bearer secret and the IP is personal data. Hash
			// both, so possession of the Redis keyspace is not possession of
			// every live share link.
			tokenHash := hashForKey(c.Param("token"))
			ipHash := hashForKey(c.RealIP())

			failKeys := []string{
				"publiclink:fail:token:" + tokenHash + ":" + windowKey,
				"publiclink:fail:ip:" + ipHash + ":" + windowKey,
			}
			failLimits := []int{perToken, perIP}

			// ---- 1. Concurrency reservation (atomic), FIRST. ----
			//
			// Codex round 2 (Medium): this used to run after the cumulative
			// check, which meant an unbounded number of goroutines could read
			// a pre-burst counter value, be descheduled, and later pick up
			// released slots still acting on that stale decision. Reserving
			// first means only slot holders ever get as far as forming an
			// admission decision, so the number of stale decisions alive at
			// any instant is bounded by the cap rather than by the attacker's
			// connection count.
			//
			// Every reservation taken is released below, including on the
			// rejection and error paths.
			inFlightKeys := []string{
				"publiclink:inflight:token:" + tokenHash,
				"publiclink:inflight:ip:" + ipHash,
			}
			inFlightLimits := []int{PublicLinkInFlightPerToken, PublicLinkInFlightPerIP}

			// A lease identity this request alone will remove. Collisions
			// would let one request cancel another's slot, so it carries 16
			// bytes of randomness as well as the nanosecond clock.
			leaseID, leaseErr := newLeaseID()
			if leaseErr != nil {
				slog.Error("public link rate limit: cannot generate a lease id, denying",
					"error", leaseErr, "ip", c.RealIP())
				return publicLinkUnavailable(c)
			}
			now := time.Now().UTC()

			var held []string
			release := func() {
				// Fresh deadline: this runs after the handler, which may have
				// taken longer than publicLinkRedisTimeout.
				relCtx, cancelRel := redisCtx()
				defer cancelRel()
				for _, key := range held {
					if err := inFlightRelease.Run(relCtx, rdb, []string{key}, leaseID).Err(); err != nil {
						// The per-lease expiry in inFlightReserve is the
						// backstop: a lease that cannot be released ages out
						// of the sorted set rather than shrinking the link's
						// concurrency permanently.
						slog.Warn("public link rate limit: in-flight release failed",
							"error", err)
					}
				}
			}
			defer release()

			reserveCtx, cancelReserve := redisCtx()
			defer cancelReserve()
			for i, key := range inFlightKeys {
				n, err := inFlightReserve.Run(reserveCtx, rdb, []string{key},
					now.UnixMilli(), publicLinkInFlightTTL.Milliseconds(),
					leaseID, int(publicLinkInFlightTTL.Seconds())+1, inFlightLimits[i]).Int64()
				if err != nil {
					slog.Error("public link rate limit: redis unavailable, denying",
						"error", err, "ip", c.RealIP())
					return publicLinkUnavailable(c)
				}
				if n < 0 {
					// Rejected inside the script; nothing was added, so there
					// is nothing to release for this key.
					slog.Warn("public link concurrency cap exceeded",
						"ip", c.RealIP(), "limit", inFlightLimits[i])
					return publicLinkTooManyRequests(c, window)
				}
				held = append(held, key)
			}

			// ---- 2. Cumulative failure budget (read-only check). ----
			checkCtx, cancelCheck := redisCtx()
			defer cancelCheck()
			for i, key := range failKeys {
				count, err := rdb.Get(checkCtx, key).Int64()
				if err != nil && !errors.Is(err, redis.Nil) {
					// Fail closed. This is a security gate on an
					// unauthenticated endpoint; admitting unlimited bcrypt
					// work because the counter is unavailable would reinstate
					// exactly the finding this exists to close.
					slog.Error("public link rate limit: redis unavailable, denying",
						"error", err, "ip", c.RealIP())
					return publicLinkUnavailable(c)
				}
				if count >= int64(failLimits[i]) {
					slog.Warn("public link rate limit exceeded",
						"ip", c.RealIP(), "limit", failLimits[i], "window", window.String())
					return publicLinkTooManyRequests(c, window)
				}
			}

			err := next(c)

			// ---- 3. Charge the cumulative budget for a rejected attempt. ----
			if publicLinkAttemptFailed(c, err) {
				// Fresh deadline for the same reason the release has one.
				chargeCtx, cancelCharge := redisCtx()
				defer cancelCharge()
				for _, key := range failKeys {
					// Reserve+expire in one round trip, for the same
					// crash-between-INCR-and-EXPIRE reason as the lease: a
					// counter left without a TTL would never expire, and a
					// brute-forced link would stay locked out forever rather
					// than for one window.
					if err := failCharge.Run(chargeCtx, rdb,
						[]string{key}, int(window.Seconds())+1).Err(); err != nil {
						slog.Warn("public link rate limit: failed attempt not counted",
							"error", err)
					}
				}
			}
			return err
		}
	}
}

// failCharge records one rejected attempt against a cumulative budget and
// asserts the window TTL in the same round trip.
//
// Self-review after Codex round 1: the plain INCR-then-conditional-EXPIRE this
// replaces had the same crash window as the lease did, with a worse
// consequence. A counter that never received its TTL would never expire, so a
// link that had been brute-forced once would stay locked out permanently
// rather than for one window — a fail-CLOSED bug, but a denial-of-service on
// the tenant's own share link.
//
// EXPIRE is unconditional rather than only-when-n==1, which is what makes it
// self-repairing. Re-asserting it does NOT extend a lockout: the key name
// already encodes the window bucket (calculateWindowKey), so at the hour
// boundary requests start consulting a different key regardless of how long
// the old one lives. The refreshed TTL only keeps a spent bucket in memory
// slightly longer than it is consulted.
var failCharge = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[1])
return n
`)

// inFlightReserve records THIS request's lease in a sorted set scored by the
// time it was taken, evicts anything older than the lease window, and returns
// how many live leases the key now holds.
//
// The set-of-lease-IDs shape replaces a plain counter, over two rounds of
// review:
//
//   - Codex round 1 (Medium): a counter needed INCR and EXPIRE as separate
//     calls. A crash between them left a key with no TTL that later
//     reservations never repaired.
//   - Codex round 2 (Medium): making the TTL unconditional fixed that but left
//     an ABA race. Request A reserves; A runs longer than the lease; A's KEY
//     expires; request B creates a fresh key and reserves; A finishes and
//     decrements B's generation, and the clamp then DELETES B's live
//     reservation. A counter cannot tell the two generations apart, because a
//     counter has no identity.
//
// A sorted set does. Each request adds a member only it will remove, so a late
// release can never cancel someone else's slot, and expiry is per-lease
// (ZREMRANGEBYSCORE by age) rather than per-key. The key TTL is now only a
// housekeeping backstop for a key nobody touches again.
//
// Codex round 3 (Medium): the cap is enforced INSIDE the script, before the
// ZADD, and a rejected request adds nothing. The earlier version always added
// and let Go compare afterwards, so a burst could grow the set in proportion
// to the attacker's concurrency rather than to the cap — TTL bounds a key's
// lifetime, not its cardinality.
//
// KEYS[1] = the in-flight key. ARGV[1] = now (unix ms), ARGV[2] = lease window
// in ms, ARGV[3] = this request's unique member, ARGV[4] = key TTL in seconds,
// ARGV[5] = the cap. Returns the live count, and -1 when the request was
// rejected without reserving (so the caller knows not to release).
var inFlightReserve = redis.NewScript(`
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', tonumber(ARGV[1]) - tonumber(ARGV[2]))
local n = redis.call('ZCARD', KEYS[1])
if n >= tonumber(ARGV[5]) then
  return -1
end
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[3])
redis.call('EXPIRE', KEYS[1], ARGV[4])
return redis.call('ZCARD', KEYS[1])
`)

// inFlightRelease removes exactly this request's lease and nothing else.
//
// ZREM of a member that is already gone (because the lease aged out) is a
// no-op returning 0, which is precisely the behaviour the counter version
// could not provide.
var inFlightRelease = redis.NewScript(`
redis.call('ZREM', KEYS[1], ARGV[1])
if redis.call('ZCARD', KEYS[1]) == 0 then
  redis.call('DEL', KEYS[1])
end
return 0
`)

// publicLinkTooManyRequests is the single 429 body, shared by the cumulative
// and concurrency rejections so a caller cannot tell which limit it hit.
//
// The message says "throttled" rather than "too many failed attempts" (Codex
// round 1, Low): the concurrency cap can reject a request that has not failed
// anything, so the old wording was stronger than what the code knows.
func publicLinkTooManyRequests(c echo.Context, window time.Duration) error {
	c.Response().Header().Set("Retry-After", fmt.Sprintf("%d", int(window.Seconds())))
	return c.JSON(http.StatusTooManyRequests, map[string]string{
		"error":       "too many requests for this share link",
		"retry_after": fmt.Sprintf("%ds", int(window.Seconds())),
	})
}

// publicLinkUnavailable is the fail-closed answer when the counters cannot be
// consulted at all.
func publicLinkUnavailable(c echo.Context) error {
	return c.JSON(http.StatusServiceUnavailable, map[string]string{
		"error": "temporarily unavailable",
	})
}

// publicLinkAttemptFailed reports whether the request that just finished was a
// rejected access attempt (403), whether the handler wrote that status itself
// or returned it as an echo.HTTPError for the error handler to write.
func publicLinkAttemptFailed(c echo.Context, err error) bool {
	if c.Response().Committed && c.Response().Status == http.StatusForbidden {
		return true
	}
	var he *echo.HTTPError
	if errors.As(err, &he) && he.Code == http.StatusForbidden {
		return true
	}
	return false
}

// newLeaseID returns a value unique to one in-flight request, used as the
// sorted-set member for its concurrency reservation. Two requests must never
// share one, or a release would cancel the wrong slot; the random half is what
// guarantees that across processes and across clock resolution.
func newLeaseID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Codex round 3 (Low): the previous fallback was the nanosecond clock
		// alone, which is NOT unique across processes or across a coarse
		// clock. Two requests sharing a member would be counted as one, and
		// either release would cancel the other's reservation — the exact ABA
		// failure the sorted set exists to prevent. Fail closed instead; the
		// caller answers 503.
		return "", fmt.Errorf("generate in-flight lease id: %w", err)
	}
	return fmt.Sprintf("t%d-%s", time.Now().UnixNano(), hex.EncodeToString(b[:])), nil
}

// hashForKey reduces a value to a hex digest suitable for a Redis key, so
// secrets (share tokens) and PII (client IPs) are not stored in plaintext in
// the keyspace.
func hashForKey(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
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
