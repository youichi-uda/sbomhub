package middleware

import (
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// TriageConcurrencyLimiter caps the number of concurrent AI triage
// requests both globally and per-tenant. It is the route-level
// complement to the runner-internal 2-stage tx split (M1 Codex review
// #F19): even with the runner releasing its DB connection during the
// slow LLM call, the SBOMHub deployment still has finite goroutine /
// LLM-provider rate-limit / memory budget. The limiter pins:
//
//   - A global semaphore (default DefaultTriageConcurrencyGlobal,
//     env override SBOMHUB_TRIAGE_CONCURRENCY_GLOBAL) so the API as a
//     whole cannot fan out more than N concurrent LLM calls regardless
//     of how many tenants are active.
//   - A per-tenant semaphore (default
//     DefaultTriageConcurrencyPerTenant, env override
//     SBOMHUB_TRIAGE_CONCURRENCY_PER_TENANT) so one noisy tenant cannot
//     starve everyone else.
//
// Both slots must be acquired before the handler runs. If either is
// full, the limiter responds 429 with a generic body and emits a slog
// warning so operators can size capacity. Slots are released on handler
// return (success OR error) via defer.
//
// Implementation: non-blocking acquire (TrySend on the chan). We
// deliberately do NOT queue requests because the upstream LLM has its
// own queueing (and queueing would itself defeat the connection-pool
// fix by holding goroutines indefinitely). Reject-fast is the policy.
const (
	// DefaultTriageConcurrencyPerTenant caps concurrent triage requests
	// per tenant. 5 is a conservative default — typical interactive
	// triage runs in single-digit parallelism; CI/CD fan-out is bursty
	// but bounded per pipeline.
	DefaultTriageConcurrencyPerTenant = 5

	// DefaultTriageConcurrencyGlobal caps total concurrent triage
	// requests across all tenants. 20 leaves headroom in the 25-slot
	// Postgres pool for other DB-backed routes — even if every Stage 3
	// write tx fires at once, 5 connections stay free for non-triage
	// requests (analytics, dashboards, SBOM upload).
	DefaultTriageConcurrencyGlobal = 20

	// EnvTriageConcurrencyPerTenant overrides DefaultTriageConcurrencyPerTenant.
	EnvTriageConcurrencyPerTenant = "SBOMHUB_TRIAGE_CONCURRENCY_PER_TENANT"

	// EnvTriageConcurrencyGlobal overrides DefaultTriageConcurrencyGlobal.
	EnvTriageConcurrencyGlobal = "SBOMHUB_TRIAGE_CONCURRENCY_GLOBAL"
)

// TriageConcurrencyLimiter holds the per-tenant and global semaphores.
// Construct via NewTriageConcurrencyLimiter; use Middleware() to obtain
// the Echo middleware.
type TriageConcurrencyLimiter struct {
	perTenant int
	global    int

	globalSlots chan struct{}

	// tenantSlots maps tenant_id → chan struct{} (the per-tenant
	// semaphore). sync.Map fits because the read-mostly pattern matches
	// "lookup existing tenant's chan on every request, create-once on
	// the first request per tenant". The chan itself is fixed-size so
	// once created it costs ~perTenant words of memory; tenants that
	// never run triage have no entry.
	tenantSlots sync.Map
}

// NewTriageConcurrencyLimiter constructs a limiter with the supplied
// caps. Zero or negative perTenant/global fall back to the package
// defaults. Production wiring calls NewTriageConcurrencyLimiterFromEnv.
func NewTriageConcurrencyLimiter(perTenant, global int) *TriageConcurrencyLimiter {
	if perTenant <= 0 {
		perTenant = DefaultTriageConcurrencyPerTenant
	}
	if global <= 0 {
		global = DefaultTriageConcurrencyGlobal
	}
	return &TriageConcurrencyLimiter{
		perTenant:   perTenant,
		global:      global,
		globalSlots: make(chan struct{}, global),
	}
}

// NewTriageConcurrencyLimiterFromEnv constructs a limiter reading caps
// from EnvTriageConcurrencyPerTenant / EnvTriageConcurrencyGlobal.
func NewTriageConcurrencyLimiterFromEnv() *TriageConcurrencyLimiter {
	return NewTriageConcurrencyLimiter(envIntDefault(EnvTriageConcurrencyPerTenant, DefaultTriageConcurrencyPerTenant),
		envIntDefault(EnvTriageConcurrencyGlobal, DefaultTriageConcurrencyGlobal))
}

func envIntDefault(name string, def int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return def
	}
	return v
}

// PerTenant returns the per-tenant cap. Exposed for tests + diagnostics.
func (l *TriageConcurrencyLimiter) PerTenant() int { return l.perTenant }

// Global returns the global cap. Exposed for tests + diagnostics.
func (l *TriageConcurrencyLimiter) Global() int { return l.global }

// getOrCreateTenantSem returns the per-tenant semaphore chan, creating
// it on first use. LoadOrStore atomically inserts a chan if not
// present, so concurrent first-time requests for the same tenant
// converge on the same chan.
func (l *TriageConcurrencyLimiter) getOrCreateTenantSem(tenantID uuid.UUID) chan struct{} {
	if v, ok := l.tenantSlots.Load(tenantID); ok {
		return v.(chan struct{})
	}
	fresh := make(chan struct{}, l.perTenant)
	actual, _ := l.tenantSlots.LoadOrStore(tenantID, fresh)
	return actual.(chan struct{})
}

// Middleware returns the Echo middleware that enforces both caps. It
// must run AFTER auth (so tenant_id is populated) and BEFORE TenantTx
// (so a rejection does not pin a DB connection). For triage routes
// where TenantTx has been stripped (the runner manages its own tx),
// the limiter sits just after the auth + role guard chain.
//
// Response body on rejection: `{"error":"triage capacity exhausted"}` —
// generic so a probe caller cannot tell whether the per-tenant cap or
// the global cap fired (would otherwise leak total-tenant-count info).
// The precise reason lives in slog warn logs only.
func (l *TriageConcurrencyLimiter) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			tenantID, _ := c.Get(ContextKeyTenantID).(uuid.UUID)
			if tenantID == uuid.Nil {
				// Defensive: triage routes always sit behind MultiAuth +
				// RequireWrite, so this branch should be unreachable.
				// Returning 401 mirrors RequireWrite's own missing-tenant
				// posture so a misconfigured route does not silently
				// degrade to "no limit applied".
				slog.Warn("TriageConcurrencyLimiter: missing tenant context",
					"path", c.Path(), "method", c.Request().Method)
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "unauthorized",
				})
			}

			// Try acquire global slot first — if global is full,
			// rejecting before touching the tenant chan keeps the
			// per-tenant counters honest.
			select {
			case l.globalSlots <- struct{}{}:
			default:
				slog.Warn("TriageConcurrencyLimiter: global cap exhausted",
					"tenant_id", tenantID, "global_cap", l.global,
					"path", c.Path(), "method", c.Request().Method)
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error": "triage capacity exhausted",
				})
			}

			sem := l.getOrCreateTenantSem(tenantID)
			select {
			case sem <- struct{}{}:
			default:
				// Release the global slot we acquired above so a
				// tenant-cap rejection does not consume global budget.
				<-l.globalSlots
				slog.Warn("TriageConcurrencyLimiter: per-tenant cap exhausted",
					"tenant_id", tenantID, "per_tenant_cap", l.perTenant,
					"path", c.Path(), "method", c.Request().Method)
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error": "triage capacity exhausted",
				})
			}

			// Release both slots when the handler returns (success OR
			// error). defer-LIFO so we drain tenant first then global —
			// matches the acquire order in reverse, no chance of a
			// transient "global free but tenant taken" inconsistency.
			defer func() {
				<-sem
				<-l.globalSlots
			}()

			return next(c)
		}
	}
}
