package middleware

import (
	"log/slog"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// CRAConcurrencyLimiter caps the number of concurrent CRA report
// drafting requests both globally and per-tenant. It is the M2-4
// analogue of TriageConcurrencyLimiter (M1 Codex review #F19) — even
// with the cra.Runner's 2-stage tx hygiene releasing the Postgres
// connection during the slow upstream LLM call, the deployment still
// has finite goroutine / LLM-provider rate-limit / memory budget.
//
// A separate limiter instance from the triage limiter is intentional:
// concurrent VEX triage runs and CRA report runs each get their own
// slot allocation so that a burst of CRA drafting (e.g. a CRA
// 11-September-2026 compliance deadline rush) cannot starve in-flight
// triage decisions and vice-versa. Operators can size the two budgets
// independently via the env knobs below.
//
// Both slots must be acquired before the handler runs. If either is
// full, the limiter responds 429 with a generic body and emits a slog
// warning so operators can size capacity. Slots are released on
// handler return (success OR error) via defer.
//
// Implementation: non-blocking acquire (TrySend on the chan). We
// deliberately do NOT queue requests because the upstream LLM has its
// own queueing (and queueing would itself defeat the connection-pool
// fix by holding goroutines indefinitely). Reject-fast is the policy.
const (
	// DefaultCRAConcurrencyPerTenant caps concurrent CRA report runs per
	// tenant. CRA drafting is typically interactive (one operator
	// drafting one report) so 3 is a conservative default — bursty
	// CI/CD fan-out is not a CRA use case (compliance is human-driven).
	DefaultCRAConcurrencyPerTenant = 3

	// DefaultCRAConcurrencyGlobal caps total concurrent CRA report runs
	// across all tenants. 10 leaves headroom in the 25-slot Postgres
	// pool for other DB-backed routes (concurrent triage + analytics
	// + dashboards).
	DefaultCRAConcurrencyGlobal = 10

	// EnvCRAConcurrencyPerTenant overrides DefaultCRAConcurrencyPerTenant.
	EnvCRAConcurrencyPerTenant = "SBOMHUB_CRA_CONCURRENCY_PER_TENANT"

	// EnvCRAConcurrencyGlobal overrides DefaultCRAConcurrencyGlobal.
	EnvCRAConcurrencyGlobal = "SBOMHUB_CRA_CONCURRENCY_GLOBAL"
)

// CRAConcurrencyLimiter holds the per-tenant and global semaphores.
// Construct via NewCRAConcurrencyLimiter; use Middleware() to obtain
// the Echo middleware.
type CRAConcurrencyLimiter struct {
	perTenant int
	global    int

	globalSlots chan struct{}

	// tenantSlots maps tenant_id → chan struct{} (the per-tenant
	// semaphore). Same sync.Map rationale as TriageConcurrencyLimiter —
	// read-mostly with create-once on the first request per tenant.
	tenantSlots sync.Map
}

// NewCRAConcurrencyLimiter constructs a limiter with the supplied
// caps. Zero or negative perTenant/global fall back to the package
// defaults. Production wiring calls NewCRAConcurrencyLimiterFromEnv.
func NewCRAConcurrencyLimiter(perTenant, global int) *CRAConcurrencyLimiter {
	if perTenant <= 0 {
		perTenant = DefaultCRAConcurrencyPerTenant
	}
	if global <= 0 {
		global = DefaultCRAConcurrencyGlobal
	}
	return &CRAConcurrencyLimiter{
		perTenant:   perTenant,
		global:      global,
		globalSlots: make(chan struct{}, global),
	}
}

// NewCRAConcurrencyLimiterFromEnv constructs a limiter reading caps
// from EnvCRAConcurrencyPerTenant / EnvCRAConcurrencyGlobal.
func NewCRAConcurrencyLimiterFromEnv() *CRAConcurrencyLimiter {
	return NewCRAConcurrencyLimiter(
		envIntDefault(EnvCRAConcurrencyPerTenant, DefaultCRAConcurrencyPerTenant),
		envIntDefault(EnvCRAConcurrencyGlobal, DefaultCRAConcurrencyGlobal),
	)
}

// PerTenant returns the per-tenant cap. Exposed for tests + diagnostics.
func (l *CRAConcurrencyLimiter) PerTenant() int { return l.perTenant }

// Global returns the global cap. Exposed for tests + diagnostics.
func (l *CRAConcurrencyLimiter) Global() int { return l.global }

// getOrCreateTenantSem returns the per-tenant semaphore chan, creating
// it on first use. Mirrors TriageConcurrencyLimiter.
func (l *CRAConcurrencyLimiter) getOrCreateTenantSem(tenantID uuid.UUID) chan struct{} {
	if v, ok := l.tenantSlots.Load(tenantID); ok {
		return v.(chan struct{})
	}
	fresh := make(chan struct{}, l.perTenant)
	actual, _ := l.tenantSlots.LoadOrStore(tenantID, fresh)
	return actual.(chan struct{})
}

// Middleware returns the Echo middleware that enforces both caps. It
// must run AFTER auth (so tenant_id is populated) and BEFORE TenantTx
// (so a rejection does not pin a DB connection). For CRA routes where
// TenantTx has been stripped (the runner manages its own tx — F19
// pattern), the limiter sits just after the auth + role guard chain.
//
// Response body on rejection: `{"error":"cra capacity exhausted"}` —
// generic so a probe caller cannot tell whether the per-tenant cap or
// the global cap fired. The precise reason lives in slog warn logs.
func (l *CRAConcurrencyLimiter) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			tenantID, _ := c.Get(ContextKeyTenantID).(uuid.UUID)
			if tenantID == uuid.Nil {
				// Defensive: CRA routes always sit behind MultiAuth +
				// RequireWrite, so this branch should be unreachable.
				// Returning 401 mirrors RequireWrite's own missing-tenant
				// posture.
				slog.Warn("CRAConcurrencyLimiter: missing tenant context",
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
				slog.Warn("CRAConcurrencyLimiter: global cap exhausted",
					"tenant_id", tenantID, "global_cap", l.global,
					"path", c.Path(), "method", c.Request().Method)
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error": "cra capacity exhausted",
				})
			}

			sem := l.getOrCreateTenantSem(tenantID)
			select {
			case sem <- struct{}{}:
			default:
				// Release the global slot we acquired above so a
				// tenant-cap rejection does not consume global budget.
				<-l.globalSlots
				slog.Warn("CRAConcurrencyLimiter: per-tenant cap exhausted",
					"tenant_id", tenantID, "per_tenant_cap", l.perTenant,
					"path", c.Path(), "method", c.Request().Method)
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error": "cra capacity exhausted",
				})
			}

			// Release both slots when the handler returns (success OR
			// error). defer-LIFO so we drain tenant first then global —
			// matches acquire order in reverse, no chance of a transient
			// "global free but tenant taken" inconsistency.
			defer func() {
				<-sem
				<-l.globalSlots
			}()

			return next(c)
		}
	}
}
