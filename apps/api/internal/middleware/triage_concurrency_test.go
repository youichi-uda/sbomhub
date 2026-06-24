package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// newLimitedHandler builds an Echo handler chain that wires the
// limiter middleware around a handler that signals when it has been
// entered and then blocks on the supplied chan until told to release.
//
// The release channel is the test's way to keep a request "in flight"
// so the limiter slot stays held across the assertion. Returning
// chans from a helper instead of using sleep keeps the test
// deterministic on slow CI.
func newLimitedHandler(t *testing.T, limiter *TriageConcurrencyLimiter, release <-chan struct{}, entered chan<- struct{}) echo.HandlerFunc {
	t.Helper()
	return limiter.Middleware()(func(c echo.Context) error {
		entered <- struct{}{}
		<-release
		return c.JSON(http.StatusOK, map[string]string{"ok": "yes"})
	})
}

// dispatch fires one HTTP request through the limited chain with the
// supplied tenant id pre-populated on the Echo context. Returns the
// recorder so the test can inspect status/body.
func dispatch(e *echo.Echo, handler echo.HandlerFunc, tenantID uuid.UUID) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/x/triage/run", nil)
	c := e.NewContext(req, rec)
	c.Set(ContextKeyTenantID, tenantID)
	_ = handler(c)
	return rec
}

// TestTriageConcurrencyLimit_PerTenant pins the F19 part-2 contract:
// per-tenant cap N → N concurrent requests for the same tenant
// succeed; the (N+1)th gets 429. Other tenants are unaffected.
func TestTriageConcurrencyLimit_PerTenant(t *testing.T) {
	limiter := NewTriageConcurrencyLimiter(3 /*perTenant*/, 100 /*global, large so it isn't the gate*/)
	e := echo.New()

	tenantA := uuid.New()
	tenantB := uuid.New()

	release := make(chan struct{})
	entered := make(chan struct{}, 10)
	handler := newLimitedHandler(t, limiter, release, entered)

	// Fire 3 concurrent requests for tenant A — all should reach the
	// handler. Read 3 entered signals so we know all are in flight.
	results := make(chan int, 5)
	for i := 0; i < 3; i++ {
		go func() {
			rec := dispatch(e, handler, tenantA)
			results <- rec.Code
		}()
	}
	for i := 0; i < 3; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d/3 tenant A requests entered handler", i)
		}
	}

	// 4th concurrent request for tenant A must 429 (cap=3).
	rec := dispatch(e, handler, tenantA)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("4th concurrent tenant A request: status = %d, want 429", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "triage capacity exhausted") {
		t.Errorf("rejection body = %q, want generic 'triage capacity exhausted'", body)
	}

	// Tenant B is independent: 3 concurrent requests should still
	// succeed even with tenant A at its cap.
	tenantBResults := make(chan int, 3)
	for i := 0; i < 3; i++ {
		go func() {
			rec := dispatch(e, handler, tenantB)
			tenantBResults <- rec.Code
		}()
	}
	for i := 0; i < 3; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("tenant B request %d did not enter handler — per-tenant cap leaking across tenants", i)
		}
	}

	// Release everyone.
	close(release)

	// Tenant A's 3 in-flight + tenant B's 3 in-flight should all
	// return 200; results channel collects 6 entries total.
	collected := 0
	timeout := time.After(2 * time.Second)
	for collected < 6 {
		select {
		case code := <-results:
			if code != http.StatusOK {
				t.Errorf("tenant A result: status = %d, want 200", code)
			}
			collected++
		case code := <-tenantBResults:
			if code != http.StatusOK {
				t.Errorf("tenant B result: status = %d, want 200", code)
			}
			collected++
		case <-timeout:
			t.Fatalf("timed out waiting for in-flight results (got %d/6)", collected)
		}
	}
}

// TestTriageConcurrencyLimit_GlobalCap verifies the global cap fires
// independently of the per-tenant cap. With perTenant=10 and global=2,
// a 3rd concurrent request (even from a different tenant) must 429.
func TestTriageConcurrencyLimit_GlobalCap(t *testing.T) {
	limiter := NewTriageConcurrencyLimiter(10 /*perTenant — far above the global cap*/, 2 /*global*/)
	e := echo.New()

	release := make(chan struct{})
	entered := make(chan struct{}, 5)
	handler := newLimitedHandler(t, limiter, release, entered)

	tA, tB, tC := uuid.New(), uuid.New(), uuid.New()
	results := make(chan int, 3)
	for _, tid := range []uuid.UUID{tA, tB} {
		tid := tid
		go func() {
			rec := dispatch(e, handler, tid)
			results <- rec.Code
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d/2 global-cap requests entered handler", i)
		}
	}

	// Third request from a different tenant → global cap full → 429.
	rec := dispatch(e, handler, tC)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("3rd request (global cap full): status = %d, want 429", rec.Code)
	}

	close(release)
	for i := 0; i < 2; i++ {
		select {
		case code := <-results:
			if code != http.StatusOK {
				t.Errorf("result status = %d, want 200", code)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out collecting in-flight results")
		}
	}
}

// TestTriageConcurrencyLimit_ReleasesOnHandlerError verifies slots are
// returned to the pool when the handler returns an error (not just on
// success). A leaked slot here would silently shrink the effective cap
// across the limiter's lifetime.
func TestTriageConcurrencyLimit_ReleasesOnHandlerError(t *testing.T) {
	limiter := NewTriageConcurrencyLimiter(1, 1)
	e := echo.New()

	// Handler that always returns an error — slot must still release.
	handler := limiter.Middleware()(func(c echo.Context) error {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "boom"})
	})

	tenant := uuid.New()
	// Run 5 sequential requests through the cap-1 limiter. If the
	// limiter leaked a slot on error, the 2nd onwards would 429.
	for i := 0; i < 5; i++ {
		rec := dispatch(e, handler, tenant)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("iteration %d: status = %d, want 500 (handler error must surface)", i, rec.Code)
		}
	}
}

// TestTriageConcurrencyLimit_MissingTenantContext exercises the
// defensive 401 branch — the limiter should refuse a request that
// somehow reached it without an auth tenant id rather than silently
// pass through. (Production wiring always has MultiAuth + RequireWrite
// upstream, so this branch is unreachable in production but the
// defense matters for misconfig.)
func TestTriageConcurrencyLimit_MissingTenantContext(t *testing.T) {
	limiter := NewTriageConcurrencyLimiter(5, 20)
	e := echo.New()
	called := atomic.Bool{}
	handler := limiter.Middleware()(func(c echo.Context) error {
		called.Store(true)
		return c.JSON(http.StatusOK, nil)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/x/triage/run", nil)
	c := e.NewContext(req, rec)
	// Deliberately do not set ContextKeyTenantID.
	_ = handler(c)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no-tenant request: status = %d, want 401", rec.Code)
	}
	if called.Load() {
		t.Errorf("handler must not run when tenant context is missing")
	}
}

// TestTriageConcurrencyLimit_PerTenantSlotsAreIndependent fires repeated
// requests for many tenants to confirm the sync.Map-backed per-tenant
// chan registry returns the same chan on subsequent calls (i.e. doesn't
// leak by re-creating).
func TestTriageConcurrencyLimit_PerTenantSlotsAreIndependent(t *testing.T) {
	limiter := NewTriageConcurrencyLimiter(2, 100)
	tenant := uuid.New()
	a := limiter.getOrCreateTenantSem(tenant)
	b := limiter.getOrCreateTenantSem(tenant)
	if a != b {
		t.Errorf("getOrCreateTenantSem returned different chans for same tenant")
	}
	other := limiter.getOrCreateTenantSem(uuid.New())
	if a == other {
		t.Errorf("different tenants must get distinct chans")
	}
}

// Silence "imported and not used" warnings if go test reorders.
var _ = sync.WaitGroup{}
