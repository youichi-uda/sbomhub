package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Per-tenant scan concurrency (M72, SBOMHUB_SCAN_TENANT_CONCURRENCY).
//
// # Why a concurrency limit and not a per-tenant deadline
//
// SBOMHUB_SCAN_DEADLINE bounds ONE scan. Nothing bounded how many scans one
// tenant runs at once: every upload and every POST .../scan starts its own
// goroutine, and each NVD sweep paces itself with its OWN ticker
// (NVDService.fetchComponents) — so a tenant that uploads 20 SBOMs runs 20
// sweeps side by side, issuing 20x the NVD request rate from the API's one IP.
// NVD throttles per IP, so every OTHER tenant's lookups start failing
// (fetch_failed) or crawling into their deadline. A per-tenant deadline
// override would not touch that: it lets one tenant run LONGER, it does not
// stop it crowding the others, and it needs a column, a migration and an
// admin path. A per-tenant slot count does stop it, needs no schema, and keeps
// the global deadline as the only deadline.
//
// # Semantics
//
//   - At most N scans of one tenant run at once in one API process (default 2;
//     "off" disables the limit). Scans of other tenants never wait for them.
//   - A scan that finds its tenant's slots taken waits, FIFO-ish (Go channel
//     order), and the wait counts against its own scan deadline: the deadline
//     still bounds the whole scan from the moment it was requested, so the
//     scan-status retention (deadline + 15m) stays sufficient. A scan whose
//     deadline fires while it waits is reported failed (deadline_exceeded)
//     without having started; one cancelled while waiting is cancelled.
//   - At most TenantScanQueueLimit scans of one tenant wait; one beyond that
//     fails at once (queue_full).
//   - The upload scan, the manual scan route and the scheduled per-project scan
//     share the same slots.
//
// Not covered: the limit is per process (two replicas allow 2N per tenant),
// and it does not pace NVD globally — N tenants still run N or more sweeps.

// DefaultTenantScanConcurrency is the limit when none is configured.
const DefaultTenantScanConcurrency = 2

// TenantScanSlots limits concurrent scans per tenant.
type TenantScanSlots struct {
	limit int // 0 = unlimited
	mu    sync.Mutex
	slots map[uuid.UUID]*tenantSlot
}

type tenantSlot struct {
	sem     chan struct{}
	refs    int // holders + waiters; the entry is dropped at 0
	waiting int
}

// TenantScanQueueLimit is how many scans of one tenant may WAIT for a slot
// when limit run (Codex M72 R1 High-4): a scan beyond it fails at once with
// reason queue_full rather than parking a goroutine for its whole deadline.
// 32 per slot (64 at the default) is far beyond a CI burst, and bounds what one
// tenant can pin in the process.
func TenantScanQueueLimit(limit int) int { return 32 * limit }

// NewTenantScanSlots returns a limiter allowing limit concurrent scans per
// tenant; limit <= 0 is unlimited.
func NewTenantScanSlots(limit int) *TenantScanSlots {
	if limit < 0 {
		limit = 0
	}
	return &TenantScanSlots{limit: limit, slots: map[uuid.UUID]*tenantSlot{}}
}

// Limit is the configured per-tenant limit (0 = unlimited).
func (s *TenantScanSlots) Limit() int { return s.limit }

// Acquire waits for one of tenantID's slots. It returns the release function
// (call exactly once) and how long it waited, or ctx's interruption
// (ErrScanDeadlineExceeded / ErrScanCancelled) if ctx ended first.
func (s *TenantScanSlots) Acquire(ctx context.Context, tenantID uuid.UUID) (func(), time.Duration, error) {
	if s == nil || s.limit == 0 {
		return func() {}, 0, nil
	}
	s.mu.Lock()
	ts := s.slots[tenantID]
	if ts == nil {
		ts = &tenantSlot{sem: make(chan struct{}, s.limit)}
		s.slots[tenantID] = ts
	}
	free := len(ts.sem) < cap(ts.sem)
	if !free && ts.waiting >= TenantScanQueueLimit(s.limit) {
		s.mu.Unlock()
		return nil, 0, fmt.Errorf("%d scans of the tenant already wait for a slot: %w", ts.waiting, ErrScanQueueFull)
	}
	ts.refs++
	ts.waiting++
	s.mu.Unlock()
	waited := func() {
		s.mu.Lock()
		ts.waiting--
		s.mu.Unlock()
	}

	drop := func() {
		s.mu.Lock()
		ts.refs--
		if ts.refs == 0 {
			delete(s.slots, tenantID)
		}
		s.mu.Unlock()
	}

	start := time.Now()
	select {
	case ts.sem <- struct{}{}:
		waited()
	default:
		select {
		case ts.sem <- struct{}{}:
			waited()
		case <-ctx.Done():
			waited()
			drop()
			return nil, time.Since(start), fmt.Errorf("waiting for a scan slot of the tenant: %w", scanInterruption(ctx))
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			<-ts.sem
			drop()
		})
	}, time.Since(start), nil
}

// InUse reports how many of tenantID's slots are held (tests, logs).
func (s *TenantScanSlots) InUse(tenantID uuid.UUID) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ts := s.slots[tenantID]; ts != nil {
		return len(ts.sem)
	}
	return 0
}

// Waiting reports how many scans of tenantID wait for a slot.
func (s *TenantScanSlots) Waiting(tenantID uuid.UUID) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ts := s.slots[tenantID]; ts != nil {
		return ts.waiting
	}
	return 0
}

// TenantScanWaiting is Waiting on the process-wide limiter.
func TenantScanWaiting(tenantID uuid.UUID) int { return tenantScanSlots.Load().Waiting(tenantID) }

// tenantScanSlots is the process-wide limiter shared by every scan path.
var tenantScanSlots atomic.Pointer[TenantScanSlots]

func init() { tenantScanSlots.Store(NewTenantScanSlots(DefaultTenantScanConcurrency)) }

// SetTenantScanConcurrency replaces the process-wide limiter (startup, from
// SBOMHUB_SCAN_TENANT_CONCURRENCY; 0 = unlimited). Scans already holding or
// waiting for a slot of the old limiter keep it.
func SetTenantScanConcurrency(limit int) {
	tenantScanSlots.Store(NewTenantScanSlots(limit))
}

// TenantScanConcurrency returns the process-wide limit (0 = unlimited).
func TenantScanConcurrency() int { return tenantScanSlots.Load().Limit() }

// AcquireTenantScanSlot takes one of tenantID's slots of the process-wide
// limiter, waiting while ctx (the scan's deadline context) allows. A wait is
// logged with its duration.
func AcquireTenantScanSlot(ctx context.Context, tenantID, sbomID uuid.UUID) (func(), error) {
	slots := tenantScanSlots.Load()
	release, waited, err := slots.Acquire(ctx, tenantID)
	if err != nil {
		slog.Warn("scan: not started; no scan slot of the tenant became free (queue full, or its deadline ended while it waited)",
			"tenant_id", tenantID, "sbom_id", sbomID, "limit", slots.Limit(),
			"waited", waited.Round(time.Millisecond).String(), "error", err)
		return nil, err
	}
	if waited >= time.Millisecond {
		slog.Info("scan: waited for one of the tenant's scan slots",
			"tenant_id", tenantID, "sbom_id", sbomID, "limit", slots.Limit(),
			"waited", waited.Round(time.Millisecond).String())
	}
	return release, nil
}
