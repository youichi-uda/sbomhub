package handler

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/service"
)

// M72: one tenant's scans hold at most SBOMHUB_SCAN_TENANT_CONCURRENCY slots;
// another tenant's scan never waits for them.

type m72Gate struct {
	release chan struct{}
	running atomic.Int32
	peak    atomic.Int32
}

func (g *m72Gate) ScanComponents(ctx context.Context, _ uuid.UUID) error {
	n := g.running.Add(1)
	for {
		p := g.peak.Load()
		if n <= p || g.peak.CompareAndSwap(p, n) {
			break
		}
	}
	defer g.running.Add(-1)
	select {
	case <-g.release:
		return nil
	case <-ctx.Done():
		return service.ErrScanDeadlineExceeded
	}
}

func withConcurrency(t *testing.T, n int) {
	t.Helper()
	prev := service.TenantScanConcurrency()
	service.SetTenantScanConcurrency(n)
	t.Cleanup(func() { service.SetTenantScanConcurrency(prev) })
}

func TestM72TenantSlots_OneTenantCannotStarveAnother(t *testing.T) {
	withConcurrency(t, 2)
	busy := &m72Gate{release: make(chan struct{})}
	tenantA, tenantB := uuid.New(), uuid.New()

	done := make(chan scanOutcome, 5)
	for i := 0; i < 5; i++ {
		go func() {
			done <- runSBOMScan(context.Background(), nil, tenantA, uuid.New(), time.Minute,
				[]scanStep{{source: "nvd", scanner: busy}})
		}()
	}
	waitUntil(t, func() bool { return busy.running.Load() == 2 })
	time.Sleep(50 * time.Millisecond)
	if got := busy.running.Load(); got != 2 {
		t.Fatalf("tenant A runs %d scans at once, want 2", got)
	}

	// Tenant B's scan starts and finishes while A's five are queued/running.
	quick := &m72Gate{release: make(chan struct{})}
	close(quick.release)
	start := time.Now()
	out := runSBOMScan(context.Background(), nil, tenantB, uuid.New(), time.Minute,
		[]scanStep{{source: "nvd", scanner: quick}})
	if out.failed() || time.Since(start) > time.Second {
		t.Fatalf("tenant B waited %s / failed %v behind tenant A", time.Since(start), out.markers)
	}

	close(busy.release)
	for i := 0; i < 5; i++ {
		if o := <-done; o.failed() {
			t.Fatalf("tenant A scan failed: %v", o.markers)
		}
	}
	if p := busy.peak.Load(); p != 2 {
		t.Fatalf("peak concurrency of tenant A = %d, want 2", p)
	}
}

// A scan whose deadline ends while it waits for a slot is reported failed
// (deadline_exceeded) without running any scanner; the wait counted against
// its deadline.
func TestM72TenantSlots_DeadlineWhileQueuedFailsTheScan(t *testing.T) {
	withConcurrency(t, 1)
	tenant := uuid.New()
	hold := &m72Gate{release: make(chan struct{})}
	defer close(hold.release)
	go runSBOMScan(context.Background(), nil, tenant, uuid.New(), time.Minute,
		[]scanStep{{source: "nvd", scanner: hold}})
	waitUntil(t, func() bool { return hold.running.Load() == 1 })

	never := &m72Gate{release: make(chan struct{})}
	// runSBOMScan's minimum deadline is whatever it is given; use a parent
	// context deadline to keep the test short.
	ctx, cancel := context.WithTimeoutCause(context.Background(), 100*time.Millisecond, service.ErrScanDeadlineExceeded)
	defer cancel()
	out := runSBOMScan(ctx, nil, tenant, uuid.New(), time.Minute, []scanStep{{source: "nvd", scanner: never}})
	if never.running.Load() != 0 || never.peak.Load() != 0 {
		t.Fatal("a scanner ran although no slot was free")
	}
	if !out.failed() || !slices.Equal(out.reasons, []string{service.ScanReasonDeadlineExceeded}) {
		t.Fatalf("outcome %v %v, want failed deadline_exceeded", out.markers, out.reasons)
	}
	if out.message() != "scan: scan failed (deadline_exceeded)" {
		t.Fatalf("marker %q", out.message())
	}
}

func TestM72TenantSlots_OffIsUnlimited(t *testing.T) {
	withConcurrency(t, 0)
	g := &m72Gate{release: make(chan struct{})}
	tenant := uuid.New()
	done := make(chan struct{}, 6)
	for i := 0; i < 6; i++ {
		go func() {
			runSBOMScan(context.Background(), nil, tenant, uuid.New(), time.Minute, []scanStep{{source: "nvd", scanner: g}})
			done <- struct{}{}
		}()
	}
	waitUntil(t, func() bool { return g.running.Load() == 6 })
	close(g.release)
	for i := 0; i < 6; i++ {
		<-done
	}
}

func TestM72TenantSlots_ReleaseIsIdempotentAndCancelledWaitIsCancelled(t *testing.T) {
	s := service.NewTenantScanSlots(1)
	tenant := uuid.New()
	rel, _, err := s.Acquire(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.Acquire(ctx, tenant); !errors.Is(err, service.ErrScanCancelled) {
		t.Fatalf("cancelled wait: %v, want ErrScanCancelled", err)
	}
	rel()
	rel()
	if n := s.InUse(tenant); n != 0 {
		t.Fatalf("in use after release: %d", n)
	}
	rel2, _, err := s.Acquire(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	rel2()
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// Codex M72 R1 High-4: the waiters of one tenant are bounded too; a scan
// beyond the queue fails at once (queue_full) instead of parking a goroutine
// for its whole deadline.
func TestM72R1_TenantQueueIsBounded(t *testing.T) {
	withConcurrency(t, 1)
	tenant := uuid.New()
	hold := &m72Gate{release: make(chan struct{})}
	go runSBOMScan(context.Background(), nil, tenant, uuid.New(), time.Minute, []scanStep{{source: "nvd", scanner: hold}})
	waitUntil(t, func() bool { return hold.running.Load() == 1 })
	q := service.TenantScanQueueLimit(1)
	waiters := make(chan scanOutcome, q)
	for i := 0; i < q; i++ {
		go func() {
			waiters <- runSBOMScan(context.Background(), nil, tenant, uuid.New(), time.Minute, []scanStep{{source: "nvd", scanner: hold}})
		}()
	}
	waitUntil(t, func() bool { return service.TenantScanWaiting(tenant) == q })
	start := time.Now()
	out := runSBOMScan(context.Background(), nil, tenant, uuid.New(), time.Minute, []scanStep{{source: "nvd", scanner: hold}})
	if time.Since(start) > time.Second || !slices.Equal(out.reasons, []string{service.ScanReasonQueueFull}) {
		t.Fatalf("scan beyond the queue: %v %v after %s, want queue_full at once", out.markers, out.reasons, time.Since(start))
	}
	close(hold.release)
	for i := 0; i < q; i++ {
		if o := <-waiters; o.failed() {
			t.Fatalf("queued scan failed: %v", o.markers)
		}
	}
}
