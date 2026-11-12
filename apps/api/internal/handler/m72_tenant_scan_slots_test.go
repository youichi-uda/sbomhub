package handler

import (
	"context"
	"errors"
	"slices"
	"sync"
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

// Codex M72 R2 High-2: the queue cap must hold under a simultaneous burst
// (the free-slot check and the reservation were not atomic).
func TestM72R2_QueueCapHoldsUnderABurst(t *testing.T) {
	s := service.NewTenantScanSlots(1)
	tenant := uuid.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const n = 300
	start := make(chan struct{})
	var full, waiting atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := s.Acquire(ctx, tenant)
			switch {
			case errors.Is(err, service.ErrScanQueueFull):
				full.Add(1)
			case err == nil:
				// holds a slot until cancel
			default:
				waiting.Add(1) // was waiting, cancelled at the end
			}
		}()
	}
	close(start)
	waitUntil(t, func() bool { return int(full.Load())+s.Waiting(tenant)+s.InUse(tenant) == n })
	if w := s.Waiting(tenant); w > service.TenantScanQueueLimit(1) {
		t.Fatalf("%d waiters, cap %d", w, service.TenantScanQueueLimit(1))
	}
	if got, want := int(full.Load()), n-1-service.TenantScanQueueLimit(1); got != want {
		t.Fatalf("queue_full for %d scans, want %d", got, want)
	}
	cancel()
	wg.Wait()
}

// Slots are handed over FIFO and a cancelled waiter never leaks a slot.
func TestM72R2_SlotHandOverAndCancelledWaiter(t *testing.T) {
	s := service.NewTenantScanSlots(1)
	tenant := uuid.New()
	rel, _, _ := s.Acquire(context.Background(), tenant)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, _, err := s.Acquire(ctx, tenant); errc <- err }()
	waitUntil(t, func() bool { return s.Waiting(tenant) == 1 })
	got := make(chan func(), 1)
	go func() { r, _, _ := s.Acquire(context.Background(), tenant); got <- r }()
	waitUntil(t, func() bool { return s.Waiting(tenant) == 2 })
	cancel()
	if err := <-errc; !errors.Is(err, service.ErrScanCancelled) {
		t.Fatalf("cancelled waiter: %v", err)
	}
	rel()
	r2 := <-got
	if s.InUse(tenant) != 1 || s.Waiting(tenant) != 0 {
		t.Fatalf("in use %d waiting %d", s.InUse(tenant), s.Waiting(tenant))
	}
	r2()
	if s.InUse(tenant) != 0 {
		t.Fatalf("slot leaked: in use %d", s.InUse(tenant))
	}
}

// Codex M72 R3 Low-3: a scan whose context already ended gets its
// interruption, not a slot and not queue_full.
func TestM72R3_EndedContextIsReportedAsSuch(t *testing.T) {
	s := service.NewTenantScanSlots(1)
	tenant := uuid.New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.Acquire(ctx, tenant); !errors.Is(err, service.ErrScanCancelled) {
		t.Fatalf("free slot, ended context: %v, want cancelled", err)
	}
	if s.InUse(tenant) != 0 {
		t.Fatal("an ended scan took a slot")
	}
	rel, _, _ := s.Acquire(context.Background(), tenant)
	defer rel()
	live, stop := context.WithCancel(context.Background())
	defer stop()
	for i := 0; i < service.TenantScanQueueLimit(1); i++ {
		go func() { _, _, _ = s.Acquire(live, tenant) }()
	}
	waitUntil(t, func() bool { return s.Waiting(tenant) == service.TenantScanQueueLimit(1) })
	if _, _, err := s.Acquire(ctx, tenant); !errors.Is(err, service.ErrScanCancelled) {
		t.Fatalf("full queue, ended context: %v, want cancelled", err)
	}
}

// Codex M72 R6 Low-4: a waiter whose context ended before the slot was
// handed to it reports the interruption and passes the slot on.
func TestM72R6_HandOffToAnEndedWaiterIsRefused(t *testing.T) {
	for i := 0; i < 300; i++ {
		s := service.NewTenantScanSlots(1)
		tenant := uuid.New()
		rel, _, _ := s.Acquire(context.Background(), tenant)
		ctx, cancel := context.WithCancel(context.Background())
		res := make(chan error, 1)
		go func() { _, _, err := s.Acquire(ctx, tenant); res <- err }()
		waitUntil(t, func() bool { return s.Waiting(tenant) == 1 })
		cancel()
		rel()
		if err := <-res; err == nil {
			t.Fatalf("iteration %d: a waiter whose context had ended got the slot", i)
		}
		if s.InUse(tenant) != 0 {
			t.Fatalf("iteration %d: slot leaked (in use %d)", i, s.InUse(tenant))
		}
	}
}
