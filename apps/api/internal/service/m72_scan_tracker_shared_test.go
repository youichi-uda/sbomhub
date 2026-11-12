package service

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// memStore is an in-memory scanStatusStore that can be switched to failing.
// It models the shared store's group semantics only as far as these tests
// need: the last begin/finish/mark of an SBOM wins.
type memStore struct {
	mu      sync.Mutex
	down    bool
	state   map[uuid.UUID]ScanState
	msg     map[uuid.UUID]string
	reasons map[uuid.UUID][]string
	runs    map[uuid.UUID]map[uint64]bool
	beats   int
	calls   int
}

var errStoreDown = errors.New("store down")

func newMemStore() *memStore {
	return &memStore{state: map[uuid.UUID]ScanState{}, msg: map[uuid.UUID]string{},
		reasons: map[uuid.UUID][]string{}, runs: map[uuid.UUID]map[uint64]bool{}}
}

func (m *memStore) setDown(d bool) { m.mu.Lock(); m.down = d; m.mu.Unlock() }

func (m *memStore) begin(_ context.Context, id uuid.UUID, gen uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.down {
		return errStoreDown
	}
	if m.runs[id] == nil {
		m.runs[id] = map[uint64]bool{}
	}
	m.runs[id][gen] = true
	m.state[id], m.msg[id], m.reasons[id] = ScanStateRunning, "", nil
	return nil
}

func (m *memStore) finish(_ context.Context, id uuid.UUID, gen uint64, msg string, reasons []string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.down {
		return false, errStoreDown
	}
	if !m.runs[id][gen] {
		return false, nil
	}
	delete(m.runs[id], gen)
	if msg != "" {
		m.state[id], m.msg[id], m.reasons[id] = ScanStateFailed, msg, reasons
	} else {
		m.state[id], m.msg[id], m.reasons[id] = ScanStateCompleted, "", nil
	}
	return true, nil
}

func (m *memStore) heartbeat(_ context.Context, id uuid.UUID, gen uint64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.down {
		return false, errStoreDown
	}
	m.beats++
	return m.runs[id][gen], nil
}

func (m *memStore) heartbeatMany(ctx context.Context, runs []runKey) ([]bool, error) {
	out := make([]bool, len(runs))
	for i, r := range runs {
		ok, err := m.heartbeat(ctx, r.sbom, r.gen)
		if err != nil {
			return nil, err
		}
		out[i] = ok
	}
	return out, nil
}

func (m *memStore) mark(_ context.Context, id uuid.UUID, st ScanState, msg string, reasons []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.down {
		return errStoreDown
	}
	delete(m.runs, id)
	m.state[id], m.msg[id], m.reasons[id] = st, msg, reasons
	return nil
}

func (m *memStore) get(_ context.Context, id uuid.UUID) (ScanState, string, []string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.down {
		return ScanStateUnknown, "", nil, false, errStoreDown
	}
	st, ok := m.state[id]
	if !ok {
		return ScanStateUnknown, "", nil, false, nil
	}
	return st, m.msg[id], m.reasons[id], true, nil
}

func trackerOn(store scanStatusStore, hb time.Duration) *ScanTracker {
	t := NewScanTracker()
	t.shared = store
	t.hbInterval = hb
	return t
}

// settle waits until tr's writes of id reached the store (they are async).
func settle(t *testing.T, tr *ScanTracker, id uuid.UUID) {
	t.Helper()
	waitFor(t, "the shared writes to land", func() bool { return !tr.pendingShared(id) })
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Another process's tracker (same store) sees this process's scan.
func TestM72Tracker_SharedStateIsReadByAnotherProcess(t *testing.T) {
	store := newMemStore()
	a, b := trackerOn(store, time.Hour), trackerOn(store, time.Hour)
	id := uuid.New()
	if st, _, _ := b.GetDetail(id); st != ScanStateUnknown {
		t.Fatalf("before: %s", st)
	}
	gen := a.Begin(id)
	settle(t, a, id)
	if st, _, _ := b.GetDetail(id); st != ScanStateRunning {
		t.Fatalf("B during A's scan: %s, want running", st)
	}
	a.Finish(id, gen, []string{ScanReasonFetchFailed}, "nvd: scan failed (fetch_failed)")
	settle(t, a, id)
	st, msg, reasons := b.GetDetail(id)
	if st != ScanStateFailed || msg != "nvd: scan failed (fetch_failed)" || !slices.Equal(reasons, []string{ScanReasonFetchFailed}) {
		t.Fatalf("B after A failed: %s %q %v", st, msg, reasons)
	}
	// A "restarted" process (fresh tracker, empty memory) still reads it.
	if st, _, _ := trackerOn(store, time.Hour).GetDetail(id); st != ScanStateFailed {
		t.Fatalf("after restart: %s", st)
	}
}

// Redis down: the scan path is not blocked, the local state answers, and the
// heartbeat loop writes the begin and the outcome once Redis is back.
func TestM72Tracker_StoreDownFallsBackAndRetries(t *testing.T) {
	store := newMemStore()
	store.setDown(true)
	a := trackerOn(store, 10*time.Millisecond)
	id := uuid.New()
	gen := a.Begin(id)
	if st, _, _ := a.GetDetail(id); st != ScanStateRunning {
		t.Fatalf("local answer while down: %s", st)
	}
	if !a.Finish(id, gen, nil, "") {
		t.Fatal("Finish must record locally while the store is down")
	}
	if st, _, _ := a.GetDetail(id); st != ScanStateCompleted {
		t.Fatalf("local answer after finish while down: %s", st)
	}
	store.setDown(false)
	other := trackerOn(store, time.Hour)
	waitFor(t, "the retried writes to reach the store", func() bool {
		st, _, _ := other.GetDetail(id)
		return st == ScanStateCompleted
	})
	waitFor(t, "the heartbeat loop to stop", func() bool {
		a.qMu.Lock()
		defer a.qMu.Unlock()
		return !a.hbActive
	})
}

// A run active in this process reads running here even if the shared store
// has a stale terminal state (its begin write failed).
func TestM72Tracker_LocalActiveRunWinsOverStaleSharedState(t *testing.T) {
	store := newMemStore()
	a := trackerOn(store, time.Hour)
	id := uuid.New()
	g1 := a.Begin(id)
	a.Finish(id, g1, nil, "")
	store.setDown(true)
	a.Begin(id)
	store.setDown(false)
	if st, _, _ := a.GetDetail(id); st != ScanStateRunning {
		t.Fatalf("this process's active run must read running, got %s", st)
	}
}

// The heartbeat loop renews the lease of an active run and stops once the run
// finished.
func TestM72Tracker_HeartbeatRenewsActiveRuns(t *testing.T) {
	store := newMemStore()
	a := trackerOn(store, 5*time.Millisecond)
	id := uuid.New()
	gen := a.Begin(id)
	waitFor(t, "heartbeats", func() bool { store.mu.Lock(); defer store.mu.Unlock(); return store.beats >= 3 })
	a.Finish(id, gen, nil, "")
	waitFor(t, "the loop to stop", func() bool { a.qMu.Lock(); defer a.qMu.Unlock(); return !a.hbActive })
	store.mu.Lock()
	n := store.beats
	store.mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.beats != n {
		t.Fatalf("heartbeats continued after the run finished: %d -> %d", n, store.beats)
	}
}

// Without a store the tracker is the pre-M72 in-memory one.
func TestM72Tracker_NoStoreIsInMemory(t *testing.T) {
	a := NewScanTracker()
	id := uuid.New()
	gen := a.Begin(id)
	a.Finish(id, gen, []string{ScanReasonTruncated}, "")
	st, msg, r := a.GetDetail(id)
	if st != ScanStateFailed || msg != "scan failed" || !slices.Equal(r, []string{ScanReasonTruncated}) {
		t.Fatalf("%s %q %v", st, msg, r)
	}
	a.qMu.Lock()
	defer a.qMu.Unlock()
	if a.hbActive {
		t.Fatal("no heartbeat loop without a store")
	}
}

func TestM72Tracker_RunGenerationsAreRandomAndNonZero(t *testing.T) {
	seen := map[uint64]bool{}
	for i := 0; i < 1000; i++ {
		g := newRunGen()
		if g == 0 || seen[g] {
			t.Fatalf("generation %d repeated or zero", g)
		}
		seen[g] = true
	}
}

// slowStore delays every call, to model a black-holed Redis under its bound.
type slowStore struct {
	*memStore
	delay time.Duration
}

func (s slowStore) begin(ctx context.Context, id uuid.UUID, gen uint64) error {
	time.Sleep(s.delay)
	return s.memStore.begin(ctx, id, gen)
}

func (s slowStore) heartbeat(ctx context.Context, id uuid.UUID, gen uint64) (bool, error) {
	time.Sleep(s.delay)
	return s.memStore.heartbeat(ctx, id, gen)
}

// Codex M72 R1 High-1: GetDetail raced Begin/Finish on the entry's map.
func TestM72R1_GetDetailDoesNotRaceBeginFinish(t *testing.T) {
	a := trackerOn(newMemStore(), time.Hour)
	id := uuid.New()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				a.GetDetail(id)
			}
		}
	}()
	for i := 0; i < 300; i++ {
		g1 := a.Begin(id)
		g2 := a.Begin(id)
		a.Finish(id, g1, nil, "")
		a.Finish(id, g2, nil, "")
	}
	close(stop)
	wg.Wait()
}

// Codex M72 R1 High-2: process A finished (its Redis finish pending) while
// process B's run of the same SBOM is still running. A must not answer its
// local "completed".
func TestM72R1_PendingFinishNeverReadsCompletedWhileAnotherRunIsActive(t *testing.T) {
	store := newMemStore()
	a, b := trackerOn(store, time.Hour), trackerOn(store, time.Hour)
	id := uuid.New()
	ga := a.Begin(id)
	b.Begin(id)
	waitFor(t, "both begins in the store", func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		return len(store.runs[id]) == 2
	})
	store.setDown(true)
	a.Finish(id, ga, nil, "") // its shared finish fails
	store.setDown(false)
	if st, _, _ := a.GetDetail(id); st != ScanStateRunning {
		t.Fatalf("A answered %s while B's run is active", st)
	}
}

// Codex M72 R1 Medium-5: Begin and Finish must not wait on the shared store
// (they run on the request path / at the end of the scan).
func TestM72R1_BeginAndFinishDoNotWaitOnTheStore(t *testing.T) {
	store := slowStore{memStore: newMemStore(), delay: 300 * time.Millisecond}
	a := trackerOn(store, time.Hour)
	id := uuid.New()
	start := time.Now()
	gen := a.Begin(id)
	if d := time.Since(start); d > beginWait+100*time.Millisecond {
		t.Fatalf("Begin took %s with a 300ms store, want <= %s", d, beginWait)
	}
	start = time.Now()
	a.Finish(id, gen, nil, "")
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("Finish took %s with a 300ms store", d)
	}
	other := trackerOn(store.memStore, time.Hour)
	waitFor(t, "the writes to land", func() bool {
		st, _, _ := other.GetDetail(id)
		return st == ScanStateCompleted
	})
}

// Codex M72 R1 Medium-6: one pass of lease renewals must not take the sum of
// every run's round trip.
func TestM72R1_HeartbeatRenewsRunsConcurrently(t *testing.T) {
	store := slowStore{memStore: newMemStore(), delay: 50 * time.Millisecond}
	a := trackerOn(store, time.Hour)
	const runs = 40
	for i := 0; i < runs; i++ {
		a.Begin(uuid.New())
	}
	waitFor(t, "begins", func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		return len(store.runs) == runs
	})
	start := time.Now()
	a.heartbeatPass()
	if d := time.Since(start); d > runs*50*time.Millisecond/4 {
		t.Fatalf("a renewal pass of %d runs took %s (serial would be %s)", runs, d, runs*50*time.Millisecond)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.beats != runs {
		t.Fatalf("renewed %d of %d", store.beats, runs)
	}
}

// Overlapping runs on two processes stay one group when the second begins
// right before the first finishes: Begin's write lands before it returns
// (Redis healthy), so the first run's failure is not dropped.
func TestM72R1_ImmediateOverlapStaysOneGroup(t *testing.T) {
	store := newGroupStore()
	a, b := trackerOn(store, time.Hour), trackerOn(store, time.Hour)
	id := uuid.New()
	ga := a.Begin(id)
	gb := b.Begin(id)
	a.Finish(id, ga, []string{ScanReasonFetchFailed}, "nvd: scan failed (fetch_failed)")
	b.Finish(id, gb, nil, "")
	settle(t, a, id)
	settle(t, b, id)
	if st, _, _ := trackerOn(store, time.Hour).GetDetail(id); st != ScanStateFailed {
		t.Fatalf("group outcome %s, want failed", st)
	}
}

// groupStore is memStore with the shared store's group rule: failed if any
// run of the group failed, terminal only when none is active.
type groupStore struct {
	*memStore
	failed map[uuid.UUID]bool
}

func newGroupStore() *groupStore {
	return &groupStore{memStore: newMemStore(), failed: map[uuid.UUID]bool{}}
}

func (g *groupStore) begin(ctx context.Context, id uuid.UUID, gen uint64) error {
	g.mu.Lock()
	if len(g.runs[id]) == 0 {
		g.failed[id] = false
	}
	g.mu.Unlock()
	return g.memStore.begin(ctx, id, gen)
}

func (g *groupStore) finish(_ context.Context, id uuid.UUID, gen uint64, msg string, _ []string) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.runs[id][gen] {
		return false, nil
	}
	delete(g.runs[id], gen)
	if msg != "" {
		g.failed[id] = true
	}
	switch {
	case len(g.runs[id]) > 0:
		g.state[id] = ScanStateRunning
	case g.failed[id]:
		g.state[id] = ScanStateFailed
	default:
		g.state[id] = ScanStateCompleted
	}
	return true, nil
}

// delayBeginStore delays the begin of one generation.
type delayBeginStore struct {
	*groupStore
	slowGen atomic.Uint64
	delay   time.Duration
}

func (d *delayBeginStore) begin(ctx context.Context, id uuid.UUID, gen uint64) error {
	if gen == d.slowGen.Load() {
		time.Sleep(d.delay)
	}
	return d.groupStore.begin(ctx, id, gen)
}

// Codex M72 R2 High-1: one process's writes of one SBOM reach the store in
// call order. B began before A finished, so A's failure belongs to B's group
// even when B's begin write is slow.
func TestM72R2_WritesOfOneSBOMKeepCallOrder(t *testing.T) {
	store := &delayBeginStore{groupStore: newGroupStore(), delay: 2 * beginWait}
	a := trackerOn(store, time.Hour)
	id := uuid.New()
	ga := a.Begin(id)
	// B's generation is random; make every begin after A's slow.
	store.slowGen.Store(0)
	orig := newRunGenFn
	newRunGenFn = func() uint64 { g := orig(); store.slowGen.Store(g); return g }
	gb := a.Begin(id)
	newRunGenFn = orig
	a.Finish(id, ga, []string{ScanReasonFetchFailed}, "nvd: scan failed (fetch_failed)")
	a.Finish(id, gb, nil, "")
	settle(t, a, id)
	if st, _, _ := trackerOn(store, time.Hour).GetDetail(id); st != ScanStateFailed {
		t.Fatalf("group outcome %s, want failed", st)
	}
}

// Codex M72 R2 Medium-4: a renewal pass costs one store round trip per batch,
// not one per run.
func TestM72R2_HeartbeatRenewsInBatches(t *testing.T) {
	store := &countingStore{memStore: newMemStore()}
	a := trackerOn(store, time.Hour)
	for i := 0; i < 300; i++ {
		a.Begin(uuid.New())
	}
	store.mu.Lock()
	store.batches = 0
	store.mu.Unlock()
	a.heartbeatPass()
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.beats != 300 || store.batches > 2 {
		t.Fatalf("renewed %d runs in %d round trips, want 300 in <= 2", store.beats, store.batches)
	}
}

type countingStore struct {
	*memStore
	batches int
}

func (c *countingStore) heartbeatMany(ctx context.Context, runs []runKey) ([]bool, error) {
	c.mu.Lock()
	c.batches++
	c.mu.Unlock()
	return c.memStore.heartbeatMany(ctx, runs)
}
