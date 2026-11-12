package service

import (
	"context"
	"errors"
	"fmt"
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
	version map[uuid.UUID]int
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
	return &memStore{version: map[uuid.UUID]int{}, state: map[uuid.UUID]ScanState{}, msg: map[uuid.UUID]string{},
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
	m.version[id]++
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
		m.version[id]++
	} else {
		m.state[id], m.msg[id], m.reasons[id] = ScanStateCompleted, "", nil
		m.version[id]++
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

func (m *memStore) rejoin(ctx context.Context, id uuid.UUID, gen uint64) error {
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
	m.state[id] = ScanStateRunning
	m.version[id]++
	return nil
}

func (m *memStore) merge(ctx context.Context, id uuid.UUID, ms *mergeSet) error {
	for g := range ms.begins {
		if err := m.rejoin(ctx, id, g); err != nil {
			return err
		}
	}
	for g := range ms.finishes {
		if _, err := m.finish(ctx, id, g, "", nil); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range ms.failures {
		m.state[id], m.msg[id], m.reasons[id] = ScanStateFailed, f.msg, f.reasons
		m.version[id]++
	}
	return nil
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
	m.version[id]++
	return nil
}

func (m *memStore) get(_ context.Context, id uuid.UUID) (statusView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.down {
		return statusView{}, errStoreDown
	}
	st, ok := m.state[id]
	if !ok {
		return statusView{}, nil
	}
	return statusView{state: st, errMsg: m.msg[id], reasons: m.reasons[id], found: true,
		version: fmt.Sprintf("m%d", m.version[id])}, nil
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
	// A local "completed" is not trusted while Redis is unreadable (another
	// replica may be scanning; Codex M72 R4 High-2): unknown.
	if st, _, _ := a.GetDetail(id); st != ScanStateUnknown {
		t.Fatalf("local answer after finish while down: %s, want unknown", st)
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

// heartbeatMany costs one delay per call (one round trip), like the
// pipelined Redis renewal.
func (s slowStore) heartbeatMany(ctx context.Context, runs []runKey) ([]bool, error) {
	time.Sleep(s.delay)
	return s.memStore.heartbeatMany(ctx, runs)
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
	store := newGroupStore()
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
	waitFor(t, "the finish to fail", func() bool {
		a.qMu.Lock()
		defer a.qMu.Unlock()
		q := a.queues[id]
		return q != nil && !q.draining
	})
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
	if g.down {
		return false, errStoreDown
	}
	known := g.runs[id][gen]
	delete(g.runs[id], gen)
	// Like the Redis store: a failure counts even for a run it did not know.
	if msg != "" {
		g.failed[id] = true
	}
	g.publishLocked(id)
	return known, nil
}

func (g *groupStore) rejoin(ctx context.Context, id uuid.UUID, gen uint64) error {
	return g.memStore.rejoin(ctx, id, gen)
}

func (g *groupStore) merge(ctx context.Context, id uuid.UUID, ms *mergeSet) error {
	if err := func() error {
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.down {
			return errStoreDown
		}
		if g.runs[id] == nil {
			g.runs[id] = map[uint64]bool{}
		}
		for b := range ms.begins {
			g.runs[id][b] = true
		}
		for f := range ms.finishes {
			delete(g.runs[id], f)
		}
		if len(ms.failures) > 0 {
			g.failed[id] = true
		}
		g.publishLocked(id)
		return nil
	}(); err != nil {
		return err
	}
	return nil
}

func (g *groupStore) publishLocked(id uuid.UUID) {
	g.version[id]++
	switch {
	case len(g.runs[id]) > 0:
		g.state[id] = ScanStateRunning
	case g.failed[id]:
		g.state[id] = ScanStateFailed
	default:
		g.state[id] = ScanStateCompleted
	}
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

// Codex M72 R3 High-1: the shared write of a Begin is queued atomically with
// its local state change. Run B has begun locally; run A's Finish arriving
// right then must not reach Redis ahead of B's begin.
func TestM72R3_BeginIsQueuedWithItsLocalStateChange(t *testing.T) {
	store := newGroupStore()
	a := trackerOn(store, time.Hour)
	id := uuid.New()
	ga := a.Begin(id)
	settle(t, a, id)
	var gb uint64
	testHookAfterLocalBegin = func(gen uint64) {
		if gen == ga {
			return
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			a.Finish(id, ga, []string{ScanReasonFetchFailed}, "nvd: scan failed (fetch_failed)")
		}()
		select {
		case <-done:
		case <-time.After(200 * time.Millisecond):
		}
	}
	defer func() { testHookAfterLocalBegin = nil }()
	gb = a.Begin(id)
	testHookAfterLocalBegin = nil
	settle(t, a, id)
	a.Finish(id, gb, nil, "")
	settle(t, a, id)
	if st, _, _ := trackerOn(store, time.Hour).GetDetail(id); st != ScanStateFailed {
		t.Fatalf("group outcome %s, want failed (A failed while B was running)", st)
	}
}

// hookGetStore runs onGet inside get, after the shared state was read and
// before it is returned — a transition racing the read.
type hookGetStore struct {
	*memStore
	onGet func()
}

func (h *hookGetStore) get(ctx context.Context, id uuid.UUID) (statusView, error) {
	v, err := h.memStore.get(ctx, id)
	if f := h.onGet; f != nil {
		h.onGet = nil
		f()
	}
	return v, err
}

// Codex M72 R4 High-1: a Begin that completes (write included) while
// GetDetail reads Redis must not let the read return the older terminal state.
func TestM72R4_ReadRacingABeginIsNotStale(t *testing.T) {
	store := &hookGetStore{memStore: newMemStore()}
	a := trackerOn(store, time.Hour)
	id := uuid.New()
	a.Finish(id, a.Begin(id), nil, "")
	settle(t, a, id)
	store.onGet = func() {
		a.Begin(id)
		settle(t, a, id)
	}
	if st, _, _ := a.GetDetail(id); st != ScanStateRunning {
		t.Fatalf("read racing a Begin: %s, want running", st)
	}
}

// Codex M72 R4 High-2: with the shared store configured but unreadable, a
// local "completed" may be stale (another replica may be scanning): it reads
// unknown. Local running and failed are safe and stay.
func TestM72R4_UnreadableStoreNeverYieldsALocalCompleted(t *testing.T) {
	store := newMemStore()
	a := trackerOn(store, time.Hour)
	done, failed, running := uuid.New(), uuid.New(), uuid.New()
	a.Finish(done, a.Begin(done), nil, "")
	a.Finish(failed, a.Begin(failed), []string{ScanReasonFetchFailed}, "nvd: scan failed (fetch_failed)")
	a.Begin(running)
	settle(t, a, done)
	settle(t, a, failed)
	settle(t, a, running)
	store.setDown(true)
	if st, _, _ := a.GetDetail(done); st != ScanStateUnknown {
		t.Errorf("completed, store unreadable: %s, want unknown", st)
	}
	if st, _, _ := a.GetDetail(failed); st != ScanStateFailed {
		t.Errorf("failed, store unreadable: %s, want failed", st)
	}
	if st, _, _ := a.GetDetail(running); st != ScanStateRunning {
		t.Errorf("running, store unreadable: %s, want running", st)
	}
}

// Codex M72 R5 High-1: GetDetail snapshots "active here" and the revision in
// one step. A Begin landing between the two (and its write draining before
// the pending check) must not let a stale "completed" through.
func TestM72R5_SnapshotIsAtomic(t *testing.T) {
	store := newMemStore()
	a := trackerOn(store, time.Hour)
	id := uuid.New()
	a.Finish(id, a.Begin(id), nil, "")
	settle(t, a, id)
	testHookAfterLocalActiveCheck = func() {
		testHookAfterLocalActiveCheck = nil
		a.Begin(id)
		settle(t, a, id)
	}
	defer func() { testHookAfterLocalActiveCheck = nil }()
	// Redis answers as it was before the Begin (the read was in flight).
	a.shared = staleGetStore{memStore: store, state: ScanStateCompleted}
	if st, _, _ := a.GetDetail(id); st != ScanStateRunning {
		t.Fatalf("Begin between the active check and the revision: %s, want running", st)
	}
}

// staleGetStore answers every get with a fixed state.
type staleGetStore struct {
	*memStore
	state ScanState
}

func (s staleGetStore) get(context.Context, uuid.UUID) (statusView, error) {
	return statusView{state: s.state, found: true, version: "stale"}, nil
}

// Codex M72 R5 High-3: queue overflow must not lose a failure. With the
// queue full, a failed run's outcome is still applied once Redis catches up.
func TestM72R5_OverflowKeepsFailures(t *testing.T) {
	store := newGroupStore()
	store.setDown(true)
	a := trackerOn(store, 5*time.Millisecond)
	a.queueCap = 8
	id := uuid.New()
	long := a.Begin(id)
	for i := 0; i < a.queueCap; i++ { // fill the queue with harmless runs
		a.Finish(id, a.Begin(id), nil, "")
	}
	failing := a.Begin(id)
	a.Finish(id, failing, []string{ScanReasonFetchFailed}, "nvd: scan failed (fetch_failed)")
	a.Finish(id, long, nil, "")
	store.setDown(false)
	settle(t, a, id)
	if st, _, _ := trackerOn(store, time.Hour).GetDetail(id); st != ScanStateFailed {
		t.Fatalf("after overflow: %s, want failed", st)
	}
}

// maxMergeRunsForTest exceeds the pre-R6 per-merge run cap.
const maxMergeRunsForTest = 4100

// Codex M72 R6 High-1: a merge keeps every run still live, however many runs
// were folded into it; Redis must show the long scan running afterwards.
func TestM72R6_MergeKeepsEveryLiveRun(t *testing.T) {
	store := newGroupStore()
	store.setDown(true)
	a := trackerOn(store, time.Hour)
	a.queueCap = 2
	a.beginWait = time.Millisecond
	id := uuid.New()
	a.Finish(id, a.Begin(id), nil, "")         // fills the queue (begin, finish)
	for i := 0; i < maxMergeRunsForTest; i++ { // runs that start and end while backlogged
		a.Finish(id, a.Begin(id), nil, "")
	}
	a.Begin(id) // the long scan, still running
	store.setDown(false)
	a.kickQueues()
	settle(t, a, id)
	if st, _, _ := trackerOn(store, time.Hour).GetDetail(id); st != ScanStateRunning {
		t.Fatalf("after the backlog: %s, want running (the long scan is live)", st)
	}
}

// Codex M72 R6 High-2/3: a queued write is not discarded for its own age
// while its SBOM's queue is still being written to (a failure would be lost,
// and pruning the in-flight head could panic). Only a whole queue whose LAST
// write is older than retention is reclaimed (R7).
func TestM72R6_OldQueuedWritesAreKept(t *testing.T) {
	store := newGroupStore()
	store.setDown(true)
	a := trackerOn(store, time.Hour)
	a.retention = 60 * time.Millisecond
	a.beginWait = time.Millisecond
	id := uuid.New()
	long := a.Begin(id)
	a.Finish(id, a.Begin(id), []string{ScanReasonFetchFailed}, "nvd: scan failed (fetch_failed)")
	time.Sleep(45 * time.Millisecond)
	a.Finish(id, long, nil, "")       // a newer write of the same SBOM (same group)
	time.Sleep(30 * time.Millisecond) // the failure is now older than retention
	a.heartbeatPass()
	store.setDown(false)
	a.kickQueues()
	settle(t, a, id)
	if st, _, _ := trackerOn(store, time.Hour).GetDetail(id); st != ScanStateFailed {
		t.Fatalf("an old queued failure: %s, want failed", st)
	}
}

// Codex M72 R7 High-1: during a long outage, queues whose last write is older
// than retention (their status would have expired anyway) are reclaimed, and
// one heartbeat retries a bounded number of stalled queues.
func TestM72R7_StalledQueuesAreBoundedAndReclaimed(t *testing.T) {
	store := newMemStore()
	store.setDown(true)
	a := trackerOn(store, time.Hour)
	a.beginWait = time.Millisecond
	const n = 100
	for i := 0; i < n; i++ {
		id := uuid.New()
		a.Finish(id, a.Begin(id), nil, "")
	}
	waitFor(t, "the first drains to fail", func() bool {
		a.qMu.Lock()
		defer a.qMu.Unlock()
		for _, q := range a.queues {
			if q.draining {
				return false
			}
		}
		return true
	})
	store.mu.Lock()
	store.calls = 0
	store.mu.Unlock()
	a.heartbeatPass()
	waitFor(t, "the retries to fail", func() bool {
		a.qMu.Lock()
		defer a.qMu.Unlock()
		for _, q := range a.queues {
			if q.draining {
				return false
			}
		}
		return true
	})
	store.mu.Lock()
	calls := store.calls
	store.mu.Unlock()
	if calls > n {
		t.Fatalf("one heartbeat made %d attempts for %d stalled queues, want <= one each", calls, n)
	}

	a.retention = time.Millisecond
	time.Sleep(5 * time.Millisecond)
	a.heartbeatPass()
	a.qMu.Lock()
	left := len(a.queues)
	a.qMu.Unlock()
	if left != 0 {
		t.Fatalf("%d queues older than retention kept", left)
	}
}

// finishFailStore fails every finish (Redis "flaky" for one kind of write).
type finishFailStore struct{ *countingStore }

func (f finishFailStore) finish(context.Context, uuid.UUID, uint64, string, []string) (bool, error) {
	return false, errStoreDown
}

// Codex M72 R8 High-1a: a run Redis already acknowledged keeps its lease
// renewed even while other writes of its SBOM are queued.
func TestM72R8_AcknowledgedRunsAreRenewedWhileWritesQueue(t *testing.T) {
	cs := &countingStore{memStore: newMemStore()}
	store := finishFailStore{cs}
	a := trackerOn(store, time.Hour)
	id := uuid.New()
	a.Begin(id) // acknowledged
	settle(t, a, id)
	a.Finish(id, a.Begin(id), nil, "") // its finish keeps failing: queued
	waitFor(t, "the finish to stall", func() bool {
		a.qMu.Lock()
		defer a.qMu.Unlock()
		q := a.queues[id]
		return q != nil && len(q.events) > 0 && !q.draining
	})
	cs.mu.Lock()
	cs.beats = 0
	cs.mu.Unlock()
	a.heartbeatPass()
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.beats == 0 {
		t.Fatal("the acknowledged run's lease was not renewed while a write of its SBOM was queued")
	}
}

// Codex M72 R8 High-1b: once Redis is back, one heartbeat gets every stalled
// queue drained (by a bounded pool), not 32 per 30s.
func TestM72R8_RecoveredQueuesAllDrainAfterOnePass(t *testing.T) {
	store := newMemStore()
	store.setDown(true)
	a := trackerOn(store, time.Hour)
	a.beginWait = time.Millisecond
	ids := make([]uuid.UUID, 100)
	for i := range ids {
		ids[i] = uuid.New()
		a.Finish(ids[i], a.Begin(ids[i]), nil, "")
	}
	waitFor(t, "the first drains to fail", func() bool {
		a.qMu.Lock()
		defer a.qMu.Unlock()
		for _, q := range a.queues {
			if q.draining {
				return false
			}
		}
		return true
	})
	store.setDown(false)
	a.heartbeatPass()
	for _, id := range ids {
		settle(t, a, id)
	}
}

// gaugeStore tracks how many store calls run at once.
type gaugeStore struct {
	*memStore
	cur, peak atomic.Int32
	delay     time.Duration
}

func (g *gaugeStore) begin(ctx context.Context, id uuid.UUID, gen uint64) error {
	n := g.cur.Add(1)
	for {
		p := g.peak.Load()
		if n <= p || g.peak.CompareAndSwap(p, n) {
			break
		}
	}
	time.Sleep(g.delay)
	g.cur.Add(-1)
	return g.memStore.begin(ctx, id, gen)
}

// Codex M72 R12 Medium-4: the first drains of many SBOMs share the bounded
// worker pool too, so a burst cannot start one Redis call per SBOM at once.
func TestM72R12_InitialDrainsAreBounded(t *testing.T) {
	store := &gaugeStore{memStore: newMemStore(), delay: 50 * time.Millisecond}
	a := trackerOn(store, time.Hour)
	a.beginWait = time.Millisecond
	ids := make([]uuid.UUID, 200)
	for i := range ids {
		ids[i] = uuid.New()
		a.Begin(ids[i])
	}
	for _, id := range ids {
		settle(t, a, id)
	}
	if p := store.peak.Load(); p > maxDrainWorkers+priorityWorkers {
		t.Fatalf("%d store calls at once, want <= %d", p, maxDrainWorkers+priorityWorkers)
	}
}

// Codex M72 R13 High-1: GetDetailVersion's version changes on every
// transition, so a reader can tell a terminal state it read before a query
// from the same-looking state read after it.
func TestM72R13_VersionChangesWithEveryTransition(t *testing.T) {
	for _, shared := range []bool{false, true} {
		var a *ScanTracker
		if shared {
			a = trackerOn(newMemStore(), time.Hour)
		} else {
			a = NewScanTracker()
		}
		id := uuid.New()
		a.Finish(id, a.Begin(id), nil, "")
		settle(t, a, id)
		st1, _, _, v1 := a.GetDetailVersion(id)
		a.Finish(id, a.Begin(id), nil, "") // a whole new scan in between
		settle(t, a, id)
		st2, _, _, v2 := a.GetDetailVersion(id)
		if st1 != ScanStateCompleted || st2 != ScanStateCompleted || v1 == v2 {
			t.Fatalf("shared=%v: %s/%q then %s/%q: the version must differ", shared, st1, v1, st2, v2)
		}
	}
}

// slowApplyStore takes d per begin/finish.
type slowApplyStore struct {
	*memStore
	d time.Duration
}

func (s slowApplyStore) begin(ctx context.Context, id uuid.UUID, gen uint64) error {
	time.Sleep(s.d)
	return s.memStore.begin(ctx, id, gen)
}

func (s slowApplyStore) finish(ctx context.Context, id uuid.UUID, gen uint64, msg string, r []string) (bool, error) {
	time.Sleep(s.d)
	return s.memStore.finish(ctx, id, gen, msg, r)
}

// Codex M72 R13 High-2: a fresh Begin is not starved by backlog drains; it
// reaches a healthy Redis within beginWait.
func TestM72R13_FreshBeginIsNotStarvedByBacklog(t *testing.T) {
	mem := newMemStore()
	store := slowApplyStore{memStore: mem, d: 2 * time.Millisecond}
	a := trackerOn(store, time.Hour)
	a.beginWait = time.Millisecond
	mem.setDown(true)
	for i := 0; i < maxDrainWorkers+8; i++ { // deep backlogs on many SBOMs
		id := uuid.New()
		for j := 0; j < 100; j++ {
			a.Finish(id, a.Begin(id), nil, "")
		}
	}
	mem.setDown(false)
	a.kickQueues()
	time.Sleep(20 * time.Millisecond) // the workers are busy with the backlog
	a.beginWait = beginWait
	fresh := uuid.New()
	start := time.Now()
	a.Begin(fresh)
	if d := time.Since(start); d >= beginWait {
		t.Fatalf("a fresh Begin waited %s behind the backlog (bound %s)", d, beginWait)
	}
	mem.mu.Lock()
	defer mem.mu.Unlock()
	if !mem.runs[fresh][0] && len(mem.runs[fresh]) == 0 {
		t.Fatal("the fresh begin did not reach the store")
	}
}

// Codex M72 R14 High-2: the priority lane is FIFO (it was a stack: a stream
// of newer arrivals pushed an older Begin back past its wait).
func TestM72R14_PriorityLaneIsFIFO(t *testing.T) {
	a := NewScanTracker()
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	a.qMu.Lock()
	a.workers = maxDrainWorkers + priorityWorkers // no worker starts
	for _, id := range ids {
		q := &sbomQueue{}
		a.queues[id] = q
		a.startDrainLocked(id, q, true)
	}
	var got []uuid.UUID
	for {
		id, ok := a.nextReadyLocked()
		if !ok {
			break
		}
		got = append(got, id)
	}
	a.qMu.Unlock()
	if !slices.Equal(got, ids) {
		t.Fatalf("priority order %v, want %v (arrival order)", got, ids)
	}
}

// Codex M72 R14 Medium-4: a run that begins (or rejoins) and finishes inside
// one merge still removes its lease: an earlier queued rejoin may have
// activated it.
func TestM72R14_MergeFinishAlwaysRemovesTheRun(t *testing.T) {
	m := newMergeSet()
	m.begin(7)
	m.finish(7)
	if !m.finishes[7] || m.begins[7] {
		t.Fatalf("begins %v finishes %v: the finish must still remove run 7", m.begins, m.finishes)
	}
}
