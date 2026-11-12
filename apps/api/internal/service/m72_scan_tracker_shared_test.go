package service

import (
	"context"
	"errors"
	"slices"
	"sync"
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
	if st, _, _ := b.GetDetail(id); st != ScanStateRunning {
		t.Fatalf("B during A's scan: %s, want running", st)
	}
	a.Finish(id, gen, []string{ScanReasonFetchFailed}, "nvd: scan failed (fetch_failed)")
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
		a.hbMu.Lock()
		defer a.hbMu.Unlock()
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
	waitFor(t, "the loop to stop", func() bool { a.hbMu.Lock(); defer a.hbMu.Unlock(); return !a.hbActive })
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
	a.hbMu.Lock()
	defer a.hbMu.Unlock()
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
