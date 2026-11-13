package service

// SBOMHUB_JVN=off (2026-11): the operator opt-out chosen while MyJVN is
// suspended (JPCERT/CC notice of 2026-10-22, no resumption date).
//
// What these pin, below the handler:
//   - a disabled JVNService sends nothing, and refuses to be mistaken for a
//     clean sweep by a caller that bypasses runSBOMScan's skip;
//   - the tracker carries a run's skipped sources to the SBOM's terminal
//     state with the SAME group semantics as its failures: the union over the
//     overlapping runs of a group, reset when a new group starts, never shown
//     while the group is still running, and cleared by a legacy Mark*.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestJVNSwitch_DisabledServiceSendsNothing(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewJVNService(nil, nil, srv.URL, false).WithDisabled(true)
	if !svc.ScanDisabled() {
		t.Fatal("ScanDisabled() = false for a service built WithDisabled(true)")
	}
	ctx := WithScanScope(context.Background(), nil, uuid.New())
	_, err := svc.ScanComponentsReport(ctx, uuid.New())
	if !errors.Is(err, ErrScanSourceDisabled) {
		t.Errorf("a disabled JVN sweep returned %v; a caller that did not skip it must not read it as clean", err)
	}
	if err := svc.ScanComponents(ctx, uuid.New()); !errors.Is(err, ErrScanSourceDisabled) {
		t.Errorf("ScanComponents on a disabled service returned %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("a disabled JVN service sent %d request(s) to MyJVN", n)
	}
	if NewJVNService(nil, nil, srv.URL, false).ScanDisabled() {
		t.Error("JVN is disabled by default; the default must be unchanged")
	}
}

func TestJVNSwitch_TrackerCompletedCarriesSkipped(t *testing.T) {
	tr := NewScanTracker()
	id := uuid.New()
	gen := tr.Begin(id)
	if st := tr.GetStatus(id); st.State != ScanStateRunning || len(st.Skipped) != 0 {
		t.Fatalf("while running: %+v", st)
	}
	tr.FinishSkipped(id, gen, nil, "", []string{"jvn"})
	st := tr.GetStatus(id)
	if st.State != ScanStateCompleted || !slices.Equal(st.Skipped, []string{"jvn"}) {
		t.Fatalf("got %+v, want completed with skipped [jvn]", st)
	}
	if st.Error != "" || len(st.Reasons) != 0 {
		t.Errorf("a skip is not a failure: %+v", st)
	}
}

func TestJVNSwitch_TrackerFailedCarriesSkipped(t *testing.T) {
	tr := NewScanTracker()
	id := uuid.New()
	gen := tr.Begin(id)
	tr.FinishSkipped(id, gen, []string{ScanReasonFetchFailed}, "nvd: scan failed (fetch_failed)", []string{"jvn"})
	st := tr.GetStatus(id)
	if st.State != ScanStateFailed || !slices.Equal(st.Skipped, []string{"jvn"}) ||
		!slices.Equal(st.Reasons, []string{ScanReasonFetchFailed}) {
		t.Fatalf("got %+v", st)
	}
}

// Overlapping runs form one group: a run that skipped JVN taints the group's
// "completed" even when another run of it did not skip, and nothing is shown
// until the last run ends.
func TestJVNSwitch_TrackerGroupUnionAndHiddenWhileRunning(t *testing.T) {
	tr := NewScanTracker()
	id := uuid.New()
	g1, g2 := tr.Begin(id), tr.Begin(id)
	tr.FinishSkipped(id, g1, nil, "", []string{"jvn"})
	if st := tr.GetStatus(id); st.State != ScanStateRunning || len(st.Skipped) != 0 {
		t.Fatalf("with one run still active: %+v", st)
	}
	tr.FinishSkipped(id, g2, nil, "", nil)
	if st := tr.GetStatus(id); st.State != ScanStateCompleted || !slices.Equal(st.Skipped, []string{"jvn"}) {
		t.Fatalf("group of a skipping and a non-skipping run: %+v, want completed [jvn]", st)
	}
}

func TestJVNSwitch_TrackerNewGroupAndMarkReset(t *testing.T) {
	tr := NewScanTracker()
	id := uuid.New()
	tr.FinishSkipped(id, tr.Begin(id), nil, "", []string{"jvn", "jvn"})
	if st := tr.GetStatus(id); !slices.Equal(st.Skipped, []string{"jvn"}) {
		t.Fatalf("skipped not de-duplicated: %+v", st)
	}
	tr.Finish(id, tr.Begin(id), nil, "") // a new group that skipped nothing
	if st := tr.GetStatus(id); st.State != ScanStateCompleted || len(st.Skipped) != 0 {
		t.Fatalf("a new group inherited the old group's skip: %+v", st)
	}
	tr.FinishSkipped(id, tr.Begin(id), nil, "", []string{"jvn"})
	tr.MarkCompleted(id)
	if st := tr.GetStatus(id); len(st.Skipped) != 0 {
		t.Fatalf("MarkCompleted kept a skip it does not know about: %+v", st)
	}
}

// GetDetailVersion is unchanged for its existing callers.
func TestJVNSwitch_GetDetailVersionAgreesWithGetStatus(t *testing.T) {
	tr := NewScanTracker()
	id := uuid.New()
	tr.FinishSkipped(id, tr.Begin(id), []string{ScanReasonTruncated}, "jvn: scan failed (truncated)", []string{"jvn"})
	s, m, r, v := tr.GetDetailVersion(id)
	st := tr.GetStatus(id)
	if s != st.State || m != st.Error || !slices.Equal(r, st.Reasons) || v != st.Version {
		t.Errorf("GetDetailVersion (%s %q %v %s) disagrees with GetStatus %+v", s, m, r, v, st)
	}
}

// The coalesced overflow of a queue (Codex M72 R5 High-3) must carry the
// skips of the finishes it folds in, or a backed-up Redis would publish a
// bare "completed".
func TestJVNSwitch_MergeSetCarriesSkipped(t *testing.T) {
	m := newMergeSet()
	m.begin(1, true)
	m.finish(1)
	m.addSkipped([]string{"jvn"})
	m.addSkipped([]string{"jvn"})
	if !slices.Equal(m.skipped, []string{"jvn"}) {
		t.Errorf("merge skipped = %v, want [jvn]", m.skipped)
	}
	if got := m.json(); !strings.Contains(got, `"s":["jvn"]`) {
		t.Errorf("merge JSON %s does not carry the skip", got)
	}
}

// finishLog records every finish a store receives.
type finishLog struct {
	*memStore
	mu    chan struct{}
	calls []finishCall
}

type finishCall struct {
	gen     uint64
	msg     string
	skipped []string
}

func (f *finishLog) record(gen uint64, msg string, skipped []string) {
	f.mu <- struct{}{}
	f.calls = append(f.calls, finishCall{gen, msg, append([]string(nil), skipped...)})
	<-f.mu
}

func (f *finishLog) forGen(gen uint64) []finishCall {
	f.mu <- struct{}{}
	defer func() { <-f.mu }()
	var out []finishCall
	for _, c := range f.calls {
		if c.gen == gen {
			out = append(out, c)
		}
	}
	return out
}

type slowIntentFinishLog struct {
	*finishLog
	d time.Duration
}

func (s slowIntentFinishLog) begin(ctx context.Context, id uuid.UUID, gen uint64) error {
	time.Sleep(s.d)
	return s.memStore.begin(ctx, id, gen)
}

func (s slowIntentFinishLog) intent(ctx context.Context, id uuid.UUID, gen uint64) error {
	time.Sleep(3 * s.d)
	return s.memStore.intent(ctx, id, gen)
}

func (s slowIntentFinishLog) finish(ctx context.Context, id uuid.UUID, gen uint64, msg string, r, skipped []string) (bool, error) {
	s.record(gen, msg, skipped)
	return s.memStore.finish(ctx, id, gen, msg, r, skipped)
}

// Codex (SBOMHUB_JVN) R1 Medium-2: the cleanup finish written after a late
// intent (Codex M72 R19 Medium-3) carried no outcome. If the key was evicted
// after the run's real finish, that cleanup recreated it as a bare
// "completed" — losing the skip, and, before this change, the failure too.
// Every finish written for a run now carries the run's outcome.
func TestJVNSwitch_LateIntentCleanupCarriesTheOutcome(t *testing.T) {
	store := slowIntentFinishLog{finishLog: &finishLog{memStore: newMemStore(), mu: make(chan struct{}, 1)}, d: 60 * time.Millisecond}
	a := trackerOn(store, time.Hour)
	a.beginWait = time.Millisecond
	id := uuid.New()
	first := a.Begin(id) // its write is in flight: the queue is busy
	gen := a.Begin(id)   // queued behind: its intent (slow) is in flight
	a.FinishSkipped(id, gen, []string{ScanReasonFetchFailed}, "nvd: scan failed (fetch_failed)", []string{"jvn"})
	a.Finish(id, first, nil, "")
	time.Sleep(400 * time.Millisecond) // the intent lands after the finish
	settle(t, a, id)
	calls := store.forGen(gen)
	if len(calls) < 2 {
		t.Fatalf("finishes for the run: %+v; want its own and the late-intent cleanup", calls)
	}
	for _, c := range calls {
		if c.msg != "nvd: scan failed (fetch_failed)" || !slices.Equal(c.skipped, []string{"jvn"}) {
			t.Errorf("a finish for the run carried %+v; every one must carry its outcome", c)
		}
	}
}

type lossyRejoinFinishLog struct {
	*lossyRejoinStore
	log *finishLog
}

func (s lossyRejoinFinishLog) finish(ctx context.Context, id uuid.UUID, gen uint64, msg string, r, skipped []string) (bool, error) {
	s.log.record(gen, msg, skipped)
	return s.lossyRejoinStore.finish(ctx, id, gen, msg, r, skipped)
}

// The rejoin cleanup (Codex M72 R21 Medium-1) carries the outcome too.
func TestJVNSwitch_LateRejoinCleanupCarriesTheOutcome(t *testing.T) {
	mem := newMemStore()
	store := lossyRejoinFinishLog{
		lossyRejoinStore: &lossyRejoinStore{memStore: mem, d: 100 * time.Millisecond},
		log:              &finishLog{memStore: mem, mu: make(chan struct{}, 1)},
	}
	a := trackerOn(store, time.Hour)
	id := uuid.New()
	gen := a.Begin(id)
	settle(t, a, id)
	a.heartbeatPass() // inactive: a rejoin starts (slow, reply lost)
	time.Sleep(20 * time.Millisecond)
	a.FinishSkipped(id, gen, nil, "", []string{"jvn"}) // before the rejoin applies
	time.Sleep(200 * time.Millisecond)
	settle(t, a, id)
	calls := store.log.forGen(gen)
	if len(calls) < 2 {
		t.Fatalf("finishes for the run: %+v; want its own and the rejoin cleanup", calls)
	}
	for _, c := range calls {
		if !slices.Equal(c.skipped, []string{"jvn"}) {
			t.Errorf("a finish for the run carried %+v; every one must carry its skip", c)
		}
	}
}
