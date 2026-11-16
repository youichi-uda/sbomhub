package service

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func full() ScanCoverage {
	return ScanCoverage{Checked: []string{"nvd", "jvn", "distro"}, Reported: true}
}

func TestScanCoverage_OrderScanSources(t *testing.T) {
	got := OrderScanSources([]string{"zeta", "distro", "", "nvd", "alpha", "distro", "jvn"})
	if want := []string{"nvd", "jvn", "distro", "alpha", "zeta"}; !slices.Equal(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
	if got := OrderScanSources(nil); got == nil || len(got) != 0 {
		t.Errorf("nil in: %#v", got)
	}
}

func TestScanCoverage_TrackerSingleRun(t *testing.T) {
	tr := NewScanTracker()
	id := uuid.New()
	tr.FinishCoverage(id, tr.Begin(id), nil, "", ScanCoverage{Checked: []string{}, Skipped: []string{"distro", "jvn", "nvd"}, Reported: true})
	st := tr.GetStatus(id)
	if st.State != ScanStateCompleted || !st.CheckedKnown || st.Checked == nil || len(st.Checked) != 0 ||
		!slices.Equal(st.Skipped, []string{"nvd", "jvn", "distro"}) {
		t.Fatalf("offline run: %+v", st)
	}
	// A new group resets the coverage.
	tr.Finish(id, tr.Begin(id), nil, "")
	if st := tr.GetStatus(id); st.CheckedKnown || st.Checked != nil || st.Skipped != nil {
		t.Fatalf("a legacy finish in a new group kept the old coverage: %+v", st)
	}
}

// Overlapping runs: checked is the intersection over the runs that reported
// coverage, skipped the union; a run that reported nothing narrows nothing.
func TestScanCoverage_TrackerGroupIntersection(t *testing.T) {
	tr := NewScanTracker()
	id := uuid.New()
	a, b, c := tr.Begin(id), tr.Begin(id), tr.Begin(id)
	tr.FinishCoverage(id, a, nil, "", full())
	tr.Finish(id, b, nil, "") // an unreported run (legacy)
	if st := tr.GetStatus(id); st.State != ScanStateRunning || st.CheckedKnown {
		t.Fatalf("while c runs: %+v", st)
	}
	tr.FinishCoverage(id, c, nil, "", ScanCoverage{Checked: []string{"nvd", "distro"}, Skipped: []string{"jvn"}, Reported: true})
	st := tr.GetStatus(id)
	if !st.CheckedKnown || !slices.Equal(st.Checked, []string{"nvd", "distro"}) || !slices.Equal(st.Skipped, []string{"jvn"}) {
		t.Fatalf("group: %+v", st)
	}
}

// A source both checked (by a reporting run) and skipped (by a run that only
// reports skips, e.g. a cleanup or an older writer) reads skipped only.
func TestScanCoverage_SkippedWinsOverChecked(t *testing.T) {
	tr := NewScanTracker()
	id := uuid.New()
	a, b := tr.Begin(id), tr.Begin(id)
	tr.FinishCoverage(id, a, nil, "", full())
	tr.FinishSkipped(id, b, nil, "", []string{"jvn"})
	st := tr.GetStatus(id)
	if !slices.Equal(st.Checked, []string{"nvd", "distro"}) || !slices.Equal(st.Skipped, []string{"jvn"}) {
		t.Fatalf("got %+v", st)
	}
}

// A legacy MarkCompleted / MarkFailed has no coverage.
func TestScanCoverage_MarkHasNoCoverage(t *testing.T) {
	tr := NewScanTracker()
	id := uuid.New()
	tr.FinishCoverage(id, tr.Begin(id), nil, "", full())
	tr.MarkCompleted(id)
	if st := tr.GetStatus(id); st.CheckedKnown || st.Checked != nil {
		t.Fatalf("got %+v", st)
	}
}

// The coalesced (merge) path folds coverage with the same rule.
func TestScanCoverage_MergeSetFoldsCoverage(t *testing.T) {
	m := newMergeSet()
	m.addCoverage(ScanCoverage{Skipped: []string{"jvn"}}) // unreported
	if m.checkedKnown {
		t.Fatal("an unreported finish made the merge's checked known")
	}
	m.addCoverage(full())
	m.addCoverage(ScanCoverage{Checked: []string{"distro", "nvd"}, Reported: true})
	if !m.checkedKnown || !slices.Equal(m.checked, []string{"nvd", "distro"}) || !slices.Equal(m.skipped, []string{"jvn"}) {
		t.Fatalf("merge: %+v", m)
	}
	if js := m.json(); !containsAll(js, `"c":["nvd","distro"]`, `"s":["jvn"]`) {
		t.Fatalf("json %s", js)
	}
	if js := newMergeSet().json(); containsAll(js, `"c"`) {
		t.Fatalf("a merge without coverage carries c: %s", js)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}

// The shared path (fake store) carries coverage to another process.
func TestScanCoverage_SharedStoreCarriesCoverage(t *testing.T) {
	store := newMemStore()
	a, b := trackerOn(store, time.Hour), trackerOn(store, time.Hour)
	id := uuid.New()
	a.FinishCoverage(id, a.Begin(id), nil, "", ScanCoverage{Checked: []string{"nvd"}, Skipped: []string{"jvn"}, Reported: true})
	settle(t, a, id)
	st := b.GetStatus(id)
	if st.State != ScanStateCompleted || !st.CheckedKnown || !slices.Equal(st.Checked, []string{"nvd"}) {
		t.Fatalf("replica B: %+v", st)
	}
}

// The cleanup finish of a late intent replays the skip but never the checked
// sources: a check replayed into a later group would be a false claim.
func TestScanCoverage_CleanupNeverReplaysChecked(t *testing.T) {
	ev := cleanupFinish(1, &liveRun{finSkipped: []string{"jvn"}})
	if ev.cov.Reported || ev.cov.Checked != nil || !slices.Equal(ev.cov.Skipped, []string{"jvn"}) {
		t.Fatalf("cleanup = %+v", ev.cov)
	}
}

// Codex coverage R1 Medium-1: a local answer that stands in for the shared
// state (Redis unreadable, or this process's writes still pending) cannot
// know another replica's overlapping run, so it states no checked sources.
func TestScanCoverage_LocalFallbackStatesNoCheckedSources(t *testing.T) {
	store := newMemStore()
	tr := trackerOn(store, time.Hour)
	id := uuid.New()
	store.setDown(true)
	tr.FinishCoverage(id, tr.Begin(id), []string{ScanReasonFetchFailed}, "jvn: scan failed (fetch_failed)",
		ScanCoverage{Checked: []string{"nvd", "distro"}, Reported: true})
	st := tr.GetStatus(id)
	if st.State != ScanStateFailed {
		t.Fatalf("state %+v", st)
	}
	if st.CheckedKnown || st.Checked != nil {
		t.Fatalf("a local fallback answer claimed checked sources: %+v", st)
	}
	// Without a shared store the process is the only writer: it answers.
	solo := NewScanTracker()
	solo.FinishCoverage(id, solo.Begin(id), nil, "", full())
	if st := solo.GetStatus(id); !st.CheckedKnown {
		t.Fatalf("in-memory-only tracker dropped its coverage: %+v", st)
	}
}

// Codex coverage R3 High: a failure from a run that reported no coverage (an
// older replica, a legacy Finish) still takes its source out of the
// group's checked sources; a failure that cannot be attributed to a source
// makes the coverage unknown.
func TestScanCoverage_UnreportedFailureNarrowsChecked(t *testing.T) {
	for _, tc := range []struct {
		marker string
		want   []string // nil = unknown
	}{
		{"jvn: scan failed (fetch_failed, source_unavailable)", []string{"nvd", "distro"}},
		{"nvd: scan failed (fetch_failed)", []string{"jvn", "distro"}},
		{"scheduled: scan failed (deadline_exceeded)", []string{"jvn"}},
		{"scan: scan failed (queue_full)", []string{}},
		{"scan: scan failed (interrupted)", nil},
		{"scan failed", nil},
		{"osv: scan failed", nil},
	} {
		tr := NewScanTracker()
		id := uuid.New()
		a, b := tr.Begin(id), tr.Begin(id)
		tr.FinishCoverage(id, a, nil, "", full())
		tr.Finish(id, b, []string{ScanReasonFetchFailed}, tc.marker)
		st := tr.GetStatus(id)
		if tc.want == nil {
			if st.CheckedKnown {
				t.Errorf("%q: coverage %v, want unknown", tc.marker, st.Checked)
			}
			continue
		}
		if !st.CheckedKnown || !slices.Equal(st.Checked, tc.want) {
			t.Errorf("%q: checked %v (known %t), want %v", tc.marker, st.Checked, st.CheckedKnown, tc.want)
		}
	}
}

// A Begin whose attempt failed is retried as one that expects its run.
type expectRecorder struct {
	*memStore
	mu       chan struct{}
	failOnce bool
	expects  []bool
}

func (e *expectRecorder) begin(ctx context.Context, id uuid.UUID, gen uint64) error {
	e.mu <- struct{}{}
	e.expects = append(e.expects, false)
	fail := e.failOnce
	e.failOnce = false
	<-e.mu
	if fail {
		return errStoreDown
	}
	return e.memStore.begin(ctx, id, gen)
}

func (e *expectRecorder) beginExpectingRun(ctx context.Context, id uuid.UUID, gen uint64) error {
	e.mu <- struct{}{}
	e.expects = append(e.expects, true)
	<-e.mu
	return e.memStore.begin(ctx, id, gen)
}

func TestScanCoverage_RetriedBeginExpectsItsRun(t *testing.T) {
	st := &expectRecorder{memStore: newMemStore(), mu: make(chan struct{}, 1), failOnce: true}
	tr := trackerOn(st, 20*time.Millisecond)
	id := uuid.New()
	tr.Begin(id)
	waitFor(t, "the retried Begin", func() bool {
		st.mu <- struct{}{}
		defer func() { <-st.mu }()
		return len(st.expects) >= 2
	})
	st.mu <- struct{}{}
	got := append([]bool(nil), st.expects...)
	<-st.mu
	if got[0] || !got[1] {
		t.Fatalf("expects = %v, want [false true ...]", got)
	}
}
