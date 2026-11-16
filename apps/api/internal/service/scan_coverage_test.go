package service

import (
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
