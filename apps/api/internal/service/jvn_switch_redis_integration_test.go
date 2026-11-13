//go:build integration

package service

// SBOMHUB_JVN=off: skipped sources through the M72 shared status store on a
// real Redis. Each tracker stands for one API replica; they share only Redis.
// The skip must be readable from a replica that did not run the scan, follow
// the store's group rules, and survive the coalesced (merge) write path.

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

// statusFrom reads tr's view once every writer's shared writes landed.
func statusFrom(tr *ScanTracker, id uuid.UUID, writers ...*ScanTracker) ScanStatusDetail {
	for _, w := range writers {
		deadline := time.Now().Add(5 * time.Second)
		for w.pendingShared(id) && time.Now().Before(deadline) {
			time.Sleep(2 * time.Millisecond)
		}
	}
	return tr.GetStatus(id)
}

func TestJVNSwitchRedis_SkipIsVisibleFromAnotherReplica(t *testing.T) {
	rdb := m72Redis(t)
	a, b := process(rdb, 0, time.Hour), process(rdb, 0, time.Hour)
	id := uuid.New()

	a.FinishSkipped(id, a.Begin(id), nil, "", []string{"jvn"})
	st := statusFrom(b, id, a)
	if st.State != ScanStateCompleted || !slices.Equal(st.Skipped, []string{"jvn"}) {
		t.Fatalf("replica B reads %+v, want completed with skipped [jvn]", st)
	}

	// A new group (B, JVN on) that skipped nothing: no stale skip.
	b.Finish(id, b.Begin(id), nil, "")
	if st := statusFrom(a, id, b); st.State != ScanStateCompleted || len(st.Skipped) != 0 {
		t.Fatalf("after a new group without a skip, replica A reads %+v", st)
	}
}

func TestJVNSwitchRedis_GroupUnionAcrossReplicas(t *testing.T) {
	rdb := m72Redis(t)
	a, b := process(rdb, 0, time.Hour), process(rdb, 0, time.Hour)
	id := uuid.New()

	ga := a.Begin(id)
	gb := b.Begin(id)
	a.FinishSkipped(id, ga, nil, "", []string{"jvn"})
	if st := statusFrom(b, id, a); st.State != ScanStateRunning || len(st.Skipped) != 0 {
		t.Fatalf("with B's run still active: %+v", st)
	}
	b.Finish(id, gb, nil, "")
	for _, tr := range []*ScanTracker{a, b} {
		if st := statusFrom(tr, id, a, b); st.State != ScanStateCompleted || !slices.Equal(st.Skipped, []string{"jvn"}) {
			t.Fatalf("group of A (skipped jvn) and B: %+v, want completed [jvn]", st)
		}
	}
}

func TestJVNSwitchRedis_FailedKeepsSkipAndMarkClearsIt(t *testing.T) {
	rdb := m72Redis(t)
	a, b := process(rdb, 0, time.Hour), process(rdb, 0, time.Hour)
	id := uuid.New()

	a.FinishSkipped(id, a.Begin(id), []string{ScanReasonFetchFailed}, "nvd: scan failed (fetch_failed)", []string{"jvn"})
	st := statusFrom(b, id, a)
	if st.State != ScanStateFailed || !slices.Equal(st.Skipped, []string{"jvn"}) ||
		!slices.Equal(st.Reasons, []string{ScanReasonFetchFailed}) {
		t.Fatalf("got %+v", st)
	}
	b.MarkCompleted(id)
	if st := statusFrom(a, id, b); len(st.Skipped) != 0 {
		t.Fatalf("a Mark* outside a run kept the old skip: %+v", st)
	}
}

// The merge script (a queue that overflowed while Redis was unreachable)
// applies the folded finishes' skips.
func TestJVNSwitchRedis_MergeCarriesSkip(t *testing.T) {
	rdb := m72Redis(t)
	a, b := process(rdb, 0, time.Hour), process(rdb, 0, time.Hour)
	id := uuid.New()
	store := a.shared.(*redisScanStatusStore)
	ctx := context.Background()

	if err := store.begin(ctx, id, 7); err != nil {
		t.Fatal(err)
	}
	m := newMergeSet()
	m.finish(7)
	m.addSkipped([]string{"jvn"})
	if err := store.merge(ctx, id, m); err != nil {
		t.Fatal(err)
	}
	if st := b.GetStatus(id); st.State != ScanStateCompleted || !slices.Equal(st.Skipped, []string{"jvn"}) {
		t.Fatalf("after a merge carrying a skip: %+v", st)
	}
}

// A finish Redis did not know (its begin never landed) still records its
// skip, exactly as it still records its failure (Codex M72 R5 High-2): the
// conservative direction.
func TestJVNSwitchRedis_UnknownRunStillRecordsSkip(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 0, time.Hour)
	id := uuid.New()
	store := a.shared.(*redisScanStatusStore)
	known, err := store.finish(context.Background(), id, 42, "", nil, []string{"jvn"})
	if err != nil || known {
		t.Fatalf("finish of an unknown run: known=%t err=%v", known, err)
	}
	v, err := store.get(context.Background(), id)
	if err != nil || !slices.Equal(v.skipped, []string{"jvn"}) {
		t.Fatalf("view = %+v err=%v, want skipped [jvn]", v, err)
	}
}
