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

// Codex (SBOMHUB_JVN) R1 High-1, the half code can fix: during a rolling
// upgrade an OLDER replica may start the next group. Its begin script resets
// a new group by clearing state/error/reasons/updated and writing
// outcomes='[]' — it knows no other field — so a skip kept in a field of its
// own survived into that group and every newer replica reported a stale
// skipped_sources. Kept inside outcomes, the old reset clears it too.
func TestJVNSwitchRedis_OldReplicaGroupResetClearsTheSkip(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 0, time.Hour)
	id := uuid.New()
	store := a.shared.(*redisScanStatusStore)
	ctx := context.Background()
	if _, err := store.finish(ctx, id, 1, "", nil, []string{"jvn"}); err != nil {
		t.Fatal(err)
	}
	if v, _ := store.get(ctx, id); !slices.Equal(v.skipped, []string{"jvn"}) {
		t.Fatalf("precondition: skipped = %v", v.skipped)
	}
	// Exactly the new-group reset of the parent commit's begin script.
	if err := rdb.Eval(ctx, `redis.call('HDEL', KEYS[1], 'state', 'error', 'reasons', 'updated')
redis.call('HSET', KEYS[1], 'outcomes', '[]')
return 1`, scanStatusKeys(id)).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.finish(ctx, id, 2, "", nil, nil); err != nil {
		t.Fatal(err)
	}
	if v, _ := store.get(ctx, id); len(v.skipped) != 0 {
		t.Fatalf("a group started by an older replica reports the previous group's skip: %v", v.skipped)
	}
}

// The skip entry inside outcomes must never read as a failure, and failures
// next to it are unchanged.
func TestJVNSwitchRedis_SkipEntryIsNotAFailure(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 0, time.Hour)
	id := uuid.New()
	store := a.shared.(*redisScanStatusStore)
	ctx := context.Background()
	if _, err := store.finish(ctx, id, 1, "", nil, []string{"jvn"}); err != nil {
		t.Fatal(err)
	}
	if v, _ := store.get(ctx, id); v.state != ScanStateCompleted || v.errMsg != "" || len(v.reasons) != 0 {
		t.Fatalf("a skip alone published %+v", v)
	}
	if _, err := store.finish(ctx, id, 2, "nvd: scan failed (fetch_failed)", []string{ScanReasonFetchFailed}, nil); err != nil {
		t.Fatal(err)
	}
	v, _ := store.get(ctx, id)
	if v.state != ScanStateFailed || v.errMsg != "nvd: scan failed (fetch_failed)" ||
		!slices.Equal(v.reasons, []string{ScanReasonFetchFailed}) || !slices.Equal(v.skipped, []string{"jvn"}) {
		t.Fatalf("failure next to a skip: %+v", v)
	}
}
