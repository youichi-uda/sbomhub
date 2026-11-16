//go:build integration

package service

// Scan coverage (checked_sources) through the M72 shared status store on a
// real Redis, including a rolling upgrade: an OLDER replica (the parent
// commit's scripts, verbatim in scan_coverage_oldreplica_test.go) writing
// and reading the same key.

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// oldScripts are the parent commit's scripts (no hold), as an older replica
// runs them.
func oldScripts(maxRunAge time.Duration) (begin, finish, merge, get *redis.Script) {
	prelude := fmt.Sprintf("local INTERRUPTED_MSG = %q\nlocal INTERRUPTED_REASON = %q\nlocal MAX_LOST = %d\nlocal MAX_RUN_AGE = %d\nlocal YOUNG = %d\nlocal YOUNG_SPAN = %d\n",
		scanInterruptedMarker, ScanReasonInterrupted, scanStatusMaxLost, maxRunAge.Milliseconds(), 0, 0)
	mk := func(body string) *redis.Script { return redis.NewScript(prelude + oldScanStatusLua + body) }
	return mk(oldScanStatusBeginLua), mk(oldScanStatusFinishLua), mk(oldScanStatusMergeLua), mk(oldScanStatusGetLua)
}

func TestCoverageRedis_VisibleFromAnotherReplica(t *testing.T) {
	rdb := m72Redis(t)
	a, b := process(rdb, 0, time.Hour), process(rdb, 0, time.Hour)
	id := uuid.New()
	a.FinishCoverage(id, a.Begin(id), nil, "", ScanCoverage{Checked: []string{}, Skipped: []string{"nvd", "jvn", "distro"}, Reported: true})
	st := statusFrom(b, id, a)
	if st.State != ScanStateCompleted || !st.CheckedKnown || st.Checked == nil || len(st.Checked) != 0 ||
		!slices.Equal(st.Skipped, []string{"nvd", "jvn", "distro"}) {
		t.Fatalf("offline run read from B: %+v", st)
	}
	// Next group: full coverage replaces it.
	b.FinishCoverage(id, b.Begin(id), nil, "", ScanCoverage{Checked: []string{"nvd", "jvn", "distro"}, Reported: true})
	st = statusFrom(a, id, b)
	if !slices.Equal(st.Checked, []string{"nvd", "jvn", "distro"}) || st.Skipped != nil {
		t.Fatalf("full run read from A: %+v", st)
	}
	// A legacy finish starts a group without coverage: unknown, not stale.
	a.Finish(id, a.Begin(id), nil, "")
	if st := statusFrom(b, id, a); st.CheckedKnown || st.Checked != nil {
		t.Fatalf("legacy group kept the old checked sources: %+v", st)
	}
}

func TestCoverageRedis_GroupIntersectionAcrossReplicas(t *testing.T) {
	rdb := m72Redis(t)
	a, b := process(rdb, 0, time.Hour), process(rdb, 0, time.Hour)
	id := uuid.New()
	ga, gb := a.Begin(id), b.Begin(id)
	a.FinishCoverage(id, ga, nil, "", ScanCoverage{Checked: []string{"nvd", "jvn", "distro"}, Reported: true})
	b.FinishCoverage(id, gb, nil, "", ScanCoverage{Checked: []string{"nvd", "distro"}, Skipped: []string{"jvn"}, Reported: true})
	for _, tr := range []*ScanTracker{a, b} {
		st := statusFrom(tr, id, a, b)
		if st.State != ScanStateCompleted || !slices.Equal(st.Checked, []string{"nvd", "distro"}) || !slices.Equal(st.Skipped, []string{"jvn"}) {
			t.Fatalf("group: %+v", st)
		}
	}
}

func TestCoverageRedis_UnreportedFinishNeitherAddsNorNarrows(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 0, time.Hour)
	store := a.shared.(*redisScanStatusStore)
	ctx := context.Background()
	id := uuid.New()
	for g := uint64(1); g <= 3; g++ {
		if err := store.begin(ctx, id, g); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.finish(ctx, id, 1, "", nil, ScanCoverage{}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.finish(ctx, id, 2, "", nil, ScanCoverage{Checked: []string{"nvd"}, Reported: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.finish(ctx, id, 3, "", nil, ScanCoverage{Skipped: []string{"jvn"}}); err != nil {
		t.Fatal(err)
	}
	v, _ := store.get(ctx, id)
	if v.state != ScanStateCompleted || !v.checkedKnown || !slices.Equal(v.checked, []string{"nvd"}) || !slices.Equal(v.skipped, []string{"jvn"}) {
		t.Fatalf("view %+v", v)
	}
	// Reported empty is known and empty.
	id2 := uuid.New()
	if err := store.begin(ctx, id2, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.finish(ctx, id2, 1, "", nil, ScanCoverage{Checked: []string{}, Reported: true}); err != nil {
		t.Fatal(err)
	}
	if v, _ := store.get(ctx, id2); !v.checkedKnown || len(v.checked) != 0 || v.checked == nil {
		t.Fatalf("after an empty report: %+v", v)
	}
}

// Codex coverage R1 High-2: a finish Redis does not know (no active run, no
// tombstone: a late write after an eviction or a long partition) may narrow
// the current group's checked sources but never SET them — it may belong to
// an earlier group, and setting would claim its checks for this one.
func TestCoverageRedis_UnknownFinishNeverSetsChecked(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 0, time.Hour)
	store := a.shared.(*redisScanStatusStore)
	ctx := context.Background()

	fresh := uuid.New()
	if known, err := store.finish(ctx, fresh, 42, "", nil, full()); err != nil || known {
		t.Fatalf("known=%t err=%v", known, err)
	}
	if v, _ := store.get(ctx, fresh); v.checkedKnown {
		t.Fatalf("an unknown finish set the checked sources: %+v", v)
	}

	// A current group whose only run reports nothing (an older replica):
	// a late unknown finish must not give it checked sources.
	id := uuid.New()
	if err := store.begin(ctx, id, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.finish(ctx, id, 99, "", nil, full()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.finish(ctx, id, 1, "", nil, ScanCoverage{}); err != nil {
		t.Fatal(err)
	}
	if v, _ := store.get(ctx, id); v.checkedKnown {
		t.Fatalf("a late unknown finish gave the group checked sources: %+v", v)
	}

	// It still narrows a group that has them (the conservative direction).
	id2 := uuid.New()
	for g := uint64(1); g <= 2; g++ {
		if err := store.begin(ctx, id2, g); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.finish(ctx, id2, 1, "", nil, full()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.finish(ctx, id2, 77, "", nil, ScanCoverage{Checked: []string{"nvd"}, Reported: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.finish(ctx, id2, 2, "", nil, ScanCoverage{}); err != nil {
		t.Fatal(err)
	}
	if v, _ := store.get(ctx, id2); !slices.Equal(v.checked, []string{"nvd"}) {
		t.Fatalf("an unknown finish did not narrow: %+v", v)
	}
}

// The merge path: folded coverage sets the group's checked sources only when
// a folded finish that reported coverage was a member of the group.
func TestCoverageRedis_MergeOfUnknownRunsNeverSetsChecked(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 0, time.Hour)
	store := a.shared.(*redisScanStatusStore)
	ctx := context.Background()
	id := uuid.New()
	m := newMergeSet()
	m.finish(5) // never begun in Redis
	m.addFinishCoverage(5, full())
	if err := store.merge(ctx, id, m); err != nil {
		t.Fatal(err)
	}
	if v, _ := store.get(ctx, id); v.checkedKnown {
		t.Fatalf("a merge of unknown runs set the checked sources: %+v", v)
	}
	// A member reporter sets them.
	id2 := uuid.New()
	if err := store.begin(ctx, id2, 6); err != nil {
		t.Fatal(err)
	}
	m2 := newMergeSet()
	m2.finish(6)
	m2.addFinishCoverage(6, ScanCoverage{Checked: []string{"nvd", "distro"}, Reported: true})
	if err := store.merge(ctx, id2, m2); err != nil {
		t.Fatal(err)
	}
	if v, _ := store.get(ctx, id2); !v.checkedKnown || !slices.Equal(v.checked, []string{"nvd", "distro"}) {
		t.Fatalf("member merge: %+v", v)
	}
}

func TestCoverageRedis_MergeCarriesCoverage(t *testing.T) {
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
	m.addFinishCoverage(7, ScanCoverage{Checked: []string{"nvd", "distro"}, Skipped: []string{"jvn"}, Reported: true})
	if err := store.merge(ctx, id, m); err != nil {
		t.Fatal(err)
	}
	st := b.GetStatus(id)
	if st.State != ScanStateCompleted || !slices.Equal(st.Checked, []string{"nvd", "distro"}) || !slices.Equal(st.Skipped, []string{"jvn"}) {
		t.Fatalf("after merge: %+v", st)
	}
	// A merge without coverage leaves a group's coverage unknown.
	id2 := uuid.New()
	m2 := newMergeSet()
	m2.addSkipped([]string{"jvn"})
	if err := store.merge(ctx, id2, m2); err != nil {
		t.Fatal(err)
	}
	if v, _ := store.get(ctx, id2); v.checkedKnown {
		t.Fatalf("merge without coverage: %+v", v)
	}
}

// Rolling upgrade: an older replica finishing a run in a group whose
// coverage this version recorded keeps it (its add_skipped re-encodes the
// entry whole) and adds a skip next to it; this version then reports the
// skip and never the skipped source as checked.
func TestCoverageRedis_OldReplicaFinishKeepsCoverage(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 0, time.Hour)
	store := a.shared.(*redisScanStatusStore)
	_, oldFinish, _, oldGet := oldScripts(a.maxRunAge)
	ctx := context.Background()
	id := uuid.New()
	keys := scanStatusKeys(id)

	if err := store.begin(ctx, id, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.begin(ctx, id, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.finish(ctx, id, 1, "", nil, ScanCoverage{Checked: []string{"nvd", "jvn", "distro"}, Reported: true}); err != nil {
		t.Fatal(err)
	}
	// The older replica's run 2 finishes with SBOMHUB_JVN=off.
	if err := oldFinish.Run(ctx, rdb, keys, "2", int64(time.Hour/time.Millisecond), "", "[]", `["jvn"]`).Err(); err != nil {
		t.Fatal(err)
	}
	v, err := store.get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if v.state != ScanStateCompleted || !v.checkedKnown || !slices.Equal(v.skipped, []string{"jvn"}) {
		t.Fatalf("view %+v", v)
	}
	if st := a.GetStatus(id); !slices.Equal(st.Checked, []string{"nvd", "distro"}) || !slices.Equal(st.Skipped, []string{"jvn"}) {
		t.Fatalf("reported %+v, want checked [nvd distro] skipped [jvn]", st)
	}
	// The older replica's read is what it was: 5 values, completed, [jvn].
	ov, err := oldGet.Run(ctx, rdb, keys).StringSlice()
	if err != nil || len(ov) != 5 || ov[0] != "completed" || ov[4] != `["jvn"]` {
		t.Fatalf("old get = %q err=%v", ov, err)
	}
	// Exactly one marker-less entry: the older add_skipped found ours.
	raw, _ := rdb.HGet(ctx, keys[0], "outcomes").Result()
	var o []map[string]any
	if err := json.Unmarshal([]byte(raw), &o); err != nil || len(o) != 1 {
		t.Fatalf("outcomes = %s (%v)", raw, err)
	}
}

// An older replica reading a key whose group recorded nothing skipped (only
// coverage) reads skipped [] as before, and an older replica starting a new
// group clears the coverage (it lives inside outcomes).
func TestCoverageRedis_OldReplicaReadsAndResets(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 0, time.Hour)
	store := a.shared.(*redisScanStatusStore)
	oldBegin, oldFinish, _, oldGet := oldScripts(a.maxRunAge)
	ctx := context.Background()
	id := uuid.New()
	keys := scanStatusKeys(id)
	ttl := int64(time.Hour / time.Millisecond)

	if err := store.begin(ctx, id, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.finish(ctx, id, 1, "", nil, ScanCoverage{Checked: []string{"nvd", "jvn", "distro"}, Reported: true}); err != nil {
		t.Fatal(err)
	}
	if v, _ := store.get(ctx, id); !v.checkedKnown {
		t.Fatalf("precondition: %+v", v)
	}
	ov, err := oldGet.Run(ctx, rdb, keys).StringSlice()
	if err != nil || len(ov) != 5 || ov[0] != "completed" || ov[4] != "[]" || ov[1] != "" {
		t.Fatalf("old get = %q err=%v", ov, err)
	}
	if err := oldBegin.Run(ctx, rdb, keys, "9", int64(ScanStatusLease/time.Millisecond), ttl).Err(); err != nil {
		t.Fatal(err)
	}
	if err := oldFinish.Run(ctx, rdb, keys, "9", ttl, "", "[]", "[]").Err(); err != nil {
		t.Fatal(err)
	}
	if v, _ := store.get(ctx, id); v.state != ScanStateCompleted || v.checkedKnown {
		t.Fatalf("a group started and finished by an older replica reports the previous group's coverage: %+v", v)
	}
}

// A failure next to coverage still publishes failed; the coverage entry is
// never a failure.
func TestCoverageRedis_CoverageEntryIsNotAFailure(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 0, time.Hour)
	store := a.shared.(*redisScanStatusStore)
	ctx := context.Background()
	id := uuid.New()
	for g := uint64(1); g <= 2; g++ {
		if err := store.begin(ctx, id, g); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.finish(ctx, id, 1, "", nil, ScanCoverage{Checked: []string{}, Reported: true}); err != nil {
		t.Fatal(err)
	}
	if v, _ := store.get(ctx, id); v.state != ScanStateRunning || v.errMsg != "" {
		t.Fatalf("coverage alone published %+v", v)
	}
	if _, err := store.finish(ctx, id, 2, "jvn: scan failed (fetch_failed, source_unavailable)",
		[]string{ScanReasonFetchFailed, ScanReasonSourceUnavailable}, ScanCoverage{Checked: []string{"nvd", "distro"}, Reported: true}); err != nil {
		t.Fatal(err)
	}
	v, _ := store.get(ctx, id)
	if v.state != ScanStateFailed || v.errMsg != "jvn: scan failed (fetch_failed, source_unavailable)" || !v.checkedKnown || len(v.checked) != 0 {
		t.Fatalf("view %+v", v)
	}
}
