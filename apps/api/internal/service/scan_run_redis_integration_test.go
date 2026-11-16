//go:build integration

package service

// scan_run (scan_run.go) through the M72 shared status store on a real Redis:
// across replicas, overlapping runs, every idle -> active path, key loss, and
// a rolling upgrade with an OLDER replica (a3a785e's scripts, verbatim in
// scan_run_oldreplica_test.go) writing the same key.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// prevScripts are a3a785e's scripts (no young hold), as an older replica
// runs them.
type prevScriptSet struct {
	begin, intent, finish, merge, heartbeat, rejoin, mark, get *redis.Script
}

func prevScripts(maxRunAge time.Duration) prevScriptSet {
	prelude := fmt.Sprintf("local INTERRUPTED_MSG = %q\nlocal INTERRUPTED_REASON = %q\nlocal MAX_LOST = %d\nlocal MAX_RUN_AGE = %d\nlocal YOUNG = %d\nlocal YOUNG_SPAN = %d\n",
		scanInterruptedMarker, ScanReasonInterrupted, scanStatusMaxLost, maxRunAge.Milliseconds(), 0, 0)
	mk := func(body string) *redis.Script { return redis.NewScript(prelude + prevScanStatusLua + body) }
	return prevScriptSet{
		begin: mk(prevScanStatusBeginLua), intent: mk(prevScanStatusIntentLua), finish: mk(prevScanStatusFinishLua),
		merge: mk(prevScanStatusMergeLua), heartbeat: mk(prevScanStatusHeartbeatLua), rejoin: mk(prevScanStatusRejoinLua),
		mark: mk(prevScanStatusMarkLua), get: mk(prevScanStatusGetLua),
	}
}

// runStore is a store on rdb (no hold) with the given lease.
func runStore(t *testing.T, rdb *redis.Client, lease time.Duration) (*ScanTracker, *redisScanStatusStore) {
	t.Helper()
	tr := process(rdb, lease, time.Hour)
	return tr, tr.shared.(*redisScanStatusStore)
}

func mustGet(t *testing.T, s *redisScanStatusStore, id uuid.UUID) statusView {
	t.Helper()
	v, err := s.get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// The residual this closes: a whole rescan between two reads, with every
// other field equal, is now visible — across replicas, as scan-status
// answers it.
func TestScanRunRedis_RescanBetweenReadsAcrossReplicas(t *testing.T) {
	rdb := m72Redis(t)
	a, b := process(rdb, 0, time.Hour), process(rdb, 0, time.Hour)
	id := uuid.New()
	gen, run202 := a.BeginRun(id)
	if run202 == "" {
		t.Fatal("BeginRun reported no scan run with Redis up")
	}
	if st := statusFrom(b, id, a); st.State != ScanStateRunning || st.Run != run202 {
		t.Fatalf("B while A runs: %+v, want running %q", st, run202)
	}
	a.Finish(id, gen, nil, "")
	first := statusFrom(b, id, a)
	if first.State != ScanStateCompleted || first.Run != run202 {
		t.Fatalf("first read: %+v, want completed %q", first, run202)
	}
	if again := statusFrom(a, id); again.Run != first.Run {
		t.Fatalf("no activity, yet the scan run moved: %q -> %q", first.Run, again.Run)
	}
	// The rescan, on the other replica, same outcome.
	b.Finish(id, b.Begin(id), nil, "")
	second := statusFrom(a, id, b)
	if second.State != first.State || second.Run == "" || second.Run == first.Run {
		t.Fatalf("after a rescan: %+v (first %+v): want completed with a new scan run", second, first)
	}
}

// Overlapping runs of two replicas are one scan: one scan run.
func TestScanRunRedis_OverlapAcrossReplicasKeepsOneScanRun(t *testing.T) {
	rdb := m72Redis(t)
	a, b := process(rdb, 0, time.Hour), process(rdb, 0, time.Hour)
	id := uuid.New()
	ga, ra := a.BeginRun(id)
	gb, rb := b.BeginRun(id)
	if ra == "" || ra != rb {
		t.Fatalf("joined run got %q, group %q", rb, ra)
	}
	a.Finish(id, ga, nil, "")
	// Read through A: B, whose run is active, answers from its own memory,
	// without a scan run (TestScanRunRedis_LocalFallbackHasNoScanRun).
	if st := statusFrom(a, id, a, b); st.State != ScanStateRunning || st.Run != ra {
		t.Fatalf("mid-group: %+v", st)
	}
	if st := b.GetStatus(id); st.State != ScanStateRunning || st.Run != "" {
		t.Fatalf("B's local answer: %+v", st)
	}
	b.Finish(id, gb, nil, "")
	if st := statusFrom(a, id, b); st.State != ScanStateCompleted || st.Run != ra {
		t.Fatalf("end of group: %+v, want %q", st, ra)
	}
}

// Every path that brings activity to an idle SBOM gives a new scan run:
// a late finish, a revived heartbeat, a rejoin, a merge, an intent.
func TestScanRunRedis_EveryIdleToActivePathChangesIt(t *testing.T) {
	rdb := m72Redis(t)
	ctx := context.Background()
	_, s := runStore(t, rdb, 0)

	settled := func(t *testing.T, id uuid.UUID) string {
		t.Helper()
		must(t, s.begin(ctx, id, 1))
		_, err := s.finish(ctx, id, 1, "", nil, ScanCoverage{})
		must(t, err)
		v := mustGet(t, s, id)
		if v.state != ScanStateCompleted || v.run == "" {
			t.Fatalf("settled: %+v", v)
		}
		return v.run
	}
	expectNew := func(t *testing.T, id uuid.UUID, before string) {
		t.Helper()
		v := mustGet(t, s, id)
		if v.run == "" || v.run == before {
			t.Fatalf("scan run %q -> %q (%+v): want a new one", before, v.run, v)
		}
	}

	t.Run("late finish", func(t *testing.T) {
		id := uuid.New()
		before := settled(t, id)
		// The outcome of a run that is not active here (its begin never
		// landed, or it lapsed).
		_, err := s.finish(ctx, id, 99, "", nil, ScanCoverage{})
		must(t, err)
		expectNew(t, id, before)
	})
	t.Run("revived heartbeat", func(t *testing.T) {
		id := uuid.New()
		_, short := runStore(t, rdb, 50*time.Millisecond)
		must(t, short.begin(ctx, id, 1))
		time.Sleep(120 * time.Millisecond)
		v := mustGet(t, s, id) // sweeps it: failed (interrupted)
		if v.state != ScanStateFailed {
			t.Fatalf("swept: %+v", v)
		}
		act, err := s.heartbeatMany(ctx, []runKey{{id, 1}})
		must(t, err)
		if !act[0] {
			t.Fatal("not revived")
		}
		expectNew(t, id, v.run)
	})
	t.Run("rejoin", func(t *testing.T) {
		id := uuid.New()
		before := settled(t, id)
		must(t, s.rejoin(ctx, id, 7))
		expectNew(t, id, before)
	})
	t.Run("merge", func(t *testing.T) {
		id := uuid.New()
		before := settled(t, id)
		m := newMergeSet()
		m.begin(5, true)
		m.finish(5)
		must(t, s.merge(ctx, id, m))
		expectNew(t, id, before)
	})
	t.Run("intent then its begin", func(t *testing.T) {
		id := uuid.New()
		before := settled(t, id)
		ir, err := s.intentScanRun(ctx, id, 8)
		must(t, err)
		if ir == "" || ir == before {
			t.Fatalf("intent on an idle SBOM reported %q (before %q)", ir, before)
		}
		br, err := s.beginScanRun(ctx, id, 8, true)
		must(t, err)
		if br != ir {
			t.Fatalf("the begin replacing its intent reported %q, intent %q", br, ir)
		}
		_, err = s.finish(ctx, id, 8, "", nil, ScanCoverage{})
		must(t, err)
		if v := mustGet(t, s, id); v.run != ir {
			t.Fatalf("terminal %q, want %q", v.run, ir)
		}
	})
	t.Run("a finish of the active group keeps it", func(t *testing.T) {
		id := uuid.New()
		must(t, s.begin(ctx, id, 1))
		r := mustGet(t, s, id).run
		must(t, s.begin(ctx, id, 2))
		for _, g := range []uint64{1, 2} {
			_, err := s.finish(ctx, id, g, "", nil, ScanCoverage{})
			must(t, err)
		}
		if v := mustGet(t, s, id); v.run != r || r == "" {
			t.Fatalf("group scan run %q, terminal %q", r, v.run)
		}
	})
}

// Rolling upgrade: an older replica's new group resets the outcomes, and with
// them the scan run: absent, not the previous group's.
func TestScanRunRedis_OldReplicaNewGroupLeavesItAbsent(t *testing.T) {
	rdb := m72Redis(t)
	ctx := context.Background()
	tr, s := runStore(t, rdb, 0)
	old := prevScripts(tr.maxRunAge)
	id := uuid.New()
	keys := scanStatusKeys(id)
	must(t, s.begin(ctx, id, 1))
	_, err := s.finish(ctx, id, 1, "", nil, ScanCoverage{})
	must(t, err)
	before := mustGet(t, s, id)
	must(t, old.begin.Run(ctx, rdb, keys, "2", 90000, 3600000, "0").Err())
	must(t, old.finish.Run(ctx, rdb, keys, "2", 3600000, "", "[]", "[]", "").Err())
	v := mustGet(t, s, id)
	if v.state != before.state || v.run != "" {
		t.Fatalf("after an older replica's group: %+v (before %+v), want the same state without a scan run", v, before)
	}
	// This version's next group gets one again.
	must(t, s.begin(ctx, id, 3))
	if v := mustGet(t, s, id); v.run == "" || v.run == before.run {
		t.Fatalf("this version's next group: %+v", v)
	}
}

// Rolling upgrade, the paths that do NOT reset the group: an older replica's
// intent / revival / rejoin / merge / late finish on an idle SBOM resumes
// activity without touching the outcomes. The scan run must not survive as a
// stale-but-plausible value.
func TestScanRunRedis_OldReplicaResumingAnIdleGroupDropsIt(t *testing.T) {
	rdb := m72Redis(t)
	ctx := context.Background()
	tr, s := runStore(t, rdb, 0)
	old := prevScripts(tr.maxRunAge)

	cases := map[string]func(keys []string) error{
		"intent + begin + finish": func(keys []string) error {
			if err := old.intent.Run(ctx, rdb, keys, "2", 90000, 3600000).Err(); err != nil {
				return err
			}
			if err := old.begin.Run(ctx, rdb, keys, "2", 90000, 3600000, "1").Err(); err != nil {
				return err
			}
			return old.finish.Run(ctx, rdb, keys, "2", 3600000, "", "[]", "[]", "").Err()
		},
		"rejoin + finish": func(keys []string) error {
			if err := old.rejoin.Run(ctx, rdb, keys, "2", 90000, 3600000).Err(); err != nil {
				return err
			}
			return old.finish.Run(ctx, rdb, keys, "2", 3600000, "", "[]", "[]", "").Err()
		},
		"merge": func(keys []string) error {
			return old.merge.Run(ctx, rdb, keys, `{"b":[],"f":["2"],"x":[],"s":[]}`, 90000, 3600000).Err()
		},
		"late finish": func(keys []string) error {
			return old.finish.Run(ctx, rdb, keys, "2", 3600000, "", "[]", "[]", "").Err()
		},
	}
	for name, resume := range cases {
		t.Run(name, func(t *testing.T) {
			id := uuid.New()
			must(t, s.begin(ctx, id, 1))
			_, err := s.finish(ctx, id, 1, "", nil, ScanCoverage{})
			must(t, err)
			before := mustGet(t, s, id)
			if before.run == "" {
				t.Fatal("no scan run to start with")
			}
			must(t, resume(scanStatusKeys(id)))
			if v := mustGet(t, s, id); v.run != "" {
				t.Fatalf("after an older replica resumed the idle SBOM: %+v, want no scan run (was %q)", v, before.run)
			}
		})
	}
}

// An older replica joining (and heartbeating) a running group of this
// version: dropped as well — what it wrote cannot be vouched for — and the
// field stays absent at the terminal state.
func TestScanRunRedis_OldReplicaInAGroupDropsIt(t *testing.T) {
	rdb := m72Redis(t)
	ctx := context.Background()
	tr, s := runStore(t, rdb, 0)
	old := prevScripts(tr.maxRunAge)
	id := uuid.New()
	keys := scanStatusKeys(id)
	must(t, s.begin(ctx, id, 1))
	must(t, old.begin.Run(ctx, rdb, keys, "2", 90000, 3600000, "0").Err())
	must(t, old.heartbeat.Run(ctx, rdb, keys, "2", 90000, 3600000).Err())
	_, err := s.finish(ctx, id, 1, "", nil, ScanCoverage{})
	must(t, err)
	must(t, old.finish.Run(ctx, rdb, keys, "2", 3600000, "", "[]", "[]", "").Err())
	if v := mustGet(t, s, id); v.state != ScanStateCompleted || v.run != "" {
		t.Fatalf("mixed group: %+v", v)
	}
}

// An older replica only READING a settled key (its get changes nothing)
// does not drop the scan run.
func TestScanRunRedis_OldReplicaPlainReadKeepsIt(t *testing.T) {
	rdb := m72Redis(t)
	ctx := context.Background()
	tr, s := runStore(t, rdb, 0)
	old := prevScripts(tr.maxRunAge)
	id := uuid.New()
	must(t, s.begin(ctx, id, 1))
	_, err := s.finish(ctx, id, 1, "", nil, ScanCoverage{})
	must(t, err)
	before := mustGet(t, s, id)
	must(t, old.get.Run(ctx, rdb, scanStatusKeys(id)).Err())
	if v := mustGet(t, s, id); v.run != before.run {
		t.Fatalf("an older replica's plain read changed the scan run: %q -> %q", before.run, v.run)
	}
}

// An older replica's legacy mark (DEL) leaves no scan run.
func TestScanRunRedis_OldReplicaMarkLeavesItAbsent(t *testing.T) {
	rdb := m72Redis(t)
	ctx := context.Background()
	tr, s := runStore(t, rdb, 0)
	old := prevScripts(tr.maxRunAge)
	id := uuid.New()
	must(t, s.begin(ctx, id, 1))
	must(t, old.mark.Run(ctx, rdb, scanStatusKeys(id), "completed", "", "[]", 3600000).Err())
	if v := mustGet(t, s, id); v.state != ScanStateCompleted || v.run != "" {
		t.Fatalf("after an older replica's mark: %+v", v)
	}
}

// Key loss (eviction, FLUSHDB): the live run rejoins a fresh key with a NEW
// scan run; a finish recreating a lost key gets one too. Neither repeats the
// lost key's, even though the fresh key's rev counter starts over (the scan
// run depends on no Redis counter or clock).
func TestScanRunRedis_KeyLoss(t *testing.T) {
	rdb := m72Redis(t)
	ctx := context.Background()
	_, s := runStore(t, rdb, 0)

	id := uuid.New()
	must(t, s.begin(ctx, id, 1))
	lost := mustGet(t, s, id)
	must(t, rdb.Del(ctx, scanStatusKeys(id)...).Err())
	must(t, s.rejoin(ctx, id, 1))
	v := mustGet(t, s, id)
	if v.state != ScanStateRunning || v.run == "" || v.run == lost.run {
		t.Fatalf("rejoin after key loss: %+v (lost %q)", v, lost.run)
	}

	id2 := uuid.New()
	must(t, s.begin(ctx, id2, 1))
	first := mustGet(t, s, id2)
	must(t, rdb.Del(ctx, scanStatusKeys(id2)...).Err())
	_, err := s.finish(ctx, id2, 1, "", nil, ScanCoverage{})
	must(t, err)
	if v := mustGet(t, s, id2); v.run == "" || v.run == first.run {
		t.Fatalf("finish on a lost key: %+v (lost %q)", v, first.run)
	}

	// Same rev on a recreated key, different scan run.
	id3 := uuid.New()
	must(t, s.begin(ctx, id3, 1))
	r1, _ := rdb.HGet(ctx, scanStatusKeys(id3)[0], "rev").Result()
	g1 := mustGet(t, s, id3).run
	must(t, rdb.Del(ctx, scanStatusKeys(id3)...).Err())
	must(t, s.begin(ctx, id3, 2))
	r2, _ := rdb.HGet(ctx, scanStatusKeys(id3)[0], "rev").Result()
	if g2 := mustGet(t, s, id3).run; r1 != r2 || g2 == "" || g2 == g1 {
		t.Fatalf("recreated key: rev %s/%s, scan run %q/%q", r1, r2, g1, g2)
	}
}

// BeginRun behind older writes of the SBOM (its intent answers within the
// wait): it reports the scan run its intent found, and that is what
// scan-status then reports.
func TestScanRunRedis_QueuedBeginReportsTheIntentsScanRun(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 0, time.Hour)
	id := uuid.New()
	g1 := a.Begin(id)
	// Hold the queue busy so the next Begin is queued behind it.
	a.qMu.Lock()
	q := a.queues[id]
	if q == nil {
		q = &sbomQueue{}
		a.queues[id] = q
	}
	q.draining = true
	a.qMu.Unlock()
	a.Finish(id, g1, nil, "")
	g2, run := a.BeginRun(id)
	if run == "" {
		t.Fatal("queued BeginRun reported no scan run")
	}
	a.qMu.Lock()
	q.draining = false
	a.qMu.Unlock()
	a.kickQueues()
	a.Finish(id, g2, nil, "")
	if st := statusFrom(process(rdb, 0, time.Hour), id, a); st.State != ScanStateCompleted || st.Run != run {
		t.Fatalf("status %+v, want completed with %q", st, run)
	}
}

// With Redis unreadable, the process's own memory answers: without a scan
// run (it cannot speak for the shared group).
func TestScanRunRedis_LocalFallbackHasNoScanRun(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 0, time.Hour)
	id := uuid.New()
	g := a.Begin(id)
	if st := a.GetStatus(id); st.State != ScanStateRunning || st.Run != "" {
		t.Fatalf("local active run answered %+v, want running without a scan run", st)
	}
	a.Finish(id, g, []string{ScanReasonFetchFailed}, "nvd: scan failed (fetch_failed)")
	statusFrom(a, id, a)
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 50 * time.Millisecond})
	t.Cleanup(func() { _ = dead.Close() })
	a.shared.(*redisScanStatusStore).client = dead
	if st := a.GetStatus(id); st.State != ScanStateFailed || st.Run != "" {
		t.Fatalf("fallback answered %+v, want failed without a scan run", st)
	}
}
