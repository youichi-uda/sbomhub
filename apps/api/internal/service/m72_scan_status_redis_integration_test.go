//go:build integration

package service

import (
	"context"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// M72: the scan-status store on a real Redis. Each tracker stands for one API
// process; they share only Redis.

func m72Redis(t *testing.T) *redis.Client {
	t.Helper()
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("requires REDIS_URL")
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	c := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		t.Fatalf("redis unreachable: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// process returns a tracker on rdb with the given lease (0 = default) whose
// heartbeat loop ticks every hb.
func process(rdb *redis.Client, lease, hb time.Duration) *ScanTracker {
	t := NewScanTracker().WithRedis(rdb)
	// No young-key hold here (TestM72R19_EvictionYoungKeyAndVersions covers
	// it): these tests read completed right after a fresh key's finish.
	t.shared.(*redisScanStatusStore).scripts = newStatusScriptsYoung(t.maxRunAge, 0)
	t.shared.(*redisScanStatusStore).immediate = nil // the override applies whatever Redis's eviction settings
	if lease > 0 {
		t.shared.(*redisScanStatusStore).lease = lease
	}
	t.hbInterval = hb
	return t
}

// detail reads tr's view of id once every tracker's writes of id landed (the
// shared writes are asynchronous).
func detail(tr *ScanTracker, id uuid.UUID, writers ...*ScanTracker) (ScanState, string, []string) {
	for _, w := range writers {
		deadline := time.Now().Add(5 * time.Second)
		for w.pendingShared(id) && time.Now().Before(deadline) {
			time.Sleep(2 * time.Millisecond)
		}
	}
	return tr.GetDetail(id)
}

func TestM72Redis_StatusCrossesProcessesAndRestarts(t *testing.T) {
	rdb := m72Redis(t)
	a, b := process(rdb, 0, time.Hour), process(rdb, 0, time.Hour)
	id := uuid.New()

	gen := a.Begin(id)
	if st, _, _ := detail(b, id, a); st != ScanStateRunning {
		t.Fatalf("B while A scans: %s", st)
	}
	a.Finish(id, gen, []string{ScanReasonDeadlineExceeded}, "nvd: scan failed (deadline_exceeded)")
	st, msg, r := detail(b, id, a)
	if st != ScanStateFailed || msg != "nvd: scan failed (deadline_exceeded)" || !slices.Equal(r, []string{ScanReasonDeadlineExceeded}) {
		t.Fatalf("B after A failed: %s %q %v", st, msg, r)
	}
	restarted := process(rdb, 0, time.Hour)
	if st, _, _ := detail(restarted, id, a); st != ScanStateFailed {
		t.Fatalf("after a restart: %s", st)
	}
	ttl := rdb.PTTL(context.Background(), scanStatusKeys(id)[0]).Val()
	if ttl <= 0 || ttl > time.Hour {
		t.Fatalf("status key TTL %s, want (0, 1h]", ttl)
	}
}

// Overlapping runs on two processes: running until both ended, then failed if
// either failed, whatever the order.
func TestM72Redis_OverlappingRunsAcrossProcesses(t *testing.T) {
	rdb := m72Redis(t)
	a, b, reader := process(rdb, 0, time.Hour), process(rdb, 0, time.Hour), process(rdb, 0, time.Hour)
	id := uuid.New()
	ga := a.Begin(id)
	gb := b.Begin(id)
	a.Finish(id, ga, []string{ScanReasonFetchFailed}, "jvn: scan failed (fetch_failed)")
	if st, _, _ := detail(reader, id, a, b); st != ScanStateRunning {
		t.Fatalf("one run still active: %s, want running", st)
	}
	b.Finish(id, gb, nil, "")
	st, msg, r := detail(reader, id, a, b)
	if st != ScanStateFailed || msg != "jvn: scan failed (fetch_failed)" || !slices.Equal(r, []string{ScanReasonFetchFailed}) {
		t.Fatalf("group outcome: %s %q %v", st, msg, r)
	}
	// A new scan starts a new group.
	g := b.Begin(id)
	b.Finish(id, g, nil, "")
	if st, _, _ := detail(reader, id, a, b); st != ScanStateCompleted {
		t.Fatalf("new group: %s", st)
	}
}

// A process that dies mid-scan (no heartbeat, no Finish): once its lease runs
// out every reader sees failed (interrupted), not running forever.
func TestM72Redis_DeadProcessReadsInterrupted(t *testing.T) {
	rdb := m72Redis(t)
	dying := process(rdb, 300*time.Millisecond, time.Hour) // never heartbeats in time
	reader := process(rdb, 0, time.Hour)
	id := uuid.New()
	dying.Begin(id)
	if st, _, _ := detail(reader, id, dying); st != ScanStateRunning {
		t.Fatalf("within the lease: %s", st)
	}
	time.Sleep(450 * time.Millisecond)
	st, msg, r := detail(reader, id, dying)
	if st != ScanStateFailed || msg != "scan: scan failed (interrupted)" || !slices.Equal(r, []string{ScanReasonInterrupted}) {
		t.Fatalf("after the lease: %s %q %v", st, msg, r)
	}
}

// A run that was alive but could not renew (Redis unreachable from its
// process longer than the lease) is revived by its next heartbeat, and its
// real outcome replaces "interrupted".
func TestM72Redis_LapsedRunIsRevivedAndReportsItsOutcome(t *testing.T) {
	rdb := m72Redis(t)
	slow := process(rdb, 200*time.Millisecond, time.Hour)
	reader := process(rdb, 0, time.Hour)
	id := uuid.New()
	gen := slow.Begin(id)
	time.Sleep(300 * time.Millisecond)
	if st, _, _ := detail(reader, id, slow); st != ScanStateFailed {
		t.Fatalf("lapsed: %s, want failed (interrupted)", st)
	}
	// The heartbeat comes back.
	slow.heartbeatPass()
	if st, _, _ := detail(reader, id, slow); st != ScanStateRunning {
		t.Fatalf("revived: %s, want running", st)
	}
	slow.Finish(id, gen, nil, "")
	if st, msg, _ := detail(reader, id, slow); st != ScanStateCompleted {
		t.Fatalf("after its finish: %s %q", st, msg)
	}

	// Lapsed and NOT revived before finishing: its finish still replaces the
	// interrupted outcome.
	id2 := uuid.New()
	g2 := slow.Begin(id2)
	time.Sleep(300 * time.Millisecond)
	if st, _, _ := detail(reader, id2, slow); st != ScanStateFailed {
		t.Fatalf("lapsed: %s", st)
	}
	slow.Finish(id2, g2, nil, "")
	if st, _, _ := detail(reader, id2, slow); st != ScanStateCompleted {
		t.Fatalf("late finish of a lapsed run: %s, want completed", st)
	}
}

// The heartbeat loop keeps a long scan alive past the lease.
func TestM72Redis_HeartbeatKeepsALongScanRunning(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 200*time.Millisecond, 50*time.Millisecond)
	reader := process(rdb, 0, time.Hour)
	id := uuid.New()
	gen := a.Begin(id)
	time.Sleep(700 * time.Millisecond)
	if st, _, _ := detail(reader, id, a); st != ScanStateRunning {
		t.Fatalf("after 3.5 leases with heartbeats: %s, want running", st)
	}
	a.Finish(id, gen, nil, "")
	if st, _, _ := detail(reader, id, a); st != ScanStateCompleted {
		t.Fatalf("%s", st)
	}
}

// MarkFailed outside a run (upload without a tenant) is shared too.
func TestM72Redis_MarkFailedIsShared(t *testing.T) {
	rdb := m72Redis(t)
	a, b := process(rdb, 0, time.Hour), process(rdb, 0, time.Hour)
	id := uuid.New()
	a.MarkFailed(id, "tenant context missing")
	if st, msg, _ := detail(b, id, a); st != ScanStateFailed || msg != "tenant context missing" {
		t.Fatalf("%s %q", st, msg)
	}
}

// Codex M72 R2 High-3: runs that fail the same way (queue_full while one
// scan is active) must not grow the shared entry without bound.
func TestM72R2_RepeatedFailuresDoNotGrowTheEntry(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 0, time.Hour)
	id := uuid.New()
	a.Begin(id) // the long scan
	for i := 0; i < 200; i++ {
		g := a.Begin(id)
		a.Finish(id, g, []string{ScanReasonQueueFull}, "scan: scan failed (queue_full)")
	}
	reader := process(rdb, 0, time.Hour)
	if st, _, _ := detail(reader, id, a); st != ScanStateRunning {
		t.Fatalf("%s", st)
	}
	raw := rdb.HGet(context.Background(), scanStatusKeys(id)[0], "outcomes").Val()
	if len(raw) > 512 {
		t.Fatalf("outcomes grew to %d bytes after 200 identical failures: %.200s", len(raw), raw)
	}
	a.mu.RLock()
	n := len(a.entries[id].groupMsgs)
	a.mu.RUnlock()
	if n > 1 {
		t.Fatalf("in-memory group kept %d copies of one marker", n)
	}
}

// Codex M72 R3 Medium-2: runs swept as interrupted do not grow the entry
// without bound either.
func TestM72R3_ManyInterruptedRunsStayBounded(t *testing.T) {
	rdb := m72Redis(t)
	long := process(rdb, 0, 50*time.Millisecond)
	crashing := process(rdb, 30*time.Millisecond, time.Hour)
	reader := process(rdb, 0, time.Hour)
	id := uuid.New()
	g := long.Begin(id)
	for i := 0; i < 200; i++ {
		crashing.Begin(id)
	}
	time.Sleep(100 * time.Millisecond)
	if st, _, _ := detail(reader, id, long, crashing); st != ScanStateRunning {
		t.Fatalf("%s, want running (the long scan is alive)", st)
	}
	keys := scanStatusKeys(id)
	raw := rdb.HGet(context.Background(), keys[0], "outcomes").Val()
	lost := countLost(t, rdb, id)
	if len(raw) > 512 || lost > scanStatusMaxLost {
		t.Fatalf("after 200 interrupted runs: outcomes %d bytes, %d lost ids", len(raw), lost)
	}
	long.Finish(id, g, nil, "")
	st, msg, r := detail(reader, id, long)
	if st != ScanStateFailed || msg != "scan: scan failed (interrupted)" || !slices.Equal(r, []string{ScanReasonInterrupted}) {
		t.Fatalf("group outcome %s %q %v, want failed (interrupted)", st, msg, r)
	}
}

// Codex M72 R4 High-3: a live run whose identity was dropped from the capped
// lost set rejoins the CURRENT group; it must not start a new one and erase
// the group's interruptions.
func TestM72R4_RejoinKeepsTheGroupsInterruptions(t *testing.T) {
	rdb := m72Redis(t)
	live := process(rdb, 60*time.Millisecond, time.Hour)
	dead := process(rdb, 60*time.Millisecond, time.Hour)
	reader := process(rdb, 0, time.Hour)
	id := uuid.New()
	g := live.Begin(id)
	dead.Begin(id)
	time.Sleep(120 * time.Millisecond)
	if st, _, _ := detail(reader, id, live, dead); st != ScanStateFailed {
		t.Fatalf("both lapsed: %s", st)
	}
	// The live run's identity is the one the cap dropped.
	keys := scanStatusKeys(id)
	rdb.HDel(context.Background(), keys[0], "l:"+genString(g))
	rdb.HSet(context.Background(), keys[0], "lost_dropped", time.Now().UnixMilli())
	live.heartbeatPass() // inactive -> rejoin (written out of line since R20)
	waitFor(t, "the rejoin", func() bool {
		st, _, _ := detail(reader, id, live)
		return st == ScanStateRunning
	})
	live.Finish(id, g, nil, "")
	st, msg, _ := detail(reader, id, live)
	if st != ScanStateFailed || msg != "scan: scan failed (interrupted)" {
		t.Fatalf("group outcome %s %q, want failed (interrupted): the dead run's interruption was erased", st, msg)
	}
}

// Codex M72 R4 Medium-4: the lost-run key a read creates expires with the
// entry.
func TestM72R4_LostKeyCreatedByAReadExpires(t *testing.T) {
	rdb := m72Redis(t)
	dead := process(rdb, 30*time.Millisecond, time.Hour)
	reader := process(rdb, 0, time.Hour)
	id := uuid.New()
	dead.Begin(id)
	time.Sleep(60 * time.Millisecond)
	detail(reader, id, dead)
	if ttl := rdb.PTTL(context.Background(), scanStatusKeys(id)[0]).Val(); ttl <= 0 {
		t.Fatalf("status key PTTL %s after a sweeping read, want a positive TTL", ttl)
	}
}

// Codex M72 R5 High-2: a finish Redis does not know (its run lapsed and a new
// group started, and the rejoin never happened) still contributes its
// failure; it is never dropped.
func TestM72R5_UnknownFinishStillCountsItsFailure(t *testing.T) {
	rdb := m72Redis(t)
	lapsing := process(rdb, 40*time.Millisecond, time.Hour)
	other := process(rdb, 0, time.Hour)
	reader := process(rdb, 0, time.Hour)
	id := uuid.New()
	ga := lapsing.Begin(id)
	time.Sleep(80 * time.Millisecond)
	detail(reader, id, lapsing) // sweeps A as interrupted
	gb := other.Begin(id)       // no active run: a new group
	settle(t, other, id)
	lapsing.Finish(id, ga, []string{ScanReasonFetchFailed}, "nvd: scan failed (fetch_failed)")
	other.Finish(id, gb, nil, "")
	st, msg, _ := detail(reader, id, lapsing, other)
	if st != ScanStateFailed || !strings.Contains(msg, "nvd: scan failed (fetch_failed)") {
		t.Fatalf("group outcome %s %q, want failed with A's failure", st, msg)
	}
}

// Codex M72 R8 High-1c: a retried begin of a run already swept as interrupted
// rejoins the group; it does not start a new one and erase the group's other
// interruptions.
func TestM72R8_RetriedBeginOfALostRunRejoins(t *testing.T) {
	rdb := m72Redis(t)
	p := process(rdb, 40*time.Millisecond, time.Hour)
	reader := process(rdb, 0, time.Hour)
	id := uuid.New()
	p.Begin(id) // dies
	ga := p.Begin(id)
	time.Sleep(80 * time.Millisecond)
	detail(reader, id, p)                                                // both swept as interrupted
	if err := p.shared.begin(context.Background(), id, ga); err != nil { // A's begin, retried
		t.Fatal(err)
	}
	if _, err := p.shared.finish(context.Background(), id, ga, "", nil); err != nil {
		t.Fatal(err)
	}
	st, msg, _ := reader.GetDetail(id)
	if st != ScanStateFailed || msg != "scan: scan failed (interrupted)" {
		t.Fatalf("%s %q, want failed (interrupted): the dead run's interruption was erased", st, msg)
	}
}

// Codex M72 R10 High-1: a new group does not erase the tombstone of a run
// swept as interrupted that may still be alive (a suspended process). Until
// that run rejoins or finishes — or is older than any scan can run — the
// SBOM reads failed (interrupted), not completed.
func TestM72R10_NewGroupKeepsLiveTombstones(t *testing.T) {
	rdb := m72Redis(t)
	suspended := process(rdb, 40*time.Millisecond, time.Hour)
	other := process(rdb, 0, time.Hour)
	reader := process(rdb, 0, time.Hour)
	id := uuid.New()
	ga := suspended.Begin(id)
	time.Sleep(80 * time.Millisecond)
	detail(reader, id, suspended) // A swept as interrupted
	other.Finish(id, other.Begin(id), nil, "")
	if st, msg, _ := detail(reader, id, other); st != ScanStateFailed || msg != "scan: scan failed (interrupted)" {
		t.Fatalf("B completed while A may still run: %s %q, want failed (interrupted)", st, msg)
	}
	suspended.Finish(id, ga, nil, "") // A resumes and finishes
	if st, _, _ := detail(reader, id, suspended); st != ScanStateCompleted {
		t.Fatalf("after A finished: %s, want completed", st)
	}

	// A tombstone older than any scan can run no longer taints new scans.
	short := process(rdb, 40*time.Millisecond, time.Hour)
	setMaxRunAge(short, 150*time.Millisecond)
	sweeper := process(rdb, 0, time.Hour)
	setMaxRunAge(sweeper, 150*time.Millisecond)
	id2 := uuid.New()
	dead := process(rdb, 40*time.Millisecond, time.Hour)
	dead.Begin(id2)
	time.Sleep(80 * time.Millisecond)
	detail(sweeper, id2, dead) // swept: a tombstone
	time.Sleep(200 * time.Millisecond)
	short.Finish(id2, short.Begin(id2), nil, "")
	if st, msg, _ := detail(reader, id2, short); st != ScanStateCompleted {
		t.Fatalf("with only an expired tombstone: %s %q, want completed", st, msg)
	}
}

// setMaxRunAge rebuilds tr's scripts for a different tombstone age.
func setMaxRunAge(tr *ScanTracker, d time.Duration) {
	tr.shared.(*redisScanStatusStore).scripts = newStatusScriptsYoung(d, 0)
	tr.shared.(*redisScanStatusStore).immediate = nil
}

// Codex M72 R11 High-1: the status of one SBOM is ONE Redis key (evicted all
// or nothing), and a missing entry does not let a stale local "completed"
// through while another replica may be scanning.
func TestM72R11_EvictionNeverYieldsAStaleCompleted(t *testing.T) {
	rdb := m72Redis(t)
	if n := len(scanStatusKeys(uuid.New())); n != 1 {
		t.Fatalf("the status is spread over %d keys; partial eviction could split it", n)
	}
	a, b := process(rdb, 0, time.Hour), process(rdb, 0, time.Hour)
	id := uuid.New()
	a.Finish(id, a.Begin(id), nil, "") // A's earlier scan: local completed
	settle(t, a, id)
	b.Begin(id) // B scans now
	settle(t, b, id)
	rdb.Del(context.Background(), scanStatusKeys(id)...) // evicted
	if st, _, _ := a.GetDetail(id); st == ScanStateCompleted {
		t.Fatal("A answered its stale local completed while B scans (entry evicted)")
	}
}

// countLost counts the tombstones (l:<gen> fields) of id's status.
func countLost(t *testing.T, rdb *redis.Client, id uuid.UUID) int64 {
	t.Helper()
	keys, err := rdb.HKeys(context.Background(), scanStatusKeys(id)[0]).Result()
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, k := range keys {
		if strings.HasPrefix(k, "l:") {
			n++
		}
	}
	return n
}

// Codex M72 R12 Medium-2: a lease renewal pass does not load its script every
// time (one SCRIPT LOAD per pass shared the pass's deadline and reset the
// breaker's count); it loads only after NOSCRIPT.
func TestM72R12_RenewalDoesNotReloadItsScript(t *testing.T) {
	rdb := m72Redis(t)
	var single atomic.Int64
	rdb.AddHook(singleCmdHook{&single})
	a := process(rdb, 0, time.Hour)
	for i := 0; i < 5; i++ {
		a.Begin(uuid.New())
	}
	a.heartbeatPass() // may load once
	single.Store(0)
	a.heartbeatPass()
	if n := single.Load(); n != 0 {
		t.Fatalf("a renewal pass issued %d non-pipelined commands (a script load), want 0", n)
	}
}

// singleCmdHook counts commands sent outside a pipeline.
type singleCmdHook struct{ n *atomic.Int64 }

func (h singleCmdHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h singleCmdHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error { h.n.Add(1); return next(ctx, cmd) }
}
func (h singleCmdHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// Codex M72 R14 High-1: the shared status version changes with EVERY write,
// even two in the same millisecond.
func TestM72R14_SharedVersionIsUniquePerWrite(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 0, time.Hour)
	store := a.shared.(*redisScanStatusStore)
	ctx := context.Background()
	id := uuid.New()
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		g := uint64(i + 1)
		if err := store.begin(ctx, id, g); err != nil {
			t.Fatal(err)
		}
		v1, _ := store.get(ctx, id)
		if _, err := store.finish(ctx, id, g, "", nil); err != nil {
			t.Fatal(err)
		}
		v2, _ := store.get(ctx, id)
		for _, v := range []string{v1.version, v2.version} {
			if seen[v] {
				t.Fatalf("version %q repeated across writes", v)
			}
			seen[v] = true
		}
	}
}

// Codex M72 R15 Medium-3: sweeping many expired runs is one pass, not one
// full hash read per run.
func TestM72R15_SweepingManyRunsIsCheap(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 0, time.Hour)
	store := a.shared.(*redisScanStatusStore)
	ctx := context.Background()
	id := uuid.New()
	// 2000 runs with a 1ms lease, written directly (one pipeline).
	key := scanStatusKeys(id)[0]
	now := time.Now().UnixMilli()
	pipe := rdb.Pipeline()
	pipe.HSet(ctx, key, "state", "running", "error", "", "reasons", "[]", "updated", now, "outcomes", "[]")
	for i := 1; i <= 2000; i++ {
		pipe.HSet(ctx, key, "r:"+genString(uint64(i)), now-1000)
	}
	pipe.PExpire(ctx, key, time.Hour)
	if _, err := pipe.Exec(ctx); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	v, err := store.get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("sweeping 2000 expired runs took %s", d)
	}
	if v.state != ScanStateFailed {
		t.Fatalf("after sweeping: %s, want failed (interrupted)", v.state)
	}
	if lost := countLost(t, rdb, id); lost > scanStatusMaxLost {
		t.Fatalf("%d tombstones kept, cap %d", lost, scanStatusMaxLost)
	}
}

// Codex M72 R18 High-1 (Redis side): an intent reads running and keeps older
// writes from publishing a terminal state; the queued Begin replaces it; an
// intent whose process died reads interrupted.
func TestM72R18_IntentReadsRunningUntilItsBeginLands(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 0, time.Hour)
	store := a.shared.(*redisScanStatusStore)
	ctx := context.Background()
	id := uuid.New()
	if err := store.begin(ctx, id, 1); err != nil { // an older run
		t.Fatal(err)
	}
	if err := store.intent(ctx, id, 2); err != nil { // the new Begin, ahead of the queue
		t.Fatal(err)
	}
	if _, err := store.finish(ctx, id, 1, "", nil); err != nil { // the older write lands
		t.Fatal(err)
	}
	if v, _ := store.get(ctx, id); v.state != ScanStateRunning {
		t.Fatalf("older finish with an intent present: %s, want running", v.state)
	}
	if err := store.begin(ctx, id, 2); err != nil { // the queued Begin lands
		t.Fatal(err)
	}
	if _, err := store.finish(ctx, id, 2, "", nil); err != nil {
		t.Fatal(err)
	}
	if v, _ := store.get(ctx, id); v.state != ScanStateCompleted {
		t.Fatalf("after the run finished: %s, want completed", v.state)
	}

	short := process(rdb, 30*time.Millisecond, time.Hour)
	id2 := uuid.New()
	if err := short.shared.intent(ctx, id2, 9); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if v, _ := store.get(ctx, id2); v.state != ScanStateFailed || v.errMsg != "scan: scan failed (interrupted)" {
		t.Fatalf("an intent whose lease ran out: %s %q, want failed (interrupted)", v.state, v.errMsg)
	}
}

// Codex M72 R19 High-1: a queued Begin replacing its intent joins the group
// the intent was part of; it does not start a new group and drop a failure.
func TestM72R19_BeginReplacingItsIntentKeepsTheGroup(t *testing.T) {
	rdb := m72Redis(t)
	store := process(rdb, 0, time.Hour).shared.(*redisScanStatusStore)
	ctx := context.Background()
	id := uuid.New()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(store.begin(ctx, id, 1))  // A runs
	must(store.intent(ctx, id, 2)) // B's Begin is queued; its intent lands
	_, err := store.finish(ctx, id, 1, "nvd: scan failed (fetch_failed)", []string{ScanReasonFetchFailed})
	must(err)
	must(store.begin(ctx, id, 2)) // B's queued Begin lands
	_, err = store.finish(ctx, id, 2, "", nil)
	must(err)
	if v, _ := store.get(ctx, id); v.state != ScanStateFailed {
		t.Fatalf("group outcome %s, want failed (A's failure)", v.state)
	}
}

// Codex M72 R19 High-2: after the status key was evicted, a short scan that
// recreates it cannot publish completed before the evicted runs could have
// rejoined (one heartbeat), and versions never repeat across incarnations.
func TestM72R19_EvictionYoungKeyAndVersions(t *testing.T) {
	rdb := m72Redis(t)
	a := process(rdb, 0, time.Hour)
	store := a.shared.(*redisScanStatusStore)
	store.scripts = newStatusScriptsYoung(DefaultScanDeadline+5*time.Minute, 300*time.Millisecond)
	store.probe, store.immediate = false, nil // exercise the hold whatever the test Redis's settings
	ctx := context.Background()
	id := uuid.New()
	if err := store.begin(ctx, id, 1); err != nil { // A runs
		t.Fatal(err)
	}
	before, _ := store.get(ctx, id)
	rdb.Del(ctx, scanStatusKeys(id)...) // evicted
	if err := store.begin(ctx, id, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.finish(ctx, id, 2, "", nil); err != nil {
		t.Fatal(err)
	}
	v, _ := store.get(ctx, id)
	if v.state == ScanStateCompleted {
		t.Fatal("completed right after the key was recreated, while an evicted run may still be scanning")
	}
	if v.version == before.version {
		t.Fatalf("version %q repeated across key incarnations", v.version)
	}
	time.Sleep(350 * time.Millisecond)
	if v, _ := store.get(ctx, id); v.state != ScanStateCompleted {
		t.Fatalf("after the young window with no run back: %s, want completed", v.state)
	}
}

// CI Web E2E (6ed0ece): on a Redis that cannot evict (the test Redis runs
// with maxmemory 0), a fast scan of a new SBOM reads completed at once, not
// after the 75s young-key hold.
func TestM72NoEvictionRedisSkipsYoungHold(t *testing.T) {
	rdb := m72Redis(t)
	store := &redisScanStatusStore{client: rdb, ttl: time.Hour, lease: ScanStatusLease}
	store.initScripts(DefaultScanDeadline + 5*time.Minute)
	if !store.probeNoEviction() {
		t.Skip("test Redis can evict keys")
	}
	store.noEvict.Store(true)
	ctx := context.Background()
	id := uuid.New()
	if err := store.begin(ctx, id, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.finish(ctx, id, 1, "", nil); err != nil {
		t.Fatal(err)
	}
	if v, _ := store.get(ctx, id); v.state != ScanStateCompleted {
		t.Fatalf("fresh key on a no-eviction Redis: %s, want completed", v.state)
	}
	// While eviction is possible (or unknown), the hold still applies.
	store.noEvict.Store(false)
	id2 := uuid.New()
	if err := store.begin(ctx, id2, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.finish(ctx, id2, 1, "", nil); err != nil {
		t.Fatal(err)
	}
	if v, _ := store.get(ctx, id2); v.state != ScanStateRunning {
		t.Fatalf("fresh key, eviction possible: %s, want running (young hold)", v.state)
	}
}

// Codex M72 eviction R1 Medium-1: the first probe runs before WithRedis
// returns, so the very first scan already uses what Redis reports.
func TestM72WithRedisProbesBeforeFirstScan(t *testing.T) {
	rdb := m72Redis(t)
	ctx := context.Background()
	cfg, err := rdb.ConfigGet(ctx, "maxmemory*").Result()
	if err != nil || !redisCannotEvict(cfg) {
		t.Skip("test Redis can evict keys or refuses CONFIG")
	}
	tr := NewScanTracker().WithRedis(rdb)
	if !tr.shared.(*redisScanStatusStore).noEvict.Load() {
		t.Fatal("WithRedis returned before learning that Redis cannot evict")
	}
}

// Codex M72 eviction R1 Medium-2: a young key completed while Redis could not
// evict reads running again once the holding scripts are back in use (Redis
// became able to evict, or stopped answering CONFIG), until it is no longer
// young. A held key reads completed as soon as the immediate scripts apply.
func TestM72YoungHoldFollowsModeSwitches(t *testing.T) {
	rdb := m72Redis(t)
	store := &redisScanStatusStore{client: rdb, ttl: time.Hour, lease: ScanStatusLease}
	maxAge := DefaultScanDeadline + 5*time.Minute
	store.scripts = newStatusScriptsYoung(maxAge, 400*time.Millisecond)
	store.immediate = newStatusScriptsSpan(maxAge, 0, 400*time.Millisecond)
	ctx := context.Background()
	run := func(id uuid.UUID) {
		if err := store.begin(ctx, id, 1); err != nil {
			t.Fatal(err)
		}
		if _, err := store.finish(ctx, id, 1, "", nil); err != nil {
			t.Fatal(err)
		}
	}
	state := func(id uuid.UUID) ScanState {
		v, err := store.get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return v.state
	}
	// immediate → holding
	store.noEvict.Store(true)
	a := uuid.New()
	run(a)
	if s := state(a); s != ScanStateCompleted {
		t.Fatalf("immediate: %s, want completed", s)
	}
	store.noEvict.Store(false)
	if s := state(a); s != ScanStateRunning {
		t.Fatalf("back to holding while young: %s, want running", s)
	}
	// holding → immediate
	b := uuid.New()
	run(b)
	if s := state(b); s != ScanStateRunning {
		t.Fatalf("holding: %s, want running", s)
	}
	store.noEvict.Store(true)
	if s := state(b); s != ScanStateCompleted {
		t.Fatalf("switched to immediate: %s, want completed", s)
	}
	// Once no longer young, completed in either mode.
	time.Sleep(450 * time.Millisecond)
	store.noEvict.Store(false)
	if s := state(a); s != ScanStateCompleted {
		t.Fatalf("aged out, holding: %s, want completed", s)
	}
	// A direct mark is not re-held.
	c := uuid.New()
	if err := store.mark(ctx, c, ScanStateCompleted, "", nil); err != nil {
		t.Fatal(err)
	}
	if s := state(c); s != ScanStateCompleted {
		t.Fatalf("marked completed: %s", s)
	}
}
