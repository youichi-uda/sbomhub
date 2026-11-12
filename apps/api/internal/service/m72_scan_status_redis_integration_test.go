//go:build integration

package service

import (
	"context"
	"os"
	"slices"
	"strings"
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
	lost := rdb.ZCard(context.Background(), keys[0]+":lost").Val()
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
	rdb.ZRem(context.Background(), keys[2], genString(g))
	rdb.HSet(context.Background(), keys[0], "lost_dropped", "1")
	live.heartbeatPass() // inactive -> rejoin
	if st, _, _ := detail(reader, id, live); st != ScanStateRunning {
		t.Fatalf("after rejoin: %s, want running", st)
	}
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
	if ttl := rdb.PTTL(context.Background(), scanStatusKeys(id)[2]).Val(); ttl <= 0 {
		t.Fatalf(":lost PTTL %s, want a positive TTL", ttl)
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
