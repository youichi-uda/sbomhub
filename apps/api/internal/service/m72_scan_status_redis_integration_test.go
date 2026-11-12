//go:build integration

package service

import (
	"context"
	"os"
	"slices"
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

func detail(tr *ScanTracker, id uuid.UUID) (ScanState, string, []string) { return tr.GetDetail(id) }

func TestM72Redis_StatusCrossesProcessesAndRestarts(t *testing.T) {
	rdb := m72Redis(t)
	a, b := process(rdb, 0, time.Hour), process(rdb, 0, time.Hour)
	id := uuid.New()

	gen := a.Begin(id)
	if st, _, _ := detail(b, id); st != ScanStateRunning {
		t.Fatalf("B while A scans: %s", st)
	}
	a.Finish(id, gen, []string{ScanReasonDeadlineExceeded}, "nvd: scan failed (deadline_exceeded)")
	st, msg, r := detail(b, id)
	if st != ScanStateFailed || msg != "nvd: scan failed (deadline_exceeded)" || !slices.Equal(r, []string{ScanReasonDeadlineExceeded}) {
		t.Fatalf("B after A failed: %s %q %v", st, msg, r)
	}
	restarted := process(rdb, 0, time.Hour)
	if st, _, _ := detail(restarted, id); st != ScanStateFailed {
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
	if st, _, _ := detail(reader, id); st != ScanStateRunning {
		t.Fatalf("one run still active: %s, want running", st)
	}
	b.Finish(id, gb, nil, "")
	st, msg, r := detail(reader, id)
	if st != ScanStateFailed || msg != "jvn: scan failed (fetch_failed)" || !slices.Equal(r, []string{ScanReasonFetchFailed}) {
		t.Fatalf("group outcome: %s %q %v", st, msg, r)
	}
	// A new scan starts a new group.
	g := b.Begin(id)
	b.Finish(id, g, nil, "")
	if st, _, _ := detail(reader, id); st != ScanStateCompleted {
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
	if st, _, _ := detail(reader, id); st != ScanStateRunning {
		t.Fatalf("within the lease: %s", st)
	}
	time.Sleep(450 * time.Millisecond)
	st, msg, r := detail(reader, id)
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
	if st, _, _ := detail(reader, id); st != ScanStateFailed {
		t.Fatalf("lapsed: %s, want failed (interrupted)", st)
	}
	// The heartbeat comes back.
	k := runKey{id, gen}
	slow.hbMu.Lock()
	r := slow.synced[k]
	slow.hbMu.Unlock()
	slow.syncRun(k, r, true)
	if st, _, _ := detail(reader, id); st != ScanStateRunning {
		t.Fatalf("revived: %s, want running", st)
	}
	slow.Finish(id, gen, nil, "")
	if st, msg, _ := detail(reader, id); st != ScanStateCompleted {
		t.Fatalf("after its finish: %s %q", st, msg)
	}

	// Lapsed and NOT revived before finishing: its finish still replaces the
	// interrupted outcome.
	id2 := uuid.New()
	g2 := slow.Begin(id2)
	time.Sleep(300 * time.Millisecond)
	if st, _, _ := detail(reader, id2); st != ScanStateFailed {
		t.Fatalf("lapsed: %s", st)
	}
	slow.Finish(id2, g2, nil, "")
	if st, _, _ := detail(reader, id2); st != ScanStateCompleted {
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
	if st, _, _ := detail(reader, id); st != ScanStateRunning {
		t.Fatalf("after 3.5 leases with heartbeats: %s, want running", st)
	}
	a.Finish(id, gen, nil, "")
	if st, _, _ := detail(reader, id); st != ScanStateCompleted {
		t.Fatalf("%s", st)
	}
}

// MarkFailed outside a run (upload without a tenant) is shared too.
func TestM72Redis_MarkFailedIsShared(t *testing.T) {
	rdb := m72Redis(t)
	a, b := process(rdb, 0, time.Hour), process(rdb, 0, time.Hour)
	id := uuid.New()
	a.MarkFailed(id, "tenant context missing")
	if st, msg, _ := detail(b, id); st != ScanStateFailed || msg != "tenant context missing" {
		t.Fatalf("%s %q", st, msg)
	}
}
