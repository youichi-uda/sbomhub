package service

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	sbomredis "github.com/sbomhub/sbomhub/internal/redis"
)

// The ScanTracker's side of the shared store (M72): every write is attempted
// once inline, bounded and best-effort; a write that failed is retried by the
// heartbeat loop, which also renews the leases of this process's active runs.
// Nothing here returns an error to the scan.

// syncedRun guards one run's shared writes, so the inline write and the
// heartbeat loop never interleave for one run.
type syncedRun struct {
	mu sync.Mutex
	localRun
	done bool
	// finishing is set (without mu) as soon as Finish is called, so the run
	// counts as pending before its goroutine records the outcome.
	finishing atomic.Bool
}

func (t *ScanTracker) logSharedError(msg string, sbomID uuid.UUID, err error) {
	if errors.Is(err, sbomredis.ErrCircuitOpen) {
		slog.Debug(msg, "sbom_id", sbomID, "error", err)
		return
	}
	slog.Warn(msg, "sbom_id", sbomID, "error", err)
}

// run returns (creating it) the shared-sync record of a run.
func (t *ScanTracker) run(k runKey) *syncedRun {
	t.hbMu.Lock()
	defer t.hbMu.Unlock()
	r, ok := t.hbRunsSynced()[k]
	if !ok {
		r = &syncedRun{localRun: localRun{began: time.Now()}}
		t.hbRunsSynced()[k] = r
	}
	if !t.hbActive {
		t.hbActive = true
		go t.heartbeatLoop()
	}
	return r
}

// hbRunsSynced is the run table. hbMu is held.
func (t *ScanTracker) hbRunsSynced() map[runKey]*syncedRun {
	if t.synced == nil {
		t.synced = map[runKey]*syncedRun{}
	}
	return t.synced
}

func (t *ScanTracker) dropRun(k runKey, r *syncedRun) {
	t.hbMu.Lock()
	defer t.hbMu.Unlock()
	if t.synced[k] == r {
		delete(t.synced, k)
	}
}

func (t *ScanTracker) sharedBegin(sbomID uuid.UUID, gen uint64) {
	if t.shared == nil {
		return
	}
	k := runKey{sbomID, gen}
	r := t.run(k)
	// Begin waits briefly for its write (Codex M72 R1 Medium-5 vs ordering):
	// a run must normally reach Redis before another process's run of the
	// SBOM finishes, or the two would not be one group and that run's
	// failure would be dropped. But it is on the request path, so the wait is
	// bounded by beginWait whatever Redis does; a write still in flight or
	// failed is completed by the goroutine or the heartbeat loop.
	done := make(chan struct{})
	go func() {
		defer close(done)
		t.syncRun(k, r, false)
	}()
	timer := time.NewTimer(beginWait)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}

// beginWait bounds how long Begin waits for its shared write.
const beginWait = 250 * time.Millisecond

func (t *ScanTracker) sharedFinish(sbomID uuid.UUID, gen uint64, errMsg string, reasons []string) {
	if t.shared == nil {
		return
	}
	k := runKey{sbomID, gen}
	r := t.run(k)
	reasons = append([]string(nil), reasons...)
	r.finishing.Store(true)
	// Asynchronous: the run's begin may still be in flight (holding r.mu).
	// Until the outcome lands the shared store still lists the run as
	// active, so every reader sees running, never a premature terminal state.
	go func() {
		r.mu.Lock()
		r.finished, r.errMsg, r.reasons = true, errMsg, reasons
		r.mu.Unlock()
		t.syncRun(k, r, false)
	}()
}

func (t *ScanTracker) sharedMark(sbomID uuid.UUID, state ScanState, errMsg string, reasons []string) {
	if t.shared == nil {
		return
	}
	// Marked dirty until the write lands, so this process answers from
	// memory meanwhile; the write itself does not hold up the caller.
	at := time.Now()
	t.hbMu.Lock()
	t.dirty[sbomID] = at
	t.hbMu.Unlock()
	reasons = append([]string(nil), reasons...)
	go func() {
		err := t.shared.mark(context.Background(), sbomID, state, errMsg, reasons)
		if err != nil {
			t.logSharedError("scan status: shared write failed; this process answers for the SBOM", sbomID, err)
			return
		}
		t.hbMu.Lock()
		if t.dirty[sbomID].Equal(at) {
			delete(t.dirty, sbomID)
		}
		t.hbMu.Unlock()
	}()
}

// syncRun brings the shared store up to date with one run: Begin if it has
// not reached Redis yet, then its outcome if it finished, else (heartbeat) a
// lease renewal.
func (t *ScanTracker) syncRun(k runKey, r *syncedRun, heartbeat bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return
	}
	ctx := context.Background()
	if !r.begun {
		if err := t.shared.begin(ctx, k.sbom, k.gen); err != nil {
			t.logSharedError("scan status: shared begin failed; retrying on the next heartbeat", k.sbom, err)
			return
		}
		r.begun = true
		heartbeat = false // Begin set a fresh lease
	}
	if r.finished {
		recorded, err := t.shared.finish(ctx, k.sbom, k.gen, r.errMsg, r.reasons)
		if err != nil {
			t.logSharedError("scan status: shared finish failed; retrying on the next heartbeat", k.sbom, err)
			return
		}
		if !recorded {
			slog.Info("scan status: outcome not recorded in the shared store; the run was superseded",
				"sbom_id", k.sbom)
		}
		r.done = true
		t.dropRun(k, r)
		return
	}
	if heartbeat {
		active, err := t.shared.heartbeat(ctx, k.sbom, k.gen)
		if err != nil {
			t.logSharedError("scan status: lease renewal failed", k.sbom, err)
			return
		}
		if !active {
			// Superseded while it was alive (its lease ran out and a new
			// group started, or a terminal state was set): join the current
			// group again on the next tick.
			r.begun = false
		}
	}
}

// heartbeatLoop renews leases and retries failed writes until this process
// has no run left to sync. A run older than retention + lease is dropped (a
// scan that never finished, e.g. an upload whose transaction rolled back).
func (t *ScanTracker) heartbeatLoop() {
	ticker := time.NewTicker(t.hbInterval)
	defer ticker.Stop()
	for range ticker.C {
		if !t.heartbeatPass() {
			return
		}
	}
}

// heartbeatPass syncs every run once; false when none is left (the loop then
// ends).
func (t *ScanTracker) heartbeatPass() bool {
	t.hbMu.Lock()
	if len(t.synced) == 0 {
		t.hbActive = false
		t.hbMu.Unlock()
		return false
	}
	type item struct {
		k runKey
		r *syncedRun
	}
	items := make([]item, 0, len(t.synced))
	for k, r := range t.synced {
		items = append(items, item{k, r})
	}
	t.hbMu.Unlock()
	// Renewed concurrently (bounded), so a pass takes about
	// len/heartbeatWorkers round trips, not len (Codex M72 R1 Medium-6): at
	// the 1s bound per call, 16 workers renew 480 runs within the 30s
	// interval, well inside the 90s lease.
	sem := make(chan struct{}, heartbeatWorkers)
	var wg sync.WaitGroup
	for _, it := range items {
		it.r.mu.Lock()
		stale := time.Since(it.r.began) > t.retention+ScanStatusLease
		it.r.mu.Unlock()
		if stale {
			t.dropRun(it.k, it.r)
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			t.syncRun(it.k, it.r, true)
		}()
	}
	wg.Wait()
	return true
}

// heartbeatWorkers bounds the concurrent renewals of one heartbeat pass.
const heartbeatWorkers = 16

// localActive reports whether a run of sbomID is active in this process.
func (t *ScanTracker) localActive(sbomID uuid.UUID) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.entries[sbomID]
	return ok && len(e.active) > 0 && time.Since(e.updatedAt) <= t.retention
}

// pendingShared reports whether this process holds state of sbomID that has
// not reached the shared store: a run whose begin or outcome is unwritten (or
// being written), or a MarkFailed / MarkCompleted that failed.
func (t *ScanTracker) pendingShared(sbomID uuid.UUID) bool {
	t.hbMu.Lock()
	defer t.hbMu.Unlock()
	if at, ok := t.dirty[sbomID]; ok {
		if time.Since(at) <= t.retention {
			return true
		}
		delete(t.dirty, sbomID)
	}
	for k, r := range t.synced {
		if k.sbom != sbomID {
			continue
		}
		if r.finishing.Load() {
			if r.mu.TryLock() {
				done := r.done
				r.mu.Unlock()
				if !done {
					return true
				}
				continue
			}
			return true
		}
		if !r.mu.TryLock() {
			return true // a write is in flight
		}
		pending := !r.done && (!r.begun || r.finished)
		r.mu.Unlock()
		if pending {
			return true
		}
	}
	return false
}
