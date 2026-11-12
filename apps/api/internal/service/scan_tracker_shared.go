package service

import (
	"context"
	"errors"
	"log/slog"
	"sync"
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
	t.syncRun(k, t.run(k), false)
}

func (t *ScanTracker) sharedFinish(sbomID uuid.UUID, gen uint64, errMsg string, reasons []string) {
	if t.shared == nil {
		return
	}
	k := runKey{sbomID, gen}
	r := t.run(k)
	r.mu.Lock()
	r.finished, r.errMsg, r.reasons = true, errMsg, append([]string(nil), reasons...)
	r.mu.Unlock()
	t.syncRun(k, r, false)
}

func (t *ScanTracker) sharedMark(sbomID uuid.UUID, state ScanState, errMsg string, reasons []string) {
	if t.shared == nil {
		return
	}
	err := t.shared.mark(context.Background(), sbomID, state, errMsg, reasons)
	t.hbMu.Lock()
	if err != nil {
		t.dirty[sbomID] = time.Now()
	} else {
		delete(t.dirty, sbomID)
	}
	t.hbMu.Unlock()
	if err != nil {
		t.logSharedError("scan status: shared write failed; this process answers for the SBOM", sbomID, err)
	}
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
		t.hbMu.Lock()
		if len(t.synced) == 0 {
			t.hbActive = false
			t.hbMu.Unlock()
			return
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
		for _, it := range items {
			it.r.mu.Lock()
			stale := time.Since(it.r.began) > t.retention+ScanStatusLease
			it.r.mu.Unlock()
			if stale {
				t.dropRun(it.k, it.r)
				continue
			}
			t.syncRun(it.k, it.r, true)
		}
	}
}

// preferLocal reports whether this process's memory is more current than the
// shared store for sbomID: a run of it is active here, or a write of it has
// not reached Redis.
func (t *ScanTracker) preferLocal(sbomID uuid.UUID) bool {
	t.mu.RLock()
	e, ok := t.entries[sbomID]
	t.mu.RUnlock()
	if ok && len(e.active) > 0 && time.Since(e.updatedAt) <= t.retention {
		return true
	}
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
		if r.mu.TryLock() {
			pending := !r.begun || (r.finished && !r.done)
			r.mu.Unlock()
			if pending {
				return true
			}
		} else {
			return true // a write is in flight
		}
	}
	return false
}
