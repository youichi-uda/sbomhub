package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"

	sbomredis "github.com/sbomhub/sbomhub/internal/redis"
)

// The ScanTracker's side of the shared store (M72).
//
// Every shared write of one SBOM goes through that SBOM's queue and is applied
// in CALL order by one goroutine at a time (Codex M72 R2 High-1): a run that
// began before another run of the SBOM finished reaches Redis before that
// finish, so the two stay one group whatever the goroutine scheduling. A write
// that fails stays at the head of its queue, and the heartbeat loop retries
// it; while an SBOM has queued writes this process's memory answers for it
// where Redis could be behind (see GetDetail). Nothing here returns an error
// to the scan, and only Begin waits, at most beginWait.

const (
	// beginWait bounds how long Begin waits for its shared write. Begin is on
	// the request path (Codex M72 R1 Medium-5).
	beginWait = 250 * time.Millisecond
	// maxQueuedWrites bounds one SBOM's queue while Redis is unreachable; a
	// write beyond it is dropped (the SBOM keeps answering from memory).
	maxQueuedWrites = 256
	// heartbeatBatch is how many lease renewals go in one pipelined round
	// trip (Codex M72 R2 Medium-4).
	heartbeatBatch = 256
)

type sharedEventKind int

const (
	evBegin sharedEventKind = iota
	evFinish
	evMark
)

type sharedEvent struct {
	kind    sharedEventKind
	gen     uint64
	state   ScanState
	msg     string
	reasons []string
	at      time.Time
	done    chan struct{} // closed once applied
}

type sbomQueue struct {
	events   []*sharedEvent
	draining bool
}

func (t *ScanTracker) logSharedError(msg string, sbomID uuid.UUID, err error) {
	if errors.Is(err, sbomredis.ErrCircuitOpen) {
		slog.Debug(msg, "sbom_id", sbomID, "error", err)
		return
	}
	slog.Warn(msg, "sbom_id", sbomID, "error", err)
}

// enqueue appends ev to sbomID's queue and starts its drain. t.qMu is held.
func (t *ScanTracker) enqueueLocked(sbomID uuid.UUID, ev *sharedEvent) bool {
	q := t.queues[sbomID]
	if q == nil {
		q = &sbomQueue{}
		t.queues[sbomID] = q
	}
	if len(q.events) >= maxQueuedWrites {
		slog.Warn("scan status: too many unwritten shared writes for the SBOM; dropping one", "sbom_id", sbomID)
		return false
	}
	ev.at = time.Now()
	ev.done = make(chan struct{})
	q.events = append(q.events, ev)
	if !q.draining {
		q.draining = true
		go t.drain(sbomID)
	}
	t.ensureHeartbeatLocked()
	return true
}

// drain applies sbomID's queued writes in order until the queue is empty or a
// write fails (it then stays queued for the heartbeat loop to retry).
func (t *ScanTracker) drain(sbomID uuid.UUID) {
	for {
		t.qMu.Lock()
		q := t.queues[sbomID]
		if q == nil || len(q.events) == 0 {
			delete(t.queues, sbomID)
			t.qMu.Unlock()
			return
		}
		ev := q.events[0]
		t.qMu.Unlock()

		err := t.apply(sbomID, ev)

		t.qMu.Lock()
		if err != nil {
			q.draining = false
			t.qMu.Unlock()
			t.logSharedError("scan status: shared write failed; retrying on the next heartbeat", sbomID, err)
			return
		}
		q.events = q.events[1:]
		close(ev.done)
		t.qMu.Unlock()
	}
}

func (t *ScanTracker) apply(sbomID uuid.UUID, ev *sharedEvent) error {
	ctx := context.Background()
	switch ev.kind {
	case evBegin:
		return t.shared.begin(ctx, sbomID, ev.gen)
	case evFinish:
		recorded, err := t.shared.finish(ctx, sbomID, ev.gen, ev.msg, ev.reasons)
		if err == nil && !recorded {
			slog.Info("scan status: outcome not recorded in the shared store; the run was superseded", "sbom_id", sbomID)
		}
		return err
	default:
		return t.shared.mark(ctx, sbomID, ev.state, ev.msg, ev.reasons)
	}
}

func (t *ScanTracker) sharedBegin(sbomID uuid.UUID, gen uint64) {
	if t.shared == nil {
		return
	}
	ev := &sharedEvent{kind: evBegin, gen: gen}
	t.qMu.Lock()
	t.live[runKey{sbomID, gen}] = time.Now()
	ok := t.enqueueLocked(sbomID, ev)
	t.qMu.Unlock()
	if !ok {
		return
	}
	// A run should normally reach Redis before another process's run of the
	// SBOM finishes, so Begin waits for its write — bounded, because it is on
	// the request path.
	timer := time.NewTimer(beginWait)
	defer timer.Stop()
	select {
	case <-ev.done:
	case <-timer.C:
	}
}

func (t *ScanTracker) sharedFinish(sbomID uuid.UUID, gen uint64, errMsg string, reasons []string) {
	if t.shared == nil {
		return
	}
	t.qMu.Lock()
	delete(t.live, runKey{sbomID, gen})
	t.enqueueLocked(sbomID, &sharedEvent{kind: evFinish, gen: gen, msg: errMsg, reasons: append([]string(nil), reasons...)})
	t.qMu.Unlock()
}

func (t *ScanTracker) sharedMark(sbomID uuid.UUID, state ScanState, errMsg string, reasons []string) {
	if t.shared == nil {
		return
	}
	t.qMu.Lock()
	// A terminal state set outside a run ends this process's runs of it.
	for k := range t.live {
		if k.sbom == sbomID {
			delete(t.live, k)
		}
	}
	t.enqueueLocked(sbomID, &sharedEvent{kind: evMark, state: state, msg: errMsg, reasons: append([]string(nil), reasons...)})
	t.qMu.Unlock()
}

// ensureHeartbeatLocked starts the heartbeat loop. t.qMu is held.
func (t *ScanTracker) ensureHeartbeatLocked() {
	if !t.hbActive {
		t.hbActive = true
		go t.heartbeatLoop()
	}
}

// heartbeatLoop renews leases and retries failed writes until this process
// has neither a live run nor a queued write.
func (t *ScanTracker) heartbeatLoop() {
	ticker := time.NewTicker(t.hbInterval)
	defer ticker.Stop()
	for range ticker.C {
		if !t.heartbeatPass() {
			return
		}
	}
}

// heartbeatPass restarts stalled queues and renews the lease of every live
// run whose SBOM has no queued write, in pipelined batches; false when there
// is nothing left to do (the loop then ends). A live run older than
// retention + lease is dropped (a scan that never finished, e.g. an upload
// whose transaction rolled back), and so is a queued write older than
// retention.
func (t *ScanTracker) heartbeatPass() bool {
	t.qMu.Lock()
	for id, q := range t.queues {
		for len(q.events) > 0 && time.Since(q.events[0].at) > t.retention {
			close(q.events[0].done)
			q.events = q.events[1:]
		}
		if len(q.events) == 0 && !q.draining {
			delete(t.queues, id)
			continue
		}
		if !q.draining {
			q.draining = true
			go t.drain(id)
		}
	}
	var renew []runKey
	for k, began := range t.live {
		if time.Since(began) > t.retention+ScanStatusLease {
			delete(t.live, k)
			continue
		}
		if q := t.queues[k.sbom]; q != nil && len(q.events) > 0 {
			continue // its writes come first; the begin sets a fresh lease
		}
		renew = append(renew, k)
	}
	if len(t.live) == 0 && len(t.queues) == 0 {
		t.hbActive = false
		t.qMu.Unlock()
		return false
	}
	t.qMu.Unlock()

	for start := 0; start < len(renew); start += heartbeatBatch {
		batch := renew[start:min(start+heartbeatBatch, len(renew))]
		active, err := t.shared.heartbeatMany(context.Background(), batch)
		if err != nil {
			t.logSharedError("scan status: lease renewal failed", batch[0].sbom, err)
			continue
		}
		t.qMu.Lock()
		for i, k := range batch {
			if active[i] {
				continue
			}
			// Superseded while alive (its lease ran out and a new group
			// started, or a terminal state was set): join the current group
			// again.
			if _, still := t.live[k]; still {
				t.enqueueLocked(k.sbom, &sharedEvent{kind: evBegin, gen: k.gen})
			}
		}
		t.qMu.Unlock()
	}
	return true
}

// localActive reports whether a run of sbomID is active in this process.
func (t *ScanTracker) localActive(sbomID uuid.UUID) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.entries[sbomID]
	return ok && len(e.active) > 0 && time.Since(e.updatedAt) <= t.retention
}

// pendingShared reports whether this process has writes of sbomID that have
// not reached the shared store.
func (t *ScanTracker) pendingShared(sbomID uuid.UUID) bool {
	t.qMu.Lock()
	defer t.qMu.Unlock()
	q := t.queues[sbomID]
	return q != nil && len(q.events) > 0
}
