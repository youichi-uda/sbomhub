package service

import (
	"context"
	"errors"
	"log/slog"
	"slices"
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
	// maxDrainWorkers bounds the goroutines draining queues (Codex M72
	// R7/R8 High-1, R12 Medium-4). A fresh Begin on an idle queue does not
	// wait for one (see enqueueLocked).
	maxDrainWorkers = 32
	// drainQuantum: a worker applies at most this many writes of one queue
	// before taking the next queue, so long backlogs share the workers.
	drainQuantum = 16
)

type sharedEventKind int

const (
	evBegin sharedEventKind = iota
	evFinish
	evMark
	evRejoin
	evMerge
)

type sharedEvent struct {
	kind    sharedEventKind
	gen     uint64
	state   ScanState
	msg     string
	reasons []string
	at      time.Time
	done    chan struct{} // closed once applied
	merged  *mergeSet     // evMerge
	// applying: an evMerge being applied; it takes no more writes.
	applying bool
}

// liveRun is one of this process's active runs.
type liveRun struct {
	began time.Time
	// acked: Redis has applied its begin (or rejoin); its lease is renewed.
	acked bool
	// rejoinPending: a rejoin of it is queued.
	rejoinPending bool
}

type sbomQueue struct {
	events   []*sharedEvent
	draining bool
	// lastWrite is when a write was last queued or folded in.
	lastWrite time.Time
}

func (t *ScanTracker) logSharedError(msg string, sbomID uuid.UUID, err error) {
	if errors.Is(err, sbomredis.ErrCircuitOpen) {
		slog.Debug(msg, "sbom_id", sbomID, "error", err)
		return
	}
	slog.Warn(msg, "sbom_id", sbomID, "error", err)
}

// enqueue appends ev to sbomID's queue and starts its drain. t.qMu is held.
func (t *ScanTracker) enqueueLocked(sbomID uuid.UUID, ev *sharedEvent) {
	q := t.queues[sbomID]
	if q == nil {
		q = &sbomQueue{}
		t.queues[sbomID] = q
	}
	q.lastWrite = time.Now()
	if len(q.events) >= t.queueCap {
		// Full: coalesce into one merge event at the tail (Codex M72 R5
		// High-3). It stays last, so call order is kept, and nothing that
		// carries a failure is dropped.
		t.coalesceLocked(sbomID, q, ev)
		return
	}
	ev.at = time.Now()
	ev.done = make(chan struct{})
	q.events = append(q.events, ev)
	if !q.draining {
		if ev.kind == evBegin {
			// A fresh Begin on an idle queue gets its own goroutine and Redis
			// attempt at once, outside the worker pool, so every Begin
			// reaches a responsive Redis within beginWait however many
			// arrive together or however busy the pool is (Codex M72
			// R13/R14/R15 High). Their number is that of the requests and
			// scans starting at that moment.
			q.draining = true
			go t.drain(sbomID)
		} else {
			t.startDrainLocked(sbomID, q)
		}
	}
	t.ensureHeartbeatLocked()
}

// coalesceLocked folds ev into an open merge event at the queue's tail.
// t.qMu is held.
func (t *ScanTracker) coalesceLocked(sbomID uuid.UUID, q *sbomQueue, ev *sharedEvent) {
	tail := q.events[len(q.events)-1]
	if tail.kind != evMerge || tail.applying {
		tail = &sharedEvent{kind: evMerge, merged: newMergeSet(), at: time.Now(), done: make(chan struct{})}
		q.events = append(q.events, tail)
		slog.Warn("scan status: shared writes of the SBOM are backing up; coalescing them",
			"sbom_id", sbomID, "queued", len(q.events))
	}
	m := tail.merged
	switch ev.kind {
	case evBegin, evRejoin:
		m.begin(ev.gen, ev.kind == evBegin)
	case evFinish:
		m.finish(ev.gen)
		if ev.msg != "" {
			m.addFailure(ev.msg, ev.reasons)
		}
	case evMark:
		if ev.state == ScanStateFailed && ev.msg != "" {
			m.addFailure(ev.msg, ev.reasons)
		}
	}
	// ev itself is never queued: a Begin waiting on it waits on the merge.
	ev.at = tail.at
	ev.done = tail.done
}

// startDrainLocked hands sbomID's queue to the drain workers: at most
// maxDrainWorkers drain at once, process-wide (Codex M72 R12 Medium-4), each
// lane in arrival order. t.qMu is held.
func (t *ScanTracker) startDrainLocked(sbomID uuid.UUID, q *sbomQueue) {
	q.draining = true
	t.queueReadyLocked(sbomID)
}

// queueReadyLocked puts an already-draining queue in line for a worker,
// starting one if fewer than maxDrainWorkers run. t.qMu is held.
func (t *ScanTracker) queueReadyLocked(sbomID uuid.UUID) {
	t.ready = append(t.ready, sbomID)
	if t.workers < maxDrainWorkers {
		t.workers++
		go t.drainWorker()
	}
}

// nextReadyLocked takes the next queue to drain, in arrival order. t.qMu is
// held.
func (t *ScanTracker) nextReadyLocked() (uuid.UUID, bool) {
	if len(t.ready) == 0 {
		return uuid.Nil, false
	}
	id := t.ready[0]
	t.ready = t.ready[1:]
	return id, true
}

// drainWorker drains ready queues until none is left.
func (t *ScanTracker) drainWorker() {
	for {
		t.qMu.Lock()
		id, ok := t.nextReadyLocked()
		if !ok {
			t.workers--
			t.qMu.Unlock()
			return
		}
		t.qMu.Unlock()
		t.drain(id)
	}
}

// drain applies sbomID's queued writes in order until the queue is empty or a
// write fails (it then stays queued for the heartbeat loop to retry).
func (t *ScanTracker) drain(sbomID uuid.UUID) {
	for applied := 0; ; applied++ {
		t.qMu.Lock()
		q := t.queues[sbomID]
		if q == nil || len(q.events) == 0 {
			delete(t.queues, sbomID)
			t.qMu.Unlock()
			return
		}
		if applied == drainQuantum {
			// Its turn is over: back of the line, still draining.
			t.queueReadyLocked(sbomID)
			t.qMu.Unlock()
			return
		}
		ev := q.events[0]
		var merged *mergeSet
		if ev.kind == evMerge {
			// Frozen from now on (later overflow opens a new merge event),
			// so it is read without the lock (Codex M72 R16 High-2: no copy
			// under qMu).
			ev.applying = true
			merged = ev.merged
		}
		t.qMu.Unlock()

		var err error
		if merged != nil {
			err = t.shared.merge(context.Background(), sbomID, merged)
		} else {
			err = t.apply(sbomID, ev)
		}

		t.qMu.Lock()
		if err != nil {
			q.draining = false
			t.qMu.Unlock()
			t.logSharedError("scan status: shared write failed; retrying on the next heartbeat", sbomID, err)
			return
		}
		// Runs Redis now knows as active: their leases are renewed from
		// here on, whatever else is queued (Codex M72 R8 High-1).
		switch {
		case ev.kind == evBegin || ev.kind == evRejoin:
			if lr := t.live[runKey{sbomID, ev.gen}]; lr != nil {
				lr.acked, lr.rejoinPending = true, false
			}
		case merged != nil:
			for g := range merged.begins {
				if lr := t.live[runKey{sbomID, g}]; lr != nil {
					lr.acked, lr.rejoinPending = true, false
				}
			}
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
	case evRejoin:
		return t.shared.rejoin(ctx, sbomID, ev.gen)
	case evFinish:
		known, err := t.shared.finish(ctx, sbomID, ev.gen, ev.msg, ev.reasons)
		if err == nil && !known {
			slog.Info("scan status: the shared store did not know this run; its outcome was merged into the current group",
				"sbom_id", sbomID, "failed", ev.msg != "")
		}
		return err
	default:
		return t.shared.mark(ctx, sbomID, ev.state, ev.msg, ev.reasons)
	}
}

// The queue* functions are called with t.mu held, in the same critical
// section as the local state change they mirror (lock order t.mu, then
// t.qMu), so one SBOM's shared writes are queued in the order of its local
// transitions.

// queueBeginLocked queues run gen's begin; nil without a shared store (or if
// the queue is full).
func (t *ScanTracker) queueBeginLocked(sbomID uuid.UUID, gen uint64) *sharedEvent {
	if t.shared == nil {
		return nil
	}
	ev := &sharedEvent{kind: evBegin, gen: gen}
	t.qMu.Lock()
	defer t.qMu.Unlock()
	t.live[runKey{sbomID, gen}] = &liveRun{began: time.Now()}
	t.enqueueLocked(sbomID, ev)
	return ev
}

// waitBegin waits, at most beginWait, for a queued begin to reach Redis: a run
// should normally be there before another process's run of the SBOM
// finishes, but Begin is on the request path.
func (t *ScanTracker) waitBegin(ev *sharedEvent) {
	if ev == nil {
		return
	}
	timer := time.NewTimer(t.beginWait)
	defer timer.Stop()
	select {
	case <-ev.done:
	case <-timer.C:
	}
}

func (t *ScanTracker) queueFinishLocked(sbomID uuid.UUID, gen uint64, errMsg string, reasons []string) {
	if t.shared == nil {
		return
	}
	t.qMu.Lock()
	defer t.qMu.Unlock()
	delete(t.live, runKey{sbomID, gen})
	t.enqueueLocked(sbomID, &sharedEvent{kind: evFinish, gen: gen, msg: errMsg, reasons: append([]string(nil), reasons...)})
}

func (t *ScanTracker) queueMarkLocked(sbomID uuid.UUID, state ScanState, errMsg string, reasons []string) {
	if t.shared == nil {
		return
	}
	t.qMu.Lock()
	defer t.qMu.Unlock()
	// A terminal state set outside a run ends this process's runs of it.
	for k := range t.live {
		if k.sbom == sbomID {
			delete(t.live, k)
		}
	}
	t.enqueueLocked(sbomID, &sharedEvent{kind: evMark, state: state, msg: errMsg, reasons: append([]string(nil), reasons...)})
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

// heartbeatPass retries stalled queues and renews the lease of every live run
// Redis has acknowledged, in pipelined batches; false when there is nothing
// left to do (the loop then ends). A live run older than retention + lease is
// dropped (a scan that never finished, e.g. an upload whose transaction
// rolled back).
func (t *ScanTracker) heartbeatPass() bool {
	t.qMu.Lock()
	// A queue is reclaimed only as a whole, when it is not being drained and
	// its LAST write is older than retention: by then the status it carries
	// would have expired in Redis and in this process anyway (Codex M72 R7
	// High-1). A single write is never dropped for its age while newer ones of
	// its SBOM wait (Codex M72 R6 High-2/3). Every stalled queue is retried,
	// least recently written first, by at most maxDrainWorkers goroutines
	// (Codex M72 R8 High-1).
	var stalled []uuid.UUID
	for id, q := range t.queues {
		switch {
		case q.draining:
		case len(q.events) == 0:
			delete(t.queues, id)
		case time.Since(q.lastWrite) > t.retention:
			for _, ev := range q.events {
				close(ev.done)
			}
			delete(t.queues, id)
			slog.Warn("scan status: dropped shared writes older than the status retention; Redis was unreachable for longer",
				"sbom_id", id)
		default:
			stalled = append(stalled, id)
		}
	}
	slices.SortFunc(stalled, func(x, y uuid.UUID) int { return t.queues[x].lastWrite.Compare(t.queues[y].lastWrite) })
	for _, id := range stalled {
		t.startDrainLocked(id, t.queues[id])
	}
	var renew []runKey
	for k, lr := range t.live {
		if time.Since(lr.began) > t.retention+ScanStatusLease {
			delete(t.live, k)
			continue
		}
		// Only runs Redis has acknowledged; a run whose begin is still
		// queued gets a fresh lease when it lands.
		if lr.acked {
			renew = append(renew, k)
		}
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
			// Not active in Redis although alive (its lease ran out and its
			// identity was dropped, or a new group started): rejoin the
			// current group, keeping its outcomes (Codex M72 R4 High-3).
			// One pending rejoin per run (Codex M72 R14 Medium-4).
			if lr := t.live[k]; lr != nil && !lr.rejoinPending {
				lr.rejoinPending = true
				t.enqueueLocked(k.sbom, &sharedEvent{kind: evRejoin, gen: k.gen})
			}
		}
		t.qMu.Unlock()
	}
	return true
}

// kickQueues restarts the drain of every stalled queue (the heartbeat loop
// does it every pass).
func (t *ScanTracker) kickQueues() {
	t.qMu.Lock()
	defer t.qMu.Unlock()
	for id, q := range t.queues {
		if len(q.events) > 0 && !q.draining {
			t.startDrainLocked(id, q)
		}
	}
}

// pendingShared reports whether this process has writes of sbomID that have
// not reached the shared store.
func (t *ScanTracker) pendingShared(sbomID uuid.UUID) bool {
	t.qMu.Lock()
	defer t.qMu.Unlock()
	q := t.queues[sbomID]
	return q != nil && len(q.events) > 0
}
