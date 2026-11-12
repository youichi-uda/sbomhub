package service

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// ScanState represents the lifecycle of a background vulnerability scan
// kicked off by SbomHandler.Upload (NVD + JVN). It is observed by CLI
// clients via GET /api/v1/projects/:id/sboms/:sbom_id/scan-status so they
// can decide whether `sbomhub scan --fail-on <severity>` should fail the
// CI job.
type ScanState string

const (
	// ScanStateUnknown is returned when no entry exists for the given sbom
	// ID. From the CLI's point of view this is treated as "not started yet
	// or evicted from the in-memory tracker" — callers must keep polling
	// (until --wait-timeout) rather than assuming completion.
	ScanStateUnknown   ScanState = "unknown"
	ScanStateRunning   ScanState = "running"
	ScanStateCompleted ScanState = "completed"
	ScanStateFailed    ScanState = "failed"
)

// ScanTracker tracks the state of background vulnerability scans by sbom
// ID.
//
// It always keeps the state of this process's scans in memory. With WithRedis
// (M72) it also keeps it in Redis (scan_status_store.go), so that a scan
// started on one API process is readable from every other and survives a
// restart; a scan whose process died reads failed with reason "interrupted"
// once its lease runs out, instead of "running" until retention. Without
// Redis — or while Redis is unreachable — it is the pre-M72 in-memory
// tracker: on restart the state is lost and pollers see `ScanStateUnknown`.
//
// The scan never depends on the tracker: every Redis write is bounded, goes
// through the client's circuit breaker, and a failed one is only logged and
// retried by the heartbeat loop; the in-memory state answers meanwhile.
//
// Entries auto-expire after `retention` to bound memory.
type ScanTracker struct {
	mu        sync.RWMutex
	entries   map[uuid.UUID]scanEntry
	retention time.Duration
	revSeq    uint64

	// shared (M72) is the Redis store; nil keeps the tracker in-memory only.
	shared scanStatusStore
	// qMu guards the shared-write queues, the live runs and the heartbeat
	// loop's state (scan_tracker_shared.go).
	qMu sync.Mutex
	// queues holds, per SBOM, the shared writes not yet applied, in call
	// order.
	queues map[uuid.UUID]*sbomQueue
	// live: this process's active runs (lease renewal), with their start.
	live       map[runKey]*liveRun
	queueCap   int           // maxQueuedWrites; smaller in tests
	beginWait  time.Duration // beginWait; shorter in tests
	hbActive   bool
	hbInterval time.Duration
}

type runKey struct {
	sbom uuid.UUID
	gen  uint64
}

type scanEntry struct {
	state     ScanState
	updatedAt time.Time
	errMsg    string
	reasons   []string
	// active holds the generations of this SBOM's runs that have begun and
	// not finished (M62). While it is non-empty the state is running.
	active map[uint64]bool
	// group* accumulate the outcomes of runs that finished while another
	// run of the same SBOM was still active; they are published when the
	// last one finishes.
	groupMsgs    []string
	groupReasons []string
	// rev is the tracker-wide sequence number of the entry's last
	// transition (M72): GetDetail detects a transition that raced its Redis
	// read (Codex M72 R4 High-1).
	rev uint64
}

// put stores e as sbomID's entry with a new revision. t.mu is held.
func (t *ScanTracker) put(sbomID uuid.UUID, e scanEntry) {
	t.revSeq++
	e.rev = t.revSeq
	t.entries[sbomID] = e
}

// snapshot returns, atomically, whether a run of sbomID is active in this
// process and the entry's revision.
func (t *ScanTracker) snapshot(sbomID uuid.UUID) (bool, uint64) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.entries[sbomID]
	return ok && len(e.active) > 0 && time.Since(e.updatedAt) <= t.retention, e.rev
}

// revision returns sbomID's entry revision (0 without an entry).
func (t *ScanTracker) revision(sbomID uuid.UUID) uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.entries[sbomID].rev
}

// NewScanTracker creates an in-memory tracker. Entries older than 1 hour
// are evicted lazily on read; 1h is well beyond CLI poll windows (default
// 5m) but short enough that long-lived servers do not accumulate state.
func NewScanTracker() *ScanTracker {
	return &ScanTracker{
		entries:    make(map[uuid.UUID]scanEntry),
		retention:  1 * time.Hour,
		queues:     map[uuid.UUID]*sbomQueue{},
		live:       map[runKey]*liveRun{},
		queueCap:   maxQueuedWrites,
		beginWait:  beginWait,
		hbInterval: ScanStatusHeartbeat,
	}
}

// WithRedis makes the tracker keep its state in Redis too (M72), shared by
// every API process on that Redis. Call it before the tracker is used.
func (t *ScanTracker) WithRedis(client *redis.Client) *ScanTracker {
	if client != nil {
		t.shared = &redisScanStatusStore{client: client, ttl: t.retention, lease: ScanStatusLease}
	}
	return t
}

// newRunGenFn is newRunGen (a variable for tests).
var newRunGenFn = newRunGen

// newRunGen returns a random non-zero run generation: unique across API
// processes without coordination (a collision needs 2^32 concurrent runs of
// one SBOM to become likely).
func newRunGen() uint64 {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic("scan tracker: crypto/rand: " + err.Error())
		}
		if g := binary.BigEndian.Uint64(b[:]); g != 0 {
			return g
		}
	}
}

// NewScanTrackerFor is NewScanTracker sized for a scan deadline (M62): a
// running entry must not be evicted while its scan can still be running, or
// a scan longer than the retention would read "unknown" and never reach a
// terminal state for the CLI. Retention is max(1h, deadline + 15m).
func NewScanTrackerFor(scanDeadline time.Duration) *ScanTracker {
	t := NewScanTracker()
	if r := scanDeadline + 15*time.Minute; r > t.retention {
		t.retention = r
	}
	return t
}

// MarkRunning records that a background scan has been launched for the
// given sbom, so that a CLI client polling immediately after upload sees
// "running" rather than "unknown". It does not start a tracked run; the scan
// routes use Begin, whose generation Finish needs. If tracked runs are active
// it changes nothing.
func (t *ScanTracker) MarkRunning(sbomID uuid.UUID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.entries[sbomID]; ok && len(e.active) > 0 {
		return
	}
	t.put(sbomID, scanEntry{state: ScanStateRunning, updatedAt: time.Now()})
}

// Begin starts a new run of the sbom's scan, marks it running, and returns the
// run's generation for Finish.
//
// Runs of one SBOM can overlap (an upload scan and a manual one, Codex M62 R1
// and R2 High). The state stays running until EVERY overlapping run has
// finished — whichever order they finish in — and is then failed if any of
// them failed (their markers and reasons merged), completed otherwise. A
// poller therefore never reads "completed" while some scan of the SBOM can
// still add findings.
func (t *ScanTracker) Begin(sbomID uuid.UUID) uint64 {
	gen := newRunGenFn()
	t.mu.Lock()
	e, ok := t.entries[sbomID]
	if !ok || len(e.active) == 0 || time.Since(e.updatedAt) > t.retention {
		e = scanEntry{active: map[uint64]bool{}}
	}
	e.state = ScanStateRunning
	e.errMsg, e.reasons = "", nil
	e.updatedAt = time.Now()
	e.active[gen] = true
	t.put(sbomID, e)
	// Queued under t.mu, with the local change: the shared writes of one SBOM
	// follow the order of its local transitions (Codex M72 R3 High-1).
	ev := t.queueBeginLocked(sbomID, gen)
	t.mu.Unlock()
	if testHookAfterLocalBegin != nil {
		testHookAfterLocalBegin(gen)
	}
	t.waitBegin(ev)
	return gen
}

// testHookAfterLocalActiveCheck runs inside GetDetail after its local
// snapshot, before the Redis read (tests only).
var testHookAfterLocalActiveCheck func()

// testHookAfterLocalBegin runs once Begin's local state change is visible
// (tests only).
var testHookAfterLocalBegin func(gen uint64)

// Finish records run gen's outcome — failed when errMsg or reasons is
// non-empty, completed otherwise. It reports whether gen was an active run.
// The SBOM's state becomes terminal only when no other run is active.
func (t *ScanTracker) Finish(sbomID uuid.UUID, gen uint64, reasons []string, errMsg string) bool {
	return t.finishLocal(sbomID, gen, reasons, errMsg)
}

func (t *ScanTracker) finishLocal(sbomID uuid.UUID, gen uint64, reasons []string, errMsg string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[sbomID]
	if !ok {
		// Evicted while running: record the outcome rather than lose it.
		e = scanEntry{active: map[uint64]bool{gen: true}}
	}
	if !e.active[gen] {
		return false
	}
	delete(e.active, gen)
	sharedMsg := errMsg
	if sharedMsg == "" && len(reasons) > 0 {
		sharedMsg = "scan failed"
	}
	t.queueFinishLocked(sbomID, gen, sharedMsg, reasons)
	if errMsg != "" || len(reasons) > 0 {
		if errMsg == "" {
			errMsg = "scan failed"
		}
		// Once per distinct marker: many runs failing the same way must not
		// grow the entry (Codex M72 R2 High-3).
		if !slices.Contains(e.groupMsgs, errMsg) {
			e.groupMsgs = append(e.groupMsgs, errMsg)
		}
		e.groupReasons = MergeScanReasons(e.groupReasons, reasons)
	}
	e.updatedAt = time.Now()
	if len(e.active) > 0 {
		e.state = ScanStateRunning
		t.put(sbomID, e)
		return true
	}
	if len(e.groupMsgs) > 0 {
		e.state = ScanStateFailed
		e.errMsg = strings.Join(e.groupMsgs, "; ")
		e.reasons = e.groupReasons
	} else {
		e.state = ScanStateCompleted
		e.errMsg, e.reasons = "", nil
	}
	e.groupMsgs, e.groupReasons = nil, nil
	t.put(sbomID, e)
	return true
}

// MarkCompleted records that all background scans for the sbom finished
// without error, ending any tracked runs (pre-M62 callers and tests; the scan
// routes use Begin / Finish).
func (t *ScanTracker) MarkCompleted(sbomID uuid.UUID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.put(sbomID, scanEntry{state: ScanStateCompleted, updatedAt: time.Now()})
	t.queueMarkLocked(sbomID, ScanStateCompleted, "", nil)
}

// MarkFailed records that at least one background scan for the sbom
// returned an error. CLI clients treat this as a non-actionable signal —
// the upload succeeded, but scan results are incomplete; they exit with
// code 2 rather than 1, matching --wait-timeout behaviour.
func (t *ScanTracker) MarkFailed(sbomID uuid.UUID, errMsg string) {
	t.MarkFailedWithReasons(sbomID, errMsg, nil)
}

// MarkFailedWithReasons is MarkFailed with the scan's reason codes
// (service.ScanReason*), exposed as `reasons` on the scan-status response.
func (t *ScanTracker) MarkFailedWithReasons(sbomID uuid.UUID, errMsg string, reasons []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.put(sbomID, scanEntry{state: ScanStateFailed, updatedAt: time.Now(), errMsg: errMsg,
		reasons: append([]string(nil), reasons...)})
	t.queueMarkLocked(sbomID, ScanStateFailed, errMsg, reasons)
}

// GetDetail is Get plus the failed scan's reason codes, read atomically.
//
// With a shared store (M72):
//   - a run of this SBOM active in THIS process: running, whatever Redis says;
//   - else the shared state, which covers every process's runs; a shared
//     "running" always wins, so a terminal state this process has not yet
//     written cannot hide another process's run (Codex M72 R1 High-2);
//   - a shared terminal state yields to this process's own unwritten one
//     (it is newer);
//   - Redis has no entry: this process's memory;
//   - Redis unreadable: this process's memory, except that a "completed"
//     reads unknown — another replica may be scanning the SBOM, and only
//     Redis would say so (Codex M72 R4 High-2). running and failed are safe.
//
// A local transition that races the Redis read makes the read be retried
// (Codex M72 R4 High-1).
func (t *ScanTracker) GetDetail(sbomID uuid.UUID) (ScanState, string, []string) {
	if t.shared == nil {
		return t.getDetailLocal(sbomID)
	}
	for attempt := 0; attempt < 3; attempt++ {
		// One snapshot of "active here" and the revision (Codex M72 R5
		// High-1): any local transition after it changes the revision.
		active, rev := t.snapshot(sbomID)
		if active {
			return t.getDetailLocal(sbomID)
		}
		if f := testHookAfterLocalActiveCheck; f != nil {
			f()
		}
		state, msg, reasons, found, err := t.shared.get(context.Background(), sbomID)
		if t.revision(sbomID) != rev {
			continue
		}
		switch {
		case err != nil:
			slog.Debug("scan status: shared store unavailable, answering from this process", "sbom_id", sbomID, "error", err)
			return t.localWithoutShared(sbomID)
		case !found:
			return t.getDetailLocal(sbomID)
		case state == ScanStateRunning:
			return state, "", nil
		case t.pendingShared(sbomID):
			return t.getDetailLocal(sbomID)
		}
		return state, msg, reasons
	}
	// Transitions kept racing the read: the safe local answer.
	return t.localWithoutShared(sbomID)
}

// localWithoutShared is this process's answer when Redis could not be
// consulted: a local "completed" is not trusted (see GetDetail).
func (t *ScanTracker) localWithoutShared(sbomID uuid.UUID) (ScanState, string, []string) {
	state, msg, reasons := t.getDetailLocal(sbomID)
	if state == ScanStateCompleted {
		return ScanStateUnknown, "", nil
	}
	return state, msg, reasons
}

func (t *ScanTracker) getDetailLocal(sbomID uuid.UUID) (ScanState, string, []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.entries[sbomID]
	if !ok {
		return ScanStateUnknown, "", nil
	}
	if time.Since(entry.updatedAt) > t.retention {
		delete(t.entries, sbomID)
		return ScanStateUnknown, "", nil
	}
	if entry.state != ScanStateFailed {
		return entry.state, entry.errMsg, nil
	}
	return entry.state, entry.errMsg, append([]string(nil), entry.reasons...)
}

// Get returns the current state of the scan and, when failed, the error
// message string. Returns ScanStateUnknown when no entry exists or when
// the entry has aged past `retention`.
func (t *ScanTracker) Get(sbomID uuid.UUID) (ScanState, string) {
	state, msg, _ := t.GetDetail(sbomID)
	return state, msg
}
