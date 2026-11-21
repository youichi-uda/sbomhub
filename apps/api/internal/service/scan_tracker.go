package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"log/slog"
	"math"
	"slices"
	"strconv"
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
	// maxRunAge (M72) is how long a scan can possibly run: its deadline plus
	// the final write's 5 minutes. A tombstone of an interrupted run older
	// than that cannot belong to a live run.
	maxRunAge time.Duration
	revSeq    uint64
	lastSweep time.Time

	// shared (M72) is the Redis store; nil keeps the tracker in-memory only.
	shared scanStatusStore
	// qMu guards the shared-write queues, the live runs and the heartbeat
	// loop's state (scan_tracker_shared.go).
	qMu sync.Mutex
	// queues holds, per SBOM, the shared writes not yet applied, in call
	// order.
	queues map[uuid.UUID]*sbomQueue
	// live: this process's active runs (lease renewal), with their start.
	live map[runKey]*liveRun
	// ready: queues waiting for a drain worker (FIFO); workers: running
	// workers.
	ready      []uuid.UUID
	workers    int
	rejoinSem  chan struct{} // bounds rejoins in flight (maxRejoins)
	queueCap   int           // maxQueuedWrites; smaller in tests
	beginWait  time.Duration // beginWait; shorter in tests
	hbActive   bool
	hbInterval time.Duration

	// results (2026-11, scan_result_store.go) records the last terminal
	// result of each SBOM in PostgreSQL; nil records nothing.
	results *scanRecorder
	// attached: the tenant of each run whose result is recorded (Attach).
	// Guarded by mu.
	attached map[runKey]uuid.UUID
}

// Sources of a scan-status answer (ScanStatusDetail.Source).
const (
	// ScanStatusSourceLive: the live status (Redis, or this process's
	// memory).
	ScanStatusSourceLive = "live"
	// ScanStatusSourceRecorded: the last terminal result recorded in
	// PostgreSQL (scan_result_store.go), the live status holding no entry.
	ScanStatusSourceRecorded = "recorded"
)

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
	// skipped is the terminal state's skipped sources: sources a run of the
	// group made no request to (SBOMHUB_JVN=off, offline mode, a
	// `?sources=` subset, the scheduled scan's JVN, no scanner;
	// scan_coverage.go). groupSkipped accumulates them like groupReasons,
	// over every run of the group, and is published with the terminal
	// state — completed or failed alike, since a skip is not a failure.
	skipped      []string
	groupSkipped []string
	// checked / checkedKnown are the terminal state's checked sources
	// (scan_coverage.go): the intersection over the group's runs that
	// reported coverage; checkedKnown is false when none did. group* hold
	// them while runs of the group are still active.
	checked           []string
	checkedKnown      bool
	groupChecked      []string
	groupCheckedKnown bool
	// run is the group's scan run (scan_run.go) in this process: set when a
	// Begin starts a new group, kept by runs that join it; "" = unknown
	// (legacy Mark*, an entry recreated by a finish). Reported only without
	// a shared store: with one, the shared store's scan run is the one every
	// replica agrees on.
	run string
	// rev is the tracker-wide sequence number of the entry's last
	// transition (M72): GetDetail detects a transition that raced its Redis
	// read (Codex M72 R4 High-1).
	rev uint64
}

// put stores e as sbomID's entry with a new revision. t.mu is held. Every
// sweepEvery transitions it also drops entries older than retention with no
// active run (Codex M72 R16 Medium-3): entries were dropped only when their
// own SBOM was read, so unpolled ones (scheduled scans) stayed forever.
func (t *ScanTracker) put(sbomID uuid.UUID, e scanEntry) {
	t.revSeq++
	e.rev = t.revSeq
	t.entries[sbomID] = e
	if t.revSeq%sweepEvery == 0 || time.Since(t.lastSweep) > t.retention {
		t.lastSweep = time.Now()
		for id, old := range t.entries {
			if len(old.active) == 0 && time.Since(old.updatedAt) > t.retention {
				delete(t.entries, id)
			}
		}
	}
}

// sweepEvery: put sweeps expired entries at least every this many transitions.
const sweepEvery = 1024

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
		maxRunAge:  DefaultScanDeadline + 5*time.Minute,
		queues:     map[uuid.UUID]*sbomQueue{},
		live:       map[runKey]*liveRun{},
		queueCap:   maxQueuedWrites,
		rejoinSem:  make(chan struct{}, maxRejoins),
		beginWait:  beginWait,
		hbInterval: ScanStatusHeartbeat,
		attached:   map[runKey]uuid.UUID{},
	}
}

// WithResultStore makes the tracker record each SBOM's last terminal scan
// result in PostgreSQL (migration 071, scan_result_store.go), and scan-status
// answer from it (GetStatusRecorded) once the live status holds no entry.
// Only runs attached to their tenant (Attach) are recorded. Call it after
// WithRedis, before the tracker is used.
func (t *ScanTracker) WithResultStore(db *sql.DB) *ScanTracker {
	if db != nil {
		t.withResultStore(&pgScanResultStore{db: db})
	}
	return t
}

func (t *ScanTracker) withResultStore(store scanResultStore) {
	r := newScanRecorder(store, t.maxRunAge+ScanStatusLease)
	if st, ok := t.shared.(interface {
		getRecord(ctx context.Context, sbomID uuid.UUID) (statusView, time.Time, error)
	}); ok {
		r.shared = st.getRecord
	} else if t.shared != nil {
		// A shared store that cannot say when a state was published (test
		// fakes): its terminal states are recorded with this process's clock.
		r.shared = func(ctx context.Context, sbomID uuid.UUID) (statusView, time.Time, error) {
			v, err := t.shared.get(ctx, sbomID)
			return v, time.Now(), err
		}
	}
	t.results = r
}

// Attach names the tenant of run gen of sbomID, so its start and its outcome
// are recorded (WithResultStore). Call it once the SBOM is committed, from
// the scan's goroutine before the run scans: it waits (at most attachWait)
// until the run's start is recorded, so that a reader that finds no live
// status for the SBOM (Redis lost it) sees the run instead of an older
// recorded result. A run that already finished is ignored.
func (t *ScanTracker) Attach(tenantID, sbomID uuid.UUID, gen uint64) {
	if t.results == nil || tenantID == uuid.Nil || gen == 0 {
		return
	}
	done := make(chan struct{})
	t.mu.Lock()
	if e, ok := t.entries[sbomID]; !ok || !e.active[gen] {
		t.mu.Unlock()
		return
	}
	k := runKey{sbomID, gen}
	if _, ok := t.attached[k]; ok {
		t.mu.Unlock()
		return
	}
	t.attached[k] = tenantID
	// Queued under t.mu: before the run's close, which is queued after its
	// finish (finishLocal, or the shared write's drain).
	t.results.enqueue(recordOp{kind: recOpen, tenantID: tenantID, sbomID: sbomID, gen: gen, at: time.Now(),
		unacked: !t.beginAcked(k), done: done})
	t.mu.Unlock()
	timer := time.NewTimer(t.results.timing.attachWait)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		slog.Warn("scan result: the run's start is not recorded yet; scanning anyway", "sbom_id", sbomID)
	}
}

// beginAcked reports whether run k's Begin has reached the shared status
// (always true without one).
func (t *ScanTracker) beginAcked(k runKey) bool {
	if t.shared == nil {
		return true
	}
	t.qMu.Lock()
	defer t.qMu.Unlock()
	lr := t.live[k]
	return lr != nil && lr.acked
}

// WithRedis makes the tracker keep its state in Redis too (M72), shared by
// every API process on that Redis. Call it before the tracker is used.
func (t *ScanTracker) WithRedis(client *redis.Client) *ScanTracker {
	if client != nil {
		st := &redisScanStatusStore{client: client, ttl: t.retention, lease: ScanStatusLease, probe: true}
		st.initScripts(t.maxRunAge)
		st.probeNow() // learn the eviction settings before the first scan
		t.shared = st
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
	if scanDeadline > 0 {
		t.maxRunAge = scanDeadline + 5*time.Minute
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
	gen, _ := t.BeginRun(sbomID)
	return gen
}

// BeginRun is Begin, also returning the scan run (scan_run.go) of the group
// the run joined or started, as scan-status will report it: from the shared
// store once its Begin (or intent) was applied within Begin's wait, from
// this process without a shared store; "" when unknown.
func (t *ScanTracker) BeginRun(sbomID uuid.UUID) (uint64, string) {
	gen := newRunGenFn()
	t.mu.Lock()
	e, ok := t.entries[sbomID]
	if !ok || len(e.active) == 0 || time.Since(e.updatedAt) > t.retention {
		e = scanEntry{active: map[uint64]bool{}, run: newScanRunIDFn()}
	}
	e.state = ScanStateRunning
	e.errMsg, e.reasons, e.skipped = "", nil, nil
	e.checked, e.checkedKnown = nil, false
	e.updatedAt = time.Now()
	e.active[gen] = true
	t.put(sbomID, e)
	// Queued under t.mu, with the local change: the shared writes of one SBOM
	// follow the order of its local transitions (Codex M72 R3 High-1).
	ev := t.queueBeginLocked(sbomID, gen)
	localRun := e.run
	t.mu.Unlock()
	if testHookAfterLocalBegin != nil {
		testHookAfterLocalBegin(gen)
	}
	if t.shared == nil {
		return gen, localRun
	}
	return gen, t.waitBegin(ev)
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
	return t.finishLocal(sbomID, gen, reasons, errMsg, ScanCoverage{})
}

// FinishSkipped is Finish for a run that skipped sources the operator
// switched off (SBOMHUB_JVN=off). The skip is not a failure: a run that
// skipped JVN and whose other sources succeeded completes. The SBOM's
// terminal state carries the union of the skips of every run of its group,
// in the shared store too, so every replica reports it.
func (t *ScanTracker) FinishSkipped(sbomID uuid.UUID, gen uint64, reasons []string, errMsg string, skipped []string) bool {
	return t.finishLocal(sbomID, gen, reasons, errMsg, ScanCoverage{Skipped: skipped})
}

// FinishCoverage is Finish for a run that reports its coverage: the sources
// it checked and the ones it skipped (scan_coverage.go). Like a skip, a
// coverage report is not a failure; the SBOM's terminal state carries the
// group's coverage, in the shared store too.
func (t *ScanTracker) FinishCoverage(sbomID uuid.UUID, gen uint64, reasons []string, errMsg string, cov ScanCoverage) bool {
	return t.finishLocal(sbomID, gen, reasons, errMsg, cov)
}

func (t *ScanTracker) finishLocal(sbomID uuid.UUID, gen uint64, reasons []string, errMsg string, cov ScanCoverage) bool {
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
	tenantID, attached := t.attached[runKey{sbomID, gen}]
	delete(t.attached, runKey{sbomID, gen})
	recTenant := uuid.Nil
	if attached && t.shared != nil {
		// Closed once the finish reached the shared store (drain).
		recTenant = tenantID
	}
	t.queueFinishLocked(sbomID, gen, sharedMsg, reasons, cov, recTenant)
	if attached && t.shared == nil {
		// Without a shared store this process's group is the SBOM's: closed
		// below, with the terminal result if the group ended.
		defer func() {
			op := recordOp{kind: recClose, tenantID: tenantID, sbomID: sbomID, gens: []uint64{gen}}
			if e := t.entries[sbomID]; len(e.active) == 0 && (e.state == ScanStateCompleted || e.state == ScanStateFailed) {
				op.rec = &scanResultRecord{state: e.state, errMsg: e.errMsg, reasons: e.reasons,
					skipped: OrderScanSources(e.skipped), checked: e.checked, checkedKnown: e.checkedKnown,
					run: e.run, finishedAt: e.updatedAt, ver: int64(e.rev & math.MaxInt64), coveredSeq: -1}
			}
			t.results.enqueue(op)
		}()
	}
	g := groupCoverage{skipped: e.groupSkipped, checked: e.groupChecked, checkedKnown: e.groupCheckedKnown}
	g.add(cov)
	e.groupSkipped, e.groupChecked, e.groupCheckedKnown = g.skipped, g.checked, g.checkedKnown
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
	e.skipped = e.groupSkipped
	e.checked, e.checkedKnown = e.groupChecked, e.groupCheckedKnown
	e.groupMsgs, e.groupReasons, e.groupSkipped = nil, nil, nil
	e.groupChecked, e.groupCheckedKnown = nil, false
	t.put(sbomID, e)
	return true
}

// MarkCompleted records that all background scans for the sbom finished
// without error, ending any tracked runs (pre-M62 callers and tests; the scan
// routes use Begin / Finish).
func (t *ScanTracker) MarkCompleted(sbomID uuid.UUID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.detachLocked(sbomID)
	t.put(sbomID, scanEntry{state: ScanStateCompleted, updatedAt: time.Now()})
	t.queueMarkLocked(sbomID, ScanStateCompleted, "", nil)
}

// detachLocked closes the recorded runs of sbomID that a legacy Mark* ends
// (they will not finish as tracked runs), recording no result: a Mark* is
// not a scan group's outcome. t.mu is held.
func (t *ScanTracker) detachLocked(sbomID uuid.UUID) {
	for k, tenantID := range t.attached {
		if k.sbom == sbomID {
			delete(t.attached, k)
			t.results.enqueue(recordOp{kind: recDrop, tenantID: tenantID, sbomID: sbomID, gens: []uint64{k.gen}})
		}
	}
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
	t.detachLocked(sbomID)
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
//   - Redis unreadable, or without an entry (expired or evicted): this
//     process's memory, except that a "completed" reads unknown — another
//     replica may be scanning the SBOM, and only Redis would say so (Codex
//     M72 R4 High-2, R11 High-1). running and failed are safe.
//
// A local transition that races the Redis read makes the read be retried
// (Codex M72 R4 High-1).
func (t *ScanTracker) GetDetail(sbomID uuid.UUID) (ScanState, string, []string) {
	state, msg, reasons, _ := t.GetDetailVersion(sbomID)
	return state, msg, reasons
}

// ScanStatusDetail is one read of an SBOM's scan status.
type ScanStatusDetail struct {
	State ScanState
	// Error and Reasons are set only when State is failed.
	Error   string
	Reasons []string
	// Skipped names the sources the scan made no request to because of
	// configuration or the request (SBOMHUB_JVN=off, offline mode, a
	// `?sources=` subset, the scheduled scan; scan_coverage.go), in
	// ScanSources order; nil when none. Set only when State is completed or
	// failed.
	Skipped []string
	// Checked names the sources the scan checked (scan_coverage.go), in
	// ScanSources order, never one in Skipped. Meaningful only when
	// CheckedKnown, which is set only when State is completed or failed and
	// a run of the group reported its coverage; then Checked is non-nil.
	Checked      []string
	CheckedKnown bool
	// Run is the scan run (scan_run.go): the same value in two answers means
	// no activity began on the SBOM between them. "" = unknown.
	Run string
	// Version changes with every transition of the status (see
	// GetDetailVersion).
	Version string
	// Source (2026-11) is where the answer came from: ScanStatusSourceLive
	// or ScanStatusSourceRecorded (GetStatusRecorded); "" for unknown.
	Source string
	// LastScanAt (2026-11) is set on recorded answers only: when the
	// recorded result was published — for a recorded interrupted run, when
	// it started (scan_result_store.go).
	LastScanAt time.Time
	// noEntry: unknown because the live status was read and holds no entry
	// for the SBOM (and nothing of it is pending or active here) — the only
	// unknown a recorded result may answer for.
	noEntry bool
}

// GetStatusRecorded is GetStatus, falling back to the SBOM's recorded result
// (WithResultStore, scan_result_store.go) when the live status holds no entry
// for it. The live status always wins: a recorded result is consulted only
// when Redis was read and holds no entry and this process has neither a
// pending write nor an active run of the SBOM (without Redis: when this
// process has no entry). tenantID must be the SBOM's tenant (the caller has
// already found the SBOM in the caller's project).
func (t *ScanTracker) GetStatusRecorded(ctx context.Context, tenantID, sbomID uuid.UUID) ScanStatusDetail {
	d := t.GetStatus(sbomID)
	if d.State != ScanStateUnknown || !d.noEntry || t.results == nil || tenantID == uuid.Nil {
		return d
	}
	row, err := t.results.store.read(ctx, tenantID, sbomID)
	if err != nil {
		slog.Warn("scan status: recorded scan result unreadable; answering unknown", "sbom_id", sbomID, "error", err)
		return d
	}
	// The live status again (Codex R4 High-1): a scan that began while the
	// row was read — its start possibly not recorded yet — wins over it.
	if d2 := t.GetStatus(sbomID); d2.State != ScanStateUnknown || !d2.noEntry {
		return d2
	}
	if rd, ok := recordedStatus(row, t.results.staleAfter, time.Now()); ok {
		return rd
	}
	return d
}

// GetDetailVersion is GetDetail plus a version that changes with every
// transition of the SBOM's status (Codex M72 R13 High-1): a caller that reads
// the status, then something else (the counts), then the status again can
// tell whether anything happened in between, even when both reads say
// "completed".
func (t *ScanTracker) GetDetailVersion(sbomID uuid.UUID) (ScanState, string, []string, string) {
	d := t.GetStatus(sbomID)
	return d.State, d.Error, d.Reasons, d.Version
}

// GetStatus is GetDetailVersion with the skipped sources, all from the same
// read (GetDetail documents which source answers).
func (t *ScanTracker) GetStatus(sbomID uuid.UUID) ScanStatusDetail {
	d := t.getStatus(sbomID)
	if d.State != ScanStateUnknown {
		d.Source = ScanStatusSourceLive
	}
	return d
}

func (t *ScanTracker) getStatus(sbomID uuid.UUID) ScanStatusDetail {
	if t.shared == nil {
		d := t.localVersioned(sbomID, false)
		d.noEntry = d.State == ScanStateUnknown
		return d
	}
	for attempt := 0; attempt < 3; attempt++ {
		// One snapshot of "active here" and the revision (Codex M72 R5
		// High-1): any local transition after it changes the revision.
		active, rev := t.snapshot(sbomID)
		if active {
			return t.localVersioned(sbomID, false)
		}
		if f := testHookAfterLocalActiveCheck; f != nil {
			f()
		}
		view, err := t.shared.get(context.Background(), sbomID)
		if t.revision(sbomID) != rev {
			continue
		}
		switch {
		case err != nil:
			slog.Debug("scan status: shared store unavailable, answering from this process", "sbom_id", sbomID, "error", err)
			return t.localVersioned(sbomID, true)
		case !view.found && t.pendingShared(sbomID):
			// Its own writes have not landed yet. Memory is newer, but a
			// local "completed" could hide another replica's run that was in
			// the missing entry (Codex M72 R20 High-2): it reads running.
			return t.localPending(sbomID)
		case !view.found:
			// No entry (never written, expired, or evicted): a local
			// "completed" may be stale — another replica's run would be in
			// that entry — so it reads unknown (Codex M72 R11 High-1).
			d := t.localVersioned(sbomID, true)
			d.noEntry = d.State == ScanStateUnknown
			return d
		case view.state == ScanStateRunning:
			return ScanStatusDetail{State: view.state, Run: view.run, Version: view.version}
		case t.pendingShared(sbomID):
			return t.localPending(sbomID)
		}
		d := ScanStatusDetail{State: view.state, Error: view.errMsg, Reasons: view.reasons,
			Skipped: view.skipped, Checked: view.checked, CheckedKnown: view.checkedKnown, Run: view.run, Version: view.version}
		normaliseCoverage(&d)
		return d
	}
	// Transitions kept racing the read: the safe local answer.
	return t.localVersioned(sbomID, true)
}

// localPending is the local answer while this process's writes of sbomID are
// pending: a local "completed" reads running until the writes land and Redis
// answers for every replica (Codex M72 R20 High-2). failed is safe.
func (t *ScanTracker) localPending(sbomID uuid.UUID) ScanStatusDetail {
	d := t.localVersioned(sbomID, false)
	if d.State == ScanStateCompleted {
		return ScanStatusDetail{State: ScanStateRunning, Version: d.Version}
	}
	withoutSharedCoverage(&d)
	return d
}

// withoutSharedCoverage drops the checked sources of a local answer that
// stands in for the shared state (Redis unreadable, or this process's writes
// still pending): another replica's overlapping run, which could narrow them,
// is only in Redis (Codex coverage R1 Medium-1). The skipped sources are
// kept, as before: they can only under-state, never over-state, a skip.
func withoutSharedCoverage(d *ScanStatusDetail) {
	d.Checked, d.CheckedKnown = nil, false
}

// localVersioned is this process's answer with its entry revision as the
// version, both read under one lock (Codex M72 R14 Medium-3). withoutShared:
// Redis could not be consulted, so a local "completed" is not trusted (see
// GetDetailVersion) and reads unknown.
func (t *ScanTracker) localVersioned(sbomID uuid.UUID, withoutShared bool) ScanStatusDetail {
	t.mu.Lock()
	defer t.mu.Unlock()
	d := t.getDetailLocked(sbomID)
	if withoutShared && d.State == ScanStateCompleted {
		d = ScanStatusDetail{State: ScanStateUnknown}
	}
	if t.shared == nil && d.State != ScanStateUnknown {
		// Without a shared store this process's group is the only one.
		// With one, a local answer stands in for the shared state, whose
		// scan run may differ (another replica's run in the same group, or
		// a later group): unknown.
		d.Run = t.entries[sbomID].run
	}
	if withoutShared {
		withoutSharedCoverage(&d)
	}
	d.Version = "l" + strconv.FormatUint(t.entries[sbomID].rev, 10)
	return d
}

// getDetailLocked is the in-memory status of sbomID (no version). t.mu is
// held.
func (t *ScanTracker) getDetailLocked(sbomID uuid.UUID) ScanStatusDetail {
	entry, ok := t.entries[sbomID]
	if !ok {
		return ScanStatusDetail{State: ScanStateUnknown}
	}
	if time.Since(entry.updatedAt) > t.retention {
		delete(t.entries, sbomID)
		return ScanStatusDetail{State: ScanStateUnknown}
	}
	d := ScanStatusDetail{State: entry.state, Error: entry.errMsg}
	if entry.state == ScanStateCompleted || entry.state == ScanStateFailed {
		d.Skipped = append([]string(nil), entry.skipped...)
		d.Checked, d.CheckedKnown = append([]string(nil), entry.checked...), entry.checkedKnown
		normaliseCoverage(&d)
	}
	if entry.state == ScanStateFailed {
		d.Reasons = append([]string(nil), entry.reasons...)
	}
	return d
}

// Get returns the current state of the scan and, when failed, the error
// message string. Returns ScanStateUnknown when no entry exists or when
// the entry has aged past `retention`.
func (t *ScanTracker) Get(sbomID uuid.UUID) (ScanState, string) {
	state, msg, _ := t.GetDetail(sbomID)
	return state, msg
}
