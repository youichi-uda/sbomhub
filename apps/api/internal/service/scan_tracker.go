package service

import (
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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
// Storage is in-process only. On API restart all tracked state is lost and
// pollers see `ScanStateUnknown` until --wait-timeout, then fail soft with
// exit 2 ("scan timed out, treating as no threshold violation"). That is
// the honest trade-off — we do not have a persistent scan_runs table yet
// (※要確認: a dedicated table is the proper long-term answer; for #12 we
// chose this hack so we do not need a new migration), and inventing a
// completion state from "vulnerability count stopped increasing" would
// produce false negatives on legitimately-clean SBOMs.
//
// Entries auto-expire after `retention` to bound memory.
type ScanTracker struct {
	mu        sync.RWMutex
	entries   map[uuid.UUID]scanEntry
	retention time.Duration
	// nextGen numbers runs (M62, Codex R1/R2 High): every Begin starts a
	// tracked run of its SBOM, and the SBOM's state is terminal only when
	// none of its runs is active; see Begin.
	nextGen uint64
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
}

// NewScanTracker creates an in-memory tracker. Entries older than 1 hour
// are evicted lazily on read; 1h is well beyond CLI poll windows (default
// 5m) but short enough that long-lived servers do not accumulate state.
func NewScanTracker() *ScanTracker {
	return &ScanTracker{
		entries:   make(map[uuid.UUID]scanEntry),
		retention: 1 * time.Hour,
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
	t.entries[sbomID] = scanEntry{state: ScanStateRunning, updatedAt: time.Now()}
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
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nextGen++
	e, ok := t.entries[sbomID]
	if !ok || len(e.active) == 0 || time.Since(e.updatedAt) > t.retention {
		e = scanEntry{active: map[uint64]bool{}}
	}
	e.state = ScanStateRunning
	e.errMsg, e.reasons = "", nil
	e.updatedAt = time.Now()
	e.active[t.nextGen] = true
	t.entries[sbomID] = e
	return t.nextGen
}

// Finish records run gen's outcome — failed when errMsg or reasons is
// non-empty, completed otherwise. It reports whether gen was an active run.
// The SBOM's state becomes terminal only when no other run is active.
func (t *ScanTracker) Finish(sbomID uuid.UUID, gen uint64, reasons []string, errMsg string) bool {
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
	if errMsg != "" || len(reasons) > 0 {
		if errMsg == "" {
			errMsg = "scan failed"
		}
		e.groupMsgs = append(e.groupMsgs, errMsg)
		e.groupReasons = MergeScanReasons(e.groupReasons, reasons)
	}
	e.updatedAt = time.Now()
	if len(e.active) > 0 {
		e.state = ScanStateRunning
		t.entries[sbomID] = e
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
	t.entries[sbomID] = e
	return true
}

// MarkCompleted records that all background scans for the sbom finished
// without error, ending any tracked runs (pre-M62 callers and tests; the scan
// routes use Begin / Finish).
func (t *ScanTracker) MarkCompleted(sbomID uuid.UUID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[sbomID] = scanEntry{state: ScanStateCompleted, updatedAt: time.Now()}
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
	t.entries[sbomID] = scanEntry{state: ScanStateFailed, updatedAt: time.Now(), errMsg: errMsg,
		reasons: append([]string(nil), reasons...)}
}

// GetDetail is Get plus the failed scan's reason codes, read atomically.
func (t *ScanTracker) GetDetail(sbomID uuid.UUID) (ScanState, string, []string) {
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
	t.mu.RLock()
	entry, ok := t.entries[sbomID]
	t.mu.RUnlock()
	if !ok {
		return ScanStateUnknown, ""
	}
	if time.Since(entry.updatedAt) > t.retention {
		t.mu.Lock()
		delete(t.entries, sbomID)
		t.mu.Unlock()
		return ScanStateUnknown, ""
	}
	return entry.state, entry.errMsg
}
