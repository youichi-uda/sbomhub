package service

import (
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
	// nextGen numbers runs (M62, Codex R1 High): every Begin / MarkRunning
	// starts a new run of its SBOM, and Finish records an outcome only for
	// the run that is still the current one.
	nextGen uint64
}

type scanEntry struct {
	state     ScanState
	updatedAt time.Time
	errMsg    string
	reasons   []string
	gen       uint64
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
// given sbom. Call this synchronously before spawning the goroutine so
// that a CLI client polling immediately after upload sees "running"
// rather than "unknown". It starts a new run; prefer Begin, which also
// returns the run's generation for Finish.
func (t *ScanTracker) MarkRunning(sbomID uuid.UUID) {
	t.Begin(sbomID)
}

// Begin starts a new run of the sbom's scan, marks it running, and returns the
// run's generation. Only the run that is current when it finishes can record
// its outcome (Finish): if a second scan of the same SBOM starts while the
// first is still running (an upload scan and a manual one), the first one's
// completion must not report "completed" while the second is still fetching
// — a poller would read the counts as final (Codex M62 R1 High).
func (t *ScanTracker) Begin(sbomID uuid.UUID) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nextGen++
	t.entries[sbomID] = scanEntry{state: ScanStateRunning, updatedAt: time.Now(), gen: t.nextGen}
	return t.nextGen
}

// Finish records run gen's outcome — completed when reasons is empty and
// errMsg is "", failed otherwise — if gen is still the sbom's current run.
// It reports whether the outcome was recorded.
func (t *ScanTracker) Finish(sbomID uuid.UUID, gen uint64, reasons []string, errMsg string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	cur, ok := t.entries[sbomID]
	if ok && cur.gen != gen {
		return false
	}
	e := scanEntry{state: ScanStateCompleted, updatedAt: time.Now(), gen: gen}
	if errMsg != "" || len(reasons) > 0 {
		e.state = ScanStateFailed
		e.errMsg = errMsg
		e.reasons = append([]string(nil), reasons...)
	}
	t.entries[sbomID] = e
	return true
}

// MarkCompleted records that all background scans for the sbom finished
// without error. It applies to whichever run is current (pre-M62 callers).
func (t *ScanTracker) MarkCompleted(sbomID uuid.UUID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[sbomID] = scanEntry{state: ScanStateCompleted, updatedAt: time.Now(), gen: t.entries[sbomID].gen}
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
		reasons: append([]string(nil), reasons...), gen: t.entries[sbomID].gen}
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
