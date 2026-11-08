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
}

type scanEntry struct {
	state     ScanState
	updatedAt time.Time
	errMsg    string
	reasons   []string
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
// rather than "unknown".
func (t *ScanTracker) MarkRunning(sbomID uuid.UUID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[sbomID] = scanEntry{state: ScanStateRunning, updatedAt: time.Now()}
}

// MarkCompleted records that all background scans for the sbom finished
// without error.
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
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[sbomID] = scanEntry{state: ScanStateFailed, updatedAt: time.Now(), errMsg: errMsg}
}

// MarkFailedWithReasons is MarkFailed with the scan's reason codes
// (service.ScanReason*), exposed as `reasons` on the scan-status response.
func (t *ScanTracker) MarkFailedWithReasons(sbomID uuid.UUID, errMsg string, reasons []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[sbomID] = scanEntry{state: ScanStateFailed, updatedAt: time.Now(), errMsg: errMsg,
		reasons: append([]string(nil), reasons...)}
}

// GetDetail is Get plus the failed scan's reason codes.
func (t *ScanTracker) GetDetail(sbomID uuid.UUID) (ScanState, string, []string) {
	state, msg := t.Get(sbomID)
	if state != ScanStateFailed {
		return state, msg, nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return state, msg, append([]string(nil), t.entries[sbomID].reasons...)
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
