package scheduler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/repository"
)

// # Full catalogue re-read (M58)
//
// The CVE sync is a delta reader: it only ever sees records NVD modified after
// its watermark (less cveSyncReplayOverlap). A catalogue row whose CVE NVD
// last modified before that is never offered again, however stale it is. Two
// classes of row are in that state, and neither is small:
//
//   - every row that existed before M57. Until M57 the sync could not parse
//     NVD's timestamps, so its refresh wrote nothing; those rows hold whatever
//     the first scanner or sync that inserted them saw. Measured 2026-11-08
//     (live NVD, three 110-day windows sampled with resultsPerPage=1): 315,761
//     of NVD's 421,074 CVEs were last modified 2026-04-21..2026-08-09 and
//     93,894 in 2026-08-09..2026-11-08 — i.e. during the months the refresh
//     was dead, and now behind the watermark;
//   - rows the JVN scanner created with JVN's metadata for a CVE NVD has not
//     touched since.
//
// reconcileCatalogue walks NVD's WHOLE modification history in
// lastModStartDate..lastModEndDate windows and offers every record to the same
// update-only write the sync uses (writeCatalogueMetadata), restricted to CVEs
// already in the catalogue. Nothing new is decided per row: the freshness
// guard on UpdateMetadata (stored NULL is writable once, otherwise strictly
// newer wins, future timestamps refused) is what makes the pass idempotent
// and safe to interrupt and repeat. There is no per-row state and no
// migration.
//
// It is also how rows stored under the pre-M67 CVSS rule converge (the sync
// ranked v4.0 above v3.x until M67). The pass offers each record at the
// lastModified the sync already stored, which `strictly newer wins` refuses,
// so UpdateMetadata carries one exception: a dated row with no cvss_version
// (migration 069) is re-derived once at an equal timestamp — only when this
// job reads NVD itself, not a mirror (canonicalNVD). A row NVD has not
// modified since the upgrade therefore converges on the first pass after it — the next one due, i.e. at most
// SBOMHUB_NVD_RECONCILE_INTERVAL (30 days by default) after the previous pass
// finished, plus the pass's own duration.
//
// # Cost (measured 2026-11-08 against live NVD, one request each)
//
// A 2000-record page is 11.4 MB and took 2.8 s. A full pass is therefore about
// ceil(421,074 / 2000) = 211 data pages plus one request per 110-day window
// since cveReconcileEpoch (~93, nearly all empty: the sampled windows in
// 1999, 2015, 2018, 2020, 2022 and 2023 held 0 records), ~2.4 GB, and with the
// doubled pacing below roughly 20 minutes with an API key, a little over an
// hour without one.
//
// # Resumption
//
// Progress is persisted after every window in system_settings — the same
// table, same writer pattern, as the sync's own watermark — as one JSON value
// (cveReconcileStateKey). A restart resumes at the window it was in, so a pass
// is never restarted from 1999 because the process restarted. The pass's end
// is fixed when it starts, so a resumed pass terminates.
//
// What a resume can miss: records that MOVED inside the window being walked
// (NVD re-modified one, it left for a later window, and the ones after it
// shifted down a page). A re-modified record is by definition recent, so the
// delta sync reads it; a record shifted past the cursor is reached by the
// next pass.
//
// # Not starving the delta sync
//
// The pass runs in the sync's own goroutine, AFTER the delta read of the same
// tick, so the two never issue NVD requests at the same time. Its requests are
// paced at twice the sync's interval (cveReconcilePaceFactor), leaving half of
// NVD's published rate for the per-component scanners, and an invocation runs
// under a cveReconcileTickBudget deadline — checked between windows and also
// imposed on the window in flight (its requests and statements are cancelled)
// — so the next delta tick is delayed by about that long at most. A window
// interrupted by the deadline is re-read whole by the next invocation; the
// largest measured window (~158 pages) takes well under an hour.

const (
	// cveReconcileStateKey is the system_settings row holding the pass state.
	cveReconcileStateKey = "cve_catalogue_reconcile"
	// cveReconcilePaceFactor multiplies the sync's per-request delay for the
	// full re-read.
	cveReconcilePaceFactor = 2
	// cveReconcileTickBudget bounds how long one invocation may walk before it
	// stops between windows and leaves the rest to the next tick.
	cveReconcileTickBudget = 6 * time.Hour
	// cveReconcileStateTimeout bounds each read or write of the progress row,
	// which runs outside the tick budget's deadline: a lock held on that row
	// must not hold the sync goroutine — and the next delta read — with it
	// (Codex M58 R2, Medium).
	cveReconcileStateTimeout = time.Minute
	// cveReconcileFailureSample caps the CVE ids a pass records as failed.
	cveReconcileFailureSample = 20
)

// cveReconcileEpoch is where a pass starts. The CVE program began in 1999, so
// no record can have been modified earlier.
var cveReconcileEpoch = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)

// Reconcile pass outcomes as recorded in the state's last_status.
const (
	cveReconcileCompleted                = "completed"
	cveReconcileCompletedWithWriteErrors = "completed_with_write_failures"
)

// cveReconcileState is the persisted progress of the full re-read.
type cveReconcileState struct {
	// PassStartedAt is set while a pass is in progress and is also that pass's
	// fixed end bound.
	PassStartedAt *time.Time `json:"pass_started_at,omitempty"`
	// Cursor is the start of the next window to read.
	Cursor *time.Time `json:"cursor,omitempty"`
	// Pass* accumulate across the invocations of the pass in progress.
	PassPages         int      `json:"pass_pages"`
	PassRecords       int      `json:"pass_records"`
	PassWritten       int      `json:"pass_written"`
	PassWriteFailures int      `json:"pass_write_failures"` // failed write attempts
	PassFailedSample  []string `json:"pass_failed_sample,omitempty"`

	LastFinishedAt    *time.Time `json:"last_finished_at,omitempty"`
	LastStatus        string     `json:"last_status,omitempty"`
	LastRecords       int        `json:"last_records"`
	LastWritten       int        `json:"last_written"`
	LastWriteFailures int        `json:"last_write_failures"`
	LastFailedSample  []string   `json:"last_failed_sample,omitempty"`
}

// WithCatalogueReconcile enables the full catalogue re-read every interval.
// Zero (the default for a job built by NewCVESyncJob) disables it.
func (j *CVESyncJob) WithCatalogueReconcile(interval time.Duration) *CVESyncJob {
	j.reconcileInterval = interval
	return j
}

// reconcileIfDue runs (or resumes) a pass when one is in progress or the last
// finished one is older than the configured interval. It is called by Start
// after each delta read.
func (j *CVESyncJob) reconcileIfDue(ctx context.Context) error {
	if j.reconcileInterval <= 0 || j.offline {
		return nil
	}
	now := time.Now().UTC()
	st, err := j.loadReconcileState(ctx)
	if err != nil {
		return err
	}
	switch {
	case st.PassStartedAt != nil:
		// A pass is in progress: resume it.
	case st.LastFinishedAt == nil:
		// Never completed.
	case st.LastFinishedAt.After(now.Add(sourceClockSkewAllowance)):
		slog.Warn("CVE reconcile: stored last-finished time is in the future; treating the re-read as due",
			"last_finished_at", st.LastFinishedAt.Format(time.RFC3339))
	case now.Sub(*st.LastFinishedAt) < j.reconcileInterval:
		return nil
	}
	_, err = j.reconcileCatalogue(ctx, now)
	return err
}

// reconcileOutcome reports what one invocation did.
type reconcileOutcome struct {
	// Finished is true when this invocation completed the pass.
	Finished bool
	// Status is the finished pass's last_status ("" while unfinished).
	Status string
}

// reconcileCatalogue starts or resumes one pass and walks until it finishes,
// the tick budget runs out (returns Finished=false, nil), or a window cannot
// be read (returns the error; the cursor stays at that window).
func (j *CVESyncJob) reconcileCatalogue(ctx context.Context, now time.Time) (reconcileOutcome, error) {
	st, err := j.loadReconcileState(ctx)
	if err != nil {
		return reconcileOutcome{}, err
	}
	epoch := j.reconcileEpoch
	if epoch.IsZero() {
		epoch = cveReconcileEpoch
	}

	if st.PassStartedAt != nil && !reconcilePassIsSane(st, epoch, now) {
		slog.Error("CVE reconcile: stored pass state is inconsistent (future start, or cursor outside the pass); "+
			"starting a new pass", "pass_started_at", st.PassStartedAt, "cursor", st.Cursor)
		st.PassStartedAt, st.Cursor = nil, nil
	}
	if st.PassStartedAt == nil {
		start, cursor := now, epoch
		st.PassStartedAt, st.Cursor = &start, &cursor
		st.PassPages, st.PassRecords, st.PassWritten, st.PassWriteFailures, st.PassFailedSample = 0, 0, 0, 0, nil
		if err := j.saveReconcileState(ctx, st); err != nil {
			return reconcileOutcome{}, err
		}
		slog.Info("CVE reconcile: starting a full re-read of NVD's catalogue",
			"from", cursor.Format(time.RFC3339), "to", start.Format(time.RFC3339))
	} else {
		slog.Info("CVE reconcile: resuming the full re-read",
			"cursor", st.Cursor.Format(time.RFC3339), "pass_started_at", st.PassStartedAt.Format(time.RFC3339))
	}

	passEnd := *st.PassStartedAt
	budget := j.reconcileBudget
	if budget <= 0 {
		budget = cveReconcileTickBudget
	}
	deadline := time.Now().Add(budget)
	pace := j.pageDelay * cveReconcilePaceFactor

	for st.Cursor.Before(passEnd) {
		windowStart := *st.Cursor
		windowEnd := windowStart.Add(cveSyncMaxFetchSpan)
		if windowEnd.After(passEnd) {
			windowEnd = passEnd
		}
		// One window's counts are added to the pass only once the window has
		// been read to the end (Codex M58 R1, Low). A window that fails is
		// re-read from its first page next time, and the counts of the
		// abandoned read would otherwise survive next to the counts of the
		// retry — a row that failed once and then succeeded would still be
		// reported as a write failure, and the sample would fill with
		// duplicates.
		var winPages, winRecords, winWritten int
		var winFailed []string
		// The budget also bounds the window in flight, not only the gap
		// between windows (Codex M58 R1, Medium): a window whose writes queue
		// on row locks, or a very slow NVD, would otherwise hold this goroutine
		// — and with it the next daily delta read — for as long as it takes.
		walkCtx, cancel := context.WithDeadline(ctx, deadline)
		err := j.walkModifiedWindow(walkCtx, windowStart, windowEnd, pace, func(page []CVEInfo) error {
			winPages++
			winRecords += len(page)
			written, failed, perr := j.reconcilePage(walkCtx, page)
			winWritten += written
			winFailed = append(winFailed, failed...)
			return perr
		})
		// Read the deadline off walkCtx BEFORE cancel: a page whose writes were
		// cut short by it can come back as per-row failures with a nil error,
		// and advancing past that window would leave its CVEs stale until the
		// next pass (Codex M58 R2, Medium).
		budgetHit := walkCtx.Err() != nil
		cancel()
		if budgetHit && ctx.Err() == nil {
			// The budget ran out inside this window. Not a failure: the cursor
			// still points at it and the next invocation re-reads it whole.
			slog.Warn("CVE reconcile: tick budget ran out inside a window; pausing, the next tick re-reads that window",
				"window_start", windowStart.Format(time.RFC3339), "window_end", windowEnd.Format(time.RFC3339),
				"budget", budget.String())
			return reconcileOutcome{}, nil
		}
		if err != nil {
			// The cursor still points at this window, so the next invocation
			// re-reads it from its first page.
			slog.Error("CVE reconcile: pass INCOMPLETE — a window could not be read; the next tick resumes at it",
				"window_start", windowStart.Format(time.RFC3339), "window_end", windowEnd.Format(time.RFC3339),
				"error", err)
			return reconcileOutcome{}, fmt.Errorf("cve reconcile: window %s..%s: %w",
				windowStart.Format(time.RFC3339), windowEnd.Format(time.RFC3339), err)
		}
		st.PassPages += winPages
		st.PassRecords += winRecords
		st.PassWritten += winWritten
		st.PassWriteFailures += len(winFailed)
		// A record modified exactly on a window boundary is returned by both
		// adjacent windows (the bounds are inclusive), so the same id can fail
		// twice; it is named once (Codex M58 R3, Low). The count stays a count
		// of failed write attempts.
		for _, id := range winFailed {
			if len(st.PassFailedSample) < cveReconcileFailureSample && !slices.Contains(st.PassFailedSample, id) {
				st.PassFailedSample = append(st.PassFailedSample, id)
			}
		}
		next := windowEnd
		st.Cursor = &next
		if err := j.saveReconcileState(ctx, st); err != nil {
			return reconcileOutcome{}, err
		}
		if !st.Cursor.Before(passEnd) {
			break
		}
		if time.Now().After(deadline) {
			slog.Info("CVE reconcile: tick budget used; pausing the re-read, the next tick resumes it",
				"cursor", st.Cursor.Format(time.RFC3339), "budget", budget.String())
			return reconcileOutcome{}, nil
		}
		select {
		case <-ctx.Done():
			return reconcileOutcome{}, ctx.Err()
		case <-time.After(pace):
		}
	}

	finished := time.Now().UTC()
	status := cveReconcileCompleted
	if st.PassWriteFailures > 0 {
		status = cveReconcileCompletedWithWriteErrors
	}
	st.LastFinishedAt = &finished
	st.LastStatus = status
	st.LastRecords, st.LastWritten, st.LastWriteFailures = st.PassRecords, st.PassWritten, st.PassWriteFailures
	st.LastFailedSample = st.PassFailedSample
	pages := st.PassPages
	st.PassStartedAt, st.Cursor = nil, nil
	st.PassPages, st.PassRecords, st.PassWritten, st.PassWriteFailures, st.PassFailedSample = 0, 0, 0, 0, nil
	if err := j.saveReconcileState(ctx, st); err != nil {
		return reconcileOutcome{}, err
	}

	logArgs := []any{"status", status, "pages", pages, "records", st.LastRecords,
		"rows_written", st.LastWritten, "write_failures", st.LastWriteFailures}
	if status == cveReconcileCompleted {
		slog.Info("CVE reconcile: full re-read finished", logArgs...)
	} else {
		// Not "completed": rows exist whose refresh the database refused, and
		// they keep their stored metadata until the next pass offers them again.
		slog.Error("CVE reconcile: full re-read finished WITH WRITE FAILURES; the CVEs below keep their previously "+
			"stored metadata until the next pass", append(logArgs, "failed_cve_ids", st.LastFailedSample)...)
	}
	return reconcileOutcome{Finished: true, Status: status}, nil
}

// reconcilePassIsSane rejects a stored pass that could never terminate or
// that would read outside its own bounds.
func reconcilePassIsSane(st cveReconcileState, epoch, now time.Time) bool {
	if st.Cursor == nil {
		return false
	}
	if st.PassStartedAt.After(now.Add(sourceClockSkewAllowance)) {
		return false
	}
	if st.Cursor.Before(epoch) || st.Cursor.After(*st.PassStartedAt) {
		return false
	}
	return true
}

// reconcilePage offers each record of one page to the catalogue's update-only
// write, for the CVEs the catalogue holds. It returns how many rows were
// written and the ids whose write the database refused. An error (the
// presence lookup failing) stops the pass at this window.
//
// The presence lookup is one statement per page rather than one UPDATE
// attempt per record: of ~421,000 records a pass reads, only the CVEs some
// component was matched to are in the catalogue.
func (j *CVESyncJob) reconcilePage(ctx context.Context, page []CVEInfo) (int, []string, error) {
	if len(page) == 0 {
		return 0, nil, nil
	}
	ids := make([]string, 0, len(page))
	for _, c := range page {
		ids = append(ids, c.ID)
	}
	// catalogueCtx: the catalogue is global and is never written or read for
	// this purpose inside a tenant transaction.
	cctx := catalogueCtx(ctx)
	present, err := j.cataloguePresence(cctx, ids)
	if err != nil {
		return 0, nil, err
	}

	written := 0
	var failed []string
	for _, c := range page {
		if !present[c.ID] {
			continue
		}
		outcome, err := j.writeCatalogueMetadata(cctx, c)
		if err != nil {
			slog.Warn("CVE reconcile: catalogue write failed", "cve_id", c.ID, "error", err)
			failed = append(failed, c.ID)
			continue
		}
		if outcome == repository.MetadataWritten {
			written++
		}
	}
	return written, failed, nil
}

// cataloguePresence returns which of ids are rows of the catalogue.
func (j *CVESyncJob) cataloguePresence(ctx context.Context, ids []string) (map[string]bool, error) {
	rows, err := j.db.QueryContext(ctx, `SELECT cve_id FROM vulnerabilities WHERE cve_id = ANY($1)`, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("cve reconcile: catalogue presence lookup: %w", err)
	}
	defer rows.Close()
	present := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("cve reconcile: catalogue presence lookup: %w", err)
		}
		present[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cve reconcile: catalogue presence lookup: %w", err)
	}
	return present, nil
}

// loadReconcileState reads the pass state. An absent row is the zero state;
// an unparseable one is reported and treated as the zero state, so a corrupt
// value costs one pass from the epoch rather than stopping the re-read for
// good.
func (j *CVESyncJob) loadReconcileState(ctx context.Context) (cveReconcileState, error) {
	sctx, cancel := context.WithTimeout(catalogueCtx(ctx), cveReconcileStateTimeout)
	defer cancel()
	var raw string
	err := j.db.QueryRowContext(sctx,
		`SELECT value FROM system_settings WHERE key = $1`, cveReconcileStateKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return cveReconcileState{}, nil
	}
	if err != nil {
		return cveReconcileState{}, fmt.Errorf("cve reconcile: read state: %w", err)
	}
	var st cveReconcileState
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		slog.Error("CVE reconcile: stored state is unreadable; starting over", "error", err)
		return cveReconcileState{}, nil
	}
	return st, nil
}

func (j *CVESyncJob) saveReconcileState(ctx context.Context, st cveReconcileState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("cve reconcile: encode state: %w", err)
	}
	sctx, cancel := context.WithTimeout(catalogueCtx(ctx), cveReconcileStateTimeout)
	defer cancel()
	if _, err := j.db.ExecContext(sctx, `
		INSERT INTO system_settings (key, value, description, updated_at)
		VALUES ($1, $2, 'Progress and last result of the full NVD catalogue re-read (M58)', NOW())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
	`, cveReconcileStateKey, string(raw)); err != nil {
		return fmt.Errorf("cve reconcile: save state: %w", err)
	}
	return nil
}
