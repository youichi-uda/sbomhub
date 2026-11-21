package service

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
)

// Recorded scan results (2026-11, migration 071): the LAST terminal result of
// each SBOM's scan, kept in PostgreSQL so scan-status can still answer once
// the live status (Redis, about an hour after the scan's last write, §25.3;
// or this process's memory) no longer holds an entry for the SBOM.
//
// # What is written, and by whom
//
//   - open: when a run is attached to its tenant (ScanTracker.Attach, called
//     by the scan's goroutine once the SBOM is committed and before it scans),
//     its generation, its start (this process's clock) and the row's write
//     sequence go into open_runs. Attach waits for this write (at most
//     attachWait), so a run normally scans only once its start is recorded.
//   - close: when the run's finish has been applied — to the shared store
//     (Redis) when there is one, else to this process's memory — its
//     generation leaves open_runs. If the SBOM's status is then terminal
//     (read back from Redis with its publish time and version, or this
//     process's group without Redis), that result is recorded with it.
//   - re-check: a finish that found the status still running (another run of
//     the group active — possibly on an older replica —, or a young key held
//     running, §25.3) reads it again (recordRechecks, then every
//     recordRecheckEvery while it still reads running); a terminal state
//     found then is recorded.
//
// A terminal result replaces the recorded one only when it was published at
// or after it — (finished_at, Redis key incarnation, Redis write counter),
// so a slow write of an older group never replaces a newer group's result,
// even within one millisecond.
//
// Every write is done by one background worker per process, in the order the
// tracker queued them (an open always lands before its own close), each in
// its own short tenant transaction. A write that fails is deferred, with the
// later writes of its SBOM behind it, and retried (recordRetries, then every
// recordOpenRetryEvery) until it lands; the other SBOMs' writes go on. A
// failed write never fails the scan: it is logged, and readers fall back to
// the conservative answers below meanwhile.
//
// # What readers see (recordedStatus)
//
// Only when the live status has no entry (Redis was read and holds none, and
// this process has no pending write or active run of the SBOM; without Redis,
// this process has no entry):
//
//   - a run still open and younger than the longest possible scan: unknown —
//     it may be running while the live status lost it (eviction, FLUSHDB, a
//     process that cannot reach Redis), so an older recorded row must not
//     stand for it;
//   - a run still open, older than that, that is later than the recorded
//     result: failed, reason interrupted — its process never reported an
//     outcome (crash, restart, Redis unreachable for longer than retention,
//     or every recording attempt of its finish failed);
//   - a recorded terminal result older than the latest recorded start (a
//     later run closed without a recorded result: its group was finished by
//     an older replica and never seen terminal): unknown;
//   - otherwise the recorded result, source "recorded", with last_scan_at.
//
// "Later than the recorded result" is decided twice, and either is enough:
// the open was written after the result (the row's write sequence), or the
// run started more than recordClockSlack after the result was published
// (starts are API-process clocks, results Redis's).
//
// The recorded answer carries no scan_run: a run an older replica started,
// or a write that failed, leaves no trace here, so equality with an earlier
// answer could not promise that no scan began in between (§37).
//
// Residual (rolling upgrade): an older replica writes no open. A scan it runs
// on an SBOM with a recorded result is hidden behind that result only if the
// live status is lost while it runs (eviction, FLUSHDB) and only until its
// run rejoins the shared status (its next heartbeat, normally within 30s).

const (
	// recordQueueCap bounds the re-checks waiting for the worker; beyond it
	// a re-check is dropped (logged). Opens and closes are dropped only
	// beyond recordQueueHardCap: a dropped open can let an older result
	// stand for a running scan, a dropped close reads interrupted later.
	recordQueueCap     = 4096
	recordQueueHardCap = 65536
	// maxRecClosed bounds the recorded runs one coalesced shared write
	// closes (mergeSet.recClosed).
	maxRecClosed = 4096
	// recordOpTimeout bounds one write or read.
	recordOpTimeout = 5 * time.Second
	// recordMaxOpen bounds open_runs: beyond it the oldest entries go.
	recordMaxOpen = 256
)

// The worker's timings: copied into each recorder when it is built
// (scanRecorder.timing), so a test that changes them for its own tracker
// does not race the workers of earlier ones.
var (
	// recordClockSlack: a start counts as later than a recorded result by
	// time only when it is later by more than this, so ordinary clock skew
	// between an API process and Redis cannot make a run of the recorded
	// group itself look later.
	recordClockSlack = 5 * time.Second
	// recordRechecks: when a finish found the status running, how long after
	// it to read the status again — once a young key's hold is over
	// (scanStatusYoung), and once a run whose process died has been swept
	// (lease + one heartbeat); then every recordRecheckEvery until a scan
	// could no longer be running.
	recordRechecks     = []time.Duration{scanStatusYoung + 5*time.Second, ScanStatusLease + ScanStatusHeartbeat + 10*time.Second}
	recordRecheckEvery = 5 * time.Minute
	// recordRecheckMaxErrs: a chain ends after this many re-checks in a row
	// could not read the shared status.
	recordRecheckMaxErrs = 12
	// recordRetries: the waits before retrying a failed write.
	recordRetries = []time.Duration{500 * time.Millisecond, 2 * time.Second, 5 * time.Second}
	// attachWait bounds how long Attach waits for the run's open.
	attachWait = 2 * time.Second
	// recordOpenRetryEvery: how often writes whose every attempt failed are
	// written again.
	recordOpenRetryEvery = 30 * time.Second
)

// scanResultRecord is one terminal result to record.
type scanResultRecord struct {
	state        ScanState
	errMsg       string
	reasons      []string
	skipped      []string
	checked      []string
	checkedKnown bool
	run          string
	finishedAt   time.Time
	// born / ver order two results published in the same millisecond: the
	// Redis key's incarnation and write counter (0 / this process's entry
	// revision without Redis).
	born, ver int64
	// coveredSeq: the row's write sequence read BEFORE the shared status was
	// read back — every open written up to it began before this result was
	// read, so it is covered by it (part of its group, or earlier). -1: the
	// row's sequence at the write (no shared store: this process's queue
	// already orders its opens after the finish that ended the group).
	coveredSeq int64
}

// openRun is one entry of open_runs.
type openRun struct {
	// Start: the run's start, epoch ms (the attaching process's clock).
	Start int64 `json:"s"`
	// Seq: the row's write sequence (rev) of the open.
	Seq int64 `json:"q"`
	// Unacked: the run's Begin had not reached the shared status when its
	// open was written, so a result read back after the open may predate
	// the run (Codex R3 High-2): the sequence cannot show it covered, only a
	// start clearly before the result can.
	Unacked bool `json:"u,omitempty"`
}

// coveredOpen: open run o is covered by a result covering opens written up
// to resultSeq and published at finishedAt — part of its group, or earlier.
func coveredOpen(o openRun, resultSeq int64, finishedAt time.Time) bool {
	st := time.UnixMilli(o.Start)
	if o.Unacked {
		return st.Before(finishedAt.Add(-recordClockSlack))
	}
	return o.Seq <= resultSeq && !st.After(finishedAt.Add(recordClockSlack))
}

// scanResultRow is one SBOM's row as read.
type scanResultRow struct {
	found        bool
	status       string // "" = no terminal result recorded
	errMsg       string
	reasons      []string
	skipped      []string
	checked      []string
	checkedKnown bool
	run          string
	finishedAt   time.Time // zero when status == ""
	// resultSeq: the write sequence of the recorded result; lastOpenSeq: of
	// the latest open.
	resultSeq   int64
	lastOpenSeq int64
	// lastOpenUnacked: the latest open was unacked (openRun.Unacked).
	lastOpenUnacked bool
	// born / ver: the recorded result's version (scanResultRecord).
	born, ver   int64
	openRuns    map[string]openRun
	lastStarted time.Time // zero when no start was recorded
	rev         int64
}

// scanResultStore is the database side.
type scanResultStore interface {
	open(ctx context.Context, tenantID, sbomID uuid.UUID, gen uint64, startedAt time.Time, unacked bool) error
	// close removes runs gens from the open runs and records rec (nil:
	// nothing) unless a result published later is recorded.
	close(ctx context.Context, tenantID, sbomID uuid.UUID, gens []uint64, rec *scanResultRecord, staleAfter time.Duration) error
	read(ctx context.Context, tenantID, sbomID uuid.UUID) (scanResultRow, error)
	// seq is the row's write sequence (0 without a row).
	seq(ctx context.Context, tenantID, sbomID uuid.UUID) (int64, error)
}

// pgScanResultStore is scanResultStore on tenant_sbom_scan_results.
type pgScanResultStore struct {
	db *sql.DB
}

// tenantTx runs a write in a short transaction of its own bound to the
// tenant (the worker has no request transaction).
func (s *pgScanResultStore) tenantTx(ctx context.Context, tenantID uuid.UUID, fn func(ctx context.Context, tx *sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(database.WithoutTx(context.WithoutCancel(ctx)), recordOpTimeout)
	defer cancel()
	return database.WithTxFunc(ctx, s.db, func(txCtx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(txCtx, `SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
			return fmt.Errorf("set tenant context: %w", err)
		}
		return fn(txCtx, tx)
	})
}

// lockRow returns the SBOM's open runs with its row locked, creating the row
// when create is set; found is false when there is no row visible to the
// tenant. The row is created only for an SBOM of the tenant (sboms is
// row-level secured; migration 071's trigger enforces the same).
func lockRow(ctx context.Context, tx *sql.Tx, tenantID, sbomID uuid.UUID, create bool) (map[string]openRun, lockedRow, bool, error) {
	if create {
		if _, err := tx.ExecContext(ctx, `INSERT INTO tenant_sbom_scan_results (sbom_id, tenant_id)
			SELECT $1, $2 WHERE EXISTS (SELECT 1 FROM sboms WHERE id = $1 AND tenant_id = $2)
			ON CONFLICT (sbom_id) DO NOTHING`, sbomID, tenantID); err != nil {
			return nil, lockedRow{}, false, fmt.Errorf("create scan result row: %w", err)
		}
	}
	var raw []byte
	var lr lockedRow
	err := tx.QueryRowContext(ctx, `SELECT open_runs, finished_at, COALESCE(result_born, 0), COALESCE(result_ver, 0), rev,
			COALESCE(result_seq, 0), COALESCE(last_open_seq, 0)
		FROM tenant_sbom_scan_results WHERE sbom_id = $1 AND tenant_id = $2 FOR UPDATE`, sbomID, tenantID).
		Scan(&raw, &lr.finished, &lr.born, &lr.ver, &lr.rev, &lr.resultSeq, &lr.lastOpenSeq)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, lockedRow{}, false, nil
	}
	if err != nil {
		return nil, lockedRow{}, false, fmt.Errorf("lock scan result row: %w", err)
	}
	return decodeOpen(raw), lr, true, nil
}

type lockedRow struct {
	finished    sql.NullTime
	born, ver   int64
	rev         int64
	resultSeq   int64
	lastOpenSeq int64
}

func decodeOpen(raw []byte) map[string]openRun {
	open := map[string]openRun{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &open); err != nil {
			return map[string]openRun{}
		}
	}
	return open
}

// capOpen keeps the recordMaxOpen newest open runs.
func capOpen(open map[string]openRun) {
	if len(open) <= recordMaxOpen {
		return
	}
	keys := slices.SortedFunc(maps.Keys(open), func(a, b string) int {
		if c := cmp.Compare(open[a].Start, open[b].Start); c != 0 {
			return c
		}
		return cmp.Compare(a, b)
	})
	for _, k := range keys[:len(keys)-recordMaxOpen] {
		delete(open, k)
	}
}

// newerOrSame: result (t, born, ver) was published at or after (t0, born0,
// ver0). Two results of one Redis key incarnation (same non-zero born) are
// ordered by its write counter, which is causal whatever Redis's clock does
// (Codex R7 Medium-1); otherwise by the publish time, then the incarnation,
// then the counter.
func newerOrSame(t time.Time, born, ver int64, t0 time.Time, born0, ver0 int64) bool {
	if born != 0 && born == born0 {
		return ver >= ver0
	}
	if c := t.Compare(t0); c != 0 {
		return c > 0
	}
	if born != born0 {
		return born > born0
	}
	return ver >= ver0
}

func (s *pgScanResultStore) open(ctx context.Context, tenantID, sbomID uuid.UUID, gen uint64, startedAt time.Time, unacked bool) error {
	return s.tenantTx(ctx, tenantID, func(ctx context.Context, tx *sql.Tx) error {
		open, lr, found, err := lockRow(ctx, tx, tenantID, sbomID, true)
		if err != nil {
			return err
		}
		if !found {
			// No SBOM of this tenant (deleted, or another tenant's).
			return errNoSuchSBOM
		}
		seq := lr.rev + 1
		open[genString(gen)] = openRun{Start: startedAt.UnixMilli(), Seq: seq, Unacked: unacked}
		capOpen(open)
		b, err := json.Marshal(open)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE tenant_sbom_scan_results
			SET open_runs = $3, last_started_at = GREATEST(last_started_at, $4), last_open_seq = $5,
			    last_open_unacked = $6, rev = $5, updated_at = NOW()
			WHERE sbom_id = $1 AND tenant_id = $2`, sbomID, tenantID, b, startedAt.UTC(), seq, unacked)
		return err
	})
}

func (s *pgScanResultStore) close(ctx context.Context, tenantID, sbomID uuid.UUID, gens []uint64, rec *scanResultRecord, staleAfter time.Duration) error {
	return s.tenantTx(ctx, tenantID, func(ctx context.Context, tx *sql.Tx) error {
		open, lr, found, err := lockRow(ctx, tx, tenantID, sbomID, rec != nil)
		if err != nil || !found {
			return err
		}
		var closedSeq int64 // the latest open among the runs closed
		for _, g := range gens {
			if o, ok := open[genString(g)]; ok {
				closedSeq = max(closedSeq, o.Seq)
			}
			delete(open, genString(g))
		}
		seq := lr.rev + 1
		record := rec != nil && (!lr.finished.Valid || newerOrSame(rec.finishedAt, rec.born, rec.ver, lr.finished.Time, lr.born, lr.ver))
		var resultSeq int64
		clearsLastUnacked := false
		if record {
			// The runs closed here finished before rec was read back (or,
			// without a shared store, are in its group): it covers them,
			// unacked or not (Codex R5 Medium-2).
			resultSeq = max(coveredBy(rec, lr, seq), closedSeq)
			clearsLastUnacked = closedSeq > 0 && closedSeq == lr.lastOpenSeq
			dropCovered(open, resultSeq, rec.finishedAt, staleAfter, time.Now())
		}
		b, err := json.Marshal(open)
		if err != nil {
			return err
		}
		if !record {
			_, err = tx.ExecContext(ctx, `UPDATE tenant_sbom_scan_results
				SET open_runs = $3, rev = $4, updated_at = NOW()
				WHERE sbom_id = $1 AND tenant_id = $2`, sbomID, tenantID, b, seq)
			return err
		}
		var checked any // NULL = coverage not reported
		if rec.checkedKnown {
			checked = pq.Array(nonNil(rec.checked))
		}
		var run any
		if rec.run != "" {
			run = rec.run
		}
		errMsg := ""
		reasons := []string{}
		if rec.state == ScanStateFailed {
			errMsg = rec.errMsg
			reasons = nonNil(rec.reasons)
		}
		_, err = tx.ExecContext(ctx, `UPDATE tenant_sbom_scan_results SET
				status = $3, error = $4, reasons = $5, checked_sources = $6, skipped_sources = $7,
				scan_run = $8, finished_at = $9, result_born = $10, result_ver = $11, open_runs = $12,
				vuln_total = (SELECT count(*) FROM component_vulnerabilities cv
				              JOIN components c ON c.id = cv.component_id WHERE c.sbom_id = $1),
				result_seq = $13, rev = $14, last_open_unacked = last_open_unacked AND NOT $15, updated_at = NOW()
			WHERE sbom_id = $1 AND tenant_id = $2`,
			sbomID, tenantID, string(rec.state), errMsg, pq.Array(reasons), checked,
			pq.Array(nonNil(rec.skipped)), run, rec.finishedAt.UTC(), rec.born, rec.ver, b, resultSeq, seq, clearsLastUnacked)
		return err
	})
}

// coveredBy is the write sequence up to which opens are covered by the
// result being written: what the result itself covers (rec.coveredSeq, or
// the write's own sequence without a shared store), and never less than what
// the recorded result covered (a result published later covers every run the
// earlier one covered; the same result replayed covers no less — and no
// more: Codex R2 High-1, a replay must not cover an open written after it was
// first read).
func coveredBy(rec *scanResultRecord, lr lockedRow, writeSeq int64) int64 {
	c := rec.coveredSeq
	if c < 0 {
		c = writeSeq
	}
	return max(c, lr.resultSeq)
}

// dropCovered removes the runs that never closed, can no longer be running
// and are covered by the result (written up to resultSeq and begun before
// it): they are part of what it reports (their interruption, §25.3) or of an
// earlier group. A run that is later by either rule stays (recordedStatus).
func dropCovered(open map[string]openRun, resultSeq int64, finishedAt time.Time, staleAfter time.Duration, now time.Time) {
	for g, o := range open {
		if now.Sub(time.UnixMilli(o.Start)) > staleAfter && coveredOpen(o, resultSeq, finishedAt) {
			delete(open, g)
		}
	}
}

func (s *pgScanResultStore) seq(ctx context.Context, tenantID, sbomID uuid.UUID) (int64, error) {
	var seq int64
	err := s.tenantTx(ctx, tenantID, func(ctx context.Context, tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT rev FROM tenant_sbom_scan_results WHERE sbom_id = $1 AND tenant_id = $2`,
			sbomID, tenantID).Scan(&seq)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	})
	return seq, err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// readSavepoint names the savepoint a read inside a request transaction uses.
const readSavepoint = "scan_result_read"

// recordCleanupTimeout bounds rolling back / releasing that savepoint.
const recordCleanupTimeout = 2 * time.Second

// read reads the SBOM's row. Inside a request transaction (scan-status runs
// in the tenant's TenantTx) it reads on that transaction, under a savepoint
// so a failed read cannot abort it, rather than taking a second pool
// connection; otherwise in a short tenant transaction of its own. Both are
// bounded by recordOpTimeout and by ctx.
func (s *pgScanResultStore) read(ctx context.Context, tenantID, sbomID uuid.UUID) (scanResultRow, error) {
	ctx, cancel := context.WithTimeout(ctx, recordOpTimeout)
	defer cancel()
	if tx, ok := database.TxFromContext(ctx); ok {
		if _, err := tx.ExecContext(ctx, `SAVEPOINT `+readSavepoint); err != nil {
			return scanResultRow{}, fmt.Errorf("scan result savepoint: %w", err)
		}
		row, err := readRow(ctx, tx, tenantID, sbomID)
		// The cleanup runs even when ctx is done (the savepoint must go),
		// under its own bound (Codex R2 Medium-3).
		cctx, ccancel := context.WithTimeout(context.WithoutCancel(ctx), recordCleanupTimeout)
		defer ccancel()
		if err != nil {
			if _, rerr := tx.ExecContext(cctx, `ROLLBACK TO SAVEPOINT `+readSavepoint); rerr != nil {
				return scanResultRow{}, errors.Join(err, rerr)
			}
		}
		if _, rerr := tx.ExecContext(cctx, `RELEASE SAVEPOINT `+readSavepoint); rerr != nil && err == nil {
			err = rerr
		}
		return row, err
	}
	var row scanResultRow
	err := database.WithTxFunc(ctx, s.db, func(txCtx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(txCtx, `SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
			return fmt.Errorf("set tenant context: %w", err)
		}
		var err error
		row, err = readRow(txCtx, tx, tenantID, sbomID)
		return err
	})
	return row, err
}

func readRow(ctx context.Context, tx *sql.Tx, tenantID, sbomID uuid.UUID) (scanResultRow, error) {
	var row scanResultRow
	var status, run sql.NullString
	var finished, started sql.NullTime
	var reasons, skipped, checked pq.StringArray
	var checkedNull bool
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT status, error, reasons, checked_sources, checked_sources IS NULL,
			skipped_sources, scan_run, finished_at, open_runs, last_started_at,
			COALESCE(result_seq, 0), COALESCE(last_open_seq, 0), last_open_unacked, rev
		FROM tenant_sbom_scan_results WHERE sbom_id = $1 AND tenant_id = $2`, sbomID, tenantID).
		Scan(&status, &row.errMsg, &reasons, &checked, &checkedNull, &skipped, &run, &finished, &raw, &started,
			&row.resultSeq, &row.lastOpenSeq, &row.lastOpenUnacked, &row.rev)
	if errors.Is(err, sql.ErrNoRows) {
		return scanResultRow{}, nil
	}
	if err != nil {
		return scanResultRow{}, err
	}
	row.found = true
	row.status = status.String
	row.reasons = []string(reasons)
	row.skipped = []string(skipped)
	row.checked = append([]string{}, checked...)
	row.checkedKnown = !checkedNull
	row.run = run.String
	if finished.Valid {
		row.finishedAt = finished.Time
	}
	if started.Valid {
		row.lastStarted = started.Time
	}
	row.openRuns = decodeOpen(raw)
	return row, nil
}

// recordedStatus turns a row into scan-status's answer (see the file
// comment); ok is false when it answers unknown. staleAfter is how long a run
// can possibly still be running; now is the reader's clock.
func recordedStatus(row scanResultRow, staleAfter time.Duration, now time.Time) (ScanStatusDetail, bool) {
	if !row.found {
		return ScanStatusDetail{}, false
	}
	later := func(o openRun) bool {
		return row.status == "" || !coveredOpen(o, row.resultSeq, row.finishedAt)
	}
	var interrupted time.Time
	for _, o := range row.openRuns {
		started := time.UnixMilli(o.Start)
		if now.Sub(started) <= staleAfter {
			return ScanStatusDetail{}, false
		}
		if later(o) && started.After(interrupted) {
			interrupted = started
		}
	}
	version := "d" + strconv.FormatInt(row.rev, 10)
	if !interrupted.IsZero() {
		return ScanStatusDetail{State: ScanStateFailed, Error: scanInterruptedMarker,
			Reasons: []string{ScanReasonInterrupted}, Source: ScanStatusSourceRecorded,
			LastScanAt: interrupted, Version: version}, true
	}
	if row.status == "" {
		return ScanStatusDetail{}, false
	}
	if row.lastOpenSeq > 0 && later(openRun{Start: row.lastStarted.UnixMilli(), Seq: row.lastOpenSeq, Unacked: row.lastOpenUnacked}) {
		// A later run closed without a recorded result.
		return ScanStatusDetail{}, false
	}
	d := ScanStatusDetail{State: ScanState(row.status), Source: ScanStatusSourceRecorded,
		LastScanAt: row.finishedAt, Version: version,
		Skipped: append([]string(nil), row.skipped...)}
	switch d.State {
	case ScanStateCompleted:
	case ScanStateFailed:
		d.Error = row.errMsg
		d.Reasons = append([]string(nil), row.reasons...)
	default:
		return ScanStatusDetail{}, false
	}
	if row.checkedKnown {
		d.Checked, d.CheckedKnown = append([]string{}, row.checked...), true
	}
	normaliseCoverage(&d)
	return d, true
}

// recordOp is one queued write of the recorder.
type recordOp struct {
	kind     recordOpKind
	tenantID uuid.UUID
	sbomID   uuid.UUID
	// gen: the run opened (unacked: see openRun); gens: the runs closed.
	gen     uint64
	unacked bool
	gens    []uint64
	at      time.Time
	// rec: a terminal result known when queued (no shared store).
	rec *scanResultRecord
	// recheck: how many re-checks of this chain came before; errs: how many
	// of the last ones in a row could not read the shared status.
	recheck int
	errs    int
	// done, if set, is closed after the write's first attempt (or when it is
	// dropped): Attach waits for it.
	done chan struct{}
}

type recordOpKind int

const (
	recOpen recordOpKind = iota
	// recClose: rec, or with a shared store the status read back.
	recClose
	// recRecheck: the shared status read again; recorded when terminal.
	recRecheck
	// recDrop: the run leaves the open runs; nothing is recorded.
	recDrop
	// recRetryDeferred: the deferred writes are written again.
	recRetryDeferred
)

// scanRecorder writes the tracker's results in queue order (one worker).
type scanRecorder struct {
	store scanResultStore
	// shared reads the shared status with the time it was published; nil
	// without a shared store.
	shared func(ctx context.Context, sbomID uuid.UUID) (statusView, time.Time, error)
	// staleAfter: how long a run can possibly still be running.
	staleAfter time.Duration
	timing     recordTiming

	mu      sync.Mutex
	queue   []recordOp
	running bool
	// idle is signalled whenever the worker empties the queue (tests).
	idle *sync.Cond
	// rechecking: SBOMs with a re-check chain scheduled (one per SBOM).
	rechecking map[uuid.UUID]bool
	// deferred: per SBOM, writes whose every attempt failed and the later
	// writes of that SBOM, retried in order every openRetryEvery until they
	// land (deferOp); deferredN counts them; deferredTimer: a retry is
	// scheduled.
	deferred      map[uuid.UUID][]recordOp
	deferredN     int
	deferredTimer bool
	// deferredRounds: retry rounds since the deferred writes were last all
	// written (the first ones come sooner).
	deferredRounds int
}

// recordTiming is a recorder's copy of the worker's timings.
type recordTiming struct {
	rechecks       []time.Duration
	recheckEvery   time.Duration
	recheckMaxErrs int
	retries        []time.Duration
	attachWait     time.Duration
	openRetryEvery time.Duration
}

func newScanRecorder(store scanResultStore, staleAfter time.Duration) *scanRecorder {
	r := &scanRecorder{store: store, staleAfter: staleAfter, rechecking: map[uuid.UUID]bool{}, deferred: map[uuid.UUID][]recordOp{},
		timing: recordTiming{rechecks: slices.Clone(recordRechecks), recheckEvery: recordRecheckEvery,
			recheckMaxErrs: recordRecheckMaxErrs, retries: slices.Clone(recordRetries), attachWait: attachWait,
			openRetryEvery: recordOpenRetryEvery}}
	r.idle = sync.NewCond(&r.mu)
	return r
}

// enqueue queues op; it never blocks.
func (r *scanRecorder) enqueue(op recordOp) {
	r.mu.Lock()
	defer r.mu.Unlock()
	full := len(r.queue) >= recordQueueHardCap || (op.kind == recRecheck && len(r.queue) >= recordQueueCap)
	if full && op.kind != recRetryDeferred { // the retry tick is never dropped (Codex R6 Low-1)
		slog.Warn("scan result: write queue full; dropping a write (the recorded result of this SBOM may stay behind)",
			"sbom_id", op.sbomID, "kind", int(op.kind))
		if op.done != nil {
			close(op.done)
		}
		if op.kind == recRecheck {
			// The chain ends here: a later finish may start a new one
			// (Codex R3 Medium-1).
			delete(r.rechecking, op.sbomID)
		}
		return
	}
	r.queue = append(r.queue, op)
	if !r.running {
		r.running = true
		go r.work()
	}
}

func (r *scanRecorder) work() {
	for {
		r.mu.Lock()
		if len(r.queue) == 0 {
			r.running = false
			r.idle.Broadcast()
			r.mu.Unlock()
			return
		}
		op := r.queue[0]
		r.queue = r.queue[1:]
		r.mu.Unlock()
		if r.deferBehind(op) {
			continue
		}
		r.apply(op)
	}
}

// waitIdle waits until the queue is empty and the worker stopped (tests).
func (r *scanRecorder) waitIdle() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for r.running || len(r.queue) > 0 {
		r.idle.Wait()
	}
}

// once runs write once; done, if set, is closed after it (Attach waits for
// that only, so a database that fails at once does not hold the scan: Codex
// R2 Medium-1). A failed write is deferred by apply, never retried in place:
// the worker goes on with the other SBOMs' writes (Codex R6 Medium-2).
func once(done chan struct{}, write func() error) error {
	err := write()
	if done != nil {
		close(done)
	}
	return err
}

// errNoSuchSBOM: the row cannot be created (the SBOM is gone, or is not the
// tenant's). Retrying cannot help.
var errNoSuchSBOM = errors.New("scan result row: no such SBOM for the tenant")

// permanentRecordError: an error a retry cannot fix — no such SBOM, or an
// integrity violation (SQLSTATE class 23: the SBOM was deleted meanwhile).
func permanentRecordError(err error) bool {
	if errors.Is(err, errNoSuchSBOM) {
		return true
	}
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code.Class() == "23"
}

func (r *scanRecorder) apply(op recordOp) {
	err := r.write(op)
	if err == nil {
		return
	}
	if permanentRecordError(err) {
		slog.Warn("scan result: recording refused", "sbom_id", op.sbomID, "kind", int(op.kind), "error", err)
		return
	}
	slog.Warn("scan result: recording failed; it is retried (until then scan-status may answer unknown for this SBOM once its live status expires)",
		"sbom_id", op.sbomID, "kind", int(op.kind), "error", err)
	r.deferOp(op)
}

// write applies op once.
func (r *scanRecorder) write(op recordOp) error {
	ctx := context.Background()
	do := once
	switch op.kind {
	case recOpen:
		return do(op.done, func() error {
			return r.store.open(ctx, op.tenantID, op.sbomID, op.gen, op.at, op.unacked)
		})
	case recRetryDeferred:
		r.retryDeferred()
		return nil
	case recDrop:
		return do(nil, func() error { return r.store.close(ctx, op.tenantID, op.sbomID, op.gens, nil, r.staleAfter) })
	case recClose, recRecheck:
		rec := op.rec
		running := false
		if r.shared != nil {
			// The row's sequence BEFORE the shared read: the opens the
			// result read back can cover (scanResultRecord.coveredSeq).
			covered, serr := r.store.seq(ctx, op.tenantID, op.sbomID)
			if serr != nil {
				covered = 0 // nothing is covered by sequence; the time rule still applies
			}
			var unreadable bool
			rec, running, unreadable = r.readShared(ctx, op)
			if rec != nil {
				rec.coveredSeq = covered
			}
			if running {
				running = r.scheduleRecheck(op, unreadable)
			}
		}
		if op.kind == recRecheck {
			if !running {
				// The chain ends: recorded now, or nothing left to see.
				r.mu.Lock()
				delete(r.rechecking, op.sbomID)
				r.mu.Unlock()
			}
			if rec == nil {
				return nil
			}
		}
		gens := op.gens
		if op.kind == recRecheck {
			gens = nil
		}
		return do(nil, func() error { return r.store.close(ctx, op.tenantID, op.sbomID, gens, rec, r.staleAfter) })
	}
	return nil
}

// deferOp keeps a write whose attempts all failed (Codex R3 High-1, R4
// High-2), to be written again every openRetryEvery, in order with the later
// writes of its SBOM (which wait behind it), until it lands.
func (r *scanRecorder) deferOp(op recordOp) {
	op.done = nil
	r.mu.Lock()
	defer r.mu.Unlock()
	if op.kind == recRecheck {
		// Replayed as a plain read-back, which starts a new chain if the
		// status still reads running: this chain ends here (Codex R5
		// Medium-3).
		op.kind, op.gens = recClose, nil
		delete(r.rechecking, op.sbomID)
	}
	if r.deferredN >= recordQueueHardCap {
		slog.Warn("scan result: too many writes waiting for the database; dropping one", "sbom_id", op.sbomID)
		return
	}
	r.deferred[op.sbomID] = append(r.deferred[op.sbomID], op)
	r.deferredN++
	r.scheduleDeferredLocked()
}

// deferBehind defers op when earlier writes of its SBOM are waiting: it
// reports whether it did.
func (r *scanRecorder) deferBehind(op recordOp) bool {
	if op.kind == recRetryDeferred {
		return false
	}
	r.mu.Lock()
	waiting := len(r.deferred[op.sbomID]) > 0
	r.mu.Unlock()
	if !waiting {
		return false
	}
	if op.done != nil {
		close(op.done)
	}
	r.deferOp(op)
	return true
}

// scheduleDeferredLocked schedules a retry of the deferred writes. r.mu is
// held.
func (r *scanRecorder) scheduleDeferredLocked() {
	if r.deferredN == 0 {
		r.deferredRounds = 0
	}
	if r.deferredTimer || r.deferredN == 0 {
		return
	}
	r.deferredTimer = true
	// Soon at first (recordRetries), then every openRetryEvery.
	delay := r.timing.openRetryEvery
	if r.deferredRounds < len(r.timing.retries) {
		delay = r.timing.retries[r.deferredRounds]
	}
	r.deferredRounds++
	time.AfterFunc(delay, func() {
		r.mu.Lock()
		r.deferredTimer = false
		r.mu.Unlock()
		r.enqueue(recordOp{kind: recRetryDeferred})
	})
}

// retryDeferred writes each SBOM's deferred writes again, in order, once
// each, stopping at an SBOM's first failure.
func (r *scanRecorder) retryDeferred() {
	r.mu.Lock()
	ids := slices.Collect(maps.Keys(r.deferred))
	r.mu.Unlock()
	for _, id := range ids {
		for {
			r.mu.Lock()
			q := r.deferred[id]
			if len(q) == 0 {
				delete(r.deferred, id)
				r.mu.Unlock()
				break
			}
			op := q[0]
			r.mu.Unlock()
			err := r.write(op)
			if err != nil && !permanentRecordError(err) {
				break
			}
			r.mu.Lock()
			r.deferred[id] = r.deferred[id][1:]
			r.deferredN--
			r.mu.Unlock()
		}
	}
	r.mu.Lock()
	r.scheduleDeferredLocked()
	r.mu.Unlock()
}

// readShared reads the shared status after a finish: the terminal result to
// record, or running (or unreadable) to re-check later.
func (r *scanRecorder) readShared(ctx context.Context, op recordOp) (*scanResultRecord, bool, bool) {
	view, published, err := r.shared(ctx, op.sbomID)
	switch {
	case err != nil:
		slog.Debug("scan result: shared status unreadable; re-checking later", "sbom_id", op.sbomID, "error", err)
		return nil, true, true
	case !view.found:
		return nil, false, false
	case view.state == ScanStateRunning:
		return nil, true, false
	case view.state != ScanStateCompleted && view.state != ScanStateFailed:
		return nil, false, false
	}
	born, ver := parseSharedVersion(view.version)
	return &scanResultRecord{state: view.state, errMsg: view.errMsg, reasons: view.reasons,
		skipped: view.skipped, checked: view.checked, checkedKnown: view.checkedKnown,
		run: view.run, finishedAt: published, born: born, ver: ver}, false, false
}

// parseSharedVersion splits a shared status version ("s<born>:<rev>") into
// its key incarnation and write counter; 0, 0 when it does not parse.
func parseSharedVersion(v string) (int64, int64) {
	b, rv, ok := strings.Cut(strings.TrimPrefix(v, "s"), ":")
	if !ok {
		return 0, 0
	}
	born, err1 := strconv.ParseInt(b, 10, 64)
	rev, err2 := strconv.ParseInt(rv, 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0
	}
	return born, rev
}

// scheduleRecheck schedules the next re-check of op's SBOM: after each of
// recordRechecks, then every recordRecheckEvery for as long as the shared
// status says running (it does so only while some run's lease is renewed,
// §25.3, so the chain ends with the scans; Codex R3 Medium-2), or until
// recordRecheckMaxErrs re-checks in a row could not read it. One chain per
// SBOM. It reports whether a chain is (still) scheduled.
func (r *scanRecorder) scheduleRecheck(op recordOp, unreadable bool) bool {
	next := recordOp{kind: recRecheck, tenantID: op.tenantID, sbomID: op.sbomID}
	r.mu.Lock()
	defer r.mu.Unlock()
	if op.kind == recRecheck {
		next.recheck = op.recheck + 1
		if unreadable {
			next.errs = op.errs + 1
		}
	} else if r.rechecking[op.sbomID] {
		return true // a chain is already scheduled
	}
	if next.errs > r.timing.recheckMaxErrs {
		delete(r.rechecking, op.sbomID)
		return false
	}
	rc := r.timing.rechecks
	delay := r.timing.recheckEvery
	if next.recheck < len(rc) {
		delay = rc[next.recheck]
		if next.recheck > 0 {
			delay -= rc[next.recheck-1]
		}
	}
	r.rechecking[op.sbomID] = true
	time.AfterFunc(delay, func() { r.enqueue(next) })
	return true
}
