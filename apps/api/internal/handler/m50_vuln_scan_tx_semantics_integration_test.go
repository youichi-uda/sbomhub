//go:build integration

// Package handler — M50: what VulnerabilityHandler.runScan's transaction
// actually does to the scanners' writes.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M50VulnScanTx' ./internal/handler
//
// Why this file exists. runScan's doc comment claimed the scanners' writes to
// the global (RLS-free) vulnerability tables "go through the raw *sql.DB and
// must survive a partial failure". The first half is false: every repository
// resolves its Queryable with database.Querier(ctx, r.db), runScan hands the
// scanners the ctx returned by WithTxFunc, and that ctx carries the *sql.Tx —
// so the writes go through the TRANSACTION. The comment described a
// durability property the code does not have by the mechanism the comment
// named, which is the "comment stronger than the implementation" defect class
// this repo treats as first-class.
//
// These two tests pin what is really true, so the corrected comment cannot
// drift back:
//
//  1. the writes are tx-bound (invisible to another connection mid-scan) and
//     DO survive a scanner returning an error, because runScan's fn returns
//     nil and WithTxFunc commits regardless; and
//  2. they do NOT survive a failed SQL STATEMENT: PostgreSQL aborts the whole
//     transaction, the later writes cannot run, and the COMMIT fails, so the
//     sweep's entire output is discarded. That is the gap the "raw *sql.DB"
//     wording implied did not exist. It is logged (WithTxFunc returns the
//     commit error and runScan logs it at ERROR) — but the per-scanner
//     "NVD scan completed" INFO line is emitted anyway, so the logs say both
//     things at once.
//
// Measurement note (2026-08-05): the first draft of the corrected doc comment
// asserted the commit "degrades to a silent ROLLBACK — no error reaches this
// function". Running these tests disproved it: lib/pq answers the COMMIT of
// an aborted tx with `pq: Could not complete operation in a failed
// transaction`, WithTxFunc wraps it, and runScan logs "vulnerability scan:
// tenant transaction failed". The replacement comment was corrected before it
// shipped. Comments that are stronger than the code are the defect being
// fixed here; that applies to the fix's own prose too.
package handler

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// m50TxProbeScanner is a componentScanner that performs the same kind of
// write the real NVD / JVN scanners do — VulnerabilityRepository.Create with
// the ctx it was handed — and records what it observed.
type m50TxProbeScanner struct {
	appDB *sql.DB
	vuln  model.Vulnerability

	// poisonFirst issues a statement that ERRORS before the write, to model
	// a scanner whose SQL fails partway through (a constraint violation, a
	// bad cast) rather than one whose HTTP call fails.
	poisonFirst bool
	// returnErr is what ScanComponents returns; runScan logs it and commits
	// anyway.
	returnErr error

	sawTx          bool
	visibleOutside int
	createErr      error
	poisonErr      error
}

func (s *m50TxProbeScanner) ScanComponents(ctx context.Context, _ uuid.UUID) error {
	_, s.sawTx = database.TxFromContext(ctx)

	if s.poisonFirst {
		// A failed statement inside a PostgreSQL transaction aborts the whole
		// block: every later command errors until the tx ends.
		var one int
		s.poisonErr = database.Querier(ctx, s.appDB).
			QueryRowContext(ctx, `SELECT 1/0`).Scan(&one)
	}

	repo := repository.NewVulnerabilityRepository(s.appDB)
	s.createErr = repo.Create(ctx, &s.vuln)

	// Read the row back on a DIFFERENT connection (the pool, not the tx). If
	// the write really went through the raw *sql.DB it would already be
	// committed and visible; a tx-bound write is not.
	if err := s.appDB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM vulnerabilities WHERE id = $1`, s.vuln.ID,
	).Scan(&s.visibleOutside); err != nil {
		s.visibleOutside = -1
	}
	return s.returnErr
}

// m50NewVuln mints a unique, ValidateCVEID-conformant vulnerability row value
// and registers its cleanup. `vulnerabilities` is the shared tenant-less CVE
// catalogue, so it is reaped explicitly (C27).
func m50NewVuln(t *testing.T, migDB *sql.DB) model.Vulnerability {
	t.Helper()
	id := uuid.New()
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, id); err != nil {
			t.Errorf("C27 cleanup: delete vuln %s: %v", id, err)
		}
	})
	now := time.Now()
	return model.Vulnerability{
		ID:          id,
		CVEID:       fmt.Sprintf("CVE-2095-%07d", id.ID()%10000000),
		Description: "m50 tx-semantics probe",
		Severity:    "HIGH",
		Source:      "NVD",
		UpdatedAt:   &now,
	}
}

// TestM50VulnScanTx_ScannerWritesAreTxBoundAndSurviveAScannerError pins the
// mechanism (tx, not raw *sql.DB) AND the property the old comment claimed
// (a scanner failure does not discard the work already written).
func TestM50VulnScanTx_ScannerWritesAreTxBoundAndSurviveAScannerError(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "m50txok")
	scanner := &m50TxProbeScanner{
		appDB:     appDB,
		vuln:      m50NewVuln(t, migDB),
		returnErr: fmt.Errorf("m50: simulated NVD outage"),
	}
	h := &VulnerabilityHandler{db: appDB, nvdService: scanner}

	h.runScan(context.Background(), seed.sbomID, seed.tenantID, "nvd")

	if !scanner.sawTx {
		t.Fatal("the scanner's ctx carried no *sql.Tx — runScan must hand the scanners the " +
			"transactional context (this is also what binds app.current_tenant_id)")
	}
	if scanner.createErr != nil {
		t.Fatalf("VulnerabilityRepository.Create inside the scan: %v", scanner.createErr)
	}
	if scanner.visibleOutside != 0 {
		t.Errorf("the scanner's write was visible on another connection mid-scan (count=%d), "+
			"want 0 — that is what a write through the raw *sql.DB would look like, and it is "+
			"NOT what this code does", scanner.visibleOutside)
	}

	// The scanner returned an error; runScan logs it and returns nil from fn,
	// so WithTxFunc commits. The write must be durable.
	var after int
	if err := appDB.QueryRow(
		`SELECT COUNT(*) FROM vulnerabilities WHERE id = $1`, scanner.vuln.ID).Scan(&after); err != nil {
		t.Fatalf("read back after runScan: %v", err)
	}
	if after != 1 {
		t.Errorf("rows after a scan whose scanner FAILED = %d, want 1 (the tx is committed "+
			"regardless of per-scanner outcome, so partial work survives)", after)
	}
}

// TestM50VulnScanTx_AFailedStatementDiscardsEverything is the half the old
// comment denied. A scanner whose SQL fails poisons the transaction: every
// later command in it is refused and the COMMIT fails, so the sweep's whole
// output is discarded. "Writes survive a partial failure" is therefore true
// of scanner-level failures ONLY.
//
// The loss is not silent — the commit error is logged at ERROR — but the
// scanner's own "NVD scan completed" INFO line is logged too, because
// ScanComponents returned nil while its writes were being refused. Both log
// assertions are pinned: an operator reading only the INFO line would
// conclude the scan worked.
func TestM50VulnScanTx_AFailedStatementDiscardsEverything(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "m50txpoison")
	scanner := &m50TxProbeScanner{
		appDB:       appDB,
		vuln:        m50NewVuln(t, migDB),
		poisonFirst: true,
	}
	h := &VulnerabilityHandler{db: appDB, nvdService: scanner}

	// No test in this package calls t.Parallel(), so swapping the process
	// logger for the duration of one test is safe (precedent:
	// reachability_targets_test.go).
	var logged strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	h.runScan(context.Background(), seed.sbomID, seed.tenantID, "nvd")
	slog.SetDefault(prev)

	if scanner.poisonErr == nil {
		t.Fatal("precondition: `SELECT 1/0` did not error, so the transaction was never poisoned")
	}
	if scanner.createErr == nil {
		t.Error("the write after a failed statement SUCCEEDED — PostgreSQL is expected to " +
			"refuse every command until the aborted transaction ends")
	}

	var after int
	if err := appDB.QueryRow(
		`SELECT COUNT(*) FROM vulnerabilities WHERE id = $1`, scanner.vuln.ID).Scan(&after); err != nil {
		t.Fatalf("read back after runScan: %v", err)
	}
	if after != 0 {
		t.Errorf("rows after a scan whose STATEMENT failed = %d, want 0. If this ever becomes 1, "+
			"the writes have moved off the transaction and runScan's doc comment must be "+
			"rewritten again", after)
	}

	logs := logged.String()
	if !strings.Contains(logs, "tenant transaction failed") {
		t.Errorf("the discarded sweep was NOT reported: logs = %q, want the WithTxFunc commit "+
			"error surfaced at ERROR (if this ever stops holding, the data loss really is "+
			"silent and the doc comment must say so)", logs)
	}
	if !strings.Contains(logs, "NVD scan completed") {
		t.Errorf("logs = %q, want the scanner's own success line too — it is emitted even "+
			"though every write it made was refused, which is why the ERROR line above is "+
			"the only honest signal", logs)
	}
}
