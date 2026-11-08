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
// must survive a partial failure". The first half is false: the repositories
// the scanners use (VulnerabilityRepository, ComponentRepository) resolve
// their Queryable with database.Querier(ctx, r.db), runScan hands the
// scanners the ctx returned by WithTxFunc, and that ctx carries the *sql.Tx —
// so the writes go through the TRANSACTION. The comment described a
// durability property the code does not have by the mechanism the comment
// named, which is the "comment stronger than the implementation" defect class
// this repo treats as first-class.
//
// These two tests pin what is really true, so the corrected comment cannot
// drift back. Note the scope of each claim carefully — Codex R2 flagged the
// first draft of this header for asserting more than the tests establish:
//
//  1. the writes are tx-bound (invisible to another connection mid-scan) and
//     survived a scanner returning an error in the ONE execution this test
//     drives: runScan's fn returns nil, so WithTxFunc ATTEMPTS the commit.
//     The durable outcome needs both halves — an un-aborted transaction AND a
//     Commit that returns nil (Codex R3, High: "provided the transaction is
//     healthy" named only the first) — so BOTH are observed, not inferred:
//     runScan swallows the WithTxFunc error into a log line, and the test
//     captures the log and requires that line's ABSENCE alongside the durable
//     row (Codex R5, High). The probe returns a synthetic non-SQL error, which
//     is the un-aborted case. A scanner whose error came FROM a failed
//     statement (ListBySbom hitting a server-side error) is case 2, not case 1
//     — the commit fails and the sibling's work goes too. That case is argued
//     from case 2's measurement, not separately driven.
//  2. the writes do NOT survive a failed SQL STATEMENT: PostgreSQL aborts the
//     transaction, later commands are refused, the COMMIT fails, and EVERY
//     RELATIONAL ROW the sweep wrote is discarded — including one written
//     successfully beforehand, which the probe establishes explicitly.
//     "Relational" is the honest boundary: this probe only ever writes to
//     PostgreSQL, so it says nothing about NVD's Redis result cache, which is
//     populated outside the transaction and survives the abort. That is the
//     gap the "raw *sql.DB" wording implied did not exist. The loss is
//     logged (WithTxFunc returns the commit error and runScan logs it at
//     ERROR) — but the per-scanner "NVD scan completed" INFO line is emitted
//     anyway, so the logs say both things at once.
//
// Measurement note (2026-08-05): the first draft of the corrected doc comment
// asserted the commit "degrades to a silent ROLLBACK — no error reaches this
// function". Running these tests disproved it: lib/pq answers the COMMIT of
// an aborted tx with `pq: Could not complete operation in a failed
// transaction`, WithTxFunc wraps it, and runScan logs "vulnerability scan:
// tenant transaction failed". The replacement comment was corrected before it
// shipped. Comments that are stronger than the code are the defect being
// fixed here; that applies to the fix's own prose too.
//
// M57 update — the probe now writes LINKS, not catalogue rows. Since M57
// VulnerabilityRepository.Create never joins the caller's transaction (the
// global catalogue row was invisible to its owner for the whole sweep, died
// with one tenant's rollback, and took the sweep down when refused — see
// internal/repository/m57_catalogue_tx_boundary_integration_test.go). What
// the scanners still write inside runScan's transaction is the
// component_vulnerabilities LINK, so that is what both tests below drive, and
// every "row" in their assertions is a link. The tx-bound claims above hold
// for links exactly as stated; for catalogue rows they are now false by
// design, and TestM50VulnScanTx_CatalogueCreateDoesNotJoinTheScanTx pins
// that half.
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
// tx-bound write the real NVD / JVN scanners do — VulnerabilityRepository.
// LinkComponent with the ctx it was handed — and records what it observed.
// The catalogue rows it links against are created by the test beforehand.
type m50TxProbeScanner struct {
	appDB       *sql.DB
	componentID uuid.UUID
	vuln        model.Vulnerability

	// earlier, when set, is written BEFORE the poison statement and must
	// succeed. It is what proves the abort discards work that had already
	// landed, rather than only refusing the writes that came after (Codex R1,
	// Medium: the first cut poisoned first and so proved the weaker claim).
	earlier *model.Vulnerability

	// poisonFirst issues a statement that ERRORS before `vuln` is written, to
	// model a scanner whose SQL fails partway through (a constraint
	// violation, a bad cast) rather than one whose HTTP call fails.
	poisonFirst bool
	// returnErr is what ScanComponents returns; runScan logs it and goes on to
	// ATTEMPT the commit regardless (whether that commit succeeds is a
	// separate question — see the file header).
	returnErr error

	sawTx            bool
	visibleOutside   int
	earlierCreateErr error
	earlierInTx      int
	createErr        error
	poisonErr        error
}

func (s *m50TxProbeScanner) ScanComponents(ctx context.Context, _ uuid.UUID) error {
	_, s.sawTx = database.TxFromContext(ctx)
	repo := repository.NewVulnerabilityRepository(s.appDB)

	if s.earlier != nil {
		s.earlierCreateErr = repo.LinkComponent(ctx, s.componentID, s.earlier.ID)
		// Confirm it really landed INSIDE the tx before anything is poisoned;
		// otherwise "it is gone afterwards" would be consistent with "it was
		// never written".
		if err := database.Querier(ctx, s.appDB).QueryRowContext(ctx,
			`SELECT COUNT(*) FROM component_vulnerabilities WHERE component_id = $1 AND vulnerability_id = $2`,
			s.componentID, s.earlier.ID,
		).Scan(&s.earlierInTx); err != nil {
			s.earlierInTx = -1
		}
	}

	if s.poisonFirst {
		// A failed statement inside a PostgreSQL transaction aborts the whole
		// block: every later command errors until the tx ends.
		var one int
		s.poisonErr = database.Querier(ctx, s.appDB).
			QueryRowContext(ctx, `SELECT 1/0`).Scan(&one)
	}

	s.createErr = repo.LinkComponent(ctx, s.componentID, s.vuln.ID)

	// Read the link back on a DIFFERENT connection (the pool, not the tx). If
	// the write really went through the raw *sql.DB it would already be
	// committed and visible; a tx-bound write is not.
	if err := s.appDB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM component_vulnerabilities WHERE component_id = $1 AND vulnerability_id = $2`,
		s.componentID, s.vuln.ID,
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
	v := model.Vulnerability{
		ID:          id,
		CVEID:       fmt.Sprintf("CVE-2095-%07d", id.ID()%10000000),
		Description: "m50 tx-semantics probe",
		Severity:    "HIGH",
		Source:      "NVD",
		UpdatedAt:   &now,
	}
	// The catalogue row the probe links against. Created up front, outside
	// any transaction, because since M57 that is where Create writes anyway.
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, source, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		v.ID, v.CVEID, v.Description, v.Severity, v.Source, now); err != nil {
		t.Fatalf("seed catalogue row %s: %v", v.CVEID, err)
	}
	return v
}

// m50LinkCount is how many durable links the probe's component has to vulnID.
func m50LinkCount(t *testing.T, db *sql.DB, componentID, vulnID uuid.UUID) int {
	t.Helper()
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM component_vulnerabilities WHERE component_id = $1 AND vulnerability_id = $2`,
		componentID, vulnID).Scan(&n); err != nil {
		t.Fatalf("count links: %v", err)
	}
	return n
}

// TestM50VulnScanTx_ScannerWritesAreTxBoundAndSurviveAScannerError pins the
// mechanism (tx, not raw *sql.DB) AND the conditional form of the property
// the old comment claimed: a scanner failure does not BY ITSELF discard the
// work already written.
//
// The probe's error is synthetic and non-SQL, so the transaction is intact.
// That is deliberate — it isolates one variable — and it is the limit of what
// this test shows: durability needs the transaction un-aborted AND Commit
// returning nil, and only one execution of that pair is observed here (Codex
// R3, High). Both halves are read off the run rather than assumed: the commit
// error, if any, would appear in runScan's log, so the log is captured and
// its absence asserted (Codex R5, High). The other case (a scanner
// error originating in a failed statement) is the sibling test below, and the
// two must not be read as one claim about "any scanner error" (Codex R2,
// High).
func TestM50VulnScanTx_ScannerWritesAreTxBoundAndSurviveAScannerError(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "m50txok")
	scanner := &m50TxProbeScanner{
		appDB:       appDB,
		componentID: seed.componentID,
		vuln:        m50NewVuln(t, migDB),
		returnErr:   fmt.Errorf("m50: simulated NVD outage"),
	}
	h := &VulnerabilityHandler{db: appDB, nvdService: scanner}

	// runScan swallows the WithTxFunc error (it logs and returns), so the only
	// way to OBSERVE that Commit returned nil is the absence of the ERROR line
	// it would otherwise emit. Capture the log rather than infer the commit
	// from a durable row (Codex R5, High). Same logger-swap safety argument as
	// the poison test below.
	var logged strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	func() {
		defer slog.SetDefault(prev)
		h.runScan(context.Background(), seed.sbomID, seed.tenantID, "nvd")
	}()

	if !scanner.sawTx {
		t.Fatal("the scanner's ctx carried no *sql.Tx — runScan must hand the scanners the " +
			"transactional context (this is also what binds app.current_tenant_id)")
	}
	if scanner.createErr != nil {
		t.Fatalf("VulnerabilityRepository.LinkComponent inside the scan: %v", scanner.createErr)
	}
	if scanner.visibleOutside != 0 {
		t.Errorf("the scanner's write was visible on another connection mid-scan (count=%d), "+
			"want 0 — that is what a write through the raw *sql.DB would look like, and it is "+
			"NOT what this code does", scanner.visibleOutside)
	}

	// The scanner returned an error; runScan logs it and returns nil from fn,
	// so WithTxFunc goes on to ATTEMPT the commit — it does not follow from
	// fn == nil that the commit succeeded (Codex R4, High). Both halves are
	// therefore observed rather than inferred: the commit did not report an
	// error, AND the row is durable.
	logs := logged.String()
	if strings.Contains(logs, "tenant transaction failed") {
		t.Errorf("the commit reported an error: logs = %q. This test's subject is the "+
			"UN-ABORTED path, so a commit failure here means the scenario was not set up "+
			"as intended and the durability assertion below proves nothing", logs)
	}

	after := m50LinkCount(t, migDB, seed.componentID, scanner.vuln.ID)
	if after != 1 {
		t.Errorf("rows after a scan whose scanner FAILED (without poisoning the tx) = %d, "+
			"want 1 — fn returns nil regardless of per-scanner outcome, so WithTxFunc still "+
			"attempts the commit, and here that attempt was observed to succeed", after)
	}
}

// TestM50VulnScanTx_AFailedStatementDiscardsEveryRelationalRow is the half
// the old comment denied. A scanner whose SQL fails poisons the transaction:
// every later command in it is refused, the COMMIT fails, and every
// PostgreSQL row the sweep wrote is discarded — including one that had
// already succeeded, which is what this test establishes and the reason it is
// not merely "later commands are refused".
//
// "Relational" is the boundary, not "everything" (Codex R2, High): this probe
// writes only to PostgreSQL, so it says nothing about NVD's Redis result
// cache, which getVulnerabilitiesWithCache populates outside the transaction
// and which survives the abort. "Writes survive a partial failure" is
// therefore true only of failures that leave the transaction healthy.
//
// The loss is not silent — the commit error is logged at ERROR — but the
// scanner's own "NVD scan completed" INFO line is logged too, because
// ScanComponents returned nil while its writes were being refused. Both log
// assertions are pinned: an operator reading only the INFO line would
// conclude the scan worked.
func TestM50VulnScanTx_AFailedStatementDiscardsEveryRelationalRow(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "m50txpoison")
	earlier := m50NewVuln(t, migDB)
	scanner := &m50TxProbeScanner{
		appDB:       appDB,
		componentID: seed.componentID,
		earlier:     &earlier,
		vuln:        m50NewVuln(t, migDB),
		poisonFirst: true,
	}
	h := &VulnerabilityHandler{db: appDB, nvdService: scanner}

	// No test in this package calls t.Parallel() and the fake scanner is
	// synchronous, so swapping the process logger for the duration of one test
	// is safe (precedent: reachability_targets_test.go). Restored with defer
	// so a panic in runScan cannot leak the replacement into later tests.
	var logged strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	func() {
		defer slog.SetDefault(prev)
		h.runScan(context.Background(), seed.sbomID, seed.tenantID, "nvd")
	}()

	// Preconditions: the earlier write really landed inside the tx, and the
	// poison really poisoned. Without both, "it is gone afterwards" would be
	// consistent with "it was never written".
	if scanner.earlierCreateErr != nil {
		t.Fatalf("the pre-failure write did not succeed: %v", scanner.earlierCreateErr)
	}
	if scanner.earlierInTx != 1 {
		t.Fatalf("the pre-failure write was not visible inside its own tx (count=%d, want 1)",
			scanner.earlierInTx)
	}
	if scanner.poisonErr == nil {
		t.Fatal("precondition: `SELECT 1/0` did not error, so the transaction was never poisoned")
	}
	if scanner.createErr == nil {
		t.Error("the write after a failed statement SUCCEEDED — PostgreSQL is expected to " +
			"refuse every command until the aborted transaction ends")
	}

	// The load-bearing assertion: the write that had ALREADY SUCCEEDED is gone
	// too. That is what makes this "every relational row is discarded" rather
	// than the much weaker "later commands are refused".
	earlierAfter := m50LinkCount(t, migDB, seed.componentID, earlier.ID)
	if earlierAfter != 0 {
		t.Errorf("rows from the write that succeeded BEFORE the failure = %d, want 0 — a "+
			"surviving row would mean the writes are not tx-bound after all", earlierAfter)
	}

	after := m50LinkCount(t, migDB, seed.componentID, scanner.vuln.ID)
	if after != 0 {
		t.Errorf("links after a scan whose STATEMENT failed = %d, want 0. If this ever becomes 1, "+
			"the links have moved off the transaction and runScan's doc comment must be "+
			"rewritten again", after)
	}

	logs := logged.String()
	if !strings.Contains(logs, `level=ERROR msg="vulnerability scan: tenant transaction failed"`) {
		t.Errorf("the discarded sweep was NOT reported at ERROR: logs = %q. The doc comment "+
			"claims the loss is logged rather than silent; if that stops holding the comment "+
			"must say so", logs)
	}
	if !strings.Contains(logs, "NVD scan completed") {
		t.Errorf("logs = %q, want the scanner's own success line too — it is emitted even "+
			"though not one of the scanner's writes survived (the first was rolled back, the "+
			"second refused outright: Codex R4, Low), which is why the ERROR line above is "+
			"the only honest signal", logs)
	}
}

// TestM50VulnScanTx_CatalogueCreateDoesNotJoinTheScanTx is the other half of
// the M57 boundary, driven through runScan: a catalogue row a scanner creates
// is visible to other connections WHILE the scan's transaction is open, and
// survives that transaction failing. The link half stays tx-bound (above).
func TestM50VulnScanTx_CatalogueCreateDoesNotJoinTheScanTx(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "m57create")
	id := uuid.New()
	cveID := fmt.Sprintf("CVE-2095-%07d", id.ID()%10000000)
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID); err != nil {
			t.Errorf("C27 cleanup: %v", err)
		}
	})
	now := time.Now()
	scanner := &m57CreateProbeScanner{appDB: appDB, vuln: model.Vulnerability{
		ID: id, CVEID: cveID, Description: "m57 create probe", Severity: "HIGH", Source: "NVD", UpdatedAt: &now,
	}}
	h := &VulnerabilityHandler{db: appDB, nvdService: scanner}
	h.runScan(context.Background(), seed.sbomID, seed.tenantID, "nvd")

	if !scanner.sawTx {
		t.Fatal("precondition: the scanner's ctx carried no *sql.Tx")
	}
	if scanner.createErr != nil {
		t.Fatalf("Create inside the scan: %v", scanner.createErr)
	}
	if scanner.visibleOutside != 1 {
		t.Errorf("catalogue row visible on another connection mid-scan = %d, want 1: it joined the tenant tx",
			scanner.visibleOutside)
	}
	var n int
	if err := migDB.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("catalogue row after a scan whose transaction was poisoned = %d, want 1: the global row died "+
			"with one tenant's transaction", n)
	}
}

// m57CreateProbeScanner creates one catalogue row, observes it from another
// connection, then poisons the scan's transaction so its commit fails.
type m57CreateProbeScanner struct {
	appDB          *sql.DB
	vuln           model.Vulnerability
	sawTx          bool
	createErr      error
	visibleOutside int
}

func (s *m57CreateProbeScanner) ScanComponents(ctx context.Context, _ uuid.UUID) error {
	_, s.sawTx = database.TxFromContext(ctx)
	s.createErr = repository.NewVulnerabilityRepository(s.appDB).Create(ctx, &s.vuln)
	if err := s.appDB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM vulnerabilities WHERE id = $1`, s.vuln.ID).Scan(&s.visibleOutside); err != nil {
		s.visibleOutside = -1
	}
	var one int
	_ = database.Querier(ctx, s.appDB).QueryRowContext(ctx, `SELECT 1/0`).Scan(&one)
	return nil
}
