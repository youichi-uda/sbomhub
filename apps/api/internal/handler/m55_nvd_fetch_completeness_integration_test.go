//go:build integration

// Package handler — M55: what a caller learns when the NVD sweep did not see
// everything.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M55NVD' ./internal/handler
//
// # Why this file drives the HANDLER rather than the service
//
// service/nvd_test.go can pin that searchByKeyword walks pages and that
// NVDScanReport.incompleteErr escalates a truncated sweep. Neither says
// anything about whether that escalation REACHES anyone, and "reaches
// someone" is the whole requirement: a truncation that only exists as a
// return value inside the service is the same silent under-report as no
// truncation detection at all, wearing a struct field.
//
// The chain being measured here is the one the CLI and the MCP server
// actually read:
//
//	NVDService.ScanComponents -> error
//	  -> SbomHandler.runScan appends to errs
//	  -> ScanTracker.MarkFailed
//	  -> GET /projects/:id/sboms/:sbom_id/scan-status  => {"status":"failed"}
//	  -> sbomhub-cli waitForScanCompletion             => exit 2, --fail-on NOT evaluated
//	  -> mcp-server                                    => counts_final: false
//
// and the second test measures the deliberate NON-escalation next to it, so
// the two cannot drift apart unnoticed.
package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

const (
	// m55PageSize / m55Budget mirror service.nvdPageSize and
	// service.nvdMaxPagesPerComponent, which are unexported. If the service
	// constants change, m55TruncatingNVDServer keeps working (it answers
	// whatever resultsPerPage is asked for) but these two numbers are used to
	// size the fixture and the expected row counts, so they are asserted
	// against the observed request stream rather than assumed.
	m55PageSize = 200
	m55Budget   = 5
	// m55TotalMatches is the measured cardinality of keywordSearch=linux
	// against the live NVD API on 2026-08-11: 21670. It is the real shape of
	// the case that exhausts the budget — not a number picked to be large.
	m55TotalMatches = 21670
)

// m55TruncatingNVDServer answers the NVD CVE API 2.0 contract for a result set
// of `total` records, honouring resultsPerPage and startIndex.
//
// CVE ids come from `ns` so concurrent runs of this package cannot collide on
// the tenant-less `vulnerabilities` table.
func m55TruncatingNVDServer(t *testing.T, total int, ns m54Namespace) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var queries []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.RawQuery)
		mu.Unlock()

		rpp, err := strconv.Atoi(r.URL.Query().Get("resultsPerPage"))
		if err != nil {
			t.Errorf("m55: resultsPerPage %q is not a number", r.URL.Query().Get("resultsPerPage"))
			rpp = 20
		}
		start, err := strconv.Atoi(r.URL.Query().Get("startIndex"))
		if err != nil {
			t.Errorf("m55: startIndex %q is not a number", r.URL.Query().Get("startIndex"))
		}

		n := rpp
		if start+n > total {
			n = total - start
		}
		if n < 0 {
			n = 0
		}
		entries := make([]m54Entry, 0, n)
		for i := 0; i < n; i++ {
			entries = append(entries, m54Entry{CVE: m54CVE{
				ID:           ns.m54CVEID(0, start+i),
				Published:    "2093-01-01T00:00:00.000",
				Descriptions: []m54Desc{{Lang: "en", Value: "m55 truncation probe"}},
				Metrics: m54Metrics{V31: []m54Metric{{
					CvssData: m54CvssData{BaseScore: 9.8, BaseSeverity: "CRITICAL"},
				}}},
			}})
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(m54Response{
			ResultsPerPage:  len(entries),
			StartIndex:      start,
			TotalResults:    total,
			Vulnerabilities: entries,
		}); err != nil {
			t.Errorf("m55: encode fake NVD page: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(queries))
		copy(out, queries)
		return out
	}
}

// TestM55NVDTruncatedResultSetIsReportedToTheCaller is the end-to-end
// assertion: a component whose match set is larger than the paging budget must
// not produce a scan the CLI can read as complete.
//
// Before M55 this exact fixture produced: 20 rows written, no warning, scan
// status "completed", and `sbomhub scan --fail-on critical` evaluating a
// threshold against 20 of 21670 matches as though that were the answer.
func TestM55NVDTruncatedResultSetIsReportedToTheCaller(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "m55trunc")

	ns := m54NewNamespace()
	fetched := m55PageSize * m55Budget
	ids := make([]string, 0, fetched)
	for i := 0; i < fetched; i++ {
		ids = append(ids, ns.m54CVEID(0, i))
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(
			`DELETE FROM vulnerabilities WHERE cve_id = ANY($1)`, m54TextArray(ids)); err != nil {
			t.Errorf("C27 cleanup: delete m55 vulnerabilities: %v", err)
		}
	})

	srv, calls := m55TruncatingNVDServer(t, m55TotalMatches, ns)

	// The API key is never validated by the fake server; it selects
	// rateLimitWithKey (700ms) over rateLimitWithoutKey (6s), which is what
	// keeps this test at a few seconds instead of thirty — the walk below
	// takes FIVE rate-limiter ticks, one per page, and that pacing is the
	// property being relied on rather than worked around (see the pacer note
	// on processComponentsParallel). m47SeedAll seeds a single component, so
	// there is exactly one work item however many workers the pool starts.
	nvd := service.NewNVDService(
		repository.NewVulnerabilityRepository(appDB),
		repository.NewComponentRepository(appDB),
		"m55-fake-api-key", srv.URL, false,
	)
	tracker := service.NewScanTracker()
	h := &SbomHandler{db: appDB, nvdService: nvd, scanTracker: tracker}
	tracker.MarkRunning(seed.sbomID)

	var logged strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	func() {
		defer slog.SetDefault(prev)
		h.runScan(context.Background(), seed.sbomID, seed.tenantID)
	}()
	logs := logged.String()

	// --- the walk itself -----------------------------------------------
	q := calls()
	if len(q) != m55Budget {
		t.Fatalf("issued %d NVD requests, want the budget %d: %v", len(q), m55Budget, q)
	}
	for i, want := range []string{"startIndex=0", "startIndex=200", "startIndex=400",
		"startIndex=600", "startIndex=800"} {
		if !strings.Contains(q[i], want) {
			t.Errorf("request %d = %q, want it to carry %q", i, q[i], want)
		}
	}

	// --- what the caller is told ---------------------------------------
	state, msg := tracker.Get(seed.sbomID)
	if state != service.ScanStateFailed {
		t.Fatalf("scan state = %q (%q), want %q.\n"+
			"The scan fetched %d of %d matches for one component and reported itself "+
			"complete; `sbomhub scan --fail-on critical` would evaluate the threshold "+
			"against a prefix of the match set and exit 0 on a set it never saw.",
			state, msg, service.ScanStateFailed, fetched, m55TotalMatches)
	}

	// The message the CLI renders is deliberately generic (F445: ScanStatus.Error
	// is echoed to the client verbatim, so raw scanner text must not reach it).
	// What must be true is that it names the scanner.
	if !strings.Contains(msg, "nvd") {
		t.Errorf("tracker error %q does not name the scanner", msg)
	}

	// The DETAIL lives server-side, and it has to be actionable: which
	// component, how much was fetched, how much exists.
	for _, want := range []string{
		"component match set truncated",
		"total=" + strconv.Itoa(m55TotalMatches),
		"fetched=" + strconv.Itoa(fetched),
		"libm47", // m47SeedAll's component
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("scan log does not contain %q; an operator cannot act on a truncation "+
				"they cannot attribute to a component", want)
		}
	}
	if !strings.Contains(logs, "truncated_components=1") {
		t.Error("the sweep summary does not carry truncated_components")
	}
	if strings.Contains(logs, "Auto NVD scan completed") {
		t.Error("the success line was emitted for a scan that provably did not see the whole " +
			"result set")
	}

	// --- and the findings it DID obtain are still recorded ---------------
	// Escalating must not mean discarding: the 1000 matches that were fetched
	// are real, and the transaction still commits (SbomHandler.runScan returns
	// nil from the tx func on a scanner error, by design).
	var durable int
	if err := appDB.QueryRow(
		`SELECT COUNT(*) FROM vulnerabilities WHERE cve_id = ANY($1)`,
		m54TextArray(ids)).Scan(&durable); err != nil {
		t.Fatalf("count durable vulnerabilities: %v", err)
	}
	if durable != fetched {
		t.Errorf("durable vulnerabilities = %d, want %d — reporting the truncation must not "+
			"throw away the matches that WERE retrieved", durable, fetched)
	}
}

// TestM55NVDPartialFetchFailureIsCountedNotSwallowed pins the OTHER half of
// this wave, and it is deliberately an assertion that the scan still succeeds.
//
// Some components answered and some did not. How many may fail before a scan
// is worthless is a threshold, i.e. a product decision, and this wave does not
// take it — so the tracker must still say "completed". What must NOT stay true
// is that the number is unavailable: before M55 the count existed only inside
// processComponentsParallel and was folded into an INFO line that read as
// success.
//
// So: the count is on the report the service returns, and the sweep summary is
// logged at WARN. If a later wave adds the threshold, it has a number to write
// the policy against; until then an operator can at least see it.
func TestM55NVDPartialFetchFailureIsCountedNotSwallowed(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "m55partial")
	// m47SeedAll seeds "libm47"; add a second component so one lookup can fail
	// while the other succeeds.
	m54AddComponent(t, migDB, seed, "m55lib")

	ns := m54NewNamespace()
	okID := ns.m54CVEID(0, 0)
	t.Cleanup(func() {
		if _, err := migDB.Exec(
			`DELETE FROM vulnerabilities WHERE cve_id = ANY($1)`,
			m54TextArray([]string{okID})); err != nil {
			t.Errorf("C27 cleanup: delete m55 partial vulnerabilities: %v", err)
		}
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// "libm47 1.0" is answered; "m55lib 1.0" is a 500, as an upstream
		// outage affecting one keyword would be.
		if strings.Contains(r.URL.Query().Get("keywordSearch"), "m55lib") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"m55 induced outage"}`))
			return
		}
		entries := []m54Entry{{CVE: m54CVE{
			ID:           okID,
			Published:    "2093-01-01T00:00:00.000",
			Descriptions: []m54Desc{{Lang: "en", Value: "m55 partial probe"}},
			Metrics: m54Metrics{V31: []m54Metric{{
				CvssData: m54CvssData{BaseScore: 9.8, BaseSeverity: "CRITICAL"},
			}}},
		}}}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(m54Response{
			ResultsPerPage:  len(entries),
			StartIndex:      0,
			TotalResults:    len(entries),
			Vulnerabilities: entries,
		}); err != nil {
			t.Errorf("m55: encode fake NVD response: %v", err)
		}
	}))
	defer srv.Close()

	nvd := service.NewNVDService(
		repository.NewVulnerabilityRepository(appDB),
		repository.NewComponentRepository(appDB),
		"m55-fake-api-key", srv.URL, false,
	)

	// --- (a) the count is available in-band -----------------------------
	var report service.NVDScanReport
	var scanErr error
	var logged strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	func() {
		defer slog.SetDefault(prev)
		report, scanErr = m55ScanInTenantTx(t, appDB, nvd, seed)
	}()
	logs := logged.String()

	if scanErr != nil {
		t.Fatalf("a PARTIAL fetch failure must not fail the scan (that needs a threshold, "+
			"which is a product decision this wave does not take): %v", scanErr)
	}
	if report.FetchFailures != 1 {
		t.Errorf("report.FetchFailures = %d, want 1 — the count is the whole point: a policy "+
			"cannot be written against a number that is not returned", report.FetchFailures)
	}
	if report.Processed != 1 {
		t.Errorf("report.Processed = %d, want 1", report.Processed)
	}
	if report.UniqueComponents != 2 {
		t.Errorf("report.UniqueComponents = %d, want 2", report.UniqueComponents)
	}
	if report.TruncatedComponents != 0 {
		t.Errorf("report.TruncatedComponents = %d, want 0", report.TruncatedComponents)
	}

	// --- (b) and it is loud in the logs ---------------------------------
	if !strings.Contains(logs, "fetch_failures=1") {
		t.Error("the sweep summary does not carry fetch_failures")
	}
	if !strings.Contains(logs, "level=WARN msg=\"component scan completed with incomplete coverage\"") {
		t.Errorf("a sweep with a failed lookup logged its summary as a plain success; "+
			"anything filtering on level reads that as a clean scan.\nlogs:\n%s",
			m55Tail(logs))
	}
}

// m55ScanInTenantTx runs one sweep the way every production caller does: inside
// a transaction with app.current_tenant_id bound, because `components` FORCEs
// row-level security and an unbound connection reads zero rows — which would
// make this test vacuously green with UniqueComponents = 0.
func m55ScanInTenantTx(
	t *testing.T,
	appDB *sql.DB,
	nvd *service.NVDService,
	seed m47Seed,
) (service.NVDScanReport, error) {
	t.Helper()
	var report service.NVDScanReport
	var scanErr error
	txErr := database.WithTxFunc(context.Background(), appDB,
		func(txCtx context.Context, tx *sql.Tx) error {
			if _, err := tx.ExecContext(txCtx,
				`SELECT set_config('app.current_tenant_id', $1, true)`,
				seed.tenantID.String()); err != nil {
				return fmt.Errorf("set tenant context: %w", err)
			}
			report, scanErr = nvd.ScanComponentsWithReport(txCtx, seed.sbomID)
			// nil so the sweep's writes still commit, exactly as
			// SbomHandler.runScan does.
			return nil
		})
	if txErr != nil {
		t.Fatalf("tenant tx: %v", txErr)
	}
	return report, scanErr
}

// m55Tail keeps a failure message readable when the scan logged a lot.
func m55Tail(s string) string {
	const maxLen = 2000
	if len(s) <= maxLen {
		return s
	}
	return "..." + s[len(s)-maxLen:]
}
