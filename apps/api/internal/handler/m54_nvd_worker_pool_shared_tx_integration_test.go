//go:build integration

// Package handler — M54: the NVD worker pool must not drive one *sql.Tx from
// several goroutines at once.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M54NVDWorkerPool' ./internal/handler
//
// # What this file pins, and why it is not a style complaint
//
// VulnerabilityHandler.runScan (and SbomHandler.runScan, and the scheduler's
// VulnerabilityScanJob.scanProject) open ONE transaction, bind
// app.current_tenant_id to it, and hand the resulting context to
// NVDService.ScanComponents. processComponentsParallel then starts
// maxConcurrentWithKey (5) goroutines when NVD_API_KEY is set and gives every
// one of them that same context, so several workers can issue statements
// against a single *sql.Tx — i.e. a single PostgreSQL connection — at the same
// time.
//
// database/sql does NOT make that safe. *sql.DB documents itself as safe for
// concurrent use; *sql.Tx does not, and the difference is not academic. A
// driverConn is locked for the duration of each individual driver call, but an
// open *sql.Rows (which is what QueryRowContext returns until Scan closes it)
// leaves the lib/pq connection mid-message on the wire. A second worker's
// Parse lands inside that message and the protocol desynchronises.
//
// Measured on this schema against PostgreSQL 15 (2026-08-05), driving the
// production path with two work items whose NVD responses arrive at the same
// instant, 400 CVEs each:
//
//	pq: unexpected Parse response 'C'   <- first collision
//	driver: bad connection              <- every statement after it
//	database.WithTxFunc: commit: driver: bad connection
//	durable vulnerabilities = 0 / 800, links = 0 / 800
//
// So the failure is not "the workers get serialised and it is slower", and it
// is not "the two colliding items are lost". The shared connection is
// destroyed, the commit fails, and EVERY row the whole sweep wrote is
// discarded — the same total loss the M50 poison test measured, reached
// without any statement being individually invalid.
//
// It is also loud in the wrong direction: the scanner keeps returning nil, so
// "NVD scan completed" is logged at INFO in the same run as the ERROR that
// reports the discarded commit (M50 established this asymmetry; this test
// pins that it still applies here).
//
// # Why the timing is ordinary rather than exotic
//
// The shared rate limiter staggers the START of each work item by 700ms
// (rateLimitWithKey), which is what made this look like a dormant hazard. But
// it staggers starts, not database sections: a worker reaches its writes at
// tick + HTTP latency, and NVD response latency varies by far more than 700ms.
// Two responses landing together is the ordinary case over a long scan, not a
// contrived one. The fake NVD server below makes that instant deterministic by
// holding both requests until both have arrived and then answering them
// together — it manufactures the *timing*, not the *possibility*.
//
// # Scope of the claim
//
// This test drives VulnerabilityHandler.runScan. The same NVDService worker
// pool is reached from SbomHandler.runScan (upload auto-scan) and from
// scheduler.VulnerabilityScanJob.scanProject (unattended, every tenant, every
// project) — both also inside a tenant transaction. The fix is in
// service/nvd.go precisely so that one change covers all three; this file
// measures one of them end to end and does not separately drive the other two.
package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

const (
	// m54WorkItems is the number of deduplicated (name, version) pairs the
	// scan sees, and therefore the number of workers that take a rate-limiter
	// tick. Two is the minimum that can collide.
	m54WorkItems = 2
	// m54CVEsPerItem sizes each worker's database section. Each CVE costs a
	// GetByCVE + a Create + one LinkComponent, so 400 CVEs is roughly 1200
	// statements (~150ms locally) — wide enough that two workers released
	// together are certain to overlap, rather than merely likely.
	m54CVEsPerItem = 400
)

// m54BarrierNVDServer answers the NVD REST contract, but holds every request
// until `release` of them have arrived and then answers them all at once.
//
// Each request gets its own contiguous block of synthetic CVE ids drawn from
// `base`, so the two workers never contend on the same `vulnerabilities` row
// and an ON CONFLICT collision cannot be mistaken for the defect under test.
func m54BarrierNVDServer(t *testing.T, release, base, perItem int) *httptest.Server {
	t.Helper()

	var mu sync.Mutex
	arrived := 0
	gate := make(chan struct{})
	var seq int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		block := int(atomic.AddInt64(&seq, 1) - 1)

		mu.Lock()
		arrived++
		if arrived == release {
			close(gate)
		}
		mu.Unlock()

		select {
		case <-gate:
		case <-time.After(30 * time.Second):
			// Never expected: the scan hands out one tick per work item and
			// there are exactly `release` items. Falling through keeps a
			// broken assumption from hanging the whole package.
			t.Errorf("m54: barrier never opened — only %d of %d NVD requests arrived", arrived, release)
		}

		entries := make([]m54Entry, 0, perItem)
		for i := 0; i < perItem; i++ {
			entries = append(entries, m54Entry{CVE: m54CVE{
				ID:           m54CVEID(base, block, i),
				Published:    "2093-01-01T00:00:00.000",
				Descriptions: []m54Desc{{Lang: "en", Value: "m54 shared-tx probe"}},
				Metrics: m54Metrics{V31: []m54Metric{{
					CvssData: m54CvssData{BaseScore: 7.5, BaseSeverity: "HIGH"},
				}}},
			}})
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(m54Response{
			ResultsPerPage:  len(entries),
			TotalResults:    len(entries),
			Vulnerabilities: entries,
		}); err != nil {
			t.Errorf("m54: encode fake NVD response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Minimal mirrors of the NVD REST shapes NVDService decodes. Declared here
// rather than reused from service/ because the service's own types are
// unexported response DTOs and this file is asserting on the wire contract it
// feeds them, not on their internals.
type m54Response struct {
	ResultsPerPage  int        `json:"resultsPerPage"`
	StartIndex      int        `json:"startIndex"`
	TotalResults    int        `json:"totalResults"`
	Vulnerabilities []m54Entry `json:"vulnerabilities"`
}
type m54Entry struct {
	CVE m54CVE `json:"cve"`
}
type m54CVE struct {
	ID           string     `json:"id"`
	Published    string     `json:"published"`
	LastModified string     `json:"lastModified"`
	Descriptions []m54Desc  `json:"descriptions"`
	Metrics      m54Metrics `json:"metrics"`
}
type m54Desc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}
type m54Metrics struct {
	V31 []m54Metric `json:"cvssMetricV31"`
}
type m54Metric struct {
	CvssData m54CvssData `json:"cvssData"`
}
type m54CvssData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// m54CVEID mints the id for CVE `i` of request `block`. The blocks are
// m54CVEsPerItem apart so they cannot overlap, and `base` is drawn per test
// run so two concurrent runs against the same dev database do not collide on
// the `vulnerabilities.cve_id` unique index.
func m54CVEID(base, block, i int) string {
	return fmt.Sprintf("CVE-2093-%07d", base+block*m54CVEsPerItem+i)
}

// m54ExpectedCVEIDs is every id the fake server will hand out for this run.
func m54ExpectedCVEIDs(base int) []string {
	ids := make([]string, 0, m54WorkItems*m54CVEsPerItem)
	for b := 0; b < m54WorkItems; b++ {
		for i := 0; i < m54CVEsPerItem; i++ {
			ids = append(ids, m54CVEID(base, b, i))
		}
	}
	return ids
}

// TestM54NVDWorkerPool_ConcurrentWorkersDoNotCorruptTheSharedTx is the
// regression test for the defect described in the file header.
//
// It is written as a durability assertion rather than a "no error was logged"
// assertion because the durable row count is the thing an operator actually
// loses: before the fix this run persists 0 of 800 vulnerabilities, after it
// 800 of 800. The log assertions are kept alongside as corroboration — in
// particular that the ERROR line reporting the discarded commit is absent,
// since the scanner's own "completed" INFO line is emitted either way and is
// therefore worthless as a signal (M50).
func TestM54NVDWorkerPool_ConcurrentWorkersDoNotCorruptTheSharedTx(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "m54pool")

	// m47SeedAll already put ONE component ("libm47") on seed.sbomID. Add one
	// more with a different name so ScanComponents deduplicates to exactly
	// m54WorkItems keys and hands out exactly that many rate-limiter ticks.
	m54AddComponent(t, migDB, seed, "m54lib")

	// A per-run base keeps the synthetic cve_id block clear of other runs.
	// uuid.ID() is a uint32; %9000*1000 spreads runs 1000 ids apart while this
	// run needs only m54WorkItems*m54CVEsPerItem = 800.
	base := int(uuid.New().ID()%9000) * 1000
	expected := m54ExpectedCVEIDs(base)
	t.Cleanup(func() {
		// `vulnerabilities` is the shared tenant-less catalogue, so it is
		// reaped explicitly (C27). component_vulnerabilities cascades from it.
		if _, err := migDB.Exec(
			`DELETE FROM vulnerabilities WHERE cve_id = ANY($1)`, m54TextArray(expected)); err != nil {
			t.Errorf("C27 cleanup: delete m54 vulnerabilities: %v", err)
		}
	})

	srv := m54BarrierNVDServer(t, m54WorkItems, base, m54CVEsPerItem)

	// A non-empty API key is what selects maxConcurrentWithKey (5) over
	// maxConcurrentNoKey (1); without it the pool is single-threaded and this
	// test would be vacuous. The key is never validated by the fake server.
	nvd := service.NewNVDService(
		repository.NewVulnerabilityRepository(appDB),
		repository.NewComponentRepository(appDB),
		"m54-fake-api-key", srv.URL, false,
	)
	h := &VulnerabilityHandler{db: appDB, nvdService: nvd}

	// Same logger-swap safety argument as the M50 tests: no test in this
	// package calls t.Parallel(), and the swap is restored with defer so a
	// panic in runScan cannot leak it into later tests.
	var logged strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	func() {
		defer slog.SetDefault(prev)
		h.runScan(context.Background(), seed.sbomID, seed.tenantID, "nvd")
	}()
	logs := logged.String()

	// A failing run emits one WARN per lost CVE — 800 of them — so the raw log
	// is useless in a test failure. Digest it once, and attach the digest
	// rather than the text to every assertion below.
	digest := m54Digest(logs)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("scan log digest: %s", digest)
		}
	})

	// Precondition: both work items really did reach the fake server and get
	// released together. If only one had, there would have been nothing to
	// collide and a green result would prove nothing.
	if !strings.Contains(logs, "api_calls=2") {
		t.Fatalf("precondition: expected exactly 2 NVD API calls (one per deduplicated component); "+
			"digest = %s", digest)
	}

	// The load-bearing assertion. Read on a connection that is not the scan's
	// transaction, after runScan has returned, so this is durability and not
	// read-your-own-writes.
	var durable int
	if err := appDB.QueryRow(
		`SELECT COUNT(*) FROM vulnerabilities WHERE cve_id = ANY($1)`,
		m54TextArray(expected)).Scan(&durable); err != nil {
		t.Fatalf("count durable vulnerabilities: %v", err)
	}
	if durable != len(expected) {
		t.Errorf("durable vulnerabilities = %d, want %d. Two workers sharing one *sql.Tx "+
			"desynchronise the lib/pq connection; the commit then fails and the ENTIRE sweep is "+
			"discarded, not just the colliding pair.", durable, len(expected))
	}

	var links int
	if err := appDB.QueryRow(`
		SELECT COUNT(*) FROM component_vulnerabilities cv
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE v.cve_id = ANY($1)`, m54TextArray(expected)).Scan(&links); err != nil {
		t.Fatalf("count durable links: %v", err)
	}
	if links != len(expected) {
		t.Errorf("durable component_vulnerabilities = %d, want %d — the link is what makes a CVE "+
			"visible on the project's vulnerability page, so losing it is the operator-visible half "+
			"of this defect", links, len(expected))
	}

	// Corroboration, in the order of usefulness to someone reading the logs
	// of a real incident.
	if strings.Contains(logs, "tenant transaction failed") {
		t.Error("the scan's commit failed")
	}
	for _, marker := range []string{
		"unexpected Parse response",      // lib/pq protocol desync
		"bad connection",                 // every statement after the desync
		"current transaction is aborted", // the M50 cascade, if a statement had failed
	} {
		if strings.Contains(logs, marker) {
			t.Errorf("found %q in the scan logs — the shared transaction was still being driven "+
				"from more than one goroutine", marker)
		}
	}
	if !strings.Contains(logs, "NVD scan completed") {
		t.Error("the scanner's success line is missing — its ABSENCE would mean the scan errored " +
			"out rather than being fixed")
	}
}

// m54Digest reduces a captured scan log to the handful of facts that
// distinguish the fixed behaviour from the broken one.
func m54Digest(logs string) string {
	counts := map[string]int{}
	var errLine string
	for _, line := range strings.Split(logs, "\n") {
		switch {
		case strings.Contains(line, "unexpected Parse response"):
			counts["pq-parse-desync"]++
		case strings.Contains(line, "bad connection"):
			counts["bad-connection"]++
		case strings.Contains(line, "current transaction is aborted"):
			counts["tx-aborted"]++
		}
		if strings.Contains(line, "level=ERROR") && errLine == "" {
			errLine = line
		}
	}
	return fmt.Sprintf("pq-parse-desync=%d bad-connection=%d tx-aborted=%d firstERROR=%q",
		counts["pq-parse-desync"], counts["bad-connection"], counts["tx-aborted"], errLine)
}

// m54AddComponent inserts one component into the seeded SBOM under the
// tenant GUC. It is reaped by m47SeedAll's tenant cascade (C27).
func m54AddComponent(t *testing.T, migDB *sql.DB, seed m47Seed, name string) {
	t.Helper()
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(
		`SELECT set_config('app.current_tenant_id', $1, true)`, seed.tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license, created_at)
		VALUES ($1, $2, $3, $4, '1.0', 'library', $5, 'MIT', NOW())`,
		uuid.New(), seed.tenantID, seed.sbomID, name, "pkg:generic/"+name+"@1.0"); err != nil {
		t.Fatalf("insert component %s: %v", name, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// m54TextArray renders ids as a PostgreSQL text[] literal. lib/pq has no
// []string driver.Valuer, and pq.Array would pull the helper into a test that
// is otherwise driver-agnostic.
func m54TextArray(ids []string) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, id := range ids {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(id)
	}
	b.WriteByte('}')
	return b.String()
}
