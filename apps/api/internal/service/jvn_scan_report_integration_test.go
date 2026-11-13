//go:build integration

// Package service — M55: the JVN sweep's truncation and failure counts must
// reach the caller.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run TestM55JVNScanReport ./internal/service
//
// Prerequisites are the ones vexSuggestionsTestEnv documents: DATABASE_URL
// (sbomhub_app) + MIGRATE_DATABASE_URL (sbomhub_migrator) against a migrated
// database. Skipped otherwise.
//
// The unit tests in jvn_fetch_completeness_test.go pin the fetch loop and the
// report-to-error mapping separately. What only a real database can show is
// the WIRING: that a sweep which truncated actually comes back out of
// ScanComponents — the method SbomHandler.runScan calls — as a non-nil error,
// and therefore reaches ScanTracker.MarkFailed and the CLI's scan-status poll,
// rather than being logged and dropped.
package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// withTenantScanTx runs fn with the context production callers hand the
// scanners. Up to M61 that was a (here: rolled-back) tenant transaction; since
// M62 it is the tenant SCOPE with no transaction — the scanner opens its own
// short transactions and refuses a context carrying one. The name is kept for
// the callers; the scanner's writes now commit.
func withTenantScanTx(t *testing.T, appDB *sql.DB, tenantID uuid.UUID, fn func(ctx context.Context)) {
	t.Helper()
	fn(WithScanScope(context.Background(), appDB, tenantID))
}

func TestM55JVNScanReport_TruncationReachesScanComponents(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	appDB := openOrSkipVS(t, appURL)
	if !schemaReadyVS(t, migDB) {
		return
	}

	tenant := seedTenantVS(t, migDB, "m55jvn")
	project := uuid.New()
	seedProjectVS(t, migDB, tenant, project, "m55jvn-"+project.String())
	sbom := seedSbomVS(t, migDB, tenant, project)
	seedComponentVS(t, migDB, tenant, sbom, "libfoo", "1.0", "pkg:generic/libfoo@1.0")
	seedComponentVS(t, migDB, tenant, sbom, "linux", "6.1", "pkg:generic/linux@6.1")

	now := time.Now()
	// "linux" is modelled on the measured live figure in spirit: far more
	// matches than the per-component budget of
	// jvnMaxCountItem*jvnMaxPagesPerComponent retrieves.
	big := cannedCorpus(now, jvnMaxCountItem*jvnMaxPagesPerComponent+37, 0)
	small := cannedCorpus(now, 4, 0)
	srv := &cannedMyJVN{
		now: now,
		corpusFor: func(keyword string) []cannedJVNAdvisory {
			if keyword == "linux" {
				return big
			}
			return small
		},
	}
	ts := srv.start(t)

	vulnRepo := repository.NewVulnerabilityRepository(appDB)
	compRepo := repository.NewComponentRepository(appDB)
	svc := NewJVNService(vulnRepo, compRepo, ts.URL, false)
	svc.requestDelay = 0

	// 1) The report carries the counts.
	withTenantScanTx(t, appDB, tenant, func(ctx context.Context) {
		rep, err := svc.ScanComponentsReport(ctx, sbom)
		t.Logf("report: %s", rep.Summary())

		if rep.Components != 2 {
			t.Fatalf("Components = %d, want 2 (seeding did not take)", rep.Components)
		}
		if rep.Scanned != 2 {
			t.Errorf("Scanned = %d, want 2", rep.Scanned)
		}
		if rep.TruncatedComponents != 1 {
			t.Errorf("TruncatedComponents = %d, want 1 (only \"linux\" exceeds the budget)",
				rep.TruncatedComponents)
		}
		if rep.EntriesRetrieved != jvnMaxCountItem*jvnMaxPagesPerComponent+4 {
			t.Errorf("EntriesRetrieved = %d, want %d",
				rep.EntriesRetrieved, jvnMaxCountItem*jvnMaxPagesPerComponent+4)
		}
		if rep.EntriesAvailable <= rep.EntriesRetrieved {
			t.Errorf("EntriesAvailable = %d must exceed EntriesRetrieved = %d for a truncated sweep",
				rep.EntriesAvailable, rep.EntriesRetrieved)
		}
		if rep.RefusedWrites != 0 {
			t.Errorf("RefusedWrites = %d, want 0 — the database declined a write it should have taken",
				rep.RefusedWrites)
		}
		if err == nil {
			t.Fatal("a truncated sweep returned nil; ScanTracker would record it as completed")
		}
		if !strings.Contains(err.Error(), "incomplete") {
			t.Errorf("error %q does not declare the results incomplete", err)
		}

		// Everything the budget did retrieve was persisted (M62: committed
		// by the scanner's own write transaction; read back in a tenant
		// transaction). Truncation reduces coverage; it must not discard
		// the coverage that was obtained.
		scope, serr := ScanScopeFrom(ctx)
		if serr != nil {
			t.Fatal(serr)
		}
		var vulns []model.Vulnerability
		if err := scope.ReadTx(ctx, func(txCtx context.Context) error {
			var lerr error
			vulns, lerr = vulnRepo.ListByProject(txCtx, project)
			return lerr
		}); err != nil {
			t.Fatalf("ListByProject: %v", err)
		}
		if len(vulns) < jvnMaxCountItem*jvnMaxPagesPerComponent {
			t.Errorf("persisted %d vulnerabilities, want at least the %d retrieved for \"linux\"",
				len(vulns), jvnMaxCountItem*jvnMaxPagesPerComponent)
		}
	})

	// 2) The SAME verdict comes out of ScanComponents, which is the method
	//    SbomHandler.runScan calls and the only channel into ScanTracker.
	withTenantScanTx(t, appDB, tenant, func(ctx context.Context) {
		if err := svc.ScanComponents(ctx, sbom); err == nil {
			t.Fatal("ScanComponents reported success for a sweep it knew was truncated — " +
				"the CLI would read \"scan completed\" off a partial answer")
		}
	})
}

// TestM55JVNScanReport_ExtraPageBudgetIsSharedAcrossComponents pins that the
// pool of pages 2..N belongs to the SWEEP, not to each component (Codex M55
// R7, Low: the unit test shares a pointer it owns itself, so reverting the
// production wiring to a fresh pool per component left it green — and that
// revert turns the bound from "components + 500" into "components x 10").
func TestM55JVNScanReport_ExtraPageBudgetIsSharedAcrossComponents(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	appDB := openOrSkipVS(t, appURL)
	if !schemaReadyVS(t, migDB) {
		return
	}

	tenant := seedTenantVS(t, migDB, "m55jvnpool")
	project := uuid.New()
	seedProjectVS(t, migDB, tenant, project, "m55jvnpool-"+project.String())
	sbom := seedSbomVS(t, migDB, tenant, project)
	for _, name := range []string{"aaa", "bbb", "ccc"} {
		seedComponentVS(t, migDB, tenant, sbom, name, "1.0", "pkg:generic/"+name+"@1.0")
	}

	now := time.Now()
	// Every component matches more than one page, so each WANTS a second
	// page; the pool only has one to give out for the whole sweep.
	srv := &cannedMyJVN{
		now:       now,
		corpusFor: func(string) []cannedJVNAdvisory { return cannedCorpus(now, 120, 0) },
	}
	ts := srv.start(t)

	svc := NewJVNService(repository.NewVulnerabilityRepository(appDB),
		repository.NewComponentRepository(appDB), ts.URL, false)
	svc.requestDelay = 0
	svc.extraPageBudget = 1

	withTenantScanTx(t, appDB, tenant, func(ctx context.Context) {
		rep, err := svc.ScanComponentsReport(ctx, sbom)
		t.Logf("report: %s", rep.Summary())
		// 3 mandatory first pages + exactly 1 from the shared pool.
		if rep.Requests != 4 {
			t.Errorf("Requests = %d, want 4 (3 first pages + 1 shared extra page); "+
				"a per-component pool would allow 3 extra", rep.Requests)
		}
		if !rep.BudgetExhausted {
			t.Error("BudgetExhausted = false; the sweep drained the pool and did not say so")
		}
		if rep.TruncatedComponents != 3 {
			t.Errorf("TruncatedComponents = %d, want 3", rep.TruncatedComponents)
		}
		if err == nil {
			t.Fatal("a sweep truncated by its own budget reported success")
		}
	})
}

// TestM55JVNScanReport_CancellationIsNotSuccess pins that a sweep killed
// part-way does not report success (Codex M55 R1, Critical).
//
// Cancellation makes the remaining lookups fail for a reason that has nothing
// to do with the components, and the first cut counted only the components
// AFTER the current one as unscanned — so a context cancelled while the LAST
// component was in flight left Unscanned == 0, and with one earlier success the
// killed sweep came back clean.
func TestM55JVNScanReport_CancellationIsNotSuccess(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	appDB := openOrSkipVS(t, appURL)
	if !schemaReadyVS(t, migDB) {
		return
	}

	tenant := seedTenantVS(t, migDB, "m55jvncancel")
	project := uuid.New()
	seedProjectVS(t, migDB, tenant, project, "m55jvncancel-"+project.String())
	sbom := seedSbomVS(t, migDB, tenant, project)
	// ORDER BY name: aaa-ok is scanned first and succeeds, zzz-last is the
	// final component and is the one the cancellation lands on.
	seedComponentVS(t, migDB, tenant, sbom, "aaa-ok", "1.0", "pkg:generic/aaa-ok@1.0")
	seedComponentVS(t, migDB, tenant, sbom, "zzz-last", "1.0", "pkg:generic/zzz-last@1.0")

	now := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	srv := &cannedMyJVN{
		now:       now,
		corpusFor: func(string) []cannedJVNAdvisory { return cannedCorpus(now, 2, 0) },
		// The last request is held until the client gives up on it, so the
		// cancellation is guaranteed to land while it is in flight. The
		// first cut cancelled here and then ANSWERED, which raced the HTTP
		// transport: about 1 run in 150 (measured 2026-11-13, -race,
		// -count=1000: 7 failures) the transport handed back the complete
		// answer before it saw the cancellation, the sweep had genuinely
		// checked both components, and it rightly reported success — the
		// test, not the scanner, was wrong.
		stall: func(q url.Values) bool {
			if q.Get("keyword") != "zzz-last" {
				return false
			}
			cancel() // killed while the last component is in flight
			return true
		},
	}
	ts := srv.start(t)

	svc := NewJVNService(repository.NewVulnerabilityRepository(appDB),
		repository.NewComponentRepository(appDB), ts.URL, false)
	svc.requestDelay = 0

	rep, err := svc.ScanComponentsReport(WithScanScope(ctx, appDB, tenant), sbom)
	t.Logf("report: %s", rep.Summary())
	if !rep.Cancelled {
		t.Errorf("Cancelled = false after the context was cancelled mid-sweep")
	}
	if err == nil {
		t.Fatal("a cancelled sweep reported success; ScanTracker would record it as completed " +
			"and the CLI would read a killed scan as a clean one")
	}
	if !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("error %q does not declare the results incomplete", err)
	}
}

// TestM55JVNScanReport_NoPauseAfterTheLastComponent pins that the sweep does
// not sit in an inter-component pause after the LAST component (Codex M55 R8,
// Low).
//
// There is nothing left to pace, and the dead wait was observable: a context
// expiring inside it turned a sweep that had in fact scanned everything into a
// cancelled, "results are incomplete" one.
//
// The assertion is on elapsed time because the pause count is what is being
// pinned, and the two shapes are far apart: with the guard, 3 components spend
// 2 pauses (~400ms); without it, 3 (~600ms). The 520ms bound sits between them
// with 80ms of headroom on each side, and the canned server answers in
// microseconds.
func TestM55JVNScanReport_NoPauseAfterTheLastComponent(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	appDB := openOrSkipVS(t, appURL)
	if !schemaReadyVS(t, migDB) {
		return
	}

	tenant := seedTenantVS(t, migDB, "m55jvntail")
	project := uuid.New()
	seedProjectVS(t, migDB, tenant, project, "m55jvntail-"+project.String())
	sbom := seedSbomVS(t, migDB, tenant, project)
	for _, name := range []string{"aaa", "bbb", "ccc"} {
		seedComponentVS(t, migDB, tenant, sbom, name, "1.0", "pkg:generic/"+name+"@1.0")
	}
	// Nameless components are never queried, so they must not be paced
	// either. NOTE, measured: ListBySbom orders by name and a blank name
	// sorts FIRST ("[  ] [   ] [aaa] [bbb] [ccc]"), so these land at the
	// HEAD of the sweep, not the tail. Codex's M55 R9 Low described a
	// nameless TAIL defeating the earlier "skip the pause on the last
	// index" form; that ordering is not reachable through this query, so
	// the scenario as stated was not reproducible. Pacing before each query
	// instead of after each component makes the question moot either way,
	// and these rows pin that a skipped component consumes no pause.
	seedComponentVS(t, migDB, tenant, sbom, "   ", "1.0", "pkg:generic/blank1@1.0")
	seedComponentVS(t, migDB, tenant, sbom, "  ", "1.0", "pkg:generic/blank2@1.0")

	now := time.Now()
	srv := &cannedMyJVN{now: now, corpusFor: func(string) []cannedJVNAdvisory { return nil }}
	ts := srv.start(t)

	svc := NewJVNService(repository.NewVulnerabilityRepository(appDB),
		repository.NewComponentRepository(appDB), ts.URL, false)
	const delay = 200 * time.Millisecond
	svc.requestDelay = delay

	withTenantScanTx(t, appDB, tenant, func(ctx context.Context) {
		start := time.Now()
		rep, err := svc.ScanComponentsReport(ctx, sbom)
		elapsed := time.Since(start)
		t.Logf("report: %s (elapsed %v)", rep.Summary(), elapsed)

		if err != nil {
			t.Fatalf("a clean sweep reported %v", err)
		}
		if rep.Scanned != 3 {
			t.Fatalf("Scanned = %d, want 3", rep.Scanned)
		}
		if rep.SkippedNoName != 2 {
			t.Fatalf("SkippedNoName = %d, want 2", rep.SkippedNoName)
		}
		if elapsed >= 520*time.Millisecond {
			t.Errorf("sweep of 3 components took %v; with no pause after the last one it should "+
				"spend 2 pauses (~%v), not 3", elapsed, 2*delay)
		}
	})
}

// TestM55JVNScanReport_PartialFetchFailureIsCounted pins the observability
// requirement: a sweep where SOME components could not be reached still
// reports success (unchanged product policy), but the number that failed is a
// return value the caller can read.
func TestM55JVNScanReport_PartialFetchFailureIsCounted(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	appDB := openOrSkipVS(t, appURL)
	if !schemaReadyVS(t, migDB) {
		return
	}

	tenant := seedTenantVS(t, migDB, "m55jvnpartial")
	project := uuid.New()
	seedProjectVS(t, migDB, tenant, project, "m55jvnpartial-"+project.String())
	sbom := seedSbomVS(t, migDB, tenant, project)
	seedComponentVS(t, migDB, tenant, sbom, "aaa-ok", "1.0", "pkg:generic/aaa-ok@1.0")
	seedComponentVS(t, migDB, tenant, sbom, "bbb-boom", "1.0", "pkg:generic/bbb-boom@1.0")
	seedComponentVS(t, migDB, tenant, sbom, "ccc-boom", "1.0", "pkg:generic/ccc-boom@1.0")

	now := time.Now()
	srv := &cannedMyJVN{
		now:       now,
		corpusFor: func(string) []cannedJVNAdvisory { return cannedCorpus(now, 2, 0) },
		fail: func(q url.Values) int {
			if strings.HasSuffix(q.Get("keyword"), "boom") {
				return 503
			}
			return 0
		},
	}
	ts := srv.start(t)

	svc := NewJVNService(repository.NewVulnerabilityRepository(appDB),
		repository.NewComponentRepository(appDB), ts.URL, false)
	svc.requestDelay = 0

	withTenantScanTx(t, appDB, tenant, func(ctx context.Context) {
		rep, err := svc.ScanComponentsReport(ctx, sbom)
		t.Logf("report: %s", rep.Summary())
		if rep.Failed != 2 {
			t.Errorf("Failed = %d, want 2 — a partial fetch failure the caller cannot count "+
				"is a partial fetch failure the caller cannot act on", rep.Failed)
		}
		if rep.Scanned != 1 {
			t.Errorf("Scanned = %d, want 1", rep.Scanned)
		}
		// M62: a partial failure now fails the sweep (it stayed a success
		// through M55-M61 pending a threshold decision).
		if !errors.Is(err, ErrScanFetchFailed) {
			t.Errorf("partial failure must fail the sweep with ErrScanFetchFailed (M62), got %v", err)
		}
	})
}

// jvnOutageSweep seeds one SBOM with the given component names, points a JVN
// service at handler, and runs one sweep. It returns the report, the error and
// the keywords the server was asked about, in order.
func jvnOutageSweep(t *testing.T, label string, names []string, handler http.HandlerFunc) (JVNScanReport, error, []string) {
	t.Helper()
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	appDB := openOrSkipVS(t, appURL)
	if !schemaReadyVS(t, migDB) {
		t.SkipNow()
	}
	tenant := seedTenantVS(t, migDB, label)
	project := uuid.New()
	seedProjectVS(t, migDB, tenant, project, label+"-"+project.String())
	sbom := seedSbomVS(t, migDB, tenant, project)
	for i, n := range names {
		seedComponentVS(t, migDB, tenant, sbom, n, "1.0", fmt.Sprintf("pkg:generic/c%d@1.0", i))
	}

	var mu sync.Mutex
	var asked []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Query().Get("keyword"))
		mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(ts.Close)

	svc := NewJVNService(repository.NewVulnerabilityRepository(appDB),
		repository.NewComponentRepository(appDB), ts.URL, false)
	svc.requestDelay = 0
	rep, err := svc.ScanComponentsReport(WithScanScope(context.Background(), appDB, tenant), sbom)
	t.Logf("report: %s", rep.Summary())
	mu.Lock()
	defer mu.Unlock()
	return rep, err, append([]string(nil), asked...)
}

// TestJVNOutage_SweepStopsAskingAnUnavailableMyJVN pins the early stop: with
// MyJVN answering 404 to everything (measured live, 2026-11-13) the sweep asks
// about jvnUnavailableAbandonAfter components, not all of them, and reports
// the rest as unchecked with source_unavailable alongside fetch_failed.
func TestJVNOutage_SweepStopsAskingAnUnavailableMyJVN(t *testing.T) {
	names := []string{"   ", "c1", "c2", "c3", "c4", "c5", "c6"} // blank sorts first
	rep, err, asked := jvnOutageSweep(t, "jvnoutage404", names, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})
	if len(asked) != jvnUnavailableAbandonAfter {
		t.Errorf("MyJVN was asked %d times (%v), want %d", len(asked), asked, jvnUnavailableAbandonAfter)
	}
	if rep.Failed != 3 || rep.UnavailableFailures != 3 || rep.AbandonedUnavailable != 3 ||
		rep.SkippedNoName != 1 || rep.Scanned != 0 || !rep.SourceUnavailable {
		t.Errorf("report = %s, want failed=3 unavailable_failures=3 abandoned_unavailable=3 "+
			"skipped_no_name=1 scanned=0 source_unavailable=true", rep.Summary())
	}
	want := []string{ScanReasonFetchFailed, ScanReasonSourceUnavailable}
	if got := ScanReasons(err); !slices.Equal(got, want) {
		t.Errorf("reasons = %v, want %v (err %v)", got, want, err)
	}
}

// A sweep shorter than the threshold is still an outage when every lookup it
// made got no answer.
func TestJVNOutage_ShortSweepAllUnavailable(t *testing.T) {
	rep, err, asked := jvnOutageSweep(t, "jvnoutageshort", []string{"a1", "a2"}, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	if len(asked) != 2 || rep.AbandonedUnavailable != 0 || !rep.SourceUnavailable {
		t.Errorf("asked=%v report=%s, want both asked and source_unavailable", asked, rep.Summary())
	}
	if !errors.Is(err, ErrScanSourceUnavailable) || !errors.Is(err, ErrScanFetchFailed) {
		t.Errorf("err = %v, want fetch_failed + source_unavailable", err)
	}
}

// Transient unavailability interleaved with answers is not an outage: no
// component is skipped and the reason stays plain fetch_failed.
func TestJVNOutage_InterleavedFailuresDoNotStopTheSweep(t *testing.T) {
	now := time.Now()
	canned := &cannedMyJVN{
		now:       now,
		corpusFor: func(string) []cannedJVNAdvisory { return cannedCorpus(now, 1, 0) },
		fail: func(q url.Values) int {
			if strings.HasSuffix(q.Get("keyword"), "-x") {
				return http.StatusBadGateway
			}
			return 0
		},
	}
	inner := canned.start(t)
	proxy := func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(inner.URL + "?" + r.URL.RawQuery)
		if err != nil {
			t.Errorf("canned MyJVN: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
	// ORDER BY name: a-ok, b-x, c-x, d-ok, e-x, f-x — never three in a row.
	names := []string{"a-ok", "b-x", "c-x", "d-ok", "e-x", "f-x"}
	rep, err, asked := jvnOutageSweep(t, "jvnoutagemix", names, proxy)
	if len(asked) != len(names) {
		t.Errorf("asked %d of %d components (%v)", len(asked), len(names), asked)
	}
	if rep.Scanned != 2 || rep.Failed != 4 || rep.AbandonedUnavailable != 0 || rep.SourceUnavailable {
		t.Errorf("report = %s, want scanned=2 failed=4 abandoned=0 source_unavailable=false", rep.Summary())
	}
	if got := ScanReasons(err); !slices.Equal(got, []string{ScanReasonFetchFailed}) {
		t.Errorf("reasons = %v, want [fetch_failed]", got)
	}
}

// A 200 that is not a MyJVN answer is MyJVN (or something in front of it)
// answering WRONGLY: it is validated per component and never stops the sweep.
func TestJVNOutage_InvalidAnswersAreNotUnavailability(t *testing.T) {
	names := []string{"v1", "v2", "v3", "v4"}
	rep, err, asked := jvnOutageSweep(t, "jvnoutagejunk", names, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>maintenance</body></html>"))
	})
	if len(asked) != 4 || rep.Failed != 4 || rep.UnavailableFailures != 0 || rep.SourceUnavailable {
		t.Errorf("asked=%d report=%s, want 4 asked, failed=4, no unavailability", len(asked), rep.Summary())
	}
	if got := ScanReasons(err); !slices.Equal(got, []string{ScanReasonFetchFailed}) {
		t.Errorf("reasons = %v, want [fetch_failed]", got)
	}
}
