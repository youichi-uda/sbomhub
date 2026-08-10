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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// withTenantScanTx runs fn against the APP role inside a rolled-back tenant
// transaction, the same shape SbomHandler.runScan gives the scanners.
func withTenantScanTx(t *testing.T, appDB *sql.DB, tenantID uuid.UUID, fn func(ctx context.Context)) {
	t.Helper()
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("set tenant context: %v", err)
	}
	fn(database.WithTx(context.Background(), tx))
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

		// Still in the SAME transaction (withTenantScanTx rolls back, so a
		// later one would see nothing): everything the budget did retrieve
		// was persisted. Truncation reduces coverage; it must not discard
		// the coverage that was obtained.
		vulns, err := vulnRepo.ListByProject(ctx, project)
		if err != nil {
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
		fail: func(q url.Values) int {
			if q.Get("keyword") == "zzz-last" {
				cancel() // killed while the last component is in flight
			}
			return 0
		},
	}
	ts := srv.start(t)

	svc := NewJVNService(repository.NewVulnerabilityRepository(appDB),
		repository.NewComponentRepository(appDB), ts.URL, false)
	svc.requestDelay = 0

	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenant.String()); err != nil {
		t.Fatalf("set tenant context: %v", err)
	}

	rep, err := svc.ScanComponentsReport(database.WithTx(ctx, tx), sbom)
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
		if err != nil {
			t.Errorf("partial failure must stay a success until a threshold is chosen "+
				"(product decision, unchanged here), got %v", err)
		}
	})
}
