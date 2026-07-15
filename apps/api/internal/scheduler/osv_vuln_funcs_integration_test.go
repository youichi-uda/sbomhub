//go:build integration

// Package scheduler - real-PG integration test for the OSV vuln_funcs
// candidate-enumeration freshness clause (M43 Wave 3 / F467 + M43 Phase D R5
// backdated-tombstone re-candidacy), migration 057 era.
//
// Why this file exists (sqlmock limitation, same rationale as the F258 /
// F234 integration files in this package):
//
//	The NOT EXISTS freshness sub-clause in osvCVECandidateQuery uses an
//	INCLUSIVE comparison — `ae.fetched_at >= $2`. That inclusive `>=` is
//	not a cosmetic choice: the whole M43 Phase D R5 backdated-tombstone
//	arithmetic (fetched_at = now - (refresh - retry), re-candidating at the
//	first daily tick AFTER the retry margin, i.e. 2–3 days rather than the
//	full 7-day window) is derived assuming the row at EXACTLY the cutoff is
//	still counted fresh. sqlmock does not evaluate SQL, so the unit tests in
//	cve_sync_test.go can only regex-pin the query TEXT; whether PostgreSQL
//	treats fetched_at == cutoff as fresh (excluded) or stale (candidate) can
//	only be observed against real PG. A regression that flipped `>=` to `>`
//	would pass every sqlmock test and silently shorten the negative cache by
//	one tick — this file catches exactly that.
//
// It also pins the NULL-fetched_at handling (a NULL compares as unknown =>
// NOT EXISTS holds => the CVE is a candidate) which sqlmock likewise cannot
// model.
//
// Run with:
//
//	cd apps/api && go test -tags=integration ./internal/scheduler -run OSVVulnFuncs
//
// Prerequisites (skipped otherwise — same env contract as the sibling
// scheduler integration files):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 057_advisory_excerpts_vuln_funcs_scoped.
//
// Source is NOT modified by this file: it constructs a bare CVESyncJob with
// only the app-role *sql.DB and drives the unexported listOSVCandidates /
// listOSVCandidatesChunk directly (same-package access), reading the real
// constants osvVulnFuncsRefreshInterval / osvVulnFuncsAnomalyRetryInterval.
package scheduler

import (
	"context"
	"database/sql"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// schedSchemaReadyOSVExcerpts extends the CVE schema check with the
// advisory_excerpts table + its migration-057 vuln_funcs_scoped column + its
// FORCE RLS state. Skips loudly if the OSV pass's storage is not present in
// the expected shape (so a pre-057 / RLS-reverted DB does not silently
// mis-test the freshness clause).
func schedSchemaReadyOSVExcerpts(t *testing.T, db *sql.DB) bool {
	t.Helper()
	if !schedSchemaReadyCVE(t, db) {
		return false
	}
	var hasScoped bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public'
			  AND table_name   = 'advisory_excerpts'
			  AND column_name  = 'vuln_funcs_scoped'
		)
	`).Scan(&hasScoped); err != nil {
		t.Skipf("advisory_excerpts.vuln_funcs_scoped existence check failed: %v -- skipping", err)
		return false
	}
	if !hasScoped {
		t.Skip("advisory_excerpts.vuln_funcs_scoped not present -- run migrations through 057 first")
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.advisory_excerpts'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("advisory_excerpts RLS-state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Skipf("advisory_excerpts RLS state: enable=%v force=%v -- migration 033 reverted? skipping",
			rlsEnabled, rlsForce)
		return false
	}
	return true
}

// osvCandFixture is one seeded tenant with a single Go-ecosystem component
// (purl matches osvCVECandidateQuery's ILIKE + repository.EcosystemFromPurl
// go-side re-check) that the test links CVEs to.
type osvCandFixture struct {
	tenantID    uuid.UUID
	componentID uuid.UUID
}

// seedOSVCandBase provisions tenant + project + sbom + one Go component
// (all FORCE RLS post-027, seeded via insertRowWithTenantGUC — reused from
// cve_sync_integration_test.go in this same package). Registers a t.Cleanup
// (LIFO-ordered vs the migDB Close cleanup) that deletes the tenant, which
// cascades to projects / sboms / components / component_vulnerabilities /
// advisory_excerpts.
func seedOSVCandBase(t *testing.T, migDB *sql.DB, tag string) osvCandFixture {
	t.Helper()
	fx := osvCandFixture{tenantID: uuid.New(), componentID: uuid.New()}
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, fx.tenantID)
	})

	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		fx.tenantID, "osvc-"+tag+"-"+fx.tenantID.String(),
		"OSVCand "+tag, "osvc-"+tag+"-"+fx.tenantID.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	projectID := uuid.New()
	if err := insertRowWithTenantGUC(migDB, fx.tenantID,
		`INSERT INTO projects (id, tenant_id, name, created_at, updated_at)
		 VALUES ($1, $2, $3, NOW(), NOW())`,
		projectID, fx.tenantID, "OSVCand project "+tag,
	); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	sbomID := uuid.New()
	if err := insertRowWithTenantGUC(migDB, fx.tenantID,
		`INSERT INTO sboms (id, project_id, tenant_id, format, version, created_at)
		 VALUES ($1, $2, $3, 'cyclonedx', '1.5', NOW())`,
		sbomID, projectID, fx.tenantID,
	); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}

	// purl is a Go module so osvCVECandidateQuery's ILIKE prefilter AND the
	// Go-side repository.EcosystemFromPurl re-check both keep the pair.
	if err := insertRowWithTenantGUC(migDB, fx.tenantID,
		`INSERT INTO components (id, sbom_id, tenant_id, name, version, type, purl, created_at)
		 VALUES ($1, $2, $3, $4, 'v1.0.0', 'library', $5, NOW())`,
		fx.componentID, sbomID, fx.tenantID, "osvcand-mod",
		"pkg:golang/example.com/candmod@v1.0.0",
	); err != nil {
		t.Fatalf("seed component: %v", err)
	}
	return fx
}

// linkOSVCandCVE upserts a global vulnerabilities row for cveID and links it
// to the fixture's component (component_vulnerabilities is non-RLS). Both are
// what the candidate JOIN chain (components -> component_vulnerabilities ->
// vulnerabilities) needs to surface the (cve_id, purl) pair. Returns nothing;
// the caller tracks cveIDs for the vulnerabilities cleanup.
func linkOSVCandCVE(t *testing.T, migDB *sql.DB, fx osvCandFixture, cveID string) {
	t.Helper()
	vulnID := uuid.New()
	if err := migDB.QueryRow(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source, published_at, updated_at)
		VALUES ($1, $2, $3, 'HIGH', 7.5, 'NVD', NOW(), NOW())
		ON CONFLICT (cve_id) DO UPDATE SET updated_at = NOW()
		RETURNING id
	`, vulnID, cveID, "OSV candidate freshness probe "+cveID).Scan(&vulnID); err != nil {
		t.Fatalf("upsert vulnerability %s: %v", cveID, err)
	}
	if _, err := migDB.Exec(`
		INSERT INTO component_vulnerabilities (component_id, vulnerability_id, detected_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT DO NOTHING
	`, fx.componentID, vulnID); err != nil {
		t.Fatalf("link component_vulnerabilities %s: %v", cveID, err)
	}
}

// seedOSVExcerpt writes one source='osv' advisory_excerpts row for (tenant,
// cveID) with the given fetched_at (nil => SQL NULL). advisory_excerpts is
// FORCE RLS so it is seeded inside a tenant-GUC tx. vuln_funcs / _scoped fall
// to their '[]' defaults — the freshness clause only reads fetched_at.
func seedOSVExcerpt(t *testing.T, migDB *sql.DB, tenantID uuid.UUID, cveID string, fetchedAt *time.Time) {
	t.Helper()
	var fa interface{}
	if fetchedAt != nil {
		fa = *fetchedAt
	}
	if err := insertRowWithTenantGUC(migDB, tenantID,
		`INSERT INTO advisory_excerpts (id, tenant_id, cve_id, source, fetched_at)
		 VALUES ($1, $2, $3, 'osv', $4)`,
		uuid.New(), tenantID, cveID, fa,
	); err != nil {
		t.Fatalf("seed advisory_excerpts osv row %s: %v", cveID, err)
	}
}

// candidateCVEs flattens a []osvTenantCandidates for the one seeded tenant
// into a sorted CVE-id slice for set assertions.
func candidateCVEs(out []osvTenantCandidates, tenantID uuid.UUID) []string {
	for _, tc := range out {
		if tc.tenantID == tenantID {
			got := append([]string(nil), tc.cveIDs...)
			sort.Strings(got)
			return got
		}
	}
	return nil
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func sameCVESet(a, b []string) bool {
	a, b = sortedCopy(a), sortedCopy(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestOSVVulnFuncs_ListOSVCandidatesChunk_FreshnessBoundary_RealPG pins the
// INCLUSIVE `ae.fetched_at >= $2` semantics against real PostgreSQL by driving
// listOSVCandidatesChunk with a CONTROLLED cutoff (unlike listOSVCandidates,
// whose cutoff is computed internally from time.Now()). Because the cutoff is
// supplied by the test, a row can be seeded at EXACTLY the cutoff and the
// inclusive vs exclusive question is decided deterministically — no seed/call
// clock skew. Four freshness classes for one tenant:
//
//   - fresh    (fetched_at = cutoff + 1h) -> excluded
//   - boundary (fetched_at = cutoff)      -> excluded  (INCLUSIVE: the load-bearing case)
//   - stale    (fetched_at = cutoff - 1h) -> candidate
//   - null     (fetched_at = NULL)        -> candidate (unknown compare -> NOT EXISTS holds)
//
// If a regression flipped `>=` to `>`, the boundary row would become a
// candidate and this test would fail — the exact blind spot sqlmock's
// text-only pin cannot see.
func TestOSVVulnFuncs_ListOSVCandidatesChunk_FreshnessBoundary_RealPG(t *testing.T) {
	appURL, migURL := schedIntEnv(t)

	migDB := schedOpenOrSkip(t, migURL)
	// C27 trap avoidance: register Close FIRST so it runs LAST; the seeder's
	// row-DELETE cleanups (registered later) run while the handle is open.
	t.Cleanup(func() { _ = migDB.Close() })
	if !schedSchemaReadyOSVExcerpts(t, migDB) {
		return
	}
	appDB := schedOpenOrSkip(t, appURL)
	t.Cleanup(func() { _ = appDB.Close() })

	fx := seedOSVCandBase(t, migDB, "boundary")
	tok := uuid.New().String()[:8]
	cveFresh := "CVE-OSVC-" + tok + "-FRESH"
	cveBound := "CVE-OSVC-" + tok + "-BOUND"
	cveStale := "CVE-OSVC-" + tok + "-STALE"
	cveNull := "CVE-OSVC-" + tok + "-NULL"
	allCVEs := []string{cveFresh, cveBound, cveStale, cveNull}
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = ANY($1)`, pq.Array(allCVEs))
	})
	for _, c := range allCVEs {
		linkOSVCandCVE(t, migDB, fx, c)
	}

	// Controlled cutoff: truncate to microseconds so the boundary row stores
	// a value BITWISE-equal to the cutoff (PG timestamptz is microsecond
	// precision; an un-truncated nanosecond cutoff would round the stored
	// fetched_at below it and turn the inclusive case into a false stale).
	cutoff := time.Now().UTC().Add(-osvVulnFuncsRefreshInterval).Truncate(time.Microsecond)
	fresh := cutoff.Add(time.Hour)
	boundary := cutoff
	stale := cutoff.Add(-time.Hour)

	seedOSVExcerpt(t, migDB, fx.tenantID, cveFresh, &fresh)
	seedOSVExcerpt(t, migDB, fx.tenantID, cveBound, &boundary)
	seedOSVExcerpt(t, migDB, fx.tenantID, cveStale, &stale)
	seedOSVExcerpt(t, migDB, fx.tenantID, cveNull, nil)

	ctx := context.Background()
	j := &CVESyncJob{db: appDB}

	conn, err := appDB.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire pooled conn: %v", err)
	}
	defer conn.Close()

	ecosystems := make(map[string]osvCVEEcosystems)
	out, chunkErr := j.listOSVCandidatesChunk(ctx, conn, 0, []uuid.UUID{fx.tenantID}, cutoff, ecosystems)
	if chunkErr != nil {
		t.Fatalf("listOSVCandidatesChunk: %v", chunkErr)
	}

	got := candidateCVEs(out, fx.tenantID)
	want := []string{cveStale, cveNull}
	if !sameCVESet(got, want) {
		t.Fatalf("candidate set = %v, want %v\n"+
			"  fresh (cutoff+1h) must be excluded; boundary (== cutoff) must be excluded (INCLUSIVE >=);\n"+
			"  stale (cutoff-1h) and null must be candidates. A `>` regression would leak %s into the set.",
			got, want, cveBound)
	}

	// The Go-ecosystem union must have flagged every candidate CVE needGo
	// (purl is pkg:golang) — a cheap co-assertion that the pair actually
	// flowed through the ecosystem-derivation path, not just the SQL.
	for _, c := range want {
		if eco, ok := ecosystems[c]; !ok || !eco.needGo {
			t.Fatalf("ecosystem union for %s = %+v (present=%v), want needGo=true", c, eco, ok)
		}
	}
	// The excluded rows must NOT appear in the ecosystem union either (they
	// were never yielded as candidate pairs).
	if _, ok := ecosystems[cveBound]; ok {
		t.Fatalf("boundary CVE %s leaked into ecosystem union despite being fresh (inclusive >= excluded it)", cveBound)
	}
}

// TestOSVVulnFuncs_ListOSVCandidates_BackdateRecandidacy_RealPG pins the M43
// Phase D R5 backdated-tombstone re-candidacy arithmetic end-to-end through
// the PRODUCTION listOSVCandidates path (internal cutoff = now -
// osvVulnFuncsRefreshInterval), tying the assertions to the real constants
// osvVulnFuncsRefreshInterval (7d) and osvVulnFuncsAnomalyRetryInterval (48h).
//
// An anomalous mass-404 tick writes its tombstones with
//
//	fetched_at = now - (osvVulnFuncsRefreshInterval - osvVulnFuncsAnomalyRetryInterval)
//
// i.e. backdated so the row sits exactly osvVulnFuncsAnomalyRetryInterval
// inside the freshness window. The claim R5 relies on is that such a row is
// negative-cached NOW (not re-fetched immediately) yet re-enters the
// candidate set once the 48h margin has elapsed — 2–3 days out, NOT the full
// 7-day window. Seeded classes (each = the backdate write value aged by a
// simulated elapsed interval; the fold `-(refresh-retry) - elapsed` crosses
// the `now - refresh` cutoff exactly at elapsed == retry, which is the whole
// point of the backdate):
//
//   - normal-fresh   (fetched_at = now)                       -> excluded (control)
//   - backdate-written (aged 0)                               -> excluded (negative-cached at the anomalous tick)
//   - backdate-notyet  (aged retry-1h)                        -> excluded (still inside the 48h margin)
//   - backdate-recand  (aged retry+1h)                        -> candidate (aged past the margin)
//   - stale          (fetched_at = now - 10d)                 -> candidate (control)
//   - null           (fetched_at = NULL)                      -> candidate (control)
//
// The ±1h offsets sit far outside the sub-second seed/call clock skew, so the
// exclusive cases here are robust; the exact inclusive-boundary case is the
// deterministic-cutoff sibling above.
func TestOSVVulnFuncs_ListOSVCandidates_BackdateRecandidacy_RealPG(t *testing.T) {
	appURL, migURL := schedIntEnv(t)

	migDB := schedOpenOrSkip(t, migURL)
	t.Cleanup(func() { _ = migDB.Close() })
	if !schedSchemaReadyOSVExcerpts(t, migDB) {
		return
	}
	appDB := schedOpenOrSkip(t, appURL)
	t.Cleanup(func() { _ = appDB.Close() })

	fx := seedOSVCandBase(t, migDB, "backdate")
	tok := uuid.New().String()[:8]
	cveNormalFresh := "CVE-OSVC-" + tok + "-NFRESH"
	cveBackWritten := "CVE-OSVC-" + tok + "-BDWRIT"
	cveBackNotYet := "CVE-OSVC-" + tok + "-BDNOTYET"
	cveBackReCand := "CVE-OSVC-" + tok + "-BDRECAND"
	cveStale := "CVE-OSVC-" + tok + "-STALE"
	cveNull := "CVE-OSVC-" + tok + "-NULL"
	allCVEs := []string{cveNormalFresh, cveBackWritten, cveBackNotYet, cveBackReCand, cveStale, cveNull}
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = ANY($1)`, pq.Array(allCVEs))
	})
	for _, c := range allCVEs {
		linkOSVCandCVE(t, migDB, fx, c)
	}

	now := time.Now().UTC()
	// The exact value an anomalous tick backdates its tombstone to.
	backdate := -(osvVulnFuncsRefreshInterval - osvVulnFuncsAnomalyRetryInterval)

	normalFresh := now
	backWritten := now.Add(backdate)                                                     // aged 0 -> inside window
	backNotYet := now.Add(backdate).Add(-(osvVulnFuncsAnomalyRetryInterval - time.Hour)) // aged 47h -> still fresh (= cutoff + 1h)
	backReCand := now.Add(backdate).Add(-(osvVulnFuncsAnomalyRetryInterval + time.Hour)) // aged 49h -> stale (= cutoff - 1h)
	stale := now.Add(-10 * 24 * time.Hour)

	seedOSVExcerpt(t, migDB, fx.tenantID, cveNormalFresh, &normalFresh)
	seedOSVExcerpt(t, migDB, fx.tenantID, cveBackWritten, &backWritten)
	seedOSVExcerpt(t, migDB, fx.tenantID, cveBackNotYet, &backNotYet)
	seedOSVExcerpt(t, migDB, fx.tenantID, cveBackReCand, &backReCand)
	seedOSVExcerpt(t, migDB, fx.tenantID, cveStale, &stale)
	seedOSVExcerpt(t, migDB, fx.tenantID, cveNull, nil)

	ctx := context.Background()
	j := &CVESyncJob{db: appDB}

	// Production path: internal cutoff = time.Now().UTC() - refreshInterval.
	out, _ := j.listOSVCandidates(ctx, []uuid.UUID{fx.tenantID})

	got := candidateCVEs(out, fx.tenantID)
	want := []string{cveBackReCand, cveStale, cveNull}
	if !sameCVESet(got, want) {
		t.Fatalf("candidate set = %v, want %v\n"+
			"  backdate-written (now-(refresh-retry)) and backdate-notyet (aged retry-1h) must stay negative-cached;\n"+
			"  backdate-recand (aged retry+1h) must re-enter the candidate set — the R5 48h-margin re-candidacy;\n"+
			"  normal-fresh excluded, stale/null candidates.",
			got, want)
	}
}
