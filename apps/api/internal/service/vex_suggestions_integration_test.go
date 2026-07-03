//go:build integration

// Package service — cross-project VEX aggregation integration test
// (M26-A / F375, issue #130).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run TestVEXSuggestions ./internal/service
//
// -count=1 is load-bearing: this test asserts against live DB rows +
// FORCE ROW LEVEL SECURITY behaviour, neither of which is an input to
// go's test cache. Re-running after re-seeding with an unchanged binary
// would otherwise return the previous cached verdict.
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 003 (vex_statements) + 027 (components
//     tenant_id NOT NULL) — the api server's auto-migrate covers this.
//
// What this test pins down:
//
//  1. A component-specific approved vex_statement in project A of tenant T
//     is surfaced as a `purl` suggestion for project B (same tenant) when
//     B has a component with the same purl affected by the same CVE.
//  2. A foreign tenant's approved vex_statement is NEVER surfaced —
//     tenant isolation holds under RLS (authoritative) AND the query's
//     explicit tenant_id predicate (defence in depth).
//  3. A project's own (self) statement is not offered back to it as a
//     suggestion, even when a same-purl sibling component is untriaged
//     (so the self-exclusion is exercised independently of the
//     already-triaged exclusion).
//  4. A (vuln, component) the target already ruled on is not re-surfaced.
//  5. A component-agnostic (component_id NULL) source statement yields a
//     `vulnerability_only` suggestion.
package service

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

func vexSuggestionsTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("vex suggestions integration test requires DATABASE_URL (sbomhub_app) and " +
			"MIGRATE_DATABASE_URL (sbomhub_migrator). Run `docker compose up -d postgres`, " +
			"apply migrations, then re-run with -tags=integration -count=1.")
	}
	return appURL, migURL
}

func openOrSkipVS(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("sql.Open: %v -- skipping", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("db unreachable: %v -- skipping", err)
	}
	return db
}

func schemaReadyVS(t *testing.T, db *sql.DB) bool {
	t.Helper()
	for _, tbl := range []string{"vex_statements", "components", "sboms", "component_vulnerabilities", "vulnerabilities", "projects"} {
		var exists bool
		if err := db.QueryRow(`
			SELECT EXISTS (SELECT 1 FROM information_schema.tables
				WHERE table_schema='public' AND table_name=$1)`, tbl).Scan(&exists); err != nil {
			t.Skipf("existence check for %s failed: %v -- skipping", tbl, err)
			return false
		}
		if !exists {
			t.Skipf("table %s not present -- run migrations first", tbl)
			return false
		}
	}
	// vex_statements must still be under FORCE RLS (migration 023). If a
	// future migration reverted it, skip loudly rather than mis-testing
	// the tenant boundary.
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.vex_statements'::regclass`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("vex_statements RLS state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Skipf("vex_statements RLS not ENABLE+FORCE (enabled=%v force=%v) -- skipping", rlsEnabled, rlsForce)
		return false
	}
	return true
}

// withTenantTxVS runs fn inside a migrator tx that has SET LOCAL
// app.current_tenant_id — required because components / sboms /
// vex_statements are FORCE RLS with a WITH CHECK on tenant_id.
func withTenantTxVS(t *testing.T, db *sql.DB, tenantID uuid.UUID, fn func(*sql.Tx)) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("withTenantTxVS begin (tenant=%s): %v", tenantID, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenantID.String() + `'`); err != nil {
		t.Fatalf("withTenantTxVS SET LOCAL %s: %v", tenantID, err)
	}
	fn(tx)
	if err := tx.Commit(); err != nil {
		t.Fatalf("withTenantTxVS commit (tenant=%s): %v", tenantID, err)
	}
	committed = true
}

func seedTenantVS(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1,$2,$3,$4)`,
		id, "vex-sugg-"+label+"-"+id.String(), "VEXSugg "+label, "vex-sugg-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

func seedProjectVS(t *testing.T, migDB *sql.DB, tenantID, projectID uuid.UUID, name string) {
	t.Helper()
	withTenantTxVS(t, migDB, tenantID, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO projects (id, tenant_id, name) VALUES ($1,$2,$3)`,
			projectID, tenantID, name); err != nil {
			t.Fatalf("seed project %s: %v", name, err)
		}
	})
}

func seedSbomVS(t *testing.T, migDB *sql.DB, tenantID, projectID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	withTenantTxVS(t, migDB, tenantID, func(tx *sql.Tx) {
		if _, err := tx.Exec(
			`INSERT INTO sboms (id, project_id, tenant_id, format, version, raw_data)
			 VALUES ($1,$2,$3,'cyclonedx','1.5','{}'::jsonb)`,
			id, projectID, tenantID); err != nil {
			t.Fatalf("seed sbom: %v", err)
		}
	})
	return id
}

func seedComponentVS(t *testing.T, migDB *sql.DB, tenantID, sbomID uuid.UUID, name, version, purl string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	withTenantTxVS(t, migDB, tenantID, func(tx *sql.Tx) {
		if _, err := tx.Exec(
			`INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license, created_at)
			 VALUES ($1,$2,$3,$4,$5,'library',$6,'MIT',NOW())`,
			id, tenantID, sbomID, name, version, purl); err != nil {
			t.Fatalf("seed component %s: %v", name, err)
		}
	})
	return id
}

// seedVulnVS inserts a global vulnerability row (cve_id is UNIQUE globally,
// RLS-exempt). Returns the id; the caller records it for explicit cleanup
// since vulnerabilities are not reaped by tenant CASCADE.
func seedVulnVS(t *testing.T, migDB *sql.DB, cveID string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score)
		 VALUES ($1,$2,'test vuln','HIGH',7.5)`, id, cveID); err != nil {
		t.Fatalf("seed vuln %s: %v", cveID, err)
	}
	return id
}

func linkCompVulnVS(t *testing.T, migDB *sql.DB, componentID, vulnID uuid.UUID) {
	t.Helper()
	// component_vulnerabilities is a global join table (no RLS).
	if _, err := migDB.Exec(
		`INSERT INTO component_vulnerabilities (component_id, vulnerability_id) VALUES ($1,$2)`,
		componentID, vulnID); err != nil {
		t.Fatalf("link comp %s vuln %s: %v", componentID, vulnID, err)
	}
}

func seedVexStmtVS(t *testing.T, migDB *sql.DB, tenantID, projectID, vulnID uuid.UUID, componentID *uuid.UUID, status string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	withTenantTxVS(t, migDB, tenantID, func(tx *sql.Tx) {
		if _, err := tx.Exec(
			`INSERT INTO vex_statements
			   (id, tenant_id, project_id, vulnerability_id, component_id, status,
			    justification, action_statement, impact_statement, created_by, created_at, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,'vulnerable_code_not_present','','not reachable','tester',NOW(),NOW())`,
			id, tenantID, projectID, vulnID, componentID, status); err != nil {
			t.Fatalf("seed vex_statement: %v", err)
		}
	})
	return id
}

// runSuggestions drives the real VEXService.GetSuggestions for (tenant,
// project) through an app-role tx that has SET LOCAL app.current_tenant_id,
// so RLS is active exactly as it is on a live request.
func runSuggestions(t *testing.T, appDB *sql.DB, tenantID, projectID uuid.UUID) []model.VEXSuggestion {
	t.Helper()
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin: %v", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenantID.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL %s: %v", tenantID, err)
	}
	svc := NewVEXService(repository.NewVEXRepository(appDB), repository.NewVulnerabilityRepository(appDB))
	ctx := database.WithTx(context.Background(), tx)
	got, err := svc.GetSuggestions(ctx, tenantID, projectID)
	if err != nil {
		t.Fatalf("GetSuggestions: %v", err)
	}
	return got
}

func TestVEXSuggestions_CrossProjectAggregation(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	// Close migDB via t.Cleanup (registered first → runs LAST under LIFO)
	// rather than defer: a deferred Close fires when the test function
	// returns, which is BEFORE any t.Cleanup, so the data-deletion cleanup
	// below would otherwise run its DELETEs against an already-closed pool
	// (error swallowed → leaked rows).
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyVS(t, migDB) {
		return
	}
	appDB := openOrSkipVS(t, appURL)
	defer appDB.Close()

	tenantT := seedTenantVS(t, migDB, "T")
	tenantF := seedTenantVS(t, migDB, "F")

	// Unique CVE ids per run (cve_id is globally UNIQUE, not tenant-scoped).
	sfx := uuid.New().String()[:8]
	cve := func(n string) string { return fmt.Sprintf("CVE-2026-%s-%s", n, sfx) }
	v1 := seedVulnVS(t, migDB, cve("0001")) // purl cross-project
	v2 := seedVulnVS(t, migDB, cve("0002")) // vulnerability_only
	v3 := seedVulnVS(t, migDB, cve("0003")) // already-triaged
	v4 := seedVulnVS(t, migDB, cve("0004")) // foreign tenant
	v5 := seedVulnVS(t, migDB, cve("0005")) // self-exclusion

	t.Cleanup(func() {
		// tenants CASCADE reaps projects → sboms → components →
		// component_vulnerabilities → vex_statements. Global vulnerabilities
		// are not tenant-scoped, so remove them explicitly.
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1,$2)`, tenantT, tenantF)
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id IN ($1,$2,$3,$4,$5)`, v1, v2, v3, v4, v5)
	})

	// --- Tenant T, project A (source) ---
	projectA := uuid.New()
	seedProjectVS(t, migDB, tenantT, projectA, "Project A")
	sbomA := seedSbomVS(t, migDB, tenantT, projectA)
	compA1 := seedComponentVS(t, migDB, tenantT, sbomA, "libshared", "1.0", "pkg:generic/shared@1.0")
	linkCompVulnVS(t, migDB, compA1, v1)
	seedVexStmtVS(t, migDB, tenantT, projectA, v1, &compA1, "not_affected") // component-specific → purl source
	// component-agnostic (NULL) approved statement for v2 → vulnerability_only source
	stmtA2 := seedVexStmtVS(t, migDB, tenantT, projectA, v2, nil, "not_affected")
	compA3 := seedComponentVS(t, migDB, tenantT, sbomA, "libtriaged", "1.0", "pkg:generic/triaged@1.0")
	linkCompVulnVS(t, migDB, compA3, v3)
	seedVexStmtVS(t, migDB, tenantT, projectA, v3, &compA3, "not_affected") // source for already-triaged case

	// --- Tenant T, project B (target we query) ---
	projectB := uuid.New()
	seedProjectVS(t, migDB, tenantT, projectB, "Project B")
	sbomB := seedSbomVS(t, migDB, tenantT, projectB)
	compB1 := seedComponentVS(t, migDB, tenantT, sbomB, "libshared", "1.0", "pkg:generic/shared@1.0") // SAME purl as compA1
	linkCompVulnVS(t, migDB, compB1, v1)
	compB2 := seedComponentVS(t, migDB, tenantT, sbomB, "libagn", "2.0", "pkg:generic/agn@2.0")
	linkCompVulnVS(t, migDB, compB2, v2)
	compB3 := seedComponentVS(t, migDB, tenantT, sbomB, "libtriaged", "1.0", "pkg:generic/triaged@1.0")
	linkCompVulnVS(t, migDB, compB3, v3)
	seedVexStmtVS(t, migDB, tenantT, projectB, v3, &compB3, "affected") // B already triaged (v3, compB3)
	compB4 := seedComponentVS(t, migDB, tenantT, sbomB, "libforeign", "1.0", "pkg:generic/foreign@1.0")
	linkCompVulnVS(t, migDB, compB4, v4)
	// self-exclusion: two same-purl components affected by v5; B has a
	// component-specific statement on compB5a only. The candidate produced
	// by B's own statement against compB5b (same purl, untriaged) must be
	// dropped by self-exclusion — NOT by already-triaged.
	compB5a := seedComponentVS(t, migDB, tenantT, sbomB, "libself", "1.0", "pkg:generic/selfshared@1.0")
	compB5b := seedComponentVS(t, migDB, tenantT, sbomB, "libself", "1.0", "pkg:generic/selfshared@1.0")
	linkCompVulnVS(t, migDB, compB5a, v5)
	linkCompVulnVS(t, migDB, compB5b, v5)
	stmtBself := seedVexStmtVS(t, migDB, tenantT, projectB, v5, &compB5a, "not_affected")

	// --- Foreign tenant F, project FP ---
	projectFP := uuid.New()
	seedProjectVS(t, migDB, tenantF, projectFP, "Foreign Project")
	sbomFP := seedSbomVS(t, migDB, tenantF, projectFP)
	compFP := seedComponentVS(t, migDB, tenantF, sbomFP, "libforeign", "1.0", "pkg:generic/foreign@1.0")
	linkCompVulnVS(t, migDB, compFP, v4)
	stmtFP := seedVexStmtVS(t, migDB, tenantF, projectFP, v4, &compFP, "not_affected")

	// --- Query suggestions for project B (tenant T) ---
	got := runSuggestions(t, appDB, tenantT, projectB)

	// Case 2 (tenant isolation) — highest priority: the foreign tenant's
	// statement must NEVER appear, and no suggestion may reference the
	// foreign project or v4.
	for _, s := range got {
		if s.Source.StatementID == stmtFP {
			t.Fatalf("TENANT LEAK: foreign tenant's vex_statement %s surfaced in tenant T's suggestions", stmtFP)
		}
		if s.Source.ProjectID == projectFP {
			t.Fatalf("TENANT LEAK: suggestion sourced from foreign project %s", projectFP)
		}
		if s.CVEID == cve("0004") {
			t.Fatalf("TENANT LEAK: suggestion for foreign-only CVE %s", cve("0004"))
		}
	}

	// Case 3 (self-exclusion): B's own statement must not be offered back.
	for _, s := range got {
		if s.Source.StatementID == stmtBself || s.Source.ProjectID == projectB {
			t.Fatalf("self-project statement %s (project B) surfaced as a suggestion for project B", stmtBself)
		}
		if s.Component.Purl == "pkg:generic/selfshared@1.0" {
			t.Fatalf("self-exclusion failed: suggestion for same-purl self component (purl selfshared)")
		}
	}

	// Case 4 (already-triaged): no suggestion for the (v3) B already ruled on.
	for _, s := range got {
		if s.CVEID == cve("0003") {
			t.Fatalf("already-triaged CVE %s must not be re-surfaced", cve("0003"))
		}
	}

	// Cases 1 + 5: exactly two suggestions survive — the purl match and the
	// vulnerability_only match, both sourced from project A.
	if len(got) != 2 {
		t.Fatalf("expected exactly 2 suggestions (purl + vulnerability_only), got %d: %+v", len(got), got)
	}

	byCVE := map[string]model.VEXSuggestion{}
	for _, s := range got {
		byCVE[s.CVEID] = s
	}

	// Case 1: purl match.
	s1, ok := byCVE[cve("0001")]
	if !ok {
		t.Fatalf("expected a suggestion for the shared-purl CVE %s", cve("0001"))
	}
	if s1.MatchType != model.VEXMatchTypePurl {
		t.Errorf("case1 match_type = %q, want %q", s1.MatchType, model.VEXMatchTypePurl)
	}
	if s1.Component.Purl != "pkg:generic/shared@1.0" {
		t.Errorf("case1 component.purl = %q", s1.Component.Purl)
	}
	if s1.Source.ProjectID != projectA || s1.Source.ProjectName != "Project A" {
		t.Errorf("case1 source provenance mismatch: %+v", s1.Source)
	}
	if s1.Source.Status != "not_affected" {
		t.Errorf("case1 source.status = %q, want not_affected", s1.Source.Status)
	}

	// Case 5: vulnerability_only match, sourced from A's component-agnostic
	// statement.
	s2, ok := byCVE[cve("0002")]
	if !ok {
		t.Fatalf("expected a suggestion for the vulnerability-only CVE %s", cve("0002"))
	}
	if s2.MatchType != model.VEXMatchTypeVulnerabilityOnly {
		t.Errorf("case5 match_type = %q, want %q", s2.MatchType, model.VEXMatchTypeVulnerabilityOnly)
	}
	if s2.Source.StatementID != stmtA2 {
		t.Errorf("case5 source.statement_id = %s, want %s (A's agnostic statement)", s2.Source.StatementID, stmtA2)
	}
	if s2.Source.ProjectID != projectA {
		t.Errorf("case5 source.project_id = %s, want project A", s2.Source.ProjectID)
	}
}

// TestVEXSuggestions_TenantIsolation_ExplicitPredicate is a focused
// companion to case 2 above. It documents the two-layer guarantee: with a
// NOBYPASSRLS app role (the CI configuration) RLS is authoritative and the
// foreign row is invisible; the query's explicit `tenant_id = $1`
// predicate is the defence-in-depth belt that becomes load-bearing only if
// RLS is ever disabled. When the connected role bypasses RLS (e.g. a
// misconfigured superuser DATABASE_URL) this test still asserts isolation,
// proving the belt holds on its own.
func TestVEXSuggestions_TenantIsolation_BeltAndBraces(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	// See TestVEXSuggestions_CrossProjectAggregation: close via t.Cleanup so
	// it runs after (not before) the data-deletion cleanup below.
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyVS(t, migDB) {
		return
	}
	appDB := openOrSkipVS(t, appURL)
	defer appDB.Close()

	// Report whether the app role bypasses RLS so the run log makes the
	// guarantee under test explicit.
	var bypass bool
	_ = appDB.QueryRow(`SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&bypass)
	t.Logf("app role bypasses RLS = %v (false → RLS authoritative; true → explicit tenant_id predicate is sole guard)", bypass)

	tenantT := seedTenantVS(t, migDB, "IT")
	tenantF := seedTenantVS(t, migDB, "IF")
	sfx := uuid.New().String()[:8]
	vX := seedVulnVS(t, migDB, fmt.Sprintf("CVE-2026-ISO-%s", sfx))
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1,$2)`, tenantT, tenantF)
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vX)
	})

	// Target project in tenant T with a component affected by vX.
	projT := uuid.New()
	seedProjectVS(t, migDB, tenantT, projT, "T target")
	sbomT := seedSbomVS(t, migDB, tenantT, projT)
	compT := seedComponentVS(t, migDB, tenantT, sbomT, "libiso", "1.0", "pkg:generic/iso@1.0")
	linkCompVulnVS(t, migDB, compT, vX)

	// Foreign tenant statement for the SAME vX with the SAME purl — the
	// strongest possible leak candidate (would match on both purl and vuln
	// if the tenant boundary were absent).
	projF := uuid.New()
	seedProjectVS(t, migDB, tenantF, projF, "F source")
	sbomF := seedSbomVS(t, migDB, tenantF, projF)
	compF := seedComponentVS(t, migDB, tenantF, sbomF, "libiso", "1.0", "pkg:generic/iso@1.0")
	linkCompVulnVS(t, migDB, compF, vX)
	stmtF := seedVexStmtVS(t, migDB, tenantF, projF, vX, &compF, "not_affected")

	got := runSuggestions(t, appDB, tenantT, projT)
	if len(got) != 0 {
		t.Fatalf("tenant isolation violated: expected 0 suggestions for tenant T, got %d: %+v", len(got), got)
	}
	for _, s := range got {
		if s.Source.StatementID == stmtF {
			t.Fatalf("tenant isolation violated: foreign statement %s surfaced", stmtF)
		}
	}
}
