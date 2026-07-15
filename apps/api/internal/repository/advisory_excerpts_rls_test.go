//go:build integration

// Package repository - advisory_excerpts tenant-isolation integration
// test (M1 Wave M1-2 / issue #23, migration 033).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestAdvisoryExcerpts ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 033_advisory_excerpts.
//
// What this test pins down:
//
//  1. The advisory_excerpts INSERT goes through the FORCE RLS WITH
//     CHECK policy installed in migration 033. A session that has not
//     set app.current_tenant_id, or that has set it to a different
//     tenant, must NOT be able to insert a row with a third tenant's
//     id.
//
//  2. A read from tenant B's session must NOT surface rows that
//     tenant A inserted. Cross-tenant advisory-excerpt leakage would
//     defeat the per-tenant parser-tuning model the design doc
//     assumes.
//
//  3. The CHECK constraint on `source` still rejects unknown values
//     even from the privileged migrator role -- caught by attempting
//     an INSERT with source='redhat' (outside the 4-entry registry of
//     migration 056: nvd / ghsa / jvn / osv).
//
//  4. ListVulnFuncsByCVEs unions sources with 'osv' rows first (M43
//     Phase D: the serving edge caps at 200 selectors, so the
//     structured OSV symbols must never be pushed off by noisy
//     heuristic sources) -- executed against real PostgreSQL because
//     the ORDER BY semantics are otherwise only regex-pinned in
//     sqlmock.
package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
)

func advisoryExcerptsTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	return llmCallsTestEnv(t) // reuse env helper from llm_calls_rls_test.go
}

// schemaReadyAdvisoryExcerpts checks that advisory_excerpts exists AND
// that RLS is still ENABLE + FORCE on it (migration 033 state). If
// RLS has been removed by a future migration without updating this
// test, we skip loudly rather than silently mis-test the policy.
func schemaReadyAdvisoryExcerpts(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'advisory_excerpts'
		)
	`).Scan(&exists); err != nil {
		t.Skipf("advisory_excerpts existence check failed: %v -- skipping", err)
		return false
	}
	if !exists {
		t.Skip("advisory_excerpts table not present -- run migrations first")
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.advisory_excerpts'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("advisory_excerpts RLS state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Skipf("advisory_excerpts RLS not in expected state (enabled=%v, force=%v); "+
			"migration 033 may have been reverted -- skipping", rlsEnabled, rlsForce)
		return false
	}
	return true
}

func seedTenantForAdvisoryExcerpts(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "advex-test-"+label+"-"+id.String(),
		"AdvEx Test "+label,
		"advex-test-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

func openOrSkipAdvisoryExcerpts(t *testing.T, url string) *sql.DB {
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

// TestAdvisoryExcerpts_TenantIsolation_RLS verifies the load-bearing
// security property of migration 033: under the sbomhub_app
// (NOBYPASSRLS) role, a row written by tenant A is invisible to
// tenant B, and tenant B cannot forge a row claiming to belong to
// tenant A (the WITH CHECK clause rejects the INSERT).
func TestAdvisoryExcerpts_TenantIsolation_RLS(t *testing.T) {
	appURL, migURL := advisoryExcerptsTestEnv(t)

	migDB := openOrSkipAdvisoryExcerpts(t, migURL)
	defer migDB.Close()
	if !schemaReadyAdvisoryExcerpts(t, migDB) {
		return
	}
	appDB := openOrSkipAdvisoryExcerpts(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForAdvisoryExcerpts(t, migDB, "A")
	tenantB := seedTenantForAdvisoryExcerpts(t, migDB, "B")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	// --- Step 1: as app role under tenant A, insert one excerpt.
	rowA := uuid.New()
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	if _, err := txA.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		_ = txA.Rollback()
		t.Fatalf("SET LOCAL tenantA: %v", err)
	}
	if _, err := txA.Exec(`
		INSERT INTO advisory_excerpts (
			id, tenant_id, cve_id, source,
			vuln_funcs, affected_paths, required_config, required_env,
			raw_excerpt, fetched_at
		) VALUES ($1, $2, 'CVE-2025-A1', 'nvd',
			'[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
			'tenantA private excerpt', NOW())
	`, rowA, tenantA); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	// --- Step 2: as app role under tenant B, count tenant A's row. RLS
	// should make it invisible -> count must be 0.
	txB, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantB: %v", err)
	}
	defer txB.Rollback()
	if _, err := txB.Exec(`SET LOCAL app.current_tenant_id = '` + tenantB.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantB: %v", err)
	}
	var seen int
	if err := txB.QueryRow(`SELECT COUNT(*) FROM advisory_excerpts WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantB count: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak: tenantB saw %d row(s) for tenantA's advisory_excerpts.id=%s; expected 0", seen, rowA)
	}

	// --- Step 3: tenantB tries to INSERT a row claiming tenant_id =
	// tenantA. WITH CHECK should reject it.
	rowForged := uuid.New()
	_, forgeErr := txB.Exec(`
		INSERT INTO advisory_excerpts (
			id, tenant_id, cve_id, source,
			vuln_funcs, affected_paths, required_config, required_env
		) VALUES ($1, $2, 'CVE-2025-FORGE', 'ghsa',
			'[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb)
	`, rowForged, tenantA)
	if forgeErr == nil {
		t.Fatalf("RLS WITH CHECK broken: tenantB session was able to insert a row "+
			"with tenant_id=%s (tenantA). This is the cross-tenant write primitive "+
			"the policy is supposed to prevent.", tenantA)
	}

	// --- Step 4: as tenant A again, confirm the original row is still
	// visible to its owner (the policy must not over-reject).
	txA2, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA2: %v", err)
	}
	defer txA2.Rollback()
	if _, err := txA2.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantA2: %v", err)
	}
	if err := txA2.QueryRow(`SELECT COUNT(*) FROM advisory_excerpts WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantA2 count: %v", err)
	}
	if seen != 1 {
		t.Fatalf("tenantA session sees %d of its own advisory_excerpts rows for id=%s; expected 1 -- RLS policy may be over-restrictive", seen, rowA)
	}
}

// TestAdvisoryExcerpts_SourceCheckConstraint verifies the CHECK
// constraint on `source` rejects unknown values even from the
// privileged migrator role. Catches the regression class where a
// future migration replaces the constraint with a stricter / looser
// one that accidentally permits free-form strings.
func TestAdvisoryExcerpts_SourceCheckConstraint(t *testing.T) {
	_, migURL := advisoryExcerptsTestEnv(t)
	migDB := openOrSkipAdvisoryExcerpts(t, migURL)
	defer migDB.Close()
	if !schemaReadyAdvisoryExcerpts(t, migDB) {
		return
	}
	tenant := seedTenantForAdvisoryExcerpts(t, migDB, "CK")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	// M9 F158: migration 023+ puts advisory_excerpts under FORCE RLS, so
	// the negative-path INSERT must run inside a tx with the tenant GUC
	// set; otherwise the row is rejected by the RLS policy before the
	// CHECK constraint fires.
	// M43 F467: migration 056 extended the allow-list to include 'osv'
	// (Go vulndb structured symbols), so the rejection probe uses a value
	// outside the 4-entry registry and 'osv' is asserted as accepted.
	err := execAsTenant(t, migDB, tenant, `
		INSERT INTO advisory_excerpts (
			id, tenant_id, cve_id, source
		) VALUES ($1, $2, 'CVE-2025-CK', 'redhat')
	`, uuid.New(), tenant)
	if err == nil {
		t.Fatalf("CHECK constraint allowed source='redhat'; the allow-list is meant to be nvd|ghsa|jvn|osv only")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check") {
		t.Fatalf("expected a CHECK constraint violation, got: %v", err)
	}

	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO advisory_excerpts (
			id, tenant_id, cve_id, source
		) VALUES ($1, $2, 'CVE-2025-CK', 'osv')
	`, uuid.New(), tenant); err != nil {
		t.Fatalf("CHECK constraint rejected source='osv'; migration 056 is meant to allow it: %v", err)
	}
}

// TestAdvisoryExcerpts_ListVulnFuncsByCVEs_OSVFirstOrdering pins the
// M43 Phase D union order on real PostgreSQL: 'osv' rows come first,
// remaining sources follow in lexicographic order (ghsa < jvn < nvd).
// The serving edge (handler normalizeVulnFuncs) keeps only the first
// 200 selectors, so if a noisy heuristic source sorted ahead of the
// structured OSV row, the precise Go vulndb symbols could be pushed
// off the wire — the sqlmock unit test only regex-pins the ORDER BY
// text; this test executes it.
func TestAdvisoryExcerpts_ListVulnFuncsByCVEs_OSVFirstOrdering(t *testing.T) {
	_, migURL := advisoryExcerptsTestEnv(t)
	migDB := openOrSkipAdvisoryExcerpts(t, migURL)
	defer migDB.Close()
	if !schemaReadyAdvisoryExcerpts(t, migDB) {
		return
	}
	tenant := seedTenantForAdvisoryExcerpts(t, migDB, "ORD")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	const cve = "CVE-2025-1111"
	// Insert in an order unrelated to the expected output so the test
	// cannot pass by insertion-order accident: nvd, osv, ghsa.
	for _, row := range []struct {
		source string
		funcs  string
	}{
		{"nvd", `["noise.FromNVD"]`},
		{"osv", `["yaml.Unmarshal","yaml.Decoder.Decode"]`},
		{"ghsa", `["extra.FromGHSA"]`},
	} {
		if err := execAsTenant(t, migDB, tenant, `
			INSERT INTO advisory_excerpts (
				id, tenant_id, cve_id, source, vuln_funcs, raw_excerpt
			) VALUES ($1, $2, $3, $4, $5::jsonb, 'ordering probe')
		`, uuid.New(), tenant, cve, row.source, row.funcs); err != nil {
			t.Fatalf("seed %s row: %v", row.source, err)
		}
	}

	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin read tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenant.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenant GUC: %v", err)
	}
	ctx := database.WithTx(context.Background(), tx)

	repo := NewAdvisoryExcerptsRepository(migDB)
	got, err := repo.ListVulnFuncsByCVEs(ctx, tenant, []string{cve})
	if err != nil {
		t.Fatalf("ListVulnFuncsByCVEs: %v", err)
	}
	want := []string{
		"yaml.Unmarshal", "yaml.Decoder.Decode", // osv first (priority 0)
		"extra.FromGHSA", // then ghsa (lexicographic)
		"noise.FromNVD",  // then nvd
	}
	// R8f: all three seeded rows carry no vuln_funcs_scoped data, so their
	// flat unions land in Unscoped (the legacy / prose-source path).
	funcs := got[cve].Unscoped
	if len(funcs) != len(want) {
		t.Fatalf("union length = %d (%v), want %d (%v)", len(funcs), funcs, len(want), want)
	}
	for i := range want {
		if funcs[i] != want[i] {
			t.Fatalf("union[%d] = %q, want %q (full: %v)", i, funcs[i], want[i], funcs)
		}
	}
}

// sameStrSlice is a local []string equality helper (kept file-scoped so the
// C5 additions do not depend on reflect or on a shared test util that another
// _test.go might also declare).
func sameStrSlice(a, b []string) bool {
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

// TestAdvisoryExcerpts_ScopedVulnFuncsRoundtrip_RealPG pins the migration
// 057 vuln_funcs_scoped write→read roundtrip on real PostgreSQL: a scoped
// osv row written through AdvisoryExcerptsRepository.Upsert (the $6 =
// vuln_funcs_scoped bind) is decoded back by ListVulnFuncsByCVEs with its
// module attribution + on-disk order intact, and — crucially — the scoped
// row's flat vuln_funcs is NOT re-broadcast into Unscoped (the R8f
// double-add guard). The sqlmock unit tests only pin the Go-side decode /
// routing branches against fabricated bytes; this drives the real JSONB
// column: the NOT NULL DEFAULT '[]' normalisation, PG's JSONB canonicalising
// of the stored value, and the lenient scoped decode path across a genuine
// round-trip. Two CVEs:
//
//   - clean scoped row (2 modules) → Scoped=2, Unscoped empty.
//   - partially-malformed scoped row (one empty-module element that the
//     decoder must skip, one well-formed element, plus a flat union) → the
//     good element still routes the row scoped-only, so the malformed shape
//     never contaminates Unscoped.
func TestAdvisoryExcerpts_ScopedVulnFuncsRoundtrip_RealPG(t *testing.T) {
	_, migURL := advisoryExcerptsTestEnv(t)
	migDB := openOrSkipAdvisoryExcerpts(t, migURL)
	// C27 trap avoidance: register Close FIRST so it runs LAST (t.Cleanup is
	// LIFO); the row DELETE registered later runs while the handle is open.
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyAdvisoryExcerpts(t, migDB) {
		return
	}
	tenant := seedTenantForAdvisoryExcerpts(t, migDB, "SCRT")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	repo := NewAdvisoryExcerptsRepository(migDB)
	fetched := time.Now().UTC()

	const (
		cveClean  = "CVE-2025-SCOPED-CLEAN"
		cveLenien = "CVE-2025-SCOPED-LENIENT"
	)

	// upsertScoped writes one osv row through the repo inside a TenantTx —
	// advisory_excerpts is FORCE RLS so the WITH CHECK needs the tenant GUC.
	upsertScoped := func(cve string, flat, scoped json.RawMessage) {
		t.Helper()
		e := &AdvisoryExcerpt{
			TenantID:        tenant,
			CVEID:           cve,
			Source:          "osv",
			VulnFuncs:       flat,
			VulnFuncsScoped: scoped,
			RawExcerpt:      "scoped roundtrip probe",
			FetchedAt:       &fetched,
		}
		tx, err := migDB.Begin()
		if err != nil {
			t.Fatalf("begin write tx (%s): %v", cve, err)
		}
		committed := false
		defer func() {
			if !committed {
				_ = tx.Rollback()
			}
		}()
		if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenant.String() + `'`); err != nil {
			t.Fatalf("SET LOCAL write (%s): %v", cve, err)
		}
		if err := repo.Upsert(database.WithTx(context.Background(), tx), e); err != nil {
			t.Fatalf("Upsert scoped row (%s): %v", cve, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit write (%s): %v", cve, err)
		}
		committed = true
	}

	upsertScoped(cveClean,
		json.RawMessage(`["a.Foo","a.Bar","b.Baz"]`),
		json.RawMessage(`[{"module":"example.com/a","vuln_funcs":["a.Foo","a.Bar"]},{"module":"example.com/b","vuln_funcs":["b.Baz"]}]`),
	)
	// One malformed element (empty module -> skipped by decodeScopedVulnFuncs)
	// alongside one well-formed element; the flat union carries the ghost
	// symbol too. The surviving well-formed entry keeps the row on the
	// scoped-only routing arm, so the flat union (incl. the ghost) must NOT
	// leak into Unscoped.
	upsertScoped(cveLenien,
		json.RawMessage(`["ghost.Fn","ok.Real"]`),
		json.RawMessage(`[{"module":"","vuln_funcs":["ghost.Fn"]},{"module":"example.com/ok","vuln_funcs":["ok.Real"]}]`),
	)

	// Read both back in a fresh TenantTx.
	readTx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin read tx: %v", err)
	}
	defer func() { _ = readTx.Rollback() }()
	if _, err := readTx.Exec(`SET LOCAL app.current_tenant_id = '` + tenant.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL read: %v", err)
	}
	got, err := repo.ListVulnFuncsByCVEs(
		database.WithTx(context.Background(), readTx), tenant, []string{cveClean, cveLenien},
	)
	if err != nil {
		t.Fatalf("ListVulnFuncsByCVEs: %v", err)
	}

	// --- clean scoped row.
	clean, ok := got[cveClean]
	if !ok {
		t.Fatalf("%s absent from result; a scoped row must materialise the key", cveClean)
	}
	if len(clean.Unscoped) != 0 {
		t.Fatalf("%s Unscoped = %v, want empty (scoped osv row must not double-add its flat union to Unscoped)",
			cveClean, clean.Unscoped)
	}
	if len(clean.Scoped) != 2 {
		t.Fatalf("%s Scoped entries = %d (%+v), want 2 through the JSONB roundtrip", cveClean, len(clean.Scoped), clean.Scoped)
	}
	if clean.Scoped[0].Module != "example.com/a" || !sameStrSlice(clean.Scoped[0].Funcs, []string{"a.Foo", "a.Bar"}) {
		t.Fatalf("%s Scoped[0] = %+v, want {example.com/a [a.Foo a.Bar]} (module attribution + on-disk order)", cveClean, clean.Scoped[0])
	}
	if clean.Scoped[1].Module != "example.com/b" || !sameStrSlice(clean.Scoped[1].Funcs, []string{"b.Baz"}) {
		t.Fatalf("%s Scoped[1] = %+v, want {example.com/b [b.Baz]}", cveClean, clean.Scoped[1])
	}

	// --- lenient scoped row: malformed element skipped, no Unscoped leak.
	lenient, ok := got[cveLenien]
	if !ok {
		t.Fatalf("%s absent from result; the one well-formed scoped element must materialise the key", cveLenien)
	}
	if len(lenient.Unscoped) != 0 {
		t.Fatalf("%s Unscoped = %v, want empty: a malformed scoped element must be skipped WITHOUT falling the row back to the flat-union (Unscoped) arm while a well-formed sibling survives",
			cveLenien, lenient.Unscoped)
	}
	if len(lenient.Scoped) != 1 {
		t.Fatalf("%s Scoped entries = %d (%+v), want 1 (empty-module element dropped)", cveLenien, len(lenient.Scoped), lenient.Scoped)
	}
	if lenient.Scoped[0].Module != "example.com/ok" || !sameStrSlice(lenient.Scoped[0].Funcs, []string{"ok.Real"}) {
		t.Fatalf("%s Scoped[0] = %+v, want {example.com/ok [ok.Real]}", cveLenien, lenient.Scoped[0])
	}
}

// TestAdvisoryExcerpts_ScopedUnionRouting_RealPG is the R8f sibling of the
// OSVFirstOrdering test: it seeds a SCOPED osv row (non-empty
// vuln_funcs_scoped) alongside two prose rows (nvd / ghsa, unscoped) for one
// CVE and pins, on real PostgreSQL, that the per-row routing + osv-first
// union interact correctly:
//
//   - the scoped osv row contributes ONLY to Scoped (its flat vuln_funcs is
//     deliberately absent from Unscoped);
//   - the prose rows contribute their flat vuln_funcs to Unscoped;
//   - within Unscoped the surviving prose rows keep lexicographic order
//     (ghsa < nvd) — the osv row leading the CASE ordering does not perturb
//     the unscoped tail because it never lands there.
//
// The existing OSVFirstOrdering test seeded three all-unscoped rows, so it
// could not observe the scoped-vs-prose split against a real JSONB column;
// this one does.
func TestAdvisoryExcerpts_ScopedUnionRouting_RealPG(t *testing.T) {
	_, migURL := advisoryExcerptsTestEnv(t)
	migDB := openOrSkipAdvisoryExcerpts(t, migURL)
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyAdvisoryExcerpts(t, migDB) {
		return
	}
	tenant := seedTenantForAdvisoryExcerpts(t, migDB, "SCUR")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	const cve = "CVE-2025-2222"

	// Scoped osv row (module-attributed) + two prose rows. Inserted nvd
	// before ghsa so the expected Unscoped order (ghsa < nvd) cannot pass by
	// insertion accident.
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO advisory_excerpts (id, tenant_id, cve_id, source, vuln_funcs, vuln_funcs_scoped, raw_excerpt)
		VALUES ($1, $2, $3, 'osv',
			'["osv.A","osv.B"]'::jsonb,
			'[{"module":"example.com/mod","vuln_funcs":["osv.A","osv.B"]}]'::jsonb,
			'scoped union probe')
	`, uuid.New(), tenant, cve); err != nil {
		t.Fatalf("seed scoped osv row: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO advisory_excerpts (id, tenant_id, cve_id, source, vuln_funcs, raw_excerpt)
		VALUES ($1, $2, $3, 'nvd', '["nvd.N"]'::jsonb, 'prose probe nvd')
	`, uuid.New(), tenant, cve); err != nil {
		t.Fatalf("seed nvd row: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO advisory_excerpts (id, tenant_id, cve_id, source, vuln_funcs, raw_excerpt)
		VALUES ($1, $2, $3, 'ghsa', '["ghsa.G"]'::jsonb, 'prose probe ghsa')
	`, uuid.New(), tenant, cve); err != nil {
		t.Fatalf("seed ghsa row: %v", err)
	}

	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin read tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenant.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenant GUC: %v", err)
	}

	repo := NewAdvisoryExcerptsRepository(migDB)
	got, err := repo.ListVulnFuncsByCVEs(database.WithTx(context.Background(), tx), tenant, []string{cve})
	if err != nil {
		t.Fatalf("ListVulnFuncsByCVEs: %v", err)
	}
	cv, ok := got[cve]
	if !ok {
		t.Fatalf("%s absent from result", cve)
	}

	// Scoped: only the osv row.
	if len(cv.Scoped) != 1 {
		t.Fatalf("Scoped entries = %d (%+v), want 1 (only the osv scoped row)", len(cv.Scoped), cv.Scoped)
	}
	if cv.Scoped[0].Module != "example.com/mod" || !sameStrSlice(cv.Scoped[0].Funcs, []string{"osv.A", "osv.B"}) {
		t.Fatalf("Scoped[0] = %+v, want {example.com/mod [osv.A osv.B]}", cv.Scoped[0])
	}

	// Unscoped: prose rows only, ghsa before nvd; osv symbols must NOT appear.
	wantUnscoped := []string{"ghsa.G", "nvd.N"}
	if !sameStrSlice(cv.Unscoped, wantUnscoped) {
		t.Fatalf("Unscoped = %v, want %v (prose rows lexicographic, scoped osv row must not leak into Unscoped)",
			cv.Unscoped, wantUnscoped)
	}
}
