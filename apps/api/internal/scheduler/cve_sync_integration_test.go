//go:build integration

// Package scheduler - real-PG integration test for the F258 chunk-based
// tx split in matchTenantsChunked (M17-3 #109).
//
// Why this file exists (anti-pattern 21 sqlmock limitation evolution,
// horizontal replication of F234 / F244 rationale):
//
//	sqlmock does NOT model PostgreSQL's "current transaction is
//	aborted, commands ignored until end of transaction block" semantics.
//	The unit tests in cve_sync_perf_test.go therefore drive the happy
//	path plus the code's error-return branches against the CODE's error
//	handling — they do NOT prove the ACID contract holds server-side.
//
//	F258 (M17-3) makes the "chunk-level tx-abort blast radius" contract
//	load-bearing for production: a PG-side error inside chunk C aborts
//	C's tx and skips only C's remaining tenants (and rolls back C's
//	component_vulnerabilities INSERTs), then chunk C+1 continues on the
//	same pooled connection with a fresh BEGIN. The only way to catch a
//	regression that breaks this against real PG is to actually run
//	against real PG.
//
//	F258 is the FIRST write-heavy application of the pattern in this
//	package — F234 / F244 were both read-only per-tenant eligibility
//	enumerations. The write-heavy blast-radius trade-off (chunk rollback
//	discards up to K tenants' worth of INSERTs) is discussed at length
//	in cve_sync.go's matchTenantsChunked docstring; this integration
//	test pins the server-side semantics that back that trade-off.
//
// Run with:
//
//	cd apps/api && go test -tags=integration ./internal/scheduler -run TestF258
//
// Prerequisites (skipped otherwise — CI mirrors these in
// .github/workflows/scheduler-integration.yml, which auto-picks up
// -tags=integration since M16 F248 dropped the -run filter):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 027_sbom_tenant_id_not_null (components
//     FORCE RLS is required for the poison policy to fire; the api
//     server's auto-migrate covers this; or run `go run ./cmd/migrate up`).
//
// What this test file pins down:
//
//  1. F258 happy-path across chunk boundaries: at N=500 with
//     chunk_size=200 the batch splits into 3 chunks (200 + 200 + 100)
//     and every seeded tenant's expected component_vulnerabilities
//     rows are durable after the call returns.
//
//  2. F258 chunk-abort blast radius (write-heavy specific): a genuine
//     PG-side error mid-chunk (a temporary RLS policy on components
//     that raises division_by_zero on a designated poison tenant)
//     aborts that chunk's tx server-side, rolls back EVERY
//     component_vulnerabilities INSERT for the poison chunk's tenants,
//     and the next chunk continues normally with a fresh BEGIN. The
//     durable INSERT count from chunks BEFORE poison survives; chunks
//     AFTER poison contribute normally. This is the exact contract
//     sqlmock cannot verify.
//
//  3. Connection cleanup: after matchTenantsChunked returns, the
//     underlying pooled connection is released (defer conn.Close()) —
//     no connection leak that would eventually deadlock the pool.
package scheduler

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/repository"
)

// schedIntEnvCVE wraps the shared schedIntEnv helper so the naming is
// obvious in this file's failure messages. The env variable contract is
// identical to the F234 / F244 files (they run in the same workflow /
// same docker compose stack).
func schedIntEnvCVE(t *testing.T) (appURL, migURL string) {
	t.Helper()
	return schedIntEnv(t)
}

// schedSchemaReadyCVE checks that components + tenants + vulnerabilities
// + component_vulnerabilities exist and that components has FORCE RLS +
// tenant_isolation_components policy in place (migration 007 + 023 + 027).
// If not, skip loudly.
func schedSchemaReadyCVE(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var tablesOK bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'tenants'
		) AND EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'components'
		) AND EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'vulnerabilities'
		) AND EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'component_vulnerabilities'
		)
	`).Scan(&tablesOK); err != nil {
		t.Skipf("schema-existence check failed: %v - skipping", err)
		return false
	}
	if !tablesOK {
		t.Skip("components / tenants / vulnerabilities / component_vulnerabilities not present - run migrations first (through 027)")
		return false
	}

	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class
		WHERE oid = 'public.components'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("components RLS-state check failed: %v - skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Skipf("components RLS state: enable=%v force=%v - migration 027 not applied, skipping",
			rlsEnabled, rlsForce)
		return false
	}
	return true
}

// f258Fixture captures one seeded tenant's fixture state so tests can
// assert on component_vulnerabilities INSERT durability.
type f258Fixture struct {
	tenantID    uuid.UUID
	sbomID      uuid.UUID
	componentID uuid.UUID
	// The keyword-matching component name (a specific string the CVE
	// keyword will find). For F258 the SELECT uses LOWER(c.name) = ANY,
	// so this must be lowercase and identical to the CVE keyword.
	componentName string
}

// seedSchedIntCVETenants provisions n tenants (as migrator) + one SBOM
// + one component per tenant. The component name is deterministic so
// the CVE keyword matches every tenant's component. Returns the
// fixtures and a cleanup closure.
//
// Uses sequential INSERTs for tenants so created_at is monotonic and
// the chunk-abort test can reason deterministically about chunk
// positions.
func seedSchedIntCVETenants(t *testing.T, migDB *sql.DB, n int, tag string) ([]f258Fixture, func()) {
	t.Helper()
	fixtures := make([]f258Fixture, n)
	for i := range fixtures {
		fixtures[i] = f258Fixture{
			tenantID:      uuid.New(),
			sbomID:        uuid.New(),
			componentID:   uuid.New(),
			componentName: "f258-comp",
		}
	}

	cleanup := func() {
		// Delete tenants; ON DELETE CASCADE cleans sboms + components +
		// component_vulnerabilities.
		for _, f := range fixtures {
			_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, f.tenantID)
		}
	}
	cleanup()

	for i, f := range fixtures {
		slug := fmt.Sprintf("f258-%s-%s", tag, f.tenantID.String()[:8])
		if _, err := migDB.Exec(
			`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
			f.tenantID,
			"f258-"+tag+"-"+f.tenantID.String(),
			fmt.Sprintf("F258 %s %d", tag, i),
			slug,
		); err != nil {
			cleanup()
			t.Fatalf("seed tenant %d: %v", i, err)
		}

		// projects table row (parent of sboms) — some deployments have
		// FK constraints from sboms.project_id -> projects.id. Insert one
		// so the sboms row is FK-valid.
		projectID := uuid.New()
		if err := insertRowWithTenantGUC(migDB, f.tenantID,
			`INSERT INTO projects (id, tenant_id, name, created_at, updated_at)
			 VALUES ($1, $2, $3, NOW(), NOW())`,
			projectID, f.tenantID, fmt.Sprintf("F258 project %d", i),
		); err != nil {
			cleanup()
			t.Fatalf("seed project for tenant %d: %v", i, err)
		}

		// sboms row (FORCE RLS, needs SET LOCAL). sboms.tenant_id must
		// match the current GUC (WITH CHECK).
		if err := insertRowWithTenantGUC(migDB, f.tenantID,
			`INSERT INTO sboms (id, project_id, tenant_id, format, spec_version, created_at)
			 VALUES ($1, $2, $3, 'cyclonedx', '1.5', NOW())`,
			f.sbomID, projectID, f.tenantID,
		); err != nil {
			cleanup()
			t.Fatalf("seed sbom for tenant %d: %v", i, err)
		}

		// components row (FORCE RLS, needs SET LOCAL). componentName
		// is lowercase so LOWER(c.name) = ANY($1) matches the CVE keyword.
		if err := insertRowWithTenantGUC(migDB, f.tenantID,
			`INSERT INTO components (id, sbom_id, tenant_id, name, version, type, created_at)
			 VALUES ($1, $2, $3, $4, '1.0.0', 'library', NOW())`,
			f.componentID, f.sbomID, f.tenantID, f.componentName,
		); err != nil {
			cleanup()
			t.Fatalf("seed component for tenant %d: %v", i, err)
		}
	}
	return fixtures, cleanup
}

// insertRowWithTenantGUC opens a migrator-role tx, binds the tenant GUC,
// runs the INSERT, and commits. Used by the fixture seeder because
// projects / sboms / components are all FORCE RLS post-027.
func insertRowWithTenantGUC(migDB *sql.DB, tenantID uuid.UUID, query string, args ...any) error {
	tx, err := migDB.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	if _, err := tx.Exec(
		`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String(),
	); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("SET LOCAL: %w", err)
	}
	if _, err := tx.Exec(query, args...); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// buildCVEIntegrationFixture returns 10 mock CVEs (M=10 per requirements)
// where each CVE's keyword is "f258-comp" so LOWER(c.name) = ANY matches
// every seeded tenant's component. Also upserts one vulnerabilities row
// per CVE (non-RLS, safe on migrator role) and returns the vulnIndex the
// matcher will consume.
func buildCVEIntegrationFixture(t *testing.T, migDB *sql.DB, m int, tag string) ([]CVEInfo, map[string]cveVulnEntry, func()) {
	t.Helper()
	cves := make([]CVEInfo, m)
	vulnIndex := make(map[string]cveVulnEntry, m)
	vulnIDs := make([]uuid.UUID, m)

	for i := 0; i < m; i++ {
		cveID := fmt.Sprintf("CVE-F258-%s-%04d", tag, i)
		vulnID := uuid.New()
		vulnIDs[i] = vulnID
		cves[i] = CVEInfo{
			ID:          cveID,
			Description: fmt.Sprintf("F258 integration test CVE %d", i),
			Severity:    "HIGH",
			CVSSScore:   7.5,
			PublishedAt: time.Now(),
			Keywords:    []string{"f258-comp"},
		}
		vulnIndex[cveID] = cveVulnEntry{
			id:    vulnID,
			isNew: true,
		}

		// vulnerabilities is non-RLS (migration 001), no GUC needed.
		if _, err := migDB.Exec(`
			INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source, published_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, 'NVD', NOW(), NOW())
			ON CONFLICT (cve_id) DO UPDATE SET updated_at = NOW()
			RETURNING id
		`, vulnID, cveID, cves[i].Description, cves[i].Severity, cves[i].CVSSScore); err != nil {
			t.Fatalf("upsert vulnerability %s: %v", cveID, err)
		}
	}

	cleanup := func() {
		for _, cveID := range func() []string {
			ids := make([]string, len(cves))
			for i, c := range cves {
				ids[i] = c.ID
			}
			return ids
		}() {
			_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID)
		}
	}
	return cves, vulnIndex, cleanup
}

// countCompVulnsForTenants returns the number of component_vulnerabilities
// rows for a given tenant set. component_vulnerabilities is NOT RLS-bound
// (migration 001), so this counts everything under the migrator role
// without needing a GUC. Used for the durability assertions.
func countCompVulnsForTenants(t *testing.T, migDB *sql.DB, componentIDs []uuid.UUID) int {
	t.Helper()
	if len(componentIDs) == 0 {
		return 0
	}
	ids := make([]string, len(componentIDs))
	for i, c := range componentIDs {
		ids[i] = c.String()
	}
	var count int
	if err := migDB.QueryRow(
		`SELECT COUNT(*) FROM component_vulnerabilities WHERE component_id = ANY($1)`,
		pq.Array(ids),
	).Scan(&count); err != nil {
		t.Fatalf("count component_vulnerabilities: %v", err)
	}
	return count
}

// TestF258_CVESyncChunkedBatch_HappyPath_RealPG_F258 runs
// matchTenantsChunked end-to-end against a real PG with N=500 tenants
// (chunk_size=200 -> 3 chunks) and M=10 CVEs, and asserts:
//
//   - Every seeded tenant's component_vulnerabilities row for every CVE
//     is durable after the call returns (N*M = 5000 INSERTs).
//   - matched / newVulns totals match N*M.
//   - The chunk boundaries are transparent to the caller.
//   - No connection leak: DB.Stats().InUse == 0 immediately after the
//     call returns (the deferred conn.Close() ran).
func TestF258_CVESyncChunkedBatch_HappyPath_RealPG_F258(t *testing.T) {
	appURL, migURL := schedIntEnvCVE(t)

	migDB := schedOpenOrSkip(t, migURL)
	defer migDB.Close()
	if !schedSchemaReadyCVE(t, migDB) {
		return
	}

	appDB := schedOpenOrSkip(t, appURL)
	defer appDB.Close()
	// Small pool so a leak surfaces as a hang / next-test-flake fast.
	appDB.SetMaxOpenConns(3)

	const (
		N = 500
		M = 10
	)

	fixtures, cleanupTenants := seedSchedIntCVETenants(t, migDB, N, "happy")
	defer cleanupTenants()

	cves, vulnIndex, cleanupCVEs := buildCVEIntegrationFixture(t, migDB, M, "happy")
	defer cleanupCVEs()

	// Confirm production chunk_size is 200 for this test.
	prev := cveMatchBatchChunkSize
	cveMatchBatchChunkSize = cveMatchBatchChunkSizeDefault
	defer func() { cveMatchBatchChunkSize = prev }()
	if cveMatchBatchChunkSize != 200 {
		t.Fatalf("chunk_size default drift: got %d, want 200", cveMatchBatchChunkSize)
	}
	wantChunks := (N + cveMatchBatchChunkSize - 1) / cveMatchBatchChunkSize
	if wantChunks != 3 {
		t.Fatalf("chunk arithmetic drift: N=%d K=%d -> %d chunks, want 3",
			N, cveMatchBatchChunkSize, wantChunks)
	}

	// Extract tenant IDs + component IDs for the F258 call + assertions.
	tenantIDs := make([]uuid.UUID, N)
	componentIDs := make([]uuid.UUID, N)
	for i, f := range fixtures {
		tenantIDs[i] = f.tenantID
		componentIDs[i] = f.componentID
	}

	j := NewCVESyncJob(appDB, repository.NewTenantRepository(appDB), "", 24*time.Hour)

	start := time.Now()
	matched, newVulns, err := j.matchTenantsChunked(
		context.Background(), tenantIDs, cves, vulnIndex,
	)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("matchTenantsChunked: %v", err)
	}
	t.Logf("F258 real-PG happy N=%d M=%d chunks=%d elapsed=%v matched=%d newVulns=%d",
		N, M, wantChunks, elapsed, matched, newVulns)

	// Every seeded tenant + every CVE should have contributed to matched.
	wantMatched := N * M
	if matched != wantMatched {
		t.Errorf("F258 happy matched: got %d, want %d (N*M)", matched, wantMatched)
	}
	// All vulnIndex entries have isNew=true, so newVulns should equal matched.
	if newVulns != wantMatched {
		t.Errorf("F258 happy newVulns: got %d, want %d (N*M, all vulnIndex isNew=true)",
			newVulns, wantMatched)
	}

	// Durable INSERT count: every (tenant, CVE) pair should have inserted
	// one component_vulnerabilities row (component_id, vulnerability_id).
	// component_vulnerabilities is not RLS-bound so we count directly.
	gotRows := countCompVulnsForTenants(t, migDB, componentIDs)
	if gotRows != wantMatched {
		t.Errorf("F258 happy component_vulnerabilities durability: got %d rows, want %d (N*M)",
			gotRows, wantMatched)
	}

	// Connection-leak check.
	stats := appDB.Stats()
	if stats.InUse != 0 {
		t.Errorf("F258 connection leak: appDB.Stats().InUse=%d after matchTenantsChunked (want 0). Full stats: %+v",
			stats.InUse, stats)
	}
}

// TestF258_CVESyncChunkAbort_RealPG_F258 pins the write-heavy chunk-local
// blast radius against real PG's ACID semantics — this is the assertion
// sqlmock literally cannot make.
//
// Fixture design (mirrors TestF234_ChunkAbort_RealPG_F234 and
// TestF244_ReportGenerationChunkAbort_RealPG_F244, adapted for the
// write-heavy write-path — key differences noted below):
//
//   - N=12 seeded tenants (F258 abort test), each with one SBOM + one
//     component whose lowercase name matches every CVE keyword.
//     cveMatchBatchChunkSize forced to 2 so 6 chunks span our seeded
//     set. That guarantees at least one CROSS-CHUNK boundary between
//     poison and other seeded tenants no matter what interleaving
//     pre-existing tenants introduce.
//   - M=3 CVEs (fewer than the happy-path test to keep the poison
//     chunk's rollback logging manageable). Every CVE keyword matches
//     every seeded component.
//   - Poison tenant is chosen AFTER seeding by querying its absolute
//     position (rank ORDER BY created_at) and picking the seeded ID
//     that lands in the MIDDLE of our seeded range — so at least one
//     seeded tenant is BEFORE poison's chunk (proves durable INSERTs
//     from earlier chunks survive) and at least one is AFTER poison's
//     chunk (proves the fresh BEGIN in the NEXT chunk continues on
//     the same pooled connection).
//
// Write-heavy contract (F258 specific — differs from F234 / F244):
//
//   - Chunks BEFORE poison: their INSERTs are durable (they COMMITted).
//   - Poison's chunk: ALL INSERTs are rolled back (chunk tx aborted
//     server-side). Not just poison's INSERTs — every tenant that
//     happened to share the chunk with poison also loses its
//     contribution. This is the intentional write-heavy blast-radius
//     trade-off documented in matchTenantsChunked's docstring.
//   - Chunks AFTER poison: fresh BEGIN, their INSERTs are durable.
//
// Assertions:
//
//	(a) The call does NOT return an error (F258 turns per-chunk error
//	    into log + continue).
//	(b) Poison tenant has ZERO component_vulnerabilities rows (its
//	    chunk was rolled back).
//	(c) Seeded tenants in chunks BEFORE poison's chunk have their
//	    N*M INSERTs durable — proves earlier COMMITs survived.
//	(d) Seeded tenants in chunks AFTER poison's chunk have their
//	    N*M INSERTs durable — proves the fresh BEGIN happened.
//	(e) Poison-chunk siblings (non-poison tenants in the SAME chunk)
//	    have ZERO durable INSERTs — proves the write-heavy blast
//	    radius is chunk-wide (not just poison-row).
//	(f) matched / newVulns totals equal the sum of (before + after
//	    chunks) * M (poison chunk's contribution is discarded, matching
//	    matchTenantsChunk's return-(0,0)-on-error contract).
//	(g) No connection leak after return.
func TestF258_CVESyncChunkAbort_RealPG_F258(t *testing.T) {
	appURL, migURL := schedIntEnvCVE(t)

	migDB := schedOpenOrSkip(t, migURL)
	defer migDB.Close()
	if !schedSchemaReadyCVE(t, migDB) {
		return
	}

	appDB := schedOpenOrSkip(t, appURL)
	defer appDB.Close()
	appDB.SetMaxOpenConns(3)

	const (
		N = 12
		M = 3
	)

	fixtures, cleanupTenants := seedSchedIntCVETenants(t, migDB, N, "abort")
	defer cleanupTenants()

	cves, vulnIndex, cleanupCVEs := buildCVEIntegrationFixture(t, migDB, M, "abort")
	defer cleanupCVEs()

	// Extract tenant IDs preserving fixture order (which == INSERT order
	// == ORDER BY created_at for the sequential seeder).
	seededIDs := make([]uuid.UUID, N)
	tenantToFixture := make(map[uuid.UUID]f258Fixture, N)
	for i, f := range fixtures {
		seededIDs[i] = f.tenantID
		tenantToFixture[f.tenantID] = f
	}

	positions := querySeededTenantPositions(t, migDB, seededIDs)

	// Pick the middle seeded tenant as poison.
	poisonID := seededIDs[N/2]

	prevChunk := cveMatchBatchChunkSize
	cveMatchBatchChunkSize = 2
	defer func() { cveMatchBatchChunkSize = prevChunk }()
	const chunkSize = 2
	poisonChunkIdx := positions[poisonID] / chunkSize

	// Classify each non-poison seeded tenant by chunk relative to poison.
	beforeChunkIDs := make([]uuid.UUID, 0)
	sameChunkIDs := make([]uuid.UUID, 0)
	afterChunkIDs := make([]uuid.UUID, 0)
	for _, id := range seededIDs {
		if id == poisonID {
			continue
		}
		cIdx := positions[id] / chunkSize
		switch {
		case cIdx < poisonChunkIdx:
			beforeChunkIDs = append(beforeChunkIDs, id)
		case cIdx == poisonChunkIdx:
			sameChunkIDs = append(sameChunkIDs, id)
		default:
			afterChunkIDs = append(afterChunkIDs, id)
		}
	}
	if len(beforeChunkIDs) == 0 {
		t.Fatalf("F258 fixture setup: no seeded tenant in a chunk BEFORE poison — "+
			"cannot pin (c). positions=%v poisonPos=%d poisonChunkIdx=%d",
			positions, positions[poisonID], poisonChunkIdx)
	}
	if len(afterChunkIDs) == 0 {
		t.Fatalf("F258 fixture setup: no seeded tenant in a chunk AFTER poison — "+
			"cannot pin (d). positions=%v poisonPos=%d poisonChunkIdx=%d",
			positions, positions[poisonID], poisonChunkIdx)
	}
	t.Logf("F258 fixture: poison=%s poisonPos=%d poisonChunkIdx=%d before=%d sameChunk=%d after=%d",
		poisonID, positions[poisonID], poisonChunkIdx, len(beforeChunkIDs), len(sameChunkIDs), len(afterChunkIDs))

	// Install the temporary poison policy AFTER the fixture is fully
	// seeded, so seeding is unaffected by the RLS trap. Use defer
	// (NOT t.Cleanup) so the restore runs BEFORE the deferred migDB.Close()
	// above.
	restorePolicy := installPoisonPolicyCVE(t, migDB, poisonID)
	defer restorePolicy()

	j := NewCVESyncJob(appDB, repository.NewTenantRepository(appDB), "", 24*time.Hour)

	// Build the tenant slice matchTenantsChunked will iterate.
	tenantIDs := seededIDs

	start := time.Now()
	matched, newVulns, err := j.matchTenantsChunked(
		context.Background(), tenantIDs, cves, vulnIndex,
	)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("matchTenantsChunked should NOT return error under F258 chunk-local abort semantics, got: %v", err)
	}
	t.Logf("F258 real-PG chunk-abort N=%d M=%d K=%d elapsed=%v matched=%d newVulns=%d (poison=%s)",
		N, M, cveMatchBatchChunkSize, elapsed, matched, newVulns, poisonID)

	// (b) Poison tenant has ZERO component_vulnerabilities rows.
	poisonRows := countCompVulnsForTenants(t, migDB, []uuid.UUID{
		tenantToFixture[poisonID].componentID,
	})
	if poisonRows != 0 {
		t.Errorf("F258 (b) chunk-abort: poison tenant %s must have 0 component_vulnerabilities rows, got %d",
			poisonID, poisonRows)
	}

	// (c) Seeded tenants BEFORE poison's chunk have their N*M INSERTs durable.
	beforeComponentIDs := make([]uuid.UUID, 0, len(beforeChunkIDs))
	for _, id := range beforeChunkIDs {
		beforeComponentIDs = append(beforeComponentIDs, tenantToFixture[id].componentID)
	}
	beforeRows := countCompVulnsForTenants(t, migDB, beforeComponentIDs)
	wantBeforeRows := len(beforeChunkIDs) * M
	if beforeRows != wantBeforeRows {
		t.Errorf("F258 (c) blast-radius: BEFORE-poison chunks lost durable INSERTs — "+
			"got %d rows, want %d (len(before)=%d M=%d). Go-side commit did not persist.",
			beforeRows, wantBeforeRows, len(beforeChunkIDs), M)
	}

	// (d) Seeded tenants AFTER poison's chunk have their N*M INSERTs durable.
	afterComponentIDs := make([]uuid.UUID, 0, len(afterChunkIDs))
	for _, id := range afterChunkIDs {
		afterComponentIDs = append(afterComponentIDs, tenantToFixture[id].componentID)
	}
	afterRows := countCompVulnsForTenants(t, migDB, afterComponentIDs)
	wantAfterRows := len(afterChunkIDs) * M
	if afterRows != wantAfterRows {
		t.Errorf("F258 (d) blast-radius: AFTER-poison chunks lost durable INSERTs — "+
			"got %d rows, want %d (len(after)=%d M=%d). The loop did not continue with a fresh BEGIN.",
			afterRows, wantAfterRows, len(afterChunkIDs), M)
	}

	// (e) Poison-chunk siblings have ZERO durable INSERTs (write-heavy
	// blast radius is chunk-wide, not just poison-row).
	if len(sameChunkIDs) > 0 {
		sameComponentIDs := make([]uuid.UUID, 0, len(sameChunkIDs))
		for _, id := range sameChunkIDs {
			sameComponentIDs = append(sameComponentIDs, tenantToFixture[id].componentID)
		}
		sameRows := countCompVulnsForTenants(t, migDB, sameComponentIDs)
		if sameRows != 0 {
			t.Errorf("F258 (e) write-heavy blast radius broken: poison-chunk siblings should have 0 durable INSERTs "+
				"(they share the aborted tx), got %d rows for %d siblings", sameRows, len(sameChunkIDs))
		}
	}

	// (f) matched / newVulns totals equal (before + after) * M
	// (poison chunk's contribution is discarded per matchTenantsChunk's
	// return-(0,0)-on-error contract).
	wantMatched := (len(beforeChunkIDs) + len(afterChunkIDs)) * M
	if matched != wantMatched {
		t.Errorf("F258 (f) matched: got %d, want %d ((before+after)*M) — poison chunk's counters must not leak",
			matched, wantMatched)
	}
	// vulnIndex isNew=true for every CVE, so newVulns equals matched.
	if newVulns != wantMatched {
		t.Errorf("F258 (f) newVulns: got %d, want %d ((before+after)*M, all vulnIndex isNew=true)",
			newVulns, wantMatched)
	}

	// (g) Connection-leak check.
	stats := appDB.Stats()
	if stats.InUse != 0 {
		t.Errorf("F258 (g) connection leak: appDB.Stats().InUse=%d after matchTenantsChunked (want 0). Full stats: %+v",
			stats.InUse, stats)
	}
}

// installPoisonPolicyCVE replaces the standard tenant_isolation_components
// RLS policy with a variant that raises division_by_zero when the current
// tenant GUC matches poisonID. Returns a restore closure that puts the
// original policy back.
//
// Technique details (same as F234's installPoisonPolicy / F244's
// installPoisonPolicyReport):
//
//	PostgreSQL evaluates the USING expression per-row during a SELECT.
//	A CASE branch that returns a division-by-zero expression forces the
//	error at policy evaluation time, which is server-side and aborts
//	the enclosing tx — exactly the failure mode F258 must contain to a
//	single chunk.
//
// Constant-folding gotcha: the naive `THEN (1/0)::text::boolean` is
// folded at plan time, firing on every SELECT — not just the poison
// tenant. Reference tenant_id inside the divisor
// (`length(tenant_id::text) - 36`, always 0 for a valid UUID) so the
// expression cannot be constant-folded but still divides by zero when
// the CASE branch is taken.
//
// Original policy (from migrations 023 / 027):
//
//	CREATE POLICY tenant_isolation_components ON components
//	    FOR ALL
//	    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
//	    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
func installPoisonPolicyCVE(t *testing.T, migDB *sql.DB, poisonID uuid.UUID) func() {
	t.Helper()

	dropOriginal := `DROP POLICY IF EXISTS tenant_isolation_components ON components`
	createOriginal := `
		CREATE POLICY tenant_isolation_components ON components
		    FOR ALL
		    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
		    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
	`

	if _, err := migDB.Exec(dropOriginal); err != nil {
		t.Fatalf("drop original policy for poison-install: %v", err)
	}

	poisonPolicy := fmt.Sprintf(`
		CREATE POLICY tenant_isolation_components ON components
		    FOR ALL
		    USING (
		        CASE
		            WHEN current_setting('app.current_tenant_id', true) = '%s'
		                THEN (1 / (length(tenant_id::text) - 36))::text::boolean
		            ELSE tenant_id = current_setting('app.current_tenant_id', true)::UUID
		        END
		    )
		    WITH CHECK (
		        tenant_id = current_setting('app.current_tenant_id', true)::UUID
		    )
	`, poisonID.String())

	if _, err := migDB.Exec(poisonPolicy); err != nil {
		// Attempt to put the standard policy back so we don't leave
		// the DB in a bad state.
		_, _ = migDB.Exec(createOriginal)
		t.Fatalf("install poison policy: %v", err)
	}

	return func() {
		if _, err := migDB.Exec(dropOriginal); err != nil {
			t.Logf("WARN: drop poison policy in cleanup: %v", err)
		}
		if _, err := migDB.Exec(createOriginal); err != nil {
			t.Logf("WARN: restore original policy in cleanup: %v (test DB may need manual repair)", err)
		}
	}
}

