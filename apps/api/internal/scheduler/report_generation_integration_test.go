//go:build integration

// Package scheduler - real-PG integration test for the F244 chunk-based
// tx split in listEnabledSettingsBatched (M16-4 #106).
//
// Why this file exists (anti-pattern 21 sqlmock limitation evolution,
// horizontal replication of F234's rationale):
//
//	sqlmock does NOT model PostgreSQL's "current transaction is
//	aborted, commands ignored until end of transaction block" semantics.
//	The unit tests in report_generation_perf_test.go therefore drive the
//	happy path plus the code's error-return branches against the CODE's
//	error handling — they do NOT prove the ACID contract holds
//	server-side.
//
//	F244 (M16-4) makes the "chunk-level tx-abort blast radius" contract
//	load-bearing for production: a PG-side error inside chunk C aborts
//	C's tx and skips only C's remaining tenants, then chunk C+1
//	continues on the same pooled connection with a fresh BEGIN. The
//	only way to catch a regression that breaks this against real PG is
//	to actually run against real PG.
//
// Run with:
//
//	cd apps/api && go test -tags=integration ./internal/scheduler -run TestF244
//
// Prerequisites (skipped otherwise — CI mirrors these in
// .github/workflows/scheduler-integration.yml):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 042_rls_force_uniformity (the api server's
//     auto-migrate covers this; or run `go run ./cmd/migrate up`).
//
// What this test file pins down:
//
//  1. F244 happy-path across chunk boundaries: at N=1200 with
//     chunk_size=500 the batch splits into 3 chunks (500 + 500 + 200)
//     and every seeded tenant's enabled report_settings row surfaces
//     in the aggregate result.
//
//  2. F244 chunk-abort blast radius: a genuine PG-side error mid-chunk
//     (a temporary RLS policy on report_settings that raises
//     division_by_zero on a designated poison tenant) aborts that
//     chunk's tx server-side, skips the remaining tenants of the
//     poison chunk, and the next chunk continues normally with a
//     fresh BEGIN. This is the exact contract sqlmock cannot verify.
//
//  3. Connection cleanup: after listEnabledSettingsBatched returns, the
//     underlying pooled connection is released (defer conn.Close()) —
//     no connection leak that would eventually deadlock the pool.
package scheduler

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/repository"
)

// schedIntEnvReport wraps the shared schedIntEnv helper so the naming is
// obvious in this file's failure messages. The env variable contract is
// identical to the F234 file (they run in the same workflow / same
// docker compose stack).
func schedIntEnvReport(t *testing.T) (appURL, migURL string) {
	t.Helper()
	return schedIntEnv(t)
}

// schedSchemaReadyReport checks that report_settings + tenants exist
// and that report_settings has the FORCE RLS + tenant_isolation policy
// in place (migration 013 + FORCE harmonisation in migration 042). If
// not, skip loudly.
func schedSchemaReadyReport(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var tablesOK bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'tenants'
		) AND EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'report_settings'
		)
	`).Scan(&tablesOK); err != nil {
		t.Skipf("schema-existence check failed: %v - skipping", err)
		return false
	}
	if !tablesOK {
		t.Skip("report_settings / tenants not present - run migrations first (through 042)")
		return false
	}

	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class
		WHERE oid = 'public.report_settings'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("report_settings RLS-state check failed: %v - skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Skipf("report_settings RLS state: enable=%v force=%v - migration 042 not applied, skipping",
			rlsEnabled, rlsForce)
		return false
	}
	return true
}

// seedSchedIntReportTenants provisions n tenants (as migrator) + one
// report_settings row per tenant with enabled=true and a schedule that
// is intentionally NOT expected to hit shouldGenerate() during the test
// (schedule_hour=99 — invalid, so shouldGenerate returns false). The
// tests exercise listEnabledSettingsBatched which returns the raw
// enabled rows regardless of due-time semantics; the shouldGenerate
// filter is asserted separately in the perf test's semantic-equivalence
// section.
//
// Returns the tenant UUIDs and a cleanup closure (report_settings rows
// are removed by ON DELETE CASCADE on the tenants FK).
//
// Uses batched multi-row INSERT for tenants (F234 seeding rationale) so
// N=1200 stays under ~1s on a local docker-compose postgres.
func seedSchedIntReportTenants(t *testing.T, migDB *sql.DB, n int, tag string) ([]uuid.UUID, func()) {
	t.Helper()
	ids := make([]uuid.UUID, n)
	for i := range ids {
		ids[i] = uuid.New()
	}

	cleanup := func() {
		// Delete in batches to keep the DELETE reasonable at N=1200.
		const batch = 500
		for start := 0; start < len(ids); start += batch {
			end := start + batch
			if end > len(ids) {
				end = len(ids)
			}
			args := make([]any, 0, end-start)
			placeholders := make([]string, 0, end-start)
			for i, id := range ids[start:end] {
				placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
				args = append(args, id)
			}
			_, _ = migDB.Exec(
				"DELETE FROM tenants WHERE id IN ("+strings.Join(placeholders, ",")+")",
				args...,
			)
		}
	}
	// Pre-cleanup in case an earlier failed run left residue.
	cleanup()

	// Multi-row INSERT for tenants (no RLS, no per-row tx needed).
	const insertBatch = 200
	for start := 0; start < n; start += insertBatch {
		end := start + insertBatch
		if end > n {
			end = n
		}
		values := make([]string, 0, end-start)
		args := make([]any, 0, 4*(end-start))
		argIdx := 1
		for _, id := range ids[start:end] {
			slug := fmt.Sprintf("f244-%s-%s", tag, id.String()[:8])
			values = append(values,
				fmt.Sprintf("($%d, $%d, $%d, $%d)", argIdx, argIdx+1, argIdx+2, argIdx+3))
			args = append(args, id, "f244-"+tag+"-"+id.String(), "F244 "+tag+" "+id.String()[:8], slug)
			argIdx += 4
		}
		if _, err := migDB.Exec(
			`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES `+strings.Join(values, ","),
			args...,
		); err != nil {
			cleanup()
			t.Fatalf("seed tenants (batch start=%d): %v", start, err)
		}
	}

	// Insert report_settings rows. report_settings is FORCE RLS post-042,
	// so we must SET LOCAL app.current_tenant_id per row.
	// One tx per tenant here is fine (this is test setup, not the
	// code-under-test).
	for _, id := range ids {
		insertReportSettingsRow(t, migDB, id, cleanup)
	}

	return ids, cleanup
}

// seedSchedIntReportTenantsSequential is the sequential-INSERT
// counterpart used by the chunk-abort test where we need monotonic
// created_at ordering to reason about chunk positions deterministically.
func seedSchedIntReportTenantsSequential(t *testing.T, migDB *sql.DB, n int, tag string) ([]uuid.UUID, func()) {
	t.Helper()
	ids := make([]uuid.UUID, n)
	for i := range ids {
		ids[i] = uuid.New()
	}
	cleanup := func() {
		for _, id := range ids {
			_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, id)
		}
	}
	cleanup()

	for i, id := range ids {
		slug := fmt.Sprintf("f244-%s-%s", tag, id.String()[:8])
		if _, err := migDB.Exec(
			`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
			id, "f244-"+tag+"-"+id.String(), fmt.Sprintf("F244 %s %d", tag, i), slug,
		); err != nil {
			cleanup()
			t.Fatalf("seed tenant %d: %v", i, err)
		}
		insertReportSettingsRow(t, migDB, id, cleanup)
	}
	return ids, cleanup
}

// insertReportSettingsRow opens a fresh migrator-role tx, binds the
// tenant GUC, inserts one enabled report_settings row, and commits.
// Panics via t.Fatalf on any step failing (the caller passes cleanup
// so the tenant residue is removed on failure).
func insertReportSettingsRow(t *testing.T, migDB *sql.DB, tenantID uuid.UUID, cleanup func()) {
	t.Helper()
	tx, err := migDB.Begin()
	if err != nil {
		cleanup()
		t.Fatalf("begin report_settings insert tx for tenant %s: %v", tenantID, err)
	}
	if _, err := tx.Exec(
		`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String(),
	); err != nil {
		_ = tx.Rollback()
		cleanup()
		t.Fatalf("SET LOCAL for tenant %s: %v", tenantID, err)
	}
	// schedule_hour=99 keeps shouldGenerate false; the tests exercise the
	// enabled-set enumeration (not the due filter).
	if _, err := tx.Exec(
		`INSERT INTO report_settings (
			id, tenant_id, enabled, report_type, schedule_type,
			schedule_day, schedule_hour, format,
			email_enabled, email_recipients, include_sections
		) VALUES ($1, $2, true, 'executive', 'weekly', 1, 99, 'pdf', false, '{}', '{}')`,
		uuid.New(), tenantID,
	); err != nil {
		_ = tx.Rollback()
		cleanup()
		t.Fatalf("insert report_settings for tenant %s: %v", tenantID, err)
	}
	if err := tx.Commit(); err != nil {
		cleanup()
		t.Fatalf("commit report_settings tx for tenant %s: %v", tenantID, err)
	}
}

// newIntegrationReportGenJob wires a ReportGenerationJob with only the
// dependencies listEnabledSettingsBatched needs. reportService is nil
// (never called by the enumeration path) and cfg is nil (only used by
// the email path). If those change, this factory must too.
func newIntegrationReportGenJob(db *sql.DB) *ReportGenerationJob {
	reportRepo := repository.NewReportRepository(db)
	tenantRepo := repository.NewTenantRepository(db)
	return NewReportGenerationJob(nil, reportRepo, tenantRepo, db, 1*time.Hour)
}

// TestF244_ReportGenerationChunkedBatch_HappyPath_RealPG_F244 runs
// listEnabledSettingsBatched end-to-end against a real PG with N=1200
// tenants (chunk_size=500 -> 3 chunks) and asserts:
//
//   - Every seeded tenant's enabled report_settings row appears in the
//     result (every seeded tenant has enabled=true).
//   - The chunk boundaries are transparent to the caller.
//   - No connection leak: DB.Stats().InUse == 0 immediately after the
//     call returns (the deferred conn.Close() ran).
func TestF244_ReportGenerationChunkedBatch_HappyPath_RealPG_F244(t *testing.T) {
	appURL, migURL := schedIntEnvReport(t)

	migDB := schedOpenOrSkip(t, migURL)
	defer migDB.Close()
	if !schedSchemaReadyReport(t, migDB) {
		return
	}

	appDB := schedOpenOrSkip(t, appURL)
	defer appDB.Close()
	// Small pool so a leak surfaces as a hang / next-test-flake fast.
	appDB.SetMaxOpenConns(3)

	beforeCount := countAllTenants(t, migDB)

	const N = 1200
	seededIDs, cleanup := seedSchedIntReportTenants(t, migDB, N, "happy")
	defer cleanup()

	if got := countAllTenants(t, migDB); got != beforeCount+N {
		t.Fatalf("fixture size drift: before=%d after=%d, want after=%d",
			beforeCount, got, beforeCount+N)
	}

	// Confirm production chunk_size is 500 for this test.
	prev := reportEligibilityBatchChunkSize
	reportEligibilityBatchChunkSize = reportEligibilityBatchChunkSizeDefault
	defer func() { reportEligibilityBatchChunkSize = prev }()
	if reportEligibilityBatchChunkSize != 500 {
		t.Fatalf("chunk_size default drift: got %d, want 500", reportEligibilityBatchChunkSize)
	}
	wantChunks := (N + reportEligibilityBatchChunkSize - 1) / reportEligibilityBatchChunkSize
	if wantChunks != 3 {
		t.Fatalf("chunk arithmetic drift: N=%d K=%d -> %d chunks, want 3",
			N, reportEligibilityBatchChunkSize, wantChunks)
	}

	j := newIntegrationReportGenJob(appDB)

	start := time.Now()
	enabled, err := j.listEnabledSettingsBatched(context.Background())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("listEnabledSettingsBatched: %v", err)
	}
	t.Logf("F244 real-PG N=%d chunks=%d elapsed=%v enabled=%d",
		N, wantChunks, elapsed, len(enabled))

	// Build set-of-tenant-ids that surfaced in the enabled result.
	tenantsWithEnabled := make(map[uuid.UUID]int, len(enabled))
	for _, s := range enabled {
		tenantsWithEnabled[s.TenantID]++
	}

	missing := 0
	for _, id := range seededIDs {
		if _, ok := tenantsWithEnabled[id]; !ok {
			missing++
			if missing <= 5 {
				t.Errorf("seeded tenant %s not represented in enabled set", id)
			}
		}
	}
	if missing > 0 {
		t.Fatalf("F244 happy-path: %d seeded tenants missing from enabled set (N=%d)", missing, N)
	}

	// Connection-leak check.
	stats := appDB.Stats()
	if stats.InUse != 0 {
		t.Errorf("F244 connection leak: appDB.Stats().InUse=%d after listEnabledSettingsBatched (want 0). Full stats: %+v",
			stats.InUse, stats)
	}
}

// TestF244_ReportGenerationChunkAbort_RealPG_F244 pins the chunk-local
// blast radius against real PG's ACID semantics — this is the assertion
// sqlmock literally cannot make.
//
// Fixture design (mirrors TestF234_ChunkAbort_RealPG_F234):
//
//   - N=12 seeded tenants (F244 abort test).
//     reportEligibilityBatchChunkSize forced to 2 so at least 6 chunks
//     span our seeded set. That guarantees at least one CROSS-CHUNK
//     boundary between poison and other seeded tenants no matter how
//     the pre-existing tenants interleave.
//   - Poison tenant is chosen AFTER seeding by querying its absolute
//     position (rank ORDER BY created_at) and picking the seeded ID
//     that lands in the MIDDLE of our seeded range — so at least one
//     seeded tenant is BEFORE poison's chunk (proves in-enabled
//     survives ROLLBACK for tenants already collected) and at least
//     one is AFTER poison's chunk (proves the fresh BEGIN in the NEXT
//     chunk continues on the same pooled connection).
//
// Assertions:
//
//	(a) The call does NOT return an error (F244 turns per-chunk
//	    error into log + continue).
//	(b) Poison tenant is NOT in the enabled set (its SELECT failed
//	    with div-by-zero server-side).
//	(c) At least one seeded tenant in a chunk BEFORE poison's chunk
//	    is in the enabled set — proves Go-side state survives the
//	    ROLLBACK.
//	(d) All seeded tenants in chunks AFTER poison's chunk are in
//	    the enabled set — proves the fresh BEGIN happens and the
//	    next chunk continues on the same pooled connection.
//	(e) No connection leak after return.
func TestF244_ReportGenerationChunkAbort_RealPG_F244(t *testing.T) {
	appURL, migURL := schedIntEnvReport(t)

	migDB := schedOpenOrSkip(t, migURL)
	defer migDB.Close()
	if !schedSchemaReadyReport(t, migDB) {
		return
	}

	appDB := schedOpenOrSkip(t, appURL)
	defer appDB.Close()
	appDB.SetMaxOpenConns(3)

	const N = 12
	seededIDs, cleanupTenants := seedSchedIntReportTenantsSequential(t, migDB, N, "abort")
	defer cleanupTenants()

	positions := querySeededTenantPositions(t, migDB, seededIDs)

	poisonID := seededIDs[N/2]

	prevChunk := reportEligibilityBatchChunkSize
	reportEligibilityBatchChunkSize = 2
	defer func() { reportEligibilityBatchChunkSize = prevChunk }()
	const chunkSize = 2
	poisonChunkIdx := positions[poisonID] / chunkSize

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
		t.Fatalf("F244 fixture setup: no seeded tenant in a chunk BEFORE poison — "+
			"cannot pin (c). positions=%v poisonPos=%d poisonChunkIdx=%d",
			positions, positions[poisonID], poisonChunkIdx)
	}
	if len(afterChunkIDs) == 0 {
		t.Fatalf("F244 fixture setup: no seeded tenant in a chunk AFTER poison — "+
			"cannot pin (d). positions=%v poisonPos=%d poisonChunkIdx=%d",
			positions, positions[poisonID], poisonChunkIdx)
	}
	t.Logf("F244 fixture: poison=%s poisonPos=%d poisonChunkIdx=%d before=%d sameChunk=%d after=%d",
		poisonID, positions[poisonID], poisonChunkIdx, len(beforeChunkIDs), len(sameChunkIDs), len(afterChunkIDs))

	// Install the temporary poison policy AFTER the fixture is fully
	// seeded so seeding is unaffected. Use defer (NOT t.Cleanup) so the
	// restore runs BEFORE the deferred migDB.Close() above — otherwise
	// the DB handle is already closed by the time t.Cleanup fires.
	restorePolicy := installPoisonPolicyReport(t, migDB, poisonID)
	defer restorePolicy()

	j := newIntegrationReportGenJob(appDB)

	start := time.Now()
	enabled, err := j.listEnabledSettingsBatched(context.Background())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("listEnabledSettingsBatched should NOT return error under F244 chunk-local abort semantics, got: %v", err)
	}
	t.Logf("F244 real-PG chunk-abort N=%d K=%d elapsed=%v enabled=%d (poison=%s)",
		N, reportEligibilityBatchChunkSize, elapsed, len(enabled), poisonID)

	tenantsWithEnabled := make(map[uuid.UUID]struct{}, len(enabled))
	for _, s := range enabled {
		tenantsWithEnabled[s.TenantID] = struct{}{}
	}

	// (b) Poison tenant MUST be absent — its SELECT raised div-by-zero.
	if _, ok := tenantsWithEnabled[poisonID]; ok {
		t.Errorf("F244 (b) chunk-abort: poison tenant %s must not appear in enabled set", poisonID)
	}

	// (c) At least one seeded tenant BEFORE poison's chunk in enabled.
	beforeMissing := 0
	for _, id := range beforeChunkIDs {
		if _, ok := tenantsWithEnabled[id]; !ok {
			beforeMissing++
		}
	}
	if beforeMissing == len(beforeChunkIDs) {
		t.Errorf("F244 (c) blast-radius broken: NO seeded tenant from a chunk BEFORE poison "+
			"(there were %d such tenants) is in enabled — Go-side state didn't survive the tx rollback",
			len(beforeChunkIDs))
	}

	// (d) All seeded tenants AFTER poison's chunk in enabled.
	afterMissing := 0
	for _, id := range afterChunkIDs {
		if _, ok := tenantsWithEnabled[id]; !ok {
			afterMissing++
		}
	}
	if afterMissing == len(afterChunkIDs) {
		t.Errorf("F244 (d) blast-radius broken: NO seeded tenant from a chunk AFTER poison "+
			"(there were %d such tenants) is in enabled — the loop did not continue past the poison chunk",
			len(afterChunkIDs))
	}
	if afterMissing > 0 {
		t.Errorf("F244 (d) strengthened: %d/%d seeded tenants in chunks AFTER poison are missing from enabled — "+
			"fresh BEGIN per chunk should let all of them succeed",
			afterMissing, len(afterChunkIDs))
	}

	// (e) Connection-leak check.
	stats := appDB.Stats()
	if stats.InUse != 0 {
		t.Errorf("F244 (e) connection leak: appDB.Stats().InUse=%d after listEnabledSettingsBatched (want 0). Full stats: %+v",
			stats.InUse, stats)
	}
}

// installPoisonPolicyReport replaces the standard
// tenant_isolation_report_settings RLS policy with a variant that raises
// division_by_zero when the current tenant GUC matches poisonID. Returns
// a restore closure that puts the original policy back.
//
// Technique details (same as F234's installPoisonPolicy):
//
//	PostgreSQL evaluates the USING expression per-row during a SELECT.
//	A CASE branch that returns a division-by-zero expression forces the
//	error at policy evaluation time, which is server-side and aborts
//	the enclosing tx — exactly the failure mode F244 must contain to a
//	single chunk.
//
// Constant-folding gotcha: the naive `THEN (1/0)::text::boolean` is
// folded at plan time, firing on every SELECT — not just the poison
// tenant. Reference tenant_id inside the divisor
// (`length(tenant_id::text) - 36`, always 0 for a valid UUID) so the
// expression cannot be constant-folded but still divides by zero when
// the CASE branch is taken.
//
// Original policy (from migration 042):
//
//	CREATE POLICY tenant_isolation_report_settings ON report_settings
//	    FOR ALL
//	    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
//	    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
func installPoisonPolicyReport(t *testing.T, migDB *sql.DB, poisonID uuid.UUID) func() {
	t.Helper()

	dropOriginal := `DROP POLICY IF EXISTS tenant_isolation_report_settings ON report_settings`
	// Also drop the legacy quoted name that migration 013 originally
	// created; migration 042 already runs both DROPs but the poison
	// installer must be idempotent against either historical state.
	dropLegacy := `DROP POLICY IF EXISTS "report_settings_tenant_isolation" ON report_settings`
	createOriginal := `
		CREATE POLICY tenant_isolation_report_settings ON report_settings
		    FOR ALL
		    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
		    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
	`

	if _, err := migDB.Exec(dropOriginal); err != nil {
		t.Fatalf("drop original policy for poison-install: %v", err)
	}
	_, _ = migDB.Exec(dropLegacy)

	poisonPolicy := fmt.Sprintf(`
		CREATE POLICY tenant_isolation_report_settings ON report_settings
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
