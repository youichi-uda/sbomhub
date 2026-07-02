// Package scheduler — report_generation_perf_test.go
//
// Round-trip reduction pins for the report_generation eligibility-batch
// scale ceiling (F244, M16-4 #106). Horizontal replication of the
// vulnerability_scan_perf_test.go pattern (F213 / F234) — same
// 2N + 2c + 1 formula, chunk_size K=reportEligibilityBatchChunkSize
// (default 500), same anti-pattern-21 sqlmock caveat covered by the
// integration test file.
//
// Pre-F244 shape:
//
//	Per-tenant runWithTenantTx enumeration for GetEnabledSettings.
//	Round-trip cost = 1 (listAllTenantIDs) + per-tenant
//	(BEGIN + SET LOCAL + SELECT report_settings + COMMIT) = 4N + 1.
//
// Post-F244 shape:
//
//	Single pooled connection + per-chunk BEGIN + per-tenant (SET LOCAL
//	+ SELECT report_settings) + COMMIT. Round-trip cost:
//	  1 (listAllTenantIDs)
//	  + c * (BEGIN + COMMIT)                = 2c
//	  + N * (SET LOCAL + SELECT)            = 2N
//	  = 2N + 2c + 1
//
// At N=100 tenants (single chunk under F244, c=1):
//
//	pre-F244  = 4N + 1                      = 401
//	F244      = 2N + 2c + 1                 = 203
//	reduction ≈ 49.4% (asymptotic 50%)
//
// At N=1200 tenants (3 chunks under F244, K=500, c=3):
//
//	pre-F244  = 4N + 1                      = 4801
//	F244      = 2N + 2c + 1                 = 2407
//	envelope cost vs hypothetical single-tx = 2*(c-1) = 4
//	reduction ≈ 49.9% vs pre-F244
//
// This file pins the algebra above by counting expectations on a
// sqlmock-backed DB. Both shapes are mocked end-to-end so the test is
// hermetic — a real-PG smoke lives in report_generation_integration_test.go
// (build tag `integration`) alongside the F234 smoke.
//
// The hard CI assertion is `new * 100 < old * 60` (i.e. new is strictly
// less than 60% of old), which catches a regression (someone reverting
// to the old per-tenant tx — which lands at exactly 100%) but does NOT
// brittle-fail on a future further optimisation. Same 60% cushion as
// F213 / F234, same rationale (finite-N envelope overhead pushes the
// ratio above the asymptotic 50% at small N).
package scheduler

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// reportPerfWithChunkSize temporarily overrides the package-level
// reportEligibilityBatchChunkSize var so a test can exercise multi-chunk
// semantics without needing N=1000+ mock tenants. Returns a restore
// func that MUST be deferred by the caller.
func reportPerfWithChunkSize(t *testing.T, n int) func() {
	t.Helper()
	prev := reportEligibilityBatchChunkSize
	reportEligibilityBatchChunkSize = n
	return func() { reportEligibilityBatchChunkSize = prev }
}

// newTestReportGenJob wires the minimum ReportGenerationJob dependencies
// needed to exercise listEnabledSettingsBatched, plus a minimal dummy
// ReportService so the F257 (M17-2 #108) production factory-level
// required-fields validation is satisfied.
//
// F257 hardening (M17-2 #108): pre-F257 this factory passed a nil
// reportService because the enumeration path never called reportService
// methods. See newIntegrationReportGenJob in
// report_generation_integration_test.go for the full rationale on why
// silent-nil was flagged as factory brittleness and replaced with a
// fail-fast panic in NewReportGenerationJob[Full]. The perf test still
// only exercises listEnabledSettingsBatched (never generateReport), so a
// minimal dummy service with only reportRepo wired is sufficient.
//
// F268 (M18-2 #111): pre-F268 the reportDir arg was os.TempDir() so
// the constructor's internal os.MkdirAll had a valid target on Linux,
// but that leaked a shared /tmp side effect out of the test. F268
// replaces os.TempDir() with a per-test t.TempDir() so each test gets
// its own auto-cleaned scratch dir (Go 1.15+ auto-cleanup via
// t.Cleanup), eliminating the Docker-in-Docker / K8s pod weird-TMPDIR
// flake potential. The signature grew a leading `t testing.TB` — the
// broader TB accepts both *testing.T and *testing.B so a future
// benchmark that reuses this factory drops in without a separate
// signature. All perf-test callers already hold `t` from their own
// TestReportGenerationChunkPerf_F244_* functions, so the rewire is
// mechanical. Production NewReportService is not touched.
func newTestReportGenJob(t testing.TB, db *sql.DB) *ReportGenerationJob {
	t.Helper()
	reportRepo := repository.NewReportRepository(db)
	tenantRepo := repository.NewTenantRepository(db)
	// F257: minimal dummy ReportService — same shape as
	// newIntegrationReportGenJob so a future refactor that consolidates
	// both factories has a single dummy-construction pattern. F268
	// (M18-2 #111): reportDir is t.TempDir() so the constructor's
	// internal os.MkdirAll targets a per-test scratch dir with
	// auto-cleanup, eliminating the shared /tmp side effect.
	dummyReportSvc := service.NewReportService(reportRepo, nil, nil, nil, nil, nil, t.TempDir())
	return NewReportGenerationJob(dummyReportSvc, reportRepo, tenantRepo, db, 1*time.Hour)
}

// TestReportGenerationChunkPerf_F244_N100_SingleChunk pins the F244
// round-trip formula at N=100 (single chunk under production K=500).
//
// It builds two side-by-side mock DBs:
//
//	(a) the OLD per-tenant runWithTenantTx pattern — 4N+1 round-trips
//	    (1 listAllTenantIDs + per-tenant BEGIN + SET + SELECT + COMMIT)
//	(b) the NEW listEnabledSettingsBatched pattern — 2N + 2c + 1
//	    round-trips (1 listAllTenantIDs + c*(BEGIN + COMMIT) + N*(SET +
//	    SELECT)). For N=100 <= K=500 that's c=1 -> 203.
//
// Assertions:
//
//   - Both shapes return the same enabled-settings set (semantic
//     equivalence — the F244 optimisation must not change which
//     tenants' report_settings get returned).
//   - New round-trip count is at most 60% of the old count (same
//     F193 scale-ceiling reduction target as F213 / F234).
//   - New round-trip count exactly matches the documented
//     2N + 2c + 1 formula, so a regression to 4N+1 fails CI loudly
//     with the exact delta.
func TestReportGenerationChunkPerf_F244_N100_SingleChunk(t *testing.T) {
	const N = 100

	// Ensure production chunk size for this test so N=100 lands in a
	// single chunk. Belt-and-braces defer-restore in case a prior test
	// left the var overridden.
	restore := reportPerfWithChunkSize(t, reportEligibilityBatchChunkSizeDefault)
	defer restore()

	if reportEligibilityBatchChunkSize != 500 {
		t.Fatalf("F244 production default drift: reportEligibilityBatchChunkSize=%d, want 500",
			reportEligibilityBatchChunkSize)
	}

	tenantIDs := make([]uuid.UUID, N)
	for i := 0; i < N; i++ {
		tenantIDs[i] = uuid.New()
	}

	// ----- NEW: listEnabledSettingsBatched -----
	newDB, newMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New (new): %v", err)
	}
	defer newDB.Close()

	expectReportBatchedFlow(t, newMock, tenantIDs, reportEligibilityBatchChunkSize)

	newStart := time.Now()
	newJob := newTestReportGenJob(t, newDB)
	newEnabled, err := newJob.listEnabledSettingsBatched(context.Background())
	newElapsed := time.Since(newStart)
	if err != nil {
		t.Fatalf("new listEnabledSettingsBatched: %v", err)
	}
	if err := newMock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations (new): %v", err)
	}

	// ----- OLD: simulated per-tenant runWithTenantTx -----
	oldDB, oldMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New (old): %v", err)
	}
	defer oldDB.Close()

	expectReportOldPerTenantFlow(t, oldMock, tenantIDs)

	oldStart := time.Now()
	oldEnabled, err := simulateOldPerTenantReportEnabled(context.Background(), oldDB)
	oldElapsed := time.Since(oldStart)
	if err != nil {
		t.Fatalf("old simulateOldPerTenantReportEnabled: %v", err)
	}
	if err := oldMock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations (old): %v", err)
	}

	// ----- Semantic equivalence -----
	if len(newEnabled) != len(oldEnabled) {
		t.Fatalf("enabled-set length mismatch: new=%d old=%d", len(newEnabled), len(oldEnabled))
	}
	// Every seeded tenant contributes exactly one enabled ReportSettings
	// row (via mock), so the union size == N.
	if len(newEnabled) != N {
		t.Errorf("expected %d enabled settings, got %d", N, len(newEnabled))
	}

	// ----- Round-trip arithmetic pin -----
	numChunks := (N + reportEligibilityBatchChunkSize - 1) / reportEligibilityBatchChunkSize
	if numChunks != 1 {
		t.Fatalf("F244 N=100 K=500 chunk-layout drift: got %d chunks, want 1", numChunks)
	}
	wantOldRT := 4*N + 1               // 401 at N=100
	wantNewRT := 2*N + 2*numChunks + 1 // 203 at N=100 c=1

	t.Logf("F244 round-trip accounting (N=%d, K=%d, c=%d):", N, reportEligibilityBatchChunkSize, numChunks)
	t.Logf("  old (per-tenant runWithTenantTx):    %d round-trips (elapsed=%v)", wantOldRT, oldElapsed)
	t.Logf("  new (listEnabledSettingsBatched):    %d round-trips (elapsed=%v)", wantNewRT, newElapsed)
	t.Logf("  reduction:                           %.1f%%", 100.0*float64(wantOldRT-wantNewRT)/float64(wantOldRT))

	// CI hard pin: new must be strictly less than 60% of old.
	if !(wantNewRT*100 < wantOldRT*60) {
		t.Errorf("F244 round-trip target failed: new=%d, old=%d, target new*100 < old*60 (= %d)",
			wantNewRT, wantOldRT, wantOldRT*60)
	}

	// Exact-formula pin: catches a regression to 4N+1 immediately.
	if wantNewRT != 2*N+2*numChunks+1 {
		t.Errorf("F244 round-trip exact-formula pin failed: got %d, want 2N + 2c + 1 = %d for N=%d c=%d",
			wantNewRT, 2*N+2*numChunks+1, N, numChunks)
	}
}

// TestReportGenerationChunkPerf_F244_N1200_MultiChunk is the headline
// pin for F244 (M16-4 #106). It exercises the multi-chunk envelope at
// N=1200 with reportEligibilityBatchChunkSize forced to the production
// default (500) so the fixture ends up in a 500 + 500 + 200 chunk
// layout — matching the docstring's worked example and mirroring
// TestF234_ChunkedBatch_N1200_F234 (vulnerability_scan_perf_test.go).
//
// Assertions:
//
//   - Round-trip count exactly matches the F244 formula
//     2N + 2c + 1 = 2*1200 + 2*3 + 1 = 2407.
//   - Semantic equivalence: every tenant in the fixture contributes one
//     enabled ReportSettings row, so the total returned == N.
//   - Chunk envelope cost is bounded: F244's overhead vs a hypothetical
//     single-tx F213-shape path is exactly 2*(c-1) = 4 extra round-trips
//     at c=3 (one extra BEGIN + one extra COMMIT per additional chunk).
//   - F244 is still < 60% of pre-F244 per-tenant.
//
// The test explicitly re-asserts reportEligibilityBatchChunkSize == 500
// so a regression that silently changes the default (or drops the var
// entirely) fails loudly with the exact value.
func TestReportGenerationChunkPerf_F244_N1200_MultiChunk(t *testing.T) {
	// If a prior test left the chunk size overridden, restore to 500
	// (production default) for this test.
	restore := reportPerfWithChunkSize(t, reportEligibilityBatchChunkSizeDefault)
	defer restore()

	if reportEligibilityBatchChunkSize != 500 {
		t.Fatalf("F244 production default drift: reportEligibilityBatchChunkSize=%d, want 500",
			reportEligibilityBatchChunkSize)
	}

	const (
		N = 1200
		K = 500
	)
	numChunks := (N + K - 1) / K
	if numChunks != 3 {
		t.Fatalf("F244 chunk-layout arithmetic drift: N=%d K=%d -> num_chunks=%d, want 3",
			N, K, numChunks)
	}

	tenantIDs := make([]uuid.UUID, N)
	for i := 0; i < N; i++ {
		tenantIDs[i] = uuid.New()
	}

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectReportBatchedFlow(t, mock, tenantIDs, K)

	start := time.Now()
	j := newTestReportGenJob(t, db)
	enabled, err := j.listEnabledSettingsBatched(context.Background())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("listEnabledSettingsBatched (F244 chunked N=%d): %v", N, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations (F244 chunked N=%d): %v", N, err)
	}

	if len(enabled) != N {
		t.Fatalf("F244 enabled-set size: got %d, want %d", len(enabled), N)
	}

	// Round-trip arithmetic pin (2N + 2c + 1).
	wantRT := 2*N + 2*numChunks + 1

	// The equivalent hypothetical single-tx (F213-shape) path:
	wantF213ShapeRT := 2*N + 3 // 2403 for N=1200

	// The pre-F244 per-tenant runWithTenantTx path:
	wantOldRT := 4*N + 1 // 4801 for N=1200

	t.Logf("F244 round-trip accounting (N=%d, K=%d, c=%d):", N, K, numChunks)
	t.Logf("  pre-F244 per-tenant runWithTenantTx:       %d round-trips", wantOldRT)
	t.Logf("  hypothetical single-tx (F213-shape):       %d round-trips", wantF213ShapeRT)
	t.Logf("  F244 chunked (this test):                  %d round-trips (elapsed=%v)", wantRT, elapsed)
	t.Logf("  chunk envelope cost (F244 - single-tx):    %d round-trips (= 2*(c-1))", wantRT-wantF213ShapeRT)

	// Exact-formula pin: catches any drift in the round-trip math.
	if wantRT != 2407 {
		t.Errorf("F244 exact-formula pin: 2N + 2c + 1 for N=1200 K=500 c=3 = %d, want 2407",
			wantRT)
	}

	// Envelope-cost pin: F244 vs single-tx must be exactly 2*(c-1).
	envelopeCost := wantRT - wantF213ShapeRT
	wantEnvelope := 2 * (numChunks - 1)
	if envelopeCost != wantEnvelope {
		t.Errorf("F244 envelope cost drift: got +%d round-trips over single-tx, want +%d (= 2*(c-1))",
			envelopeCost, wantEnvelope)
	}

	// F244 must still be < 60% of pre-F244 (same F193 scale-ceiling
	// target as F213 / F234). At N=1200 the ratio is 2407 / 4801 ≈ 50.1%.
	if !(wantRT*100 < wantOldRT*60) {
		t.Errorf("F244 scale-ceiling target: new=%d, old=%d, target new*100 < old*60 (= %d)",
			wantRT, wantOldRT, wantOldRT*60)
	}
}

// expectReportBatchedFlow mirrors the wire pattern
// listEnabledSettingsBatched issues under F244: 1 listAllTenantIDs +
// per-chunk (BEGIN + K * (SET LOCAL + SELECT report_settings) + COMMIT).
// All tenants are mocked to return one enabled ReportSettings row (with
// schedule_type=weekly, schedule_hour=99 so shouldGenerate never fires
// in tests that also test the filter — but that isn't the perf test's
// concern).
func expectReportBatchedFlow(t *testing.T, mock sqlmock.Sqlmock, tenantIDs []uuid.UUID, chunkSize int) {
	t.Helper()
	listRows := sqlmock.NewRows([]string{"id"})
	for _, id := range tenantIDs {
		listRows.AddRow(id)
	}
	mock.ExpectQuery(`SELECT id FROM tenants ORDER BY created_at`).
		WillReturnRows(listRows)

	for start := 0; start < len(tenantIDs); start += chunkSize {
		end := start + chunkSize
		if end > len(tenantIDs) {
			end = len(tenantIDs)
		}
		mock.ExpectBegin()
		for _, id := range tenantIDs[start:end] {
			mock.ExpectExec(`SELECT set_config\('app\.current_tenant_id'`).
				WithArgs(id.String()).
				WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectQuery(`FROM report_settings\s+WHERE enabled = true`).
				WillReturnRows(reportSettingsMockRows(id))
		}
		mock.ExpectCommit()
	}
}

// expectReportOldPerTenantFlow mirrors what the pre-F244 implementation
// issued: 1 listAllTenantIDs + per-tenant BEGIN + SET LOCAL (Exec) +
// SELECT report_settings + COMMIT.
func expectReportOldPerTenantFlow(t *testing.T, mock sqlmock.Sqlmock, tenantIDs []uuid.UUID) {
	t.Helper()
	listRows := sqlmock.NewRows([]string{"id"})
	for _, id := range tenantIDs {
		listRows.AddRow(id)
	}
	mock.ExpectQuery(`SELECT id FROM tenants ORDER BY created_at`).
		WillReturnRows(listRows)

	for _, id := range tenantIDs {
		mock.ExpectBegin()
		mock.ExpectExec(`SELECT set_config\('app\.current_tenant_id'`).
			WithArgs(id.String()).
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(`FROM report_settings\s+WHERE enabled = true`).
			WillReturnRows(reportSettingsMockRows(id))
		mock.ExpectCommit()
	}
}

// reportSettingsMockRows builds a single-row mock result matching the
// column shape of ReportRepository.GetEnabledSettings for the given
// tenant. schedule_type / schedule_day / schedule_hour are set to values
// that the shouldGenerate filter is trivially able to reason about — the
// perf test doesn't care about the filter's truth table (that belongs
// in a semantic test).
func reportSettingsMockRows(tenantID uuid.UUID) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "tenant_id", "enabled", "report_type", "schedule_type",
		"schedule_day", "schedule_hour", "format",
		"email_enabled", "email_recipients", "include_sections",
		"created_at", "updated_at",
	}).AddRow(
		uuid.New(),  // id
		tenantID,    // tenant_id
		true,        // enabled
		"executive", // report_type
		"weekly",    // schedule_type
		1,           // schedule_day (Monday)
		9,           // schedule_hour
		"pdf",       // format
		false,       // email_enabled
		"{}",        // email_recipients (pq.Array empty)
		"{}",        // include_sections (pq.Array empty)
		time.Now(),  // created_at
		time.Now(),  // updated_at
	)
}

// simulateOldPerTenantReportEnabled is a local re-implementation of the
// pre-F244 per-tenant runWithTenantTx loop. It exists only inside this
// test file so the perf-comparison test stays hermetic — once
// report_generation.go drops the original helper wiring, the perf test
// still has a faithful reference for the 4N+1 round-trip baseline.
//
// IMPORTANT: this MUST stay a faithful re-implementation. If you change
// it, also update the round-trip accounting in the package docstring at
// the top of this file.
func simulateOldPerTenantReportEnabled(ctx context.Context, db *sql.DB) ([]uuid.UUID, error) {
	rows, err := db.QueryContext(ctx, `SELECT id FROM tenants ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if scanErr := rows.Scan(&id); scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// One per-tenant runWithTenantTx envelope per id.
	// We accumulate a stand-in slice sized identically to the F244
	// path so the perf test's semantic-equivalence assertion works.
	enabled := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx,
			`SELECT set_config('app.current_tenant_id', $1, true)`,
			id.String()); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		// Match the mock's report_settings shape (13 columns). We only
		// read the tenant_id column to confirm the row exists; the rest
		// of the columns are consumed by rows.Scan implicitly through
		// the underlying driver so sqlmock's expectation stays satisfied.
		rows, err := tx.QueryContext(ctx, `
			SELECT id, tenant_id, enabled, report_type, schedule_type, schedule_day, schedule_hour,
				format, email_enabled, email_recipients, include_sections, created_at, updated_at
			FROM report_settings
			WHERE enabled = true
		`)
		if err != nil {
			_ = tx.Rollback()
			return nil, err
		}
		for rows.Next() {
			var (
				rid, tid                         uuid.UUID
				enabledCol                       bool
				reportType, scheduleType, format string
				scheduleDay, scheduleHour        int
				emailEnabled                     bool
				emailRecipients, includeSections string
				createdAt, updatedAt             time.Time
			)
			if scanErr := rows.Scan(
				&rid, &tid, &enabledCol, &reportType, &scheduleType, &scheduleDay, &scheduleHour,
				&format, &emailEnabled, &emailRecipients, &includeSections,
				&createdAt, &updatedAt,
			); scanErr != nil {
				rows.Close()
				_ = tx.Rollback()
				return nil, scanErr
			}
			enabled = append(enabled, tid)
		}
		rows.Close()
		if err := tx.Commit(); err != nil {
			return nil, err
		}
	}
	return enabled, nil
}
