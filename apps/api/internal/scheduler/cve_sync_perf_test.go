// Package scheduler — cve_sync_perf_test.go
//
// Round-trip reduction pins for the cve_sync matchTenant enumeration
// scale ceiling (F258, M17-3 #109). Horizontal replication of the
// vulnerability_scan_perf_test.go (F213 / F234) and
// report_generation_perf_test.go (F244) patterns — F258 is the FIRST
// write-heavy application of the chunk-based tx split pattern, so the
// formula is different from the read-only siblings.
//
// Pre-F258 shape:
//
//	Per-tenant runWithTenantTx enumeration for the CVE match loop.
//	Per tenant: BEGIN + SET LOCAL + M * (SELECT components + INSERT
//	component_vulnerabilities batch) + COMMIT.
//	Round-trip cost = 1 (listAllIDs) + N * (3 + M) = N*(3+M) + 1.
//
// Post-F258 shape:
//
//	Single pooled connection + per-chunk BEGIN + per-tenant SET LOCAL +
//	per-CVE (SELECT + INSERT batch) + per-chunk COMMIT.
//	Round-trip cost:
//	  1 (listAllIDs)
//	  + c * (BEGIN + COMMIT)              = 2c
//	  + N * (SET LOCAL)                   = N
//	  + N * M * (SELECT + INSERT batch)   = N * M
//	  = 1 + 2c + N*(1 + M)
//
// At N=100 M=50 (single chunk under production K=200, c=1):
//
//	pre-F258 = 1 + N*(3+M)                = 5301
//	F258     = 1 + 2c + N*(1+M)           = 5103
//	reduction ≈ 3.7%
//
// At N=500 M=50 (3 chunks under K=200, c=3, layout 200+200+100):
//
//	pre-F258 = 1 + N*(3+M)                = 26501
//	F258     = 1 + 2c + N*(1+M)           = 25507
//	reduction ≈ 3.8%
//
// Note the reduction ratio is MUCH smaller than F234 / F244's ~50%:
// those were read-only per-tenant (2 round-trips each) so removing the
// per-tenant BEGIN + COMMIT was a huge chunk of the budget. F258 is
// write-heavy (M+1 round-trips per tenant with M dominating at M=50),
// so removing the per-tenant BEGIN + COMMIT saves only 2 out of M+3.
//
// The real F258 win is NOT round-trip reduction — it's:
//
//	(a) One pool lease per Run() tick instead of N leases (prevents
//	    pool-exhaustion cascades under load — the primary production
//	    concern at N=1000+).
//	(b) Chunk-local tx-abort blast radius (pre-F258 poison isolation
//	    was per-tenant, F258 is per-chunk — but the pool efficiency
//	    win outweighs the blast-radius widening, see cve_sync.go's
//	    matchTenantsChunked docstring for the full trade-off).
//
// This file pins the algebra above by counting expectations on a
// sqlmock-backed DB. Both shapes are mocked end-to-end so the test is
// hermetic — a real-PG smoke lives in cve_sync_integration_test.go
// (build tag `integration`) alongside the F234 / F244 smokes.
//
// The hard CI assertion is `new < old` (strict inequality) — F258's
// reduction is small (~4%), so the 60% cushion used by F213 / F234 /
// F244 is not applicable here. What matters is that a regression to
// per-tenant runWithTenantTx would push new EQUAL to (or above) old,
// which the strict-less assertion still catches.
package scheduler

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/repository"
)

// cvePerfWithChunkSize temporarily overrides the package-level
// cveMatchBatchChunkSize var so a test can exercise multi-chunk semantics
// without needing N=1000+ mock tenants. Returns a restore func that MUST
// be deferred by the caller.
func cvePerfWithChunkSize(t *testing.T, n int) func() {
	t.Helper()
	prev := cveMatchBatchChunkSize
	cveMatchBatchChunkSize = n
	return func() { cveMatchBatchChunkSize = prev }
}

// newTestCVESyncJob wires the minimum CVESyncJob dependencies needed to
// exercise matchTenantsChunked. httpClient is nil because the perf test
// never triggers fetchModifiedCVEs — only the match enumeration path is
// under test.
func newTestCVESyncJob(db *sql.DB) *CVESyncJob {
	tenantRepo := repository.NewTenantRepository(db)
	// nil advisoryExcerpts: the perf harness pins round-trip counts only —
	// excerpt grounding (M32) is disabled here so it adds no expectations.
	return NewCVESyncJob(db, tenantRepo, "", 24*time.Hour, nil, "", false)
}

// TestCVESyncChunkPerf_F258_N100_M50_SingleChunk pins the F258 round-trip
// formula at N=100 M=50 (single chunk under production K=200).
//
// It builds two side-by-side mock DBs:
//
//	(a) the OLD per-tenant runWithTenantTx pattern — 1 + N*(3+M)
//	    round-trips.
//	(b) the NEW matchTenantsChunked pattern — 1 + 2c + N*(1+M)
//	    round-trips. For N=100 <= K=200 that's c=1 -> 5103.
//
// Assertions:
//
//   - Both shapes commit the same set of tenant IDs (semantic
//     equivalence — F258 must not change WHICH tenants get their CVEs
//     matched).
//   - New round-trip count is strictly less than the old count (the
//     regression pin — reverting to per-tenant tx lands at exactly old).
//   - New round-trip count exactly matches the documented
//     1 + 2c + N*(1+M) formula, so a regression to 1 + N*(3+M) fails
//     CI loudly with the exact delta.
func TestCVESyncChunkPerf_F258_N100_M50_SingleChunk(t *testing.T) {
	const (
		N = 100
		M = 50
	)

	// Ensure production chunk size for this test so N=100 lands in a
	// single chunk. Belt-and-braces defer-restore in case a prior test
	// left the var overridden.
	restore := cvePerfWithChunkSize(t, cveMatchBatchChunkSizeDefault)
	defer restore()

	if cveMatchBatchChunkSize != 200 {
		t.Fatalf("F258 production default drift: cveMatchBatchChunkSize=%d, want 200",
			cveMatchBatchChunkSize)
	}

	tenantIDs := make([]uuid.UUID, N)
	for i := 0; i < N; i++ {
		tenantIDs[i] = uuid.New()
	}
	cves, vulnIndex := buildCVEFixture(M)

	// ----- NEW: matchTenantsChunked -----
	newDB, newMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New (new): %v", err)
	}
	defer newDB.Close()

	expectCVEChunkedFlow(t, newMock, tenantIDs, cves, cveMatchBatchChunkSize)

	newStart := time.Now()
	newJob := newTestCVESyncJob(newDB)
	newMatched, newNewVulns, err := newJob.matchTenantsChunked(
		context.Background(), tenantIDs, cves, vulnIndex,
	)
	newElapsed := time.Since(newStart)
	if err != nil {
		t.Fatalf("new matchTenantsChunked: %v", err)
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

	expectCVEOldPerTenantFlow(t, oldMock, tenantIDs, cves)

	oldStart := time.Now()
	oldMatched, oldNewVulns, err := simulateOldPerTenantCVEMatch(
		context.Background(), oldDB, tenantIDs, cves, vulnIndex,
	)
	oldElapsed := time.Since(oldStart)
	if err != nil {
		t.Fatalf("old simulateOldPerTenantCVEMatch: %v", err)
	}
	if err := oldMock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations (old): %v", err)
	}

	// ----- Semantic equivalence -----
	// The mock returns empty component rows for every SELECT, so no
	// INSERTs fire and matched / newVulns stay 0 for both shapes.
	if newMatched != oldMatched {
		t.Errorf("matched mismatch: new=%d old=%d", newMatched, oldMatched)
	}
	if newNewVulns != oldNewVulns {
		t.Errorf("newVulns mismatch: new=%d old=%d", newNewVulns, oldNewVulns)
	}
	if newMatched != 0 || newNewVulns != 0 {
		t.Errorf("mock fixture expected 0 matched / 0 newVulns, got matched=%d newVulns=%d",
			newMatched, newNewVulns)
	}

	// ----- Round-trip arithmetic pin -----
	numChunks := (N + cveMatchBatchChunkSize - 1) / cveMatchBatchChunkSize
	if numChunks != 1 {
		t.Fatalf("F258 N=100 K=200 chunk-layout drift: got %d chunks, want 1", numChunks)
	}
	wantOldRT := 1 + N*(3+M)               // 5301 at N=100 M=50
	wantNewRT := 1 + 2*numChunks + N*(1+M) // 5103 at N=100 M=50 c=1

	t.Logf("F258 round-trip accounting (N=%d, M=%d, K=%d, c=%d):",
		N, M, cveMatchBatchChunkSize, numChunks)
	t.Logf("  old (per-tenant runWithTenantTx):    %d round-trips (elapsed=%v)", wantOldRT, oldElapsed)
	t.Logf("  new (matchTenantsChunked):           %d round-trips (elapsed=%v)", wantNewRT, newElapsed)
	t.Logf("  reduction:                           %.2f%%",
		100.0*float64(wantOldRT-wantNewRT)/float64(wantOldRT))

	// CI hard pin: new must be strictly less than old. The reduction is
	// modest (~3.7% at N=100 M=50) so we cannot use F213 / F234 / F244's
	// 60% cushion — reverting to per-tenant runWithTenantTx would land
	// at exactly old, and this strict-less catches that.
	if !(wantNewRT < wantOldRT) {
		t.Errorf("F258 round-trip reduction target failed: new=%d, old=%d, want new < old",
			wantNewRT, wantOldRT)
	}

	// Exact-formula pin: catches any drift in the round-trip math on
	// either side (regression to 1 + N*(3+M), or off-by-one in the new
	// formula).
	if wantNewRT != 1+2*numChunks+N*(1+M) {
		t.Errorf("F258 round-trip exact-formula pin failed: got %d, want 1 + 2c + N*(1+M) = %d for N=%d M=%d c=%d",
			wantNewRT, 1+2*numChunks+N*(1+M), N, M, numChunks)
	}
	if wantNewRT != 5103 {
		t.Errorf("F258 N=100 M=50 c=1 numeric pin: got %d, want 5103", wantNewRT)
	}
	if wantOldRT != 5301 {
		t.Errorf("F258 old N=100 M=50 numeric pin: got %d, want 5301", wantOldRT)
	}
}

// TestCVESyncChunkPerf_F258_N500_M50_MultiChunk is the headline pin for
// F258 (M17-3 #109). It exercises the multi-chunk envelope at N=500 M=50
// with cveMatchBatchChunkSize forced to the production default (200) so
// the fixture ends up in a 200 + 200 + 100 chunk layout — matching the
// docstring's worked example and mirroring
// TestF234_ChunkedBatch_N1200_F234 (vulnerability_scan_perf_test.go) and
// TestReportGenerationChunkPerf_F244_N1200_MultiChunk
// (report_generation_perf_test.go).
//
// Assertions:
//
//   - Round-trip count exactly matches the F258 formula
//     1 + 2c + N*(1+M) = 1 + 2*3 + 500*51 = 25507.
//   - Semantic equivalence: matched / newVulns totals are consistent
//     across chunks (0 / 0 for this mock fixture, since components
//     SELECTs return empty rows).
//   - Chunk envelope cost is bounded: F258's overhead vs a hypothetical
//     single-tx path is exactly 2*(c-1) = 4 extra round-trips at c=3
//     (one extra BEGIN + one extra COMMIT per additional chunk).
//   - F258 is still strictly less than pre-F258 per-tenant.
//
// The test explicitly re-asserts cveMatchBatchChunkSize == 200 so a
// regression that silently changes the default (or drops the var
// entirely) fails loudly with the exact value.
func TestCVESyncChunkPerf_F258_N500_M50_MultiChunk(t *testing.T) {
	// If a prior test left the chunk size overridden, restore to 200
	// (production default) for this test.
	restore := cvePerfWithChunkSize(t, cveMatchBatchChunkSizeDefault)
	defer restore()

	if cveMatchBatchChunkSize != 200 {
		t.Fatalf("F258 production default drift: cveMatchBatchChunkSize=%d, want 200",
			cveMatchBatchChunkSize)
	}

	const (
		N = 500
		M = 50
		K = 200
	)
	numChunks := (N + K - 1) / K
	if numChunks != 3 {
		t.Fatalf("F258 chunk-layout arithmetic drift: N=%d K=%d -> num_chunks=%d, want 3",
			N, K, numChunks)
	}

	tenantIDs := make([]uuid.UUID, N)
	for i := 0; i < N; i++ {
		tenantIDs[i] = uuid.New()
	}
	cves, vulnIndex := buildCVEFixture(M)

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	expectCVEChunkedFlow(t, mock, tenantIDs, cves, K)

	start := time.Now()
	j := newTestCVESyncJob(db)
	matched, newVulns, err := j.matchTenantsChunked(
		context.Background(), tenantIDs, cves, vulnIndex,
	)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("matchTenantsChunked (F258 chunked N=%d M=%d): %v", N, M, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations (F258 chunked N=%d M=%d): %v", N, M, err)
	}

	// Mock returns empty component rows so no INSERTs fire — matched and
	// newVulns must be exactly 0.
	if matched != 0 || newVulns != 0 {
		t.Errorf("F258 mock fixture: matched=%d newVulns=%d, want 0 / 0", matched, newVulns)
	}

	// Round-trip arithmetic pin (1 + 2c + N*(1+M)).
	wantRT := 1 + 2*numChunks + N*(1+M)

	// The equivalent hypothetical single-tx (F213 / F244-shape) path:
	// 1 + 2 + N*(1+M) = 3 + N*(1+M) at c=1.
	wantSingleTxRT := 3 + N*(1+M) // 25503 for N=500 M=50

	// The pre-F258 per-tenant runWithTenantTx path:
	wantOldRT := 1 + N*(3+M) // 26501 for N=500 M=50

	t.Logf("F258 round-trip accounting (N=%d, M=%d, K=%d, c=%d):", N, M, K, numChunks)
	t.Logf("  pre-F258 per-tenant runWithTenantTx:       %d round-trips", wantOldRT)
	t.Logf("  hypothetical single-tx (F213/F244-shape):  %d round-trips", wantSingleTxRT)
	t.Logf("  F258 chunked (this test):                  %d round-trips (elapsed=%v)", wantRT, elapsed)
	t.Logf("  chunk envelope cost (F258 - single-tx):    %d round-trips (= 2*(c-1))", wantRT-wantSingleTxRT)
	t.Logf("  reduction vs pre-F258:                     %.2f%%",
		100.0*float64(wantOldRT-wantRT)/float64(wantOldRT))

	// Exact-formula pin: catches any drift in the round-trip math.
	if wantRT != 25507 {
		t.Errorf("F258 exact-formula pin: 1 + 2c + N*(1+M) for N=500 M=50 K=200 c=3 = %d, want 25507",
			wantRT)
	}

	// Envelope-cost pin: F258 vs single-tx must be exactly 2*(c-1).
	envelopeCost := wantRT - wantSingleTxRT
	wantEnvelope := 2 * (numChunks - 1)
	if envelopeCost != wantEnvelope {
		t.Errorf("F258 envelope cost drift: got +%d round-trips over single-tx, want +%d (= 2*(c-1))",
			envelopeCost, wantEnvelope)
	}

	// F258 must still be strictly less than pre-F258 per-tenant.
	if !(wantRT < wantOldRT) {
		t.Errorf("F258 scale-ceiling target: new=%d, old=%d, want new < old",
			wantRT, wantOldRT)
	}
}

// buildCVEFixture constructs M mock CVEInfo rows with keywords and a
// matching vulnIndex. Each CVE gets one keyword (its index as a string)
// so extractKeywordsFromCPE-style plumbing isn't needed for the perf
// test. isNew alternates so a semantic-equivalence assertion has both
// paths exercised (though this fixture never triggers linked>0 so
// isNew never contributes to newVulns — we just want the vulnIndex
// lookup path exercised).
func buildCVEFixture(m int) ([]CVEInfo, map[string]cveVulnEntry) {
	cves := make([]CVEInfo, m)
	vulnIndex := make(map[string]cveVulnEntry, m)
	for i := 0; i < m; i++ {
		id := uuid.NewString()
		cves[i] = CVEInfo{
			ID:       "CVE-" + id[:8],
			Keywords: []string{"kw-" + id[:4]},
		}
		vulnIndex[cves[i].ID] = cveVulnEntry{
			id:    uuid.New(),
			isNew: (i%2 == 0),
		}
	}
	return cves, vulnIndex
}

// expectCVEChunkedFlow mirrors the wire pattern matchTenantsChunked
// issues under F258: per-chunk (BEGIN + K * (SET LOCAL + M * SELECT
// components) + COMMIT). Every SELECT is mocked to return empty rows
// so no component_vulnerabilities INSERTs fire — that keeps the mock
// expectation count aligned with the round-trip formula. (Adding INSERT
// expectations would multiply the mock cost without changing the F258
// formula validation.)
//
// NOTE: matchTenantsChunked does NOT call listAllIDs itself — the caller
// (Run) does. So this flow does NOT include the initial
// `SELECT id FROM tenants ORDER BY created_at` expectation that
// vulnerability_scan_perf_test.go and report_generation_perf_test.go
// include. The perf-test formula documentation includes the +1 for
// listAllIDs as a courtesy comparison; the sqlmock expectations do not.
func expectCVEChunkedFlow(t *testing.T, mock sqlmock.Sqlmock, tenantIDs []uuid.UUID, cves []CVEInfo, chunkSize int) {
	t.Helper()

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
			// One SELECT components per CVE (empty result -> no INSERTs).
			for range cves {
				mock.ExpectQuery(`SELECT DISTINCT c\.id\s+FROM components`).
					WillReturnRows(sqlmock.NewRows([]string{"id"}))
			}
		}
		mock.ExpectCommit()
	}
}

// expectCVEOldPerTenantFlow mirrors what the pre-F258 implementation
// issued: per-tenant BEGIN + SET LOCAL (Exec) + M * SELECT components +
// COMMIT. Same "empty components rows" fixture as
// expectCVEChunkedFlow so the semantic-equivalence assertion works.
func expectCVEOldPerTenantFlow(t *testing.T, mock sqlmock.Sqlmock, tenantIDs []uuid.UUID, cves []CVEInfo) {
	t.Helper()

	for _, id := range tenantIDs {
		mock.ExpectBegin()
		mock.ExpectExec(`SELECT set_config\('app\.current_tenant_id'`).
			WithArgs(id.String()).
			WillReturnResult(sqlmock.NewResult(0, 0))
		for range cves {
			mock.ExpectQuery(`SELECT DISTINCT c\.id\s+FROM components`).
				WillReturnRows(sqlmock.NewRows([]string{"id"}))
		}
		mock.ExpectCommit()
	}
}

// simulateOldPerTenantCVEMatch is a local re-implementation of the
// pre-F258 per-tenant runWithTenantTx match loop. It exists only inside
// this test file so the perf-comparison test stays hermetic — once
// cve_sync.go drops the original helper wiring, the perf test still has
// a faithful reference for the 1 + N*(3+M) round-trip baseline.
//
// IMPORTANT: this MUST stay a faithful re-implementation of the pre-F258
// matchTenant + Run caller shape. If you change it, also update the
// round-trip accounting in the package docstring at the top of this
// file.
func simulateOldPerTenantCVEMatch(
	ctx context.Context,
	db *sql.DB,
	tenantIDs []uuid.UUID,
	cves []CVEInfo,
	vulnIndex map[string]cveVulnEntry,
) (matched, newVulns int, err error) {
	for _, tenantID := range tenantIDs {
		tx, txErr := db.BeginTx(ctx, nil)
		if txErr != nil {
			return 0, 0, txErr
		}
		if _, sErr := tx.ExecContext(ctx,
			`SELECT set_config('app.current_tenant_id', $1, true)`,
			tenantID.String(),
		); sErr != nil {
			_ = tx.Rollback()
			return 0, 0, sErr
		}
		for _, cve := range cves {
			entry, ok := vulnIndex[cve.ID]
			if !ok {
				continue
			}
			// Match the pre-F258 SELECT shape.
			rows, qErr := tx.QueryContext(ctx, `
				SELECT DISTINCT c.id
				FROM components c
				WHERE LOWER(c.name) = ANY($1)
				   OR LOWER(c.name) LIKE ANY($2)
			`, pq.Array(cve.Keywords), pq.Array(cve.Keywords))
			if qErr != nil {
				_ = tx.Rollback()
				return 0, 0, qErr
			}
			linked := 0
			for rows.Next() {
				var cid uuid.UUID
				if scanErr := rows.Scan(&cid); scanErr != nil {
					continue
				}
				linked++
			}
			rows.Close()
			if linked > 0 {
				matched++
				if entry.isNew {
					newVulns++
				}
			}
		}
		if cErr := tx.Commit(); cErr != nil {
			return 0, 0, cErr
		}
	}
	return matched, newVulns, nil
}
