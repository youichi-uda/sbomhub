//go:build integration

// Package service — EPSS sync staleness regression test (M46 Codex round C,
// Medium: service/epss.go malformed-item skip).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run TestEPSSSync_MalformedItem ./internal/service
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's
// test cache.
//
// Prerequisites (skipped otherwise — same env contract as the VEX
// suggestions integration test, whose env/open helpers this file reuses):
// postgres up, DATABASE_URL = sbomhub_app, MIGRATE_DATABASE_URL =
// sbomhub_migrator, schema migrated through 055 (vulnerabilities.epss_*).
//
// What this test pins down (the Codex finding's exact failure scenario):
//
// ca94806 made fetchEPSSScores skip a FIRST item whose epss/percentile
// string does not parse (correct: never fabricate 0.0). But `continue`
// leaves the previous sync's row values in place: a CVE that already has
// epss_score=0.1 in the DB and comes back from FIRST as
// {epss:"0.9", percentile:"broken"} kept serving the stale 0.1 as if
// current — SSVC auto-assessment (GetByCVE -> EPSSScore > 0.5 =>
// automatable), the dashboards, notifications and reports all read it with
// no freshness signal. A percentile-only parse failure additionally threw
// away a perfectly good score.
//
// Contract after the fix (kept by this test):
//   - percentile malformed, score OK  -> score UPDATED, percentile NULL;
//   - score malformed                 -> BOTH columns cleared to NULL
//     ("no data" — the state every reader already handles) instead of
//     silently serving the previous value;
//   - the cleared/updated values are visible through
//     VulnerabilityRepository.GetByCVE — the exact read
//     SSVCService.AutoAssessVulnerability performs.
//
// Timestamp contract (M46 Codex final round, Low #2 — migration 059):
//
// def6a46 bumped epss_updated_at on clears too, so it could carry a fresh
// timestamp while epss_score was NULL. That contradicts migration 055, whose
// DDL COMMENT defines the column as "last successful EPSS sync ... NULL until
// the scheduled epss_sync writes a score" — an API consumer seeing a recent
// epss_updated_at could reasonably read it as "a score was refreshed just
// now". 059 splits the two questions instead of silently redefining a column
// that is already published as `epss_updated_at` in the JSON API:
//
//	epss_updated_at  = when a SCORE was last written  (055 semantics, restored)
//	epss_checked_at  = when FIRST was last CONSULTED  (new, additive)
//
// which restores the invariant `epss_updated_at IS NOT NULL <=> epss_score
// IS NOT NULL` and keeps the three states def6a46 needed distinguishable:
//
//	never synced      : score NULL, updated_at NULL, checked_at NULL
//	cleared by a sync : score NULL, updated_at NULL, checked_at set
//	scored            : score set,  updated_at set,  checked_at set
//
// The test drives fetchEPSSScores + UpdateEPSSScores — the two steps
// SyncScores runs per batch — rather than SyncScores itself, because
// SyncScores sweeps GetAllCVEIDs over the whole shared dev DB (measured
// 10,898 CVEs on 2026-07-27 = 109 batches x 500ms sleep); the batching loop
// adds nothing to the parse/persist contract under test.
//
// vulnerabilities is a global cache without RLS or tenant CASCADE, so seeds
// go through the migrator handle and are reaped explicitly via t.Cleanup
// (C27). No tenant rows are created.
package service

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/repository"
)

func TestEPSSSync_MalformedItem_ClearsStaleValuesInsteadOfKeepingThem(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	appDB := openOrSkipVS(t, appURL)
	migDB := openOrSkipVS(t, migURL)

	// Schema readiness: the 055 EPSS columns must exist.
	var hasEPSS bool
	if err := appDB.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM information_schema.columns
			WHERE table_schema='public' AND table_name='vulnerabilities'
			AND column_name='epss_score')`).Scan(&hasEPSS); err != nil {
		t.Skipf("epss_score existence check failed: %v -- skipping", err)
	}
	if !hasEPSS {
		t.Skip("vulnerabilities.epss_score not present -- run migrations through 055 first")
	}
	var hasChecked bool
	if err := appDB.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM information_schema.columns
			WHERE table_schema='public' AND table_name='vulnerabilities'
			AND column_name='epss_checked_at')`).Scan(&hasChecked); err != nil {
		t.Skipf("epss_checked_at existence check failed: %v -- skipping", err)
	}
	if !hasChecked {
		t.Fatal("vulnerabilities.epss_checked_at not present -- run migrations through 059 first (M46 Codex final round Low #2)")
	}

	// Unique, ValidateCVEID-conformant IDs (^CVE-\d{4}-\d{4,}$) so parallel
	// runs on the shared dev DB cannot collide on the cve_id UNIQUE key.
	suffix := uuid.New().ID() % 10000000
	cvePartial := fmt.Sprintf("CVE-2099-%07d", suffix)   // FIRST: score OK, percentile broken
	cveTombstone := fmt.Sprintf("CVE-2098-%07d", suffix) // FIRST: score broken

	// Both rows start with a STALE value from a previous sync.
	staleTS := time.Now().Add(-30 * 24 * time.Hour).UTC()
	seed := func(cve string, score, pct float64) {
		t.Helper()
		id := uuid.New()
		if _, err := migDB.Exec(`
			INSERT INTO vulnerabilities (id, cve_id, description, severity,
				epss_score, epss_percentile, epss_updated_at)
			VALUES ($1, $2, 'epss stale regression seed', 'HIGH', $3, $4, $5)`,
			id, cve, score, pct, staleTS); err != nil {
			t.Fatalf("seed vulnerability %s: %v", cve, err)
		}
		t.Cleanup(func() {
			if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, id); err != nil {
				t.Errorf("C27 cleanup: delete vulnerability %s (%s): %v", id, cve, err)
			}
		})
	}
	seed(cvePartial, 0.1, 0.5)   // the finding's literal example: stale 0.1
	seed(cveTombstone, 0.8, 0.6) // stale HIGH score that must not survive

	// Control row: never answered by FIRST at all. Its all-NULL timestamp
	// pair is what the cleared row must stay distinguishable FROM (059).
	cveNeverSynced := fmt.Sprintf("CVE-2095-%07d", suffix)
	neverID := uuid.New()
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity)
		VALUES ($1, $2, 'epss never-synced control', 'HIGH')`,
		neverID, cveNeverSynced); err != nil {
		t.Fatalf("seed never-synced control %s: %v", cveNeverSynced, err)
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, neverID); err != nil {
			t.Errorf("C27 cleanup: delete vulnerability %s (%s): %v", neverID, cveNeverSynced, err)
		}
	})

	// Canned FIRST response: one percentile-broken item, one score-broken item.
	body := fmt.Sprintf(`{
		"status": "OK", "status-code": 200, "version": "1.0", "total": 2,
		"data": [
			{"cve": %q, "epss": "0.9", "percentile": "broken", "date": "2026-07-27"},
			{"cve": %q, "epss": "broken", "percentile": "0.95", "date": "2026-07-27"}
		]
	}`, cvePartial, cveTombstone)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	vulnRepo := repository.NewVulnerabilityRepository(appDB)
	svc := NewEPSSService(vulnRepo, server.URL, false)
	ctx := context.Background()

	// The two steps SyncScores performs per batch, guard included: pre-fix,
	// both items were skipped, scores came back empty and the UPDATE never
	// ran — which is exactly how the stale values survived.
	scores, err := svc.fetchEPSSScores(ctx, []string{cvePartial, cveTombstone})
	if err != nil {
		t.Fatalf("fetchEPSSScores: %v", err)
	}
	if len(scores) > 0 {
		if err := vulnRepo.UpdateEPSSScores(ctx, scores); err != nil {
			t.Fatalf("UpdateEPSSScores: %v", err)
		}
	}
	if len(scores) != 2 {
		t.Errorf("scores map covers %d of 2 answered CVEs; a malformed item must yield an explicit entry (partial keep or clear), not a skip", len(scores))
	}

	// --- Raw column state (reader-independent proof).
	readRow := func(cve string) (score, pct sql.NullFloat64, updated, checked sql.NullTime) {
		t.Helper()
		if err := appDB.QueryRow(`
			SELECT epss_score, epss_percentile, epss_updated_at, epss_checked_at
			FROM vulnerabilities WHERE cve_id = $1`, cve).Scan(&score, &pct, &updated, &checked); err != nil {
			t.Fatalf("read row %s: %v", cve, err)
		}
		return score, pct, updated, checked
	}
	freshAfter := staleTS.Add(time.Hour) // any bump is >> stale-30d; clock-skew safe

	scoreA, pctA, updA, chkA := readRow(cvePartial)
	if !scoreA.Valid || scoreA.Float64 != 0.9 {
		t.Errorf("%s epss_score = %+v, want 0.9 (score parsed fine; percentile failure must not discard it — stale 0.1 must be replaced)", cvePartial, scoreA)
	}
	if pctA.Valid {
		t.Errorf("%s epss_percentile = %v, want NULL (malformed percentile is no-data, not the stale 0.5)", cvePartial, pctA.Float64)
	}
	// A score WAS written this round, so both timestamps advance.
	if !updA.Valid || !updA.Time.After(freshAfter) {
		t.Errorf("%s epss_updated_at = %+v, want bumped past %v (a score was written)", cvePartial, updA, freshAfter)
	}
	if !chkA.Valid || !chkA.Time.After(freshAfter) {
		t.Errorf("%s epss_checked_at = %+v, want bumped past %v (FIRST was consulted)", cvePartial, chkA, freshAfter)
	}

	scoreB, pctB, updB, chkB := readRow(cveTombstone)
	if scoreB.Valid {
		t.Errorf("%s epss_score = %v, want NULL (malformed score must clear the stale 0.8, not keep serving it as current)", cveTombstone, scoreB.Float64)
	}
	if pctB.Valid {
		t.Errorf("%s epss_percentile = %v, want NULL (a percentile without a score reads as fabricated '0 score at 0.95 percentile' through the COALESCE readers)", cveTombstone, pctB.Float64)
	}
	// No score was written, so epss_updated_at must be CLEARED — not bumped
	// (059 / Low #2): migration 055 defines it as "last successful sync,
	// NULL until a score is written", and a fresh timestamp beside a NULL
	// score reads to an API consumer as a just-refreshed score. The stale
	// 30-day-old value must not survive either.
	if updB.Valid {
		t.Errorf("%s epss_updated_at = %+v, want NULL: no score was written this round, and 055 defines the column as the last SUCCESSFUL sync (a timestamp beside a NULL score reads as a fresh score)", cveTombstone, updB)
	}
	// ...but the sync DID happen, and that is what keeps a cleared row
	// distinguishable from a never-synced one.
	if !chkB.Valid || !chkB.Time.After(freshAfter) {
		t.Errorf("%s epss_checked_at = %+v, want bumped past %v (cleared-by-sync must stay distinguishable from never-synced)", cveTombstone, chkB, freshAfter)
	}

	// Control: never answered by FIRST => both timestamps still NULL. This is
	// what makes the cleared row's checked_at meaningful.
	scoreC, pctC, updC, chkC := readRow(cveNeverSynced)
	if scoreC.Valid || pctC.Valid || updC.Valid || chkC.Valid {
		t.Errorf("%s (never synced) = score %+v pct %+v updated %+v checked %+v, want all NULL",
			cveNeverSynced, scoreC, pctC, updC, chkC)
	}

	// The invariant 055 promised and 059 restores, stated directly.
	for _, tc := range []struct {
		cve     string
		score   sql.NullFloat64
		updated sql.NullTime
	}{
		{cvePartial, scoreA, updA},
		{cveTombstone, scoreB, updB},
		{cveNeverSynced, scoreC, updC},
	} {
		if tc.score.Valid != tc.updated.Valid {
			t.Errorf("%s violates `epss_updated_at IS NOT NULL <=> epss_score IS NOT NULL`: score valid=%v, updated_at valid=%v",
				tc.cve, tc.score.Valid, tc.updated.Valid)
		}
	}

	// --- The SSVC boundary: AutoAssessVulnerability reads EPSS through
	// GetByCVE and applies `*EPSSScore > 0.5 => automatable=yes`. The stale
	// 0.8 tombstone row must read as nil ("no data" -> automatable stays
	// no/manual), and the partial row must expose the fresh 0.9.
	va, err := vulnRepo.GetByCVE(ctx, cvePartial)
	if err != nil {
		t.Fatalf("GetByCVE(%s): %v", cvePartial, err)
	}
	if va.EPSSScore == nil || *va.EPSSScore != 0.9 {
		t.Errorf("GetByCVE(%s).EPSSScore = %v, want 0.9 (SSVC auto-assess must see the fresh score)", cvePartial, va.EPSSScore)
	}
	if va.EPSSPercentile != nil {
		t.Errorf("GetByCVE(%s).EPSSPercentile = %v, want nil", cvePartial, *va.EPSSPercentile)
	}
	vb, err := vulnRepo.GetByCVE(ctx, cveTombstone)
	if err != nil {
		t.Fatalf("GetByCVE(%s): %v", cveTombstone, err)
	}
	if vb.EPSSScore != nil {
		t.Errorf("GetByCVE(%s).EPSSScore = %v, want nil (cleared; SSVC must see 'no data', not the stale 0.8)", cveTombstone, *vb.EPSSScore)
	}
}
