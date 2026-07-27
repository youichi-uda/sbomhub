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
//   - epss_updated_at is bumped in both cases (it records the last time
//     FIRST answered authoritatively; a cleared row stays distinguishable
//     from a never-synced row, whose epss_updated_at is NULL);
//   - the cleared/updated values are visible through
//     VulnerabilityRepository.GetByCVE — the exact read
//     SSVCService.AutoAssessVulnerability performs.
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
	readRow := func(cve string) (score, pct sql.NullFloat64, ts sql.NullTime) {
		t.Helper()
		if err := appDB.QueryRow(`
			SELECT epss_score, epss_percentile, epss_updated_at
			FROM vulnerabilities WHERE cve_id = $1`, cve).Scan(&score, &pct, &ts); err != nil {
			t.Fatalf("read row %s: %v", cve, err)
		}
		return score, pct, ts
	}
	freshAfter := staleTS.Add(time.Hour) // any bump is >> stale-30d; clock-skew safe

	scoreA, pctA, tsA := readRow(cvePartial)
	if !scoreA.Valid || scoreA.Float64 != 0.9 {
		t.Errorf("%s epss_score = %+v, want 0.9 (score parsed fine; percentile failure must not discard it — stale 0.1 must be replaced)", cvePartial, scoreA)
	}
	if pctA.Valid {
		t.Errorf("%s epss_percentile = %v, want NULL (malformed percentile is no-data, not the stale 0.5)", cvePartial, pctA.Float64)
	}
	if !tsA.Valid || !tsA.Time.After(freshAfter) {
		t.Errorf("%s epss_updated_at = %+v, want bumped past %v", cvePartial, tsA, freshAfter)
	}

	scoreB, pctB, tsB := readRow(cveTombstone)
	if scoreB.Valid {
		t.Errorf("%s epss_score = %v, want NULL (malformed score must clear the stale 0.8, not keep serving it as current)", cveTombstone, scoreB.Float64)
	}
	if pctB.Valid {
		t.Errorf("%s epss_percentile = %v, want NULL (a percentile without a score reads as fabricated '0 score at 0.95 percentile' through the COALESCE readers)", cveTombstone, pctB.Float64)
	}
	if !tsB.Valid || !tsB.Time.After(freshAfter) {
		t.Errorf("%s epss_updated_at = %+v, want bumped (cleared-by-sync stays distinguishable from never-synced)", cveTombstone, tsB)
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
