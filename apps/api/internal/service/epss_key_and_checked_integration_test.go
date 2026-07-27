//go:build integration

// Package service — EPSS write-key fidelity and fetch-attempt timestamp
// (M46 Codex final round, Medium #2 and Medium #3).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run TestEPSSSync_VerbatimKey ./internal/service
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's
// test cache.
//
// Prerequisites (skipped otherwise, same env contract as the sibling EPSS
// integration test whose env/open helpers this file reuses): postgres up,
// DATABASE_URL = sbomhub_app, MIGRATE_DATABASE_URL = sbomhub_migrator,
// schema migrated through 059 (vulnerabilities.epss_checked_at).
//
// The two findings this pins down, both of which are invisible from the
// service's own return values and only observable in the ROW:
//
// Medium #2 — write-key fidelity. vulnerabilities.cve_id is
// `character varying(50)` with a case-sensitive UNIQUE index, no CHECK
// constraint, and neither ingestion path normalizes it
// (VulnerabilityRepository.Create and scheduler/cve_sync.upsertVulnerability
// both store the upstream string verbatim). fetchEPSSScores canonicalizes
// ids with ValidateCVEID because that is the grammar FIRST speaks — pre-fix
// it also KEYED its result map on the canonical form, and that key went
// straight into `UPDATE vulnerabilities ... WHERE cve_id = $3`. For a row
// stored as `cve-2199-...` the sync asked FIRST correctly, matched ZERO rows
// on write, logged a successful batch, and left the stale score being served
// as current — the exact staleness def6a46/9704eb9 set out to eliminate,
// reintroduced through the key. (Measured on the dev DB 2026-07-27: 10,898
// vulnerability rows, of which 0 are currently in this dangerous class, and
// 107 carry synthetic non-CVE ids that ValidateCVEID rejects outright. So
// this is a latent defect, not an active outage — but nothing in the schema
// or the writers prevents it, which is why the fix is structural rather than
// a data migration.)
//
// Medium #3 — epss_checked_at must mean "last fetch attempt". Migration 059
// says exactly that, but pre-fix only CVEs PRESENT in the response `data`
// moved any timestamp. FIRST represents "no EPSS data for this CVE" by
// OMITTING it while still answering HTTP 200 / status OK (verified against
// the live API on 2026-07-27: `?cve=CVE-2026-0001` -> total 0, data []), so
// a CVE FIRST does not cover was fetched every sync and never timestamped.
// The fix advances ONLY epss_checked_at for omitted CVEs; it deliberately
// does NOT tombstone them, because an omission is indistinguishable from a
// truncated page (`total` counts matches, `data` is capped at `limit`, whose
// default 100 equals epssBatchSize exactly) and clearing on omission would
// let one partial upstream response wipe scores on global, cross-tenant rows.
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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/repository"
)

func TestEPSSSync_VerbatimKeyAndCheckedTimestamp(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	appDB := openOrSkipVS(t, appURL)
	migDB := openOrSkipVS(t, migURL)

	var hasChecked bool
	if err := appDB.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM information_schema.columns
			WHERE table_schema='public' AND table_name='vulnerabilities'
			AND column_name='epss_checked_at')`).Scan(&hasChecked); err != nil {
		t.Skipf("epss_checked_at existence check failed: %v -- skipping", err)
	}
	if !hasChecked {
		t.Fatal("vulnerabilities.epss_checked_at not present -- run migrations through 059 first")
	}

	suffix := uuid.New().ID() % 10000000
	// Stored NON-canonically (lowercase). ValidateCVEID normalizes it to the
	// canonical form for the wire, so FIRST is asked the right question — the
	// pre-fix bug was entirely on the write side.
	cveLower := fmt.Sprintf("cve-2199-%07d", suffix)
	// Covered by no EPSS data: FIRST omits it from an otherwise-successful
	// 200. It already carries a score from an earlier sync that must SURVIVE.
	cveOmitted := fmt.Sprintf("CVE-2094-%07d", suffix)

	staleTS := time.Now().Add(-30 * 24 * time.Hour).UTC()
	seed := func(cve string, score, pct float64) {
		t.Helper()
		id := uuid.New()
		if _, err := migDB.Exec(`
			INSERT INTO vulnerabilities (id, cve_id, description, severity,
				epss_score, epss_percentile, epss_updated_at, epss_checked_at)
			VALUES ($1, $2, 'epss key/checked regression seed', 'HIGH', $3, $4, $5, $5)`,
			id, cve, score, pct, staleTS); err != nil {
			t.Fatalf("seed vulnerability %s: %v", cve, err)
		}
		t.Cleanup(func() {
			if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, id); err != nil {
				t.Errorf("C27 cleanup: delete vulnerability %s (%s): %v", id, cve, err)
			}
		})
	}
	seed(cveLower, 0.1, 0.5)   // stale; FIRST answers with a fresh 0.9
	seed(cveOmitted, 0.4, 0.6) // FIRST says nothing; the 0.4 must survive

	// The row really is stored non-canonically — if some future ingestion
	// normalization lands, this test would silently stop testing anything.
	var storedKey string
	if err := appDB.QueryRow(
		`SELECT cve_id FROM vulnerabilities WHERE cve_id = $1`, cveLower).Scan(&storedKey); err != nil {
		t.Fatalf("read back the non-canonical seed key: %v", err)
	}
	if storedKey != cveLower || storedKey == strings.ToUpper(storedKey) {
		t.Fatalf("seed key = %q, want the verbatim non-canonical %q -- the premise of this test is gone", storedKey, cveLower)
	}

	// Canned FIRST response: answers the canonical form of cveLower, and
	// omits cveOmitted entirely (total counts only what is returned).
	canonical := strings.ToUpper(cveLower)
	body := fmt.Sprintf(`{
		"status": "OK", "status-code": 200, "version": "1.0", "total": 1,
		"data": [
			{"cve": %q, "epss": "0.9", "percentile": "0.95", "date": "2026-07-27"}
		]
	}`, canonical)

	var gotCVEParam string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCVEParam = r.URL.Query().Get("cve")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	vulnRepo := repository.NewVulnerabilityRepository(appDB)
	svc := NewEPSSService(vulnRepo, server.URL, false)
	ctx := context.Background()

	// The three steps SyncScores runs per batch.
	scores, unanswered, err := svc.fetchEPSSScores(ctx, []string{cveLower, cveOmitted})
	if err != nil {
		t.Fatalf("fetchEPSSScores: %v", err)
	}
	if len(scores) > 0 {
		if err := vulnRepo.UpdateEPSSScores(ctx, scores); err != nil {
			t.Fatalf("UpdateEPSSScores: %v", err)
		}
	}
	if len(unanswered) > 0 {
		if err := vulnRepo.MarkEPSSChecked(ctx, unanswered); err != nil {
			t.Fatalf("MarkEPSSChecked: %v", err)
		}
	}

	// The request itself was canonical — the DB's casing must never leak onto
	// the wire (FIRST's grammar is the canonical form).
	if !strings.Contains(gotCVEParam, canonical) {
		t.Errorf("cve param = %q, want it to carry the canonical %q", gotCVEParam, canonical)
	}

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

	// --- Medium #2: the non-canonically stored row was actually written.
	scoreL, pctL, updL, chkL := readRow(cveLower)
	if !scoreL.Valid || scoreL.Float64 != 0.9 {
		t.Errorf("%s epss_score = %+v, want 0.9: the UPDATE must target the VERBATIM stored key. A canonicalized key matches no row here, so the sync reports success while the stale 0.1 keeps being served",
			cveLower, scoreL)
	}
	if !pctL.Valid || pctL.Float64 != 0.95 {
		t.Errorf("%s epss_percentile = %+v, want 0.95", cveLower, pctL)
	}
	if !updL.Valid || !updL.Time.After(freshAfter) {
		t.Errorf("%s epss_updated_at = %+v, want bumped past %v (a score was written)", cveLower, updL, freshAfter)
	}
	if !chkL.Valid || !chkL.Time.After(freshAfter) {
		t.Errorf("%s epss_checked_at = %+v, want bumped past %v", cveLower, chkL, freshAfter)
	}

	// --- Medium #3: the omitted CVE keeps its score but records the attempt.
	scoreO, pctO, updO, chkO := readRow(cveOmitted)
	if !chkO.Valid || !chkO.Time.After(freshAfter) {
		t.Errorf("%s epss_checked_at = %+v, want bumped past %v: migration 059 defines the column as the last fetch ATTEMPT, and this CVE WAS fetched — FIRST simply omitted it (its normal encoding of 'no data')",
			cveOmitted, chkO, freshAfter)
	}
	if !scoreO.Valid || scoreO.Float64 != 0.4 {
		t.Errorf("%s epss_score = %+v, want the previous 0.4 preserved: an omission is not an authoritative 'no data' — it is indistinguishable from a truncated page, and tombstoning on it would wipe scores on a GLOBAL cross-tenant row from one partial upstream response",
			cveOmitted, scoreO)
	}
	if !pctO.Valid || pctO.Float64 != 0.6 {
		t.Errorf("%s epss_percentile = %+v, want the previous 0.6 preserved", cveOmitted, pctO)
	}
	if !updO.Valid || updO.Time.After(freshAfter) {
		t.Errorf("%s epss_updated_at = %+v, want the ORIGINAL stale timestamp: no score was written this round, and the gap between checked_at and updated_at is exactly the freshness signal",
			cveOmitted, updO)
	}

	// The 059 invariant still holds on both rows.
	for _, tc := range []struct {
		cve     string
		score   sql.NullFloat64
		updated sql.NullTime
	}{{cveLower, scoreL, updL}, {cveOmitted, scoreO, updO}} {
		if tc.score.Valid != tc.updated.Valid {
			t.Errorf("%s violates `epss_updated_at IS NOT NULL <=> epss_score IS NOT NULL`: score valid=%v, updated_at valid=%v",
				tc.cve, tc.score.Valid, tc.updated.Valid)
		}
	}

	// And the SSVC boundary (GetByCVE is what AutoAssessVulnerability reads)
	// sees the refreshed value under the stored key.
	v, err := vulnRepo.GetByCVE(ctx, cveLower)
	if err != nil {
		t.Fatalf("GetByCVE(%s): %v", cveLower, err)
	}
	if v.EPSSScore == nil || *v.EPSSScore != 0.9 {
		t.Errorf("GetByCVE(%s).EPSSScore = %v, want 0.9", cveLower, v.EPSSScore)
	}
}
