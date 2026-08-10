//go:build integration

// Package scheduler — M55: who owns the metadata on a `vulnerabilities` row,
// and what has to be true for a re-scored CVE to reach the product.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M55CVEMetadata' ./internal/scheduler
//
// # The question this file answers
//
// `vulnerabilities` is the GLOBAL, RLS-free CVE catalogue: one row per CVE,
// shared by every tenant. Two code paths can write it:
//
//	scan     service/nvd.go persistWorkItem — per project, inside the
//	         REQUEST's / the scan job's tenant transaction. On a GetByCVE HIT
//	         it writes the component LINK and nothing else, so a severity NVD
//	         has since raised is discarded. Measured 2026-08-11: a row seeded
//	         LOW / 2.0 is still LOW / 2.0 after a scan whose NVD answer said
//	         CRITICAL / 9.8.
//	cve_sync THIS package — daily, on a tx-free pooled connection, replaying
//	         NVD's lastModStartDate window.
//
// M55 makes cve_sync the OWNER and leaves the scanner as a pure linker. The
// scanner is per-tenant and runs inside a tenant transaction; letting it
// rewrite a global row there would (a) have every tenant's scan fight every
// other tenant's over one shared row and (b) put a global write inside a
// tenant tx, where one refusal discards the whole sweep (M54). cve_sync
// already had the shape of an owner — it just did not finish the job.
//
// # The three holes measured before the fix (2026-08-11, PostgreSQL 15)
//
//		seeded row                       upstream answer          result
//		-------------------------------- ------------------------ ------------
//		LOW, CVE has a vulnerable CPE    CRITICAL                 CRITICAL  ok
//		LOW, CVE has NO CPE at all       CRITICAL                 LOW       #1
//		LOW, source='JVN'                NVD CRITICAL             CRITICAL,
//		                                                          source
//		                                                          still JVN #2
//		CRITICAL from lastModified 07-01 LOW from lastMod 01-01    LOW       #3
//
//	 1. Run() skipped the whole upsert for a CVE whose CPE configurations
//	    yielded no match keywords (`if len(cve.Keywords) == 0 { continue }`).
//	    The keyword list exists for the component-MATCH phase, and gating the
//	    metadata refresh on it means a CVE already in our catalogue — put there
//	    by the keyword-search scanner, which does not need CPE data to match —
//	    is never refreshed. Its severity is frozen at whatever the first fetch
//	    said, forever.
//
//	 2. The refresh wrote NVD's description and severity over a JVN-authored
//	    row while leaving `source` reading 'JVN'. The row then attributed NVD
//	    content to JVN.
//
//	 3. Nothing compared the incoming record's age to the stored one, so
//	    replaying an older NVD page downgraded a severity.
//
// A frozen severity is the failure this product cannot absorb: a CVE
// re-scored LOW -> CRITICAL keeps rendering LOW on the vulnerability page,
// in the CRA report drafted from it, and in `sbomhub scan --fail-on
// critical`, which exits 0.
package scheduler

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

// m55CPEWithKeywords is a `configurations` block carrying one VULNERABLE cpe
// match, which extractKeywordsFromCPE turns into {"acme", "widget"}.
const m55CPEWithKeywords = `[{"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*","vulnerable":true}]}]}]`

// m55CPEEmpty is the shape that froze the row: NVD publishes plenty of CVEs
// with no CPE applicability data — CNA-only records, records still in
// analysis, and records whose only cpeMatch entries are `"vulnerable": false`
// (which extractKeywordsFromCPE also discards). The keyword-search scanner
// matches on DESCRIPTION text, so exactly these CVEs can be in our catalogue.
const m55CPEEmpty = `[]`

// m55Feed renders one NVD 2.0 `/cves/2.0` page holding a single CVE.
func m55Feed(cveID, severity string, score float64, description, published, lastModified, configurations string) string {
	return fmt.Sprintf(`{
		"totalResults": 1, "startIndex": 0, "resultsPerPage": 2000,
		"vulnerabilities": [{"cve": {
			"id": %q,
			"published": %q,
			"lastModified": %q,
			"descriptions": [{"lang": "en", "value": %q}],
			"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": %v, "baseSeverity": %q}}]},
			"configurations": %s
		}}]
	}`, cveID, published, lastModified, description, score, severity, configurations)
}

// m55Row is the catalogue state the product reads.
type m55Row struct {
	severity     string
	score        sql.NullFloat64
	description  string
	source       string
	publishedAt  sql.NullTime
	sourceModAt  sql.NullTime
	epssScore    sql.NullFloat64
	epssChecked  sql.NullTime
	inKEV        bool
	kevDateAdded sql.NullTime
}

func m55Read(t *testing.T, db *sql.DB, cveID string) m55Row {
	t.Helper()
	var r m55Row
	if err := db.QueryRow(`
		SELECT COALESCE(severity, ''), cvss_score, COALESCE(description, ''),
		       COALESCE(source, ''), published_at, source_modified_at,
		       epss_score, epss_checked_at, in_kev, kev_date_added
		FROM vulnerabilities WHERE cve_id = $1`, cveID).
		Scan(&r.severity, &r.score, &r.description, &r.source, &r.publishedAt,
			&r.sourceModAt, &r.epssScore, &r.epssChecked, &r.inKEV, &r.kevDateAdded); err != nil {
		t.Fatalf("read catalogue row %s: %v", cveID, err)
	}
	return r
}

// m55Sync runs ONE CVE-sync tick against a canned single-CVE NVD feed.
// tenantRepo is real but the tenant list is normally empty, so the per-tenant
// match phase is a no-op and only the catalogue write is exercised.
func m55Sync(t *testing.T, appDB *sql.DB, body string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	j := NewCVESyncJob(appDB, repository.NewTenantRepository(appDB), "", 24*time.Hour, nil, srv.URL, false)
	if err := j.Run(context.Background()); err != nil {
		t.Fatalf("CVESyncJob.Run: %v", err)
	}
}

// m55SeedLegacy writes the row a previous scan would have left: LOW, scored
// 2.0, with EPSS and KEV columns already populated by their own jobs so the
// refresh can be shown NOT to touch them.
func m55SeedLegacy(t *testing.T, migDB *sql.DB, cveID, source string) {
	t.Helper()
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID); err != nil {
			t.Errorf("cleanup: delete %s: %v", cveID, err)
		}
	})
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source,
			published_at, updated_at, epss_score, epss_percentile, epss_updated_at, epss_checked_at,
			in_kev, kev_date_added)
		VALUES ($1, $2, 'first-fetch description', 'LOW', 2.0, $3,
			'2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z', 0.25, 0.9, NOW(), NOW(),
			true, '2025-02-02')`,
		uuid.New(), cveID, source); err != nil {
		t.Fatalf("seed %s: %v", cveID, err)
	}
}

func m55CVEID(t *testing.T) string {
	t.Helper()
	return "CVE-2091-" + fmt.Sprintf("%07d", uuid.New().ID()%10000000)
}

// TestM55CVEMetadata_RefreshDoesNotDependOnCPEKeywords is hole #1: the CVE is
// already in the catalogue, NVD has re-scored it LOW -> CRITICAL, and the
// record carries no CPE applicability data. Pre-fix the row stays LOW.
func TestM55CVEMetadata_RefreshDoesNotDependOnCPEKeywords(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	cveID := m55CVEID(t)
	m55SeedLegacy(t, migDB, cveID, "NVD")

	m55Sync(t, appDB, m55Feed(cveID, "CRITICAL", 9.8, "re-scored: remote code execution",
		"2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z", m55CPEEmpty))

	got := m55Read(t, migDB, cveID)
	if got.severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL: NVD re-scored this CVE and the catalogue kept the first fetch's value. "+
			"A CVE with no CPE applicability data is still a CVE we are serving; gating the metadata refresh on the "+
			"component-MATCH keyword list freezes its severity forever", got.severity)
	}
	if !got.score.Valid || got.score.Float64 != 9.8 {
		t.Errorf("cvss_score = %v (valid=%v), want 9.8", got.score.Float64, got.score.Valid)
	}
	if got.description != "re-scored: remote code execution" {
		t.Errorf("description = %q, want the re-scored text", got.description)
	}
	// published_at is part of the record and NVD does correct it.
	if !got.publishedAt.Valid || !got.publishedAt.Time.UTC().Equal(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("published_at = %v (valid=%v), want 2026-06-01", got.publishedAt.Time.UTC(), got.publishedAt.Valid)
	}
	// The refresh must stay out of the columns other jobs own.
	if !got.epssScore.Valid || got.epssScore.Float64 != 0.25 {
		t.Errorf("epss_score = %v (valid=%v), want the EPSS job's 0.25 untouched — EPSS is owned by "+
			"repository.UpdateEPSSScores / MarkEPSSChecked, not by the catalogue refresh", got.epssScore.Float64, got.epssScore.Valid)
	}
	if !got.epssChecked.Valid {
		t.Error("epss_checked_at was cleared; the catalogue refresh must not touch EPSS freshness columns")
	}
	if !got.inKEV || !got.kevDateAdded.Valid {
		t.Errorf("in_kev = %v / kev_date_added valid = %v, want the KEV job's values untouched", got.inKEV, got.kevDateAdded.Valid)
	}
}

// TestM55CVEMetadata_RefreshStillWorksWithCPEKeywords is the control for the
// test above: the path that already worked must keep working.
func TestM55CVEMetadata_RefreshStillWorksWithCPEKeywords(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	cveID := m55CVEID(t)
	m55SeedLegacy(t, migDB, cveID, "NVD")

	m55Sync(t, appDB, m55Feed(cveID, "CRITICAL", 9.8, "re-scored with cpe data",
		"2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z", m55CPEWithKeywords))

	if got := m55Read(t, migDB, cveID); got.severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL", got.severity)
	}
}

// TestM55CVEMetadata_StaleUpstreamRecordCannotDowngrade is hole #3. The first
// tick applies a CRITICAL record modified 2026-07-01; the second replays an
// older record (lastModified 2026-01-01) that says LOW. The older record must
// not win.
func TestM55CVEMetadata_StaleUpstreamRecordCannotDowngrade(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	cveID := m55CVEID(t)
	m55SeedLegacy(t, migDB, cveID, "NVD")

	m55Sync(t, appDB, m55Feed(cveID, "CRITICAL", 9.8, "current: remote code execution",
		"2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z", m55CPEWithKeywords))
	if got := m55Read(t, migDB, cveID); got.severity != "CRITICAL" {
		t.Fatalf("setup: severity = %q after the fresh record, want CRITICAL", got.severity)
	}

	m55Sync(t, appDB, m55Feed(cveID, "LOW", 2.0, "superseded: minor issue",
		"2026-06-01T00:00:00Z", "2026-01-01T00:00:00Z", m55CPEWithKeywords))

	got := m55Read(t, migDB, cveID)
	if got.severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL: an NVD record modified 2026-01-01 overwrote one modified "+
			"2026-07-01. updated_at cannot arbitrate this — it is OUR write clock, so the stale write always "+
			"looks like the most recent one", got.severity)
	}
	if got.description != "current: remote code execution" {
		t.Errorf("description = %q, want the newer record's text", got.description)
	}
	if !got.sourceModAt.Valid || !got.sourceModAt.Time.UTC().Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("source_modified_at = %v (valid=%v), want 2026-07-01 — the refused write must not move it backwards either",
			got.sourceModAt.Time.UTC(), got.sourceModAt.Valid)
	}
}

// TestM55CVEMetadata_ReapplyingTheSameRecordIsAllowed keeps the staleness
// guard from freezing the row: `<=`, not `<`. Re-running a tick over an
// unchanged NVD record must still be able to repair a half-written row.
func TestM55CVEMetadata_ReapplyingTheSameRecordIsAllowed(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	cveID := m55CVEID(t)
	m55SeedLegacy(t, migDB, cveID, "NVD")

	feed := func(desc string) string {
		return m55Feed(cveID, "HIGH", 7.5, desc, "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z", m55CPEWithKeywords)
	}
	m55Sync(t, appDB, feed("first application"))
	m55Sync(t, appDB, feed("second application of the same lastModified"))

	if got := m55Read(t, migDB, cveID); got.description != "second application of the same lastModified" {
		t.Errorf("description = %q: a record with the SAME lastModified must still be applied, "+
			"or a row that was half-written can never be repaired", got.description)
	}
}

// TestM55CVEMetadata_SourceFollowsTheContent is hole #2: the refresh writes
// NVD's content, so the row must say NVD. Leaving 'JVN' there attributes NVD
// text and an NVD score to a Japanese advisory that never said either.
func TestM55CVEMetadata_SourceFollowsTheContent(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	cveID := m55CVEID(t)
	m55SeedLegacy(t, migDB, cveID, "JVN")

	m55Sync(t, appDB, m55Feed(cveID, "CRITICAL", 9.8, "nvd english description",
		"2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z", m55CPEWithKeywords))

	got := m55Read(t, migDB, cveID)
	if got.description != "nvd english description" || got.severity != "CRITICAL" {
		t.Fatalf("setup: row was not refreshed (severity=%q description=%q)", got.severity, got.description)
	}
	if got.source != "NVD" {
		t.Errorf("source = %q, want NVD: the row now carries NVD's description and NVD's score, so attributing "+
			"it to JVN is a false provenance claim on the record an auditor reads", got.source)
	}
}

// TestM55CVEMetadata_UnparseablePublishedStaysNULL: `published` that does not
// parse must leave published_at unset, not store the year-1 zero time. Same
// class as the cvss_score 0.0 sentinel M46 removed — a sentinel that reads as
// a real value to everything downstream.
func TestM55CVEMetadata_UnparseablePublishedStaysNULL(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	// INSERT path: the CVE is not in the catalogue yet.
	cveID := m55CVEID(t)
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID); err != nil {
			t.Errorf("cleanup: delete %s: %v", cveID, err)
		}
	})
	m55Sync(t, appDB, m55Feed(cveID, "HIGH", 7.5, "no usable published date",
		"", "2026-07-01T00:00:00Z", m55CPEWithKeywords))

	got := m55Read(t, migDB, cveID)
	if got.publishedAt.Valid {
		t.Errorf("published_at = %v, want NULL: an unparseable `published` was stored as the year-1 zero time, "+
			"which every reader renders as a real date", got.publishedAt.Time.UTC())
	}

	// UPDATE path: a stored published_at must survive a record that has none,
	// rather than being overwritten with the sentinel or cleared.
	existing := m55CVEID(t)
	m55SeedLegacy(t, migDB, existing, "NVD")
	m55Sync(t, appDB, m55Feed(existing, "HIGH", 7.5, "refresh without a published date",
		"", "2026-07-01T00:00:00Z", m55CPEWithKeywords))

	upd := m55Read(t, migDB, existing)
	if upd.description != "refresh without a published date" {
		t.Fatalf("setup: row was not refreshed (description=%q)", upd.description)
	}
	if !upd.publishedAt.Valid || !upd.publishedAt.Time.UTC().Equal(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("published_at = %v (valid=%v), want the seeded 2025-01-01 preserved", upd.publishedAt.Time.UTC(), upd.publishedAt.Valid)
	}
}

// TestM55CVEMetadata_KeywordlessCVENotInCatalogueIsNotInserted pins the other
// half of hole #1's fix. Refreshing a keyword-less CVE must NOT turn into
// "insert every CVE NVD has ever modified": the catalogue holds CVEs we can
// tie to a component, and a CVE with no CPE data and no existing row is
// neither matched nor wanted.
func TestM55CVEMetadata_KeywordlessCVENotInCatalogueIsNotInserted(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	cveID := m55CVEID(t)
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID); err != nil {
			t.Errorf("cleanup: delete %s: %v", cveID, err)
		}
	})

	m55Sync(t, appDB, m55Feed(cveID, "CRITICAL", 9.8, "unrelated cve with no cpe data",
		"2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z", m55CPEEmpty))

	var n int
	if err := migDB.QueryRow(`SELECT count(*) FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("catalogue rows for an unmatched keyword-less CVE = %d, want 0: the refresh must be "+
			"update-only, or one tick imports NVD's entire modification window", n)
	}
}
