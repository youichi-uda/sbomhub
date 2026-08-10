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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
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

// m55FeedMany renders one NVD 2.0 page holding several CVEs, all with the same
// scoring — the shape a post-migration sync sees when a batch of legacy rows is
// re-scored together.
func m55FeedMany(cveIDs []string, severity string, score float64, description, published, lastModified, configurations string) string {
	items := make([]string, 0, len(cveIDs))
	for _, id := range cveIDs {
		items = append(items, fmt.Sprintf(`{"cve": {
			"id": %q,
			"published": %q,
			"lastModified": %q,
			"descriptions": [{"lang": "en", "value": %q}],
			"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": %v, "baseSeverity": %q}}]},
			"configurations": %s
		}}`, id, published, lastModified, description, score, severity, configurations))
	}
	return fmt.Sprintf(`{"totalResults": %d, "startIndex": 0, "resultsPerPage": 2000, "vulnerabilities": [%s]}`,
		len(items), strings.Join(items, ","))
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
	m55ProtectWatermark(t, migDB)

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
	m55ProtectWatermark(t, migDB)

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
	m55ProtectWatermark(t, migDB)

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

// TestM55CVEMetadata_ReapplyingTheSameRecordDoesNotOverwrite is the sync-level
// half of the `<` rule (Codex M55 S2, High). Replaying a tick over an
// unchanged upstream timestamp must be a no-op on the row, not a
// last-write-wins race between whatever two bodies happen to carry that
// timestamp.
func TestM55CVEMetadata_ReapplyingTheSameRecordDoesNotOverwrite(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m55ProtectWatermark(t, migDB)

	cveID := m55CVEID(t)
	m55SeedLegacy(t, migDB, cveID, "NVD")

	feed := func(desc, severity string, score float64) string {
		return m55Feed(cveID, severity, score, desc, "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z", m55CPEWithKeywords)
	}
	m55Sync(t, appDB, feed("first application", "CRITICAL", 9.8))
	if got := m55Read(t, migDB, cveID); got.severity != "CRITICAL" {
		t.Fatalf("setup: severity = %q after the first application, want CRITICAL", got.severity)
	}

	m55Sync(t, appDB, feed("stale mirror body at the same lastModified", "LOW", 2.0))
	got := m55Read(t, migDB, cveID)
	if got.severity != "CRITICAL" || got.description != "first application" {
		t.Errorf("row = %s / %q, want CRITICAL / \"first application\": a replay under an unchanged upstream "+
			"timestamp overwrote the row", got.severity, got.description)
	}
}

// TestM55CVEMetadata_SourceFollowsTheContent is hole #2: the refresh writes
// NVD's content, so the row must say NVD. Leaving 'JVN' there attributes NVD
// text and an NVD score to a Japanese advisory that never said either.
func TestM55CVEMetadata_SourceFollowsTheContent(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m55ProtectWatermark(t, migDB)

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
	m55ProtectWatermark(t, migDB)

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
	m55ProtectWatermark(t, migDB)

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

// m55AwaitLockWaiter blocks until some backend is waiting for a lock, i.e.
// until the racing insert has demonstrably reached the contended
// unique-index entry. A speculative insertion blocks on the inserting
// transaction's XID rather than on the relation, so this looks at every
// ungranted lock. pg_locks is readable by any role.
func m55AwaitLockWaiter(t *testing.T, db *sql.DB, holderXID int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		// Scoped to the HOLDER'S transaction id. "Any ungranted lock in the
		// cluster" would be satisfied by an unrelated waiter, and the test
		// would then commit before the race ever happened and pass against the
		// check-then-insert implementation too (Codex M55 R3, Low). A duplicate
		// key against an uncommitted inserter is a ShareLock wait on that
		// inserter's XID.
		if err := db.QueryRow(`
			SELECT count(*) FROM pg_locks
			WHERE NOT granted AND locktype = 'transactionid' AND transactionid = $1::text::xid`,
			holderXID).Scan(&waiting); err != nil {
			t.Fatalf("poll pg_locks: %v", err)
		}
		if waiting > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no backend ever blocked on the competing creator's transaction: the racing insert never reached the " +
		"contended unique-index entry, so this test would pass against the check-then-insert implementation too")
}

// m55PinWatermark snapshots system_settings.cve_sync_last_run (including its
// absence), sets it to `at`, and restores the original in t.Cleanup.
//
// Every m55Sync call runs the real job, which moves this GLOBAL row. Leaving
// it moved would hand the next suite — or a shared integration database — a
// different scheduler position than it started with (Codex M55 R1, Low).
func m55PinWatermark(t *testing.T, migDB *sql.DB, at time.Time) {
	t.Helper()
	m55ProtectWatermark(t, migDB)
	if _, err := migDB.Exec(`
		INSERT INTO system_settings (key, value, updated_at) VALUES ('cve_sync_last_run', $1, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()`, at.Format(time.RFC3339)); err != nil {
		t.Fatalf("pin cve_sync_last_run: %v", err)
	}
}

// m55ProtectWatermark restores system_settings.cve_sync_last_run — including
// its absence — after the test.
//
// EVERY test that calls m55Sync needs it, not just the ones that assert on it
// (Codex M55 R2, Low): m55Sync runs the real job, which moves this GLOBAL row,
// so an unprotected test hands the next one a scheduler position it did not
// choose.
func m55ProtectWatermark(t *testing.T, migDB *sql.DB) {
	t.Helper()
	m55ProtectSetting(t, migDB, "cve_sync_last_run")
}

// m55ProtectSetting snapshots one system_settings row (or its absence) and
// restores it in t.Cleanup.
func m55ProtectSetting(t *testing.T, migDB *sql.DB, key string) {
	t.Helper()
	var before sql.NullString
	if err := migDB.QueryRow(`SELECT value FROM system_settings WHERE key = $1`, key).Scan(&before); err != nil {
		if err != sql.ErrNoRows {
			t.Fatalf("read %s: %v", key, err)
		}
		before = sql.NullString{}
	}
	t.Cleanup(func() {
		var err error
		if before.Valid {
			_, err = migDB.Exec(`
				INSERT INTO system_settings (key, value, updated_at) VALUES ($1, $2, NOW())
				ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`, key, before.String)
		} else {
			_, err = migDB.Exec(`DELETE FROM system_settings WHERE key = $1`, key)
		}
		if err != nil {
			t.Errorf("restore %s: %v", key, err)
		}
	})
}

func m55Watermark(t *testing.T, migDB *sql.DB) string {
	t.Helper()
	var v string
	if err := migDB.QueryRow(`SELECT value FROM system_settings WHERE key = 'cve_sync_last_run'`).Scan(&v); err != nil {
		t.Fatalf("read cve_sync_last_run: %v", err)
	}
	return v
}

// TestM55CVEMetadata_AFailedWriteIsNotRetried states the ACCEPTED LIMITATION
// rather than a fix, and it is here so the limitation is measured instead of
// asserted in a comment.
//
// A catalogue write that the database refuses is not retried: the watermark
// advances, the CVE keeps its previously stored metadata, and it is offered
// again only when upstream next modifies it.
//
// M55 built a retry policy for this — hold the watermark, bound the hold, mark
// when retries began — and removed it again after six review rounds in which
// that machinery produced five High findings of its own and closed nothing the
// freshness guard needed. What makes the removal safe is the second half of
// this test: the failed write leaves source_modified_at untouched, so the
// guard still admits the NEXT record for that CVE. The failure costs one
// refresh opportunity; it is not sticky.
//
// The failure used here is a severity longer than `severity varchar(20)` — a
// real shape (an upstream vocabulary change) and, unlike a killed connection,
// reproducible.
func TestM55CVEMetadata_AFailedWriteIsNotRetried(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	pinned := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	m55PinWatermark(t, migDB, pinned)

	cveID := m55CVEID(t)
	m55SeedLegacy(t, migDB, cveID, "NVD")

	oversized := "CRITICALCRITICALCRITICALCRITICA" // 31 chars: refused by the column
	m55Sync(t, appDB, m55Feed(cveID, oversized, 9.8, "write will be refused",
		"2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z", m55CPEEmpty))

	// The limitation: the window moves on regardless.
	if got := m55Watermark(t, migDB); got == pinned.Format(time.RFC3339) {
		t.Errorf("cve_sync_last_run = %q, want it advanced: this build does NOT hold the watermark to retry "+
			"failed catalogue writes, and a test that lets the old hold back in silently would hide that", got)
	}
	row := m55Read(t, migDB, cveID)
	if row.severity != "LOW" {
		t.Errorf("severity = %q, want the seeded LOW — the refused write must not have partially landed", row.severity)
	}
	// The reason the limitation is affordable: nothing was poisoned.
	if row.sourceModAt.Valid {
		t.Errorf("source_modified_at = %v, want NULL: a REFUSED write must not record a freshness timestamp, or "+
			"the guard would defend metadata that was never written", row.sourceModAt.Time.UTC())
	}

	// And the next record for the same CVE is still accepted.
	m55Sync(t, appDB, m55Feed(cveID, "CRITICAL", 9.8, "the next record lands",
		"2026-06-01T00:00:00Z", "2026-07-02T00:00:00Z", m55CPEEmpty))
	if got := m55Read(t, migDB, cveID); got.severity != "CRITICAL" {
		t.Errorf("severity = %q after the next record, want CRITICAL: a failed write must not make the row "+
			"permanently unwritable — that is what makes dropping the retry policy affordable", got.severity)
	}
}

// TestM55CVEMetadata_LegacyNULLRowsAreRefreshedByTheFirstSync is the migration
// question in its production shape: on the day 066 ships, EVERY row in the
// catalogue has source_modified_at NULL.
//
// NULL must mean "unknown", not "newer than everything". If the guard read it
// as the latter, shipping 066 would freeze the entire existing catalogue —
// strictly worse than the defect M55 set out to fix. This drives a batch of
// legacy rows through one real sync tick and requires every one of them to be
// refreshed AND dated, after which they are arbitrated normally.
func TestM55CVEMetadata_LegacyNULLRowsAreRefreshedByTheFirstSync(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m55ProtectWatermark(t, migDB)

	const n = 25
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id := m55CVEID(t)
		// Seeded WITHOUT source_modified_at: exactly what every pre-066 row
		// and every scanner-created row looks like.
		if _, err := migDB.Exec(`
			INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source, published_at, updated_at)
			VALUES ($1, $2, 'pre-066 row', 'LOW', 2.0, 'NVD', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')`,
			uuid.New(), id); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
		ids = append(ids, id)
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = ANY($1)`, pq.Array(ids)); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	var nullBefore int
	if err := migDB.QueryRow(`SELECT count(*) FROM vulnerabilities WHERE cve_id = ANY($1) AND source_modified_at IS NULL`,
		pq.Array(ids)).Scan(&nullBefore); err != nil {
		t.Fatalf("count before: %v", err)
	}
	if nullBefore != n {
		t.Fatalf("setup: %d of %d rows carry a NULL source_modified_at, want all of them", nullBefore, n)
	}

	// One tick, one page, every seeded CVE re-scored CRITICAL.
	body := m55FeedMany(ids, "CRITICAL", 9.8, "refreshed by the first post-066 sync",
		"2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z", m55CPEEmpty)
	m55Sync(t, appDB, body)

	var refreshed, dated int
	if err := migDB.QueryRow(`
		SELECT count(*) FILTER (WHERE severity = 'CRITICAL'),
		       count(*) FILTER (WHERE source_modified_at IS NOT NULL)
		FROM vulnerabilities WHERE cve_id = ANY($1)`, pq.Array(ids)).Scan(&refreshed, &dated); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if refreshed != n {
		t.Errorf("%d of %d legacy rows refreshed, want all: a stored NULL must be writable, or shipping 066 "+
			"freezes the whole existing catalogue", refreshed, n)
	}
	if dated != n {
		t.Errorf("%d of %d legacy rows recorded an upstream timestamp, want all: a row that is refreshed but not "+
			"dated stays unarbitrable and can be downgraded by the next stale page", dated, n)
	}

	// Dated now means arbitrated: an older record must no longer win.
	m55Sync(t, appDB, m55FeedMany(ids, "LOW", 2.0, "stale replay after the first sync",
		"2026-06-01T00:00:00Z", "2026-01-01T00:00:00Z", m55CPEEmpty))
	var downgraded int
	if err := migDB.QueryRow(`SELECT count(*) FROM vulnerabilities WHERE cve_id = ANY($1) AND severity = 'LOW'`,
		pq.Array(ids)).Scan(&downgraded); err != nil {
		t.Fatalf("count after replay: %v", err)
	}
	if downgraded != 0 {
		t.Errorf("%d legacy rows were downgraded by a stale replay, want 0: the first sync is what arms the guard "+
			"for these rows", downgraded)
	}
}

// TestM55CVEMetadata_FutureWatermarkIsIgnored: a stored watermark in the
// future is corrupt (a clock jump, an operator edit, a restored backup). Used
// as-is it makes lastModStartDate later than lastModEndDate, which NVD rejects
// outright — so every subsequent tick repeats the same impossible request and
// the whole catalogue stops updating, silently and permanently (Codex M55 R3,
// High).
func TestM55CVEMetadata_FutureWatermarkIsIgnored(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	m55PinWatermark(t, migDB, time.Now().UTC().Add(365*24*time.Hour).Truncate(time.Second))

	cveID := m55CVEID(t)
	m55SeedLegacy(t, migDB, cveID, "NVD")

	// Assert on what was REQUESTED, not just on the final watermark: the old
	// unconditional advance leaves the same final state, so a final-state-only
	// assertion passes against an implementation that never fixed the window
	// at all (Codex M55 S1, Medium). The canned server records the request.
	var gotStart, gotEnd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gotStart == "" {
			gotStart = r.URL.Query().Get("lastModStartDate")
			gotEnd = r.URL.Query().Get("lastModEndDate")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(m55Feed(cveID, "CRITICAL", 9.8, "after the bad watermark",
			"2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z", m55CPEEmpty)))
	}))
	defer srv.Close()
	j := NewCVESyncJob(appDB, repository.NewTenantRepository(appDB), "", 24*time.Hour, nil, srv.URL, false)
	if err := j.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if gotStart == "" {
		t.Fatal("the job never issued a request")
	}
	const nvdLayout = "2006-01-02T15:04:05.000"
	start, err := time.Parse(nvdLayout, gotStart)
	if err != nil {
		t.Fatalf("lastModStartDate %q does not parse: %v", gotStart, err)
	}
	end, err := time.Parse(nvdLayout, gotEnd)
	if err != nil {
		t.Fatalf("lastModEndDate %q does not parse: %v", gotEnd, err)
	}
	if start.After(end) {
		t.Errorf("requested window is inverted: start %s > end %s. NVD rejects that outright, so every tick "+
			"repeats the same impossible request and the whole catalogue stops updating", start, end)
	}
	if age := end.Sub(start); age > 48*time.Hour {
		t.Errorf("requested window span = %s, want the normal ~24h fallback: a future watermark must be "+
			"discarded, not merely survived", age)
	}
}

// TestM55CVEMetadata_ImpossiblyOldWatermarkIsClamped (Codex M55 R4, High).
//
// NVD answers a lastModStartDate..lastModEndDate span of at most 120 days and
// rejects anything wider. A watermark older than that — a long outage, a
// restored backup, a fresh deployment against an old database — makes EVERY
// request invalid, so the fetch fails, Run returns before it can advance
// anything, and the identical impossible request is repeated forever. The
// whole catalogue stops updating, not one CVE.
//
// The canned server here records what it was asked for; the assertion is on
// the requested window, not on the response.
func TestM55CVEMetadata_ImpossiblyOldWatermarkIsClamped(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m55ProtectWatermark(t, migDB)
	m55PinWatermark(t, migDB, time.Now().UTC().Add(-365*24*time.Hour).Truncate(time.Second))

	cveID := m55CVEID(t)
	m55SeedLegacy(t, migDB, cveID, "NVD")

	var gotStart string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gotStart == "" {
			gotStart = r.URL.Query().Get("lastModStartDate")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(m55Feed(cveID, "CRITICAL", 9.8, "clamped window",
			"2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z", m55CPEEmpty)))
	}))
	defer srv.Close()
	j := NewCVESyncJob(appDB, repository.NewTenantRepository(appDB), "", 24*time.Hour, nil, srv.URL, false)
	if err := j.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if gotStart == "" {
		t.Fatal("the job never issued a request")
	}
	start, err := time.Parse("2006-01-02T15:04:05.000", gotStart)
	if err != nil {
		t.Fatalf("lastModStartDate %q does not parse: %v", gotStart, err)
	}
	span := time.Now().UTC().Sub(start)
	if span > cveSyncMaxFetchSpan+time.Hour {
		t.Errorf("requested window span = %s, want it clamped to %s: NVD rejects a span wider than 120 days "+
			"outright, so every tick would repeat the same impossible request and the whole catalogue would stop "+
			"updating", span, cveSyncMaxFetchSpan)
	}
}

// TestM55CVEMetadata_FutureUpstreamTimestampCannotFreezeARow is the guard's own
// worst case (Codex M55 S1, High).
//
// The guard is monotonic: whatever source_modified_at a record establishes,
// every later record must beat it. So a record carrying a timestamp from the
// FUTURE does not merely land — it FREEZES the row until real time catches up.
// A corrupt "2099" on a LOW record would refuse every legitimate CRITICAL for
// seventy years, which is the exact failure the guard exists to prevent, with
// the sign flipped. And unlike a missed refresh, this one is caused BY the
// mechanism M55 added, so it is a regression this wave owns.
//
// A row must therefore never be dated from an implausible timestamp: it stays
// unarbitrated (NULL) instead, which is writable once and self-heals.
func TestM55CVEMetadata_FutureUpstreamTimestampCannotFreezeARow(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m55ProtectWatermark(t, migDB)

	// --- the UPDATE path: an existing row must not take the bogus date ---
	existing := m55CVEID(t)
	m55SeedLegacy(t, migDB, existing, "NVD")
	m55Sync(t, appDB, m55Feed(existing, "LOW", 2.0, "record from the year 2099",
		"2026-06-01T00:00:00Z", "2099-01-01T00:00:00Z", m55CPEWithKeywords))

	row := m55Read(t, migDB, existing)
	if row.sourceModAt.Valid {
		t.Errorf("source_modified_at = %v: an implausible upstream timestamp was recorded as the freshness "+
			"arbiter, and every legitimate record until then is now refused as stale", row.sourceModAt.Time.UTC())
	}
	// A legitimate record must still get through afterwards.
	m55Sync(t, appDB, m55Feed(existing, "CRITICAL", 9.8, "legitimate re-score",
		"2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z", m55CPEWithKeywords))
	if got := m55Read(t, migDB, existing); got.severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL: the row was frozen by a bogus future timestamp", got.severity)
	}

	// --- the INSERT path: a new row must be stored unarbitrated, not dated ---
	fresh := m55CVEID(t)
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, fresh); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	m55Sync(t, appDB, m55Feed(fresh, "LOW", 2.0, "new cve dated 2099",
		"2026-06-01T00:00:00Z", "2099-01-01T00:00:00Z", m55CPEWithKeywords))
	var present int
	if err := migDB.QueryRow(`SELECT count(*) FROM vulnerabilities WHERE cve_id = $1`, fresh).Scan(&present); err != nil {
		t.Fatalf("count: %v", err)
	}
	if present == 0 {
		t.Skip("the CVE was not inserted (no tenant match); the INSERT half of this test needs the row to exist")
	}
	inserted := m55Read(t, migDB, fresh)
	if inserted.sourceModAt.Valid {
		t.Errorf("source_modified_at = %v on a newly inserted row: an implausible timestamp must be stored as "+
			"NULL (unarbitrated, writable once) rather than as an arbiter no real record can beat",
			inserted.sourceModAt.Time.UTC())
	}
	m55Sync(t, appDB, m55Feed(fresh, "CRITICAL", 9.8, "legitimate re-score",
		"2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z", m55CPEWithKeywords))
	if got := m55Read(t, migDB, fresh); got.severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL: the newly inserted row was frozen at insert time", got.severity)
	}
}

// TestM55CVEMetadata_UndateableRecordIsNotWrittenAndNotRetried: NVD always
// publishes `lastModified`; its absence means the field did not parse. Such a
// record cannot be arbitrated against the stored one, so it must not be
// written — and it must NOT be booked as retryable debt either, because
// re-fetching the window returns the same malformed record and the watermark
// would never move again.
func TestM55CVEMetadata_UndateableRecordIsNotWrittenAndNotRetried(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	pinned := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	m55PinWatermark(t, migDB, pinned)

	cveID := m55CVEID(t)
	m55SeedLegacy(t, migDB, cveID, "NVD")

	// CPE keywords PRESENT on purpose: with m55CPEEmpty the pre-M55 loop skips
	// the CVE outright and every assertion below is satisfied without the
	// timestamp rule ever running (Codex M55 S1, Low).
	m55Sync(t, appDB, m55Feed(cveID, "CRITICAL", 9.8, "undateable record",
		"2026-06-01T00:00:00Z", "", m55CPEWithKeywords))

	got := m55Read(t, migDB, cveID)
	if got.severity != "LOW" || got.description != "first-fetch description" {
		t.Errorf("row = %s / %q, want the seeded LOW / \"first-fetch description\": a record we cannot date "+
			"must not overwrite one we can", got.severity, got.description)
	}
	if wm := m55Watermark(t, migDB); wm == pinned.Format(time.RFC3339) {
		t.Errorf("cve_sync_last_run = %q, want it advanced: an undateable record is permanent, not retryable, "+
			"and booking it as debt would freeze the watermark forever", wm)
	}
}

// TestM55CVEMetadata_ConcurrentCreatorIsRefreshedNotRejected covers the
// conflict-safe insert (Codex M55 R1, Medium).
//
// The previous shape was check-then-insert: SELECT id, INSERT on a miss.
// Another writer creating the same CVE in between — a scanner racing this job,
// or two ticks overlapping — turned that into a unique violation, which
// excluded the CVE from vulnIndex and dropped its links for the tick.
//
// The race is driven, not hoped for: a second connection INSERTs the row and
// holds the transaction open, so the row is invisible to a SELECT while its
// unique-index entry is already there. The job's insert therefore blocks and
// resolves only once the other transaction commits.
func TestM55CVEMetadata_ConcurrentCreatorIsRefreshedNotRejected(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	cveID := m55CVEID(t)
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, cveID); err != nil {
			t.Errorf("cleanup: delete %s: %v", cveID, err)
		}
	})

	// The competing creator: inserted, not yet committed.
	otherID := uuid.New()
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin competing creator: %v", err)
	}
	committed := false
	t.Cleanup(func() {
		if !committed {
			_ = tx.Rollback()
		}
	})
	if _, err := tx.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source, published_at, updated_at)
		VALUES ($1, $2, 'created by the racing writer', 'LOW', 2.0, 'JVN', '2025-01-01T00:00:00Z', NOW())`,
		otherID, cveID); err != nil {
		t.Fatalf("competing insert: %v", err)
	}
	var holderXID int64
	if err := tx.QueryRow(`SELECT txid_current()`).Scan(&holderXID); err != nil {
		t.Fatalf("read competing creator xid: %v", err)
	}

	j := NewCVESyncJob(appDB, repository.NewTenantRepository(appDB), "", 24*time.Hour, nil, "", false)
	score := 9.8
	type result struct {
		id    uuid.UUID
		isNew bool
		err   error
	}
	done := make(chan result, 1)
	go func() {
		id, isNew, err := j.upsertVulnerability(context.Background(), CVEInfo{
			ID:          cveID,
			Description: "written by the sync",
			Severity:    "CRITICAL",
			CVSSScore:   &score,
			PublishedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			ModifiedAt:  time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
			Keywords:    []string{"acme"},
		})
		done <- result{id, isNew, err}
	}()

	// Wait until the job's insert is demonstrably blocked on the competing
	// creator's uncommitted unique-index entry, then let that creator win. A
	// fixed sleep would let a slow goroutine observe only the post-commit
	// state and pass against the check-then-insert shape too (Codex M55 R2,
	// Low). A speculative-insertion wait registers as an ungranted lock on the
	// index's transaction, so pg_stat_activity's wait_event_type is what shows
	// it.
	m55AwaitLockWaiter(t, migDB, holderXID)
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit competing creator: %v", err)
	}
	committed = true

	got := <-done
	if got.err != nil {
		t.Fatalf("upsertVulnerability lost the create race and returned an error: %v.\n"+
			"A CVE created by another writer must become a refresh, not a unique violation — the error path "+
			"drops the CVE from the match index and its component links with it", got.err)
	}
	if got.isNew {
		t.Error("isNew = true, but the row was created by the other writer")
	}
	if got.id != otherID {
		t.Errorf("returned id = %s, want the stored %s — the match phase links against it", got.id, otherID)
	}
	if row := m55Read(t, migDB, cveID); row.severity != "CRITICAL" || row.source != "NVD" {
		t.Errorf("row = %s / %s, want CRITICAL / NVD: the loser of the create race must still refresh the row",
			row.severity, row.source)
	}
}

// TestM55CVEMetadata_CatalogueWriteEscapesATenantTransaction: the catalogue is
// global, and a global write enlisted in a tenant transaction is discarded
// when that transaction rolls back. In production Run is started from a
// tx-free context, so this pins the boundary rather than a live path — but a
// convention that nothing enforces is one call site away from being false
// (Codex M55 R1, Medium).
func TestM55CVEMetadata_CatalogueWriteEscapesATenantTransaction(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)

	cveID := m55CVEID(t)
	m55SeedLegacy(t, migDB, cveID, "NVD")

	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	txCtx := database.WithTx(context.Background(), tx)

	j := NewCVESyncJob(appDB, repository.NewTenantRepository(appDB), "", 24*time.Hour, nil, "", false)
	score := 9.8
	if err := j.refreshCatalogueMetadata(txCtx, CVEInfo{
		ID:          cveID,
		Description: "written from inside a tenant tx",
		Severity:    "CRITICAL",
		CVSSScore:   &score,
		PublishedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		ModifiedAt:  time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("refreshCatalogueMetadata: %v", err)
	}

	// Throw the transaction away. A write that had joined it dies here.
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	if got := m55Read(t, migDB, cveID); got.severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL: the catalogue write joined the tenant transaction and was "+
			"discarded with it", got.severity)
	}
}
