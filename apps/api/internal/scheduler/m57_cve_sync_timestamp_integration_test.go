//go:build integration

// Package scheduler — M57: cve_sync must read the timestamps NVD actually
// sends.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M57CVESync_NVDsZoneless' ./internal/scheduler
package scheduler

import (
	"testing"
	"time"
)

// TestM57CVESync_NVDsZonelessTimestampsAreParsed: the NVD 2.0 API publishes
// `published` / `lastModified` WITHOUT an offset — measured live 2026-11-08:
// CVE-2021-44228 lastModified "2026-08-11T19:33:44.513". cve_sync parsed both
// with time.RFC3339, which requires one, and discarded the error.
//
// Consequence on real data, not on this file's older fixtures (which all
// carry a "Z" and so never exercised it): every fetched record had a zero
// ModifiedAt, usableSourceModifiedAt turned that into "undateable", and
// writeCatalogueMetadata refused EVERY refresh ("NVD record carries no
// believable lastModified; not written"). The M55 metadata refresh — the
// owner's only write path for an existing row — wrote nothing in production,
// and every row it inserted got published_at and source_modified_at NULL.
// service/nvd.go fixed the identical bug for the scanner in M54
// (nvdTimestampLayouts); the sync was never given the same parser.
func TestM57CVESync_NVDsZonelessTimestampsAreParsed(t *testing.T) {
	appURL, migURL := schedIntEnv(t)
	appDB := schedOpenOrSkip(t, appURL)
	migDB := schedOpenOrSkip(t, migURL)
	m55ProtectWatermark(t, migDB)

	// Refresh path: an existing row, keyword-less record.
	existing := m55CVEID(t)
	m55SeedLegacy(t, migDB, existing, "NVD")
	m55Sync(t, appDB, m55Feed(existing, "CRITICAL", 9.8, "re-scored", "2026-06-01T00:00:00.000",
		"2026-07-01T12:34:56.789", m55CPEEmpty))
	row := m55Read(t, migDB, existing)
	if row.severity != "CRITICAL" {
		t.Errorf("refresh with NVD's real timestamp format: severity = %q, want CRITICAL — the record was "+
			"treated as undateable and refused", row.severity)
	}
	wantMod := time.Date(2026, 7, 1, 12, 34, 56, 789_000_000, time.UTC)
	if !row.sourceModAt.Valid || !row.sourceModAt.Time.UTC().Equal(wantMod) {
		t.Errorf("source_modified_at = %v (valid=%v), want %v", row.sourceModAt.Time.UTC(), row.sourceModAt.Valid, wantMod)
	}

	// Insert path: an absent CVE with CPE keywords.
	inserted := m55CVEID(t)
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE cve_id = $1`, inserted); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	m55Sync(t, appDB, m55Feed(inserted, "HIGH", 7.5, "new", "2026-06-01T00:00:00.000",
		"2026-07-01T12:34:56.789", m55CPEWithKeywords))
	row = m55Read(t, migDB, inserted)
	if !row.publishedAt.Valid || !row.sourceModAt.Valid {
		t.Errorf("inserted row: published_at valid=%v, source_modified_at valid=%v, want both set from NVD's "+
			"zoneless timestamps", row.publishedAt.Valid, row.sourceModAt.Valid)
	}
}
