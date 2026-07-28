package repository

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// TestSearchByCVE_ReadsRealEPSSColumn pins the M36-A / F432 flip of the
// SearchByCVE vulnerability lookup: the positional SELECT must read the real
// epss_score column in the SAME 5th position it previously held as the
// 0::numeric sentinel, so the Scan target order (id, cve_id, description,
// cvss_score, EPSSScore, severity) still aligns.
//
// M47 W4 inverted the shape this test pins: the column is now read BARE
// (no COALESCE) into *float64, so a NULL surfaces as nil and a real 0.0000
// stays non-nil. Both the 0::numeric and the COALESCE forms must fail the
// structural regex.
func TestSearchByCVE_ReadsRealEPSSColumn(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewSearchRepository(db)

	// M46 B2: severity is COALESCE'd to '' in the same position.
	pattern := regexp.MustCompile(`(?is)cvss_score,\s*epss_score,\s*` + regexp.QuoteMeta("COALESCE(severity, '')"))
	if pattern.MatchString("cvss_score, 0::numeric, COALESCE(severity, '')") {
		t.Fatalf("pattern is vacuous: it also matches the old 0::numeric sentinel")
	}
	if pattern.MatchString("cvss_score, COALESCE(epss_score, 0), COALESCE(severity, '')") {
		t.Fatalf("pattern is vacuous: it also matches the COALESCE sentinel form")
	}

	vulnID := uuid.New()
	// Query 1: the vulnerability lookup carrying the flipped EPSS column.
	mock.ExpectQuery(pattern.String()).
		WithArgs("CVE-2026-0007").
		WillReturnRows(sqlmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "epss_score", "severity"}).
			// Un-synced row: the bare column yields a raw NULL in the 5th
			// position -> nil pointer.
			AddRow(vulnID, "CVE-2026-0007", "desc", 7.5, nil, "HIGH"))
	// Query 2: affected projects (empty result is fine for this assertion).
	mock.ExpectQuery(`(?is)FROM\s+projects\s+p`).
		WithArgs(vulnID).
		WillReturnRows(sqlmock.NewRows([]string{"project_id", "project_name", "component_id", "component_name", "component_version"}))
	// Query 3: unaffected projects.
	mock.ExpectQuery(`(?is)p\.id\s+NOT\s+IN`).
		WithArgs(vulnID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name"}))

	got, err := repo.SearchByCVE(context.Background(), "CVE-2026-0007")
	if err != nil {
		t.Fatalf("SearchByCVE: %v", err)
	}
	if got == nil {
		t.Fatalf("expected non-nil result for a known CVE")
	}
	if got.EPSSScore != nil {
		t.Errorf("EPSSScore = %v, want nil (un-scored is NOT 0%%)", *got.EPSSScore)
	}
	if got.CVSSScore == nil || *got.CVSSScore != 7.5 || got.Severity != "HIGH" {
		t.Errorf("positional Scan misaligned: cvss=%v severity=%q, want 7.5/HIGH", got.CVSSScore, got.Severity)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestGetComponentVulnerabilities_ReadsRealEPSSColumns pins the M36-A / F432
// flip of the two-sentinel site: both epss_score and epss_percentile must read
// the real columns in their SAME 6th/7th positions, so the Scan targets
// (…cvss_score, epssScore, epssPercentile, source…) still align.
//
// M47 W4 inverted the value contract. The old form was COALESCE(...,0) plus a
// `> 0` guard, which left the model pointers nil for BOTH a NULL and a real
// 0.0000 — so a CVE FIRST scores at ~0% was reported as un-scored. The columns
// are now read bare into sql.NullFloat64 and only a NULL yields nil.
func TestGetComponentVulnerabilities_ReadsRealEPSSColumns(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewSearchRepository(db)

	pattern := regexp.MustCompile(`(?is)v\.epss_score,\s*v\.epss_percentile,`)
	if pattern.MatchString("0::numeric, 0::numeric,") {
		t.Fatalf("pattern is vacuous: it also matches the old 0::numeric sentinels")
	}
	if pattern.MatchString("COALESCE(v.epss_score, 0), COALESCE(v.epss_percentile, 0),") {
		t.Fatalf("pattern is vacuous: it also matches the COALESCE sentinel form")
	}

	compID := uuid.New()
	now := time.Now()
	mock.ExpectQuery(pattern.String()).
		WithArgs(compID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "cve_id", "description", "severity", "cvss_score",
			"epss_score", "epss_percentile", "source", "published_at", "updated_at",
		}).
			// Un-synced row: both columns are raw NULL -> pointers stay nil.
			AddRow(uuid.New(), "CVE-2026-0010", "d1", "HIGH", 7.5, nil, nil, "NVD", now, now).
			// Synced row: real score/percentile -> pointers set.
			AddRow(uuid.New(), "CVE-2026-0011", "d2", "CRITICAL", 9.8, 0.5, 0.9, "NVD", now, now))

	vulns, err := repo.getComponentVulnerabilities(context.Background(), compID)
	if err != nil {
		t.Fatalf("getComponentVulnerabilities: %v", err)
	}
	if len(vulns) != 2 {
		t.Fatalf("len(vulns) = %d, want 2", len(vulns))
	}
	// Un-synced row: NULL leaves both pointers nil.
	if vulns[0].EPSSScore != nil {
		t.Errorf("vulns[0].EPSSScore = %v, want nil (NULL means un-scored)", *vulns[0].EPSSScore)
	}
	if vulns[0].EPSSPercentile != nil {
		t.Errorf("vulns[0].EPSSPercentile = %v, want nil (NULL means un-scored)", *vulns[0].EPSSPercentile)
	}
	// Synced row: pointers set to the real values, and positional Scan aligns.
	if vulns[1].EPSSScore == nil || *vulns[1].EPSSScore != 0.5 {
		t.Errorf("vulns[1].EPSSScore = %v, want 0.5", vulns[1].EPSSScore)
	}
	if vulns[1].EPSSPercentile == nil || *vulns[1].EPSSPercentile != 0.9 {
		t.Errorf("vulns[1].EPSSPercentile = %v, want 0.9", vulns[1].EPSSPercentile)
	}
	if vulns[1].Source != "NVD" || vulns[1].Severity != "CRITICAL" {
		t.Errorf("positional Scan misaligned: source=%q severity=%q, want NVD/CRITICAL", vulns[1].Source, vulns[1].Severity)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
