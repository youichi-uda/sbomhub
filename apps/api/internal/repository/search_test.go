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
// epss_score column via COALESCE(epss_score, 0) in the SAME 5th position it
// previously held as the 0::numeric sentinel, so the Scan target order
// (id, cve_id, description, cvss_score, EPSSScore, severity) still aligns. The
// COALESCE assertion is structural; a revert to 0::numeric fails it. The seeded
// row is un-synced, so the DB's COALESCE yields EPSSScore == 0.
func TestSearchByCVE_ReadsRealEPSSColumn(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewSearchRepository(db)

	pattern := regexp.MustCompile(`(?is)cvss_score,\s*` + regexp.QuoteMeta("COALESCE(epss_score, 0)") + `,\s*severity`)
	if pattern.MatchString("cvss_score, 0::numeric, severity") {
		t.Fatalf("pattern is vacuous: it also matches the old 0::numeric sentinel")
	}

	vulnID := uuid.New()
	// Query 1: the vulnerability lookup carrying the flipped EPSS column.
	mock.ExpectQuery(pattern.String()).
		WithArgs("CVE-2026-0007").
		WillReturnRows(sqlmock.NewRows([]string{"id", "cve_id", "description", "cvss_score", "epss_score", "severity"}).
			// Un-synced row: COALESCE(epss_score, 0) -> 0, held in the 5th position.
			AddRow(vulnID, "CVE-2026-0007", "desc", 7.5, float64(0), "HIGH"))
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
	if got.EPSSScore != 0 {
		t.Errorf("EPSSScore = %v, want 0 (un-synced row COALESCEs to 0)", got.EPSSScore)
	}
	if got.CVSSScore != 7.5 || got.Severity != "HIGH" {
		t.Errorf("positional Scan misaligned: cvss=%v severity=%q, want 7.5/HIGH", got.CVSSScore, got.Severity)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestGetComponentVulnerabilities_ReadsRealEPSSColumns pins the M36-A / F432 flip
// of the two-sentinel site: both epss_score and epss_percentile must read the
// real columns via COALESCE in their SAME 6th/7th positions, so the Scan targets
// (…cvss_score, epssScore, epssPercentile, source…) still align. It also pins the
// preserved `> 0` guard: an un-synced (COALESCE-0) row leaves the model pointers
// nil (web >0 badge suppression, F391), while a synced row sets them.
func TestGetComponentVulnerabilities_ReadsRealEPSSColumns(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewSearchRepository(db)

	pattern := regexp.MustCompile(`(?is)` + regexp.QuoteMeta("COALESCE(v.epss_score, 0)") + `,\s*` + regexp.QuoteMeta("COALESCE(v.epss_percentile, 0)"))
	if pattern.MatchString("0::numeric, 0::numeric,") {
		t.Fatalf("pattern is vacuous: it also matches the old 0::numeric sentinels")
	}

	compID := uuid.New()
	now := time.Now()
	mock.ExpectQuery(pattern.String()).
		WithArgs(compID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "cve_id", "description", "severity", "cvss_score",
			"epss_score", "epss_percentile", "source", "published_at", "updated_at",
		}).
			// Un-synced row: both COALESCE to 0 -> pointers stay nil (> 0 guard).
			AddRow(uuid.New(), "CVE-2026-0010", "d1", "HIGH", 7.5, float64(0), float64(0), "NVD", now, now).
			// Synced row: real score/percentile -> pointers set.
			AddRow(uuid.New(), "CVE-2026-0011", "d2", "CRITICAL", 9.8, 0.5, 0.9, "NVD", now, now))

	vulns, err := repo.getComponentVulnerabilities(context.Background(), compID)
	if err != nil {
		t.Fatalf("getComponentVulnerabilities: %v", err)
	}
	if len(vulns) != 2 {
		t.Fatalf("len(vulns) = %d, want 2", len(vulns))
	}
	// Un-synced row: > 0 guard leaves both pointers nil.
	if vulns[0].EPSSScore != nil {
		t.Errorf("vulns[0].EPSSScore = %v, want nil (un-synced COALESCE-0 leaves pointer nil)", *vulns[0].EPSSScore)
	}
	if vulns[0].EPSSPercentile != nil {
		t.Errorf("vulns[0].EPSSPercentile = %v, want nil (un-synced COALESCE-0 leaves pointer nil)", *vulns[0].EPSSPercentile)
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
