package repository

import (
	"context"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// TestGroupImpactRows_RollupAndOrder pins the pure rollup step of the
// cross-project blast-radius aggregation (M28-A / F388, #134): flat
// (project, component) rows fold into one ImpactProject per project, each
// component_count equals the number of its affected components, and the
// query's first-seen project order (ORDER BY p.name) is preserved. This is the
// real-PG-free half of the aggregation — the SQL is exercised by the
// integration test.
func TestGroupImpactRows_RollupAndOrder(t *testing.T) {
	pA := uuid.New()
	pB := uuid.New()
	pC := uuid.New()

	comp := func(name, version, purl string) model.ImpactComponent {
		return model.ImpactComponent{Name: name, Version: version, Purl: purl}
	}

	// Rows arrive already ordered by (project name, component name). A appears
	// first with two components, then B with one, then C with three.
	rows := []impactRow{
		{ProjectID: pA, ProjectName: "app-a", Component: comp("libx", "1.0", "pkg:generic/libx@1.0")},
		{ProjectID: pA, ProjectName: "app-a", Component: comp("liby", "2.0", "pkg:generic/liby@2.0")},
		{ProjectID: pB, ProjectName: "app-b", Component: comp("libx", "1.0", "pkg:generic/libx@1.0")},
		{ProjectID: pC, ProjectName: "app-c", Component: comp("libx", "1.0", "pkg:generic/libx@1.0")},
		{ProjectID: pC, ProjectName: "app-c", Component: comp("libz", "3.0", "pkg:generic/libz@3.0")},
		{ProjectID: pC, ProjectName: "app-c", Component: comp("libw", "4.0", "pkg:generic/libw@4.0")},
	}

	got := groupImpactRows(rows)

	if len(got) != 3 {
		t.Fatalf("expected 3 projects, got %d: %+v", len(got), got)
	}

	// Order preserved.
	wantOrder := []struct {
		id    uuid.UUID
		name  string
		count int
	}{
		{pA, "app-a", 2},
		{pB, "app-b", 1},
		{pC, "app-c", 3},
	}
	for i, w := range wantOrder {
		if got[i].ProjectID != w.id {
			t.Errorf("project[%d] id = %s, want %s (order not preserved)", i, got[i].ProjectID, w.id)
		}
		if got[i].ProjectName != w.name {
			t.Errorf("project[%d] name = %q, want %q", i, got[i].ProjectName, w.name)
		}
		if got[i].ComponentCount != w.count {
			t.Errorf("project[%d] component_count = %d, want %d", i, got[i].ComponentCount, w.count)
		}
		if len(got[i].AffectedComponents) != w.count {
			t.Errorf("project[%d] len(components) = %d, want %d", i, len(got[i].AffectedComponents), w.count)
		}
	}

	// Component payload preserved (purl carried through, first component of A).
	if got[0].AffectedComponents[0].Purl != "pkg:generic/libx@1.0" {
		t.Errorf("component purl = %q, want pkg:generic/libx@1.0", got[0].AffectedComponents[0].Purl)
	}
}

// TestGroupImpactRows_Empty ensures a zero-affected CVE folds to an empty
// (non-nil) slice — the blast-radius-0 case that must render as a valid 200
// with an empty list rather than a 404.
func TestGroupImpactRows_Empty(t *testing.T) {
	got := groupImpactRows(nil)
	if got == nil {
		t.Fatalf("expected non-nil empty slice, got nil")
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 projects, got %d", len(got))
	}
}

// TestGetVulnerabilityImpactMeta_ReadsRealEPSSColumn pins the M36-A / F432
// flip: GetVulnerabilityImpactMeta must SELECT the real epss_score column,
// NOT the old fixed 0::numeric sentinel.
//
// M47 W4 inverted the shape this test pins. It previously required
// COALESCE(epss_score, 0) and asserted an un-synced row reads 0 — pinning the
// sentinel contract as correct. The column is now read BARE: an un-synced row
// must surface as nil, and a real 0.0000 (a FIRST score rounded down by the
// DECIMAL(5,4) column) must stay non-nil so the two remain distinguishable.
func TestGetVulnerabilityImpactMeta_ReadsRealEPSSColumn(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewSearchRepository(db)

	// Requires the real column read bare; neither the 0::numeric sentinel
	// nor the retired COALESCE form may match.
	// sqlmock normalises the statement to a single spaced line, so the
	// discriminator anchors on the surrounding columns: the bare form emits
	// "cvss_score, epss_score, in_kev" while both sentinel forms interpose
	// either 0::numeric or a COALESCE wrapper.
	pattern := regexp.MustCompile(`(?is)cvss_score,\s*epss_score,\s*in_kev`)
	if pattern.MatchString("cvss_score, 0::numeric AS epss_score, in_kev") {
		t.Fatalf("pattern is vacuous: it also matches the old 0::numeric sentinel")
	}
	if pattern.MatchString("cvss_score, COALESCE(epss_score, 0) AS epss_score, in_kev") {
		t.Fatalf("pattern is vacuous: it also matches the COALESCE sentinel form")
	}

	vulnID := uuid.New()
	mock.ExpectQuery(pattern.String()).
		WithArgs("CVE-2026-0001").
		WillReturnRows(sqlmock.NewRows([]string{"id", "severity", "cvss_score", "epss_score", "in_kev"}).
			// Real 0.0000: a FIRST score below 0.00005 rounded down by the
			// DECIMAL(5,4) column. Must stay non-nil.
			AddRow(vulnID, "HIGH", 7.5, float64(0), false))

	got, err := repo.GetVulnerabilityImpactMeta(context.Background(), "CVE-2026-0001")
	if err != nil {
		t.Fatalf("GetVulnerabilityImpactMeta: %v", err)
	}
	if got == nil {
		t.Fatalf("expected non-nil meta for a known CVE")
	}
	if got.EPSSScore == nil {
		t.Fatalf("EPSSScore = nil, want *0.0 (a rounded-to-zero FIRST score is a measurement)")
	}
	if *got.EPSSScore != 0 {
		t.Fatalf("EPSSScore = %v, want 0.0", *got.EPSSScore)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestGetVulnerabilityImpactMeta_NullEPSSScansCleanly is the M47 W4 inversion
// of the old ..._NullEPSSWithoutCoalesceErrors, which asserted that a raw NULL
// epss_score MUST error and used that to justify the COALESCE. That only held
// while CVEImpactMeta.EPSSScore was a bare float64. It is now *float64, so the
// NULL an un-synced (or 059-tombstoned) row carries must scan cleanly to nil
// rather than 500 on a KNOWN CVE.
func TestGetVulnerabilityImpactMeta_NullEPSSScansCleanly(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewSearchRepository(db)

	vulnID := uuid.New()
	mock.ExpectQuery(`(?is)FROM\s+vulnerabilities`).
		WithArgs("CVE-2026-0002").
		WillReturnRows(sqlmock.NewRows([]string{"id", "severity", "cvss_score", "epss_score", "in_kev"}).
			// A raw NULL — what a bare (non-COALESCE) epss_score column would
			// return for an un-synced row.
			AddRow(vulnID, "HIGH", 7.5, nil, false))

	got, err := repo.GetVulnerabilityImpactMeta(context.Background(), "CVE-2026-0002")
	if err != nil {
		t.Fatalf("a raw NULL epss_score must scan cleanly into *float64, got: %v", err)
	}
	if got == nil {
		t.Fatalf("expected non-nil meta for a known CVE")
	}
	if got.EPSSScore != nil {
		t.Fatalf("EPSSScore = %v, want nil (un-scored is NOT 0%%)", *got.EPSSScore)
	}
}
