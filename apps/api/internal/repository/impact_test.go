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

// TestGetVulnerabilityImpactMeta_ReadsRealEPSSColumn pins the M36-A / F432 flip:
// GetVulnerabilityImpactMeta must SELECT the real epss_score column wrapped in
// COALESCE(epss_score, 0), NOT the old fixed 0::numeric sentinel. The assertion
// is structural on the SQL — a revert to 0::numeric (which can never surface a
// synced score) would fail the regex even if the scanned value happened to be 0.
// The row here is an un-synced CVE (the DB's COALESCE turns its NULL epss_score
// into 0), so the scan yields EPSSScore == 0 without error.
func TestGetVulnerabilityImpactMeta_ReadsRealEPSSColumn(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewSearchRepository(db)

	// Requires the real column read through COALESCE; the bare 0::numeric
	// sentinel would not match and neither would an un-guarded bare column.
	pattern := regexp.MustCompile(`(?is)` + regexp.QuoteMeta("COALESCE(epss_score, 0)") + `\s+AS\s+epss_score`)
	if pattern.MatchString("0::numeric AS epss_score") {
		t.Fatalf("pattern is vacuous: it also matches the old 0::numeric sentinel")
	}

	vulnID := uuid.New()
	mock.ExpectQuery(pattern.String()).
		WithArgs("CVE-2026-0001").
		WillReturnRows(sqlmock.NewRows([]string{"id", "severity", "cvss_score", "epss_score", "in_kev"}).
			// Un-synced row: the real DB's COALESCE(epss_score, 0) turns the
			// underlying NULL into 0 before it reaches Scan.
			AddRow(vulnID, "HIGH", 7.5, float64(0), false))

	got, err := repo.GetVulnerabilityImpactMeta(context.Background(), "CVE-2026-0001")
	if err != nil {
		t.Fatalf("GetVulnerabilityImpactMeta: %v", err)
	}
	if got == nil {
		t.Fatalf("expected non-nil meta for a known CVE")
	}
	if got.EPSSScore != 0 {
		t.Fatalf("EPSSScore = %v, want 0 (un-synced row COALESCEs to 0)", got.EPSSScore)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestGetVulnerabilityImpactMeta_NullEPSSWithoutCoalesceErrors documents WHY the
// COALESCE is load-bearing (M36-A / F432): CVEImpactMeta.EPSSScore is a bare
// float64, so a raw SQL NULL scanned into it errors — which for a KNOWN CVE
// (no ErrNoRows fallback) would 500. The 055 migration adds the column nullable
// and it stays NULL until epss_sync runs, so a bare `epss_score` read would hit
// exactly this. COALESCE(epss_score, 0) makes the DB return 0 instead, which is
// why the flip uses COALESCE rather than the bare column. Here we feed the raw
// NULL a bare column would have yielded and confirm it is the error path.
func TestGetVulnerabilityImpactMeta_NullEPSSWithoutCoalesceErrors(t *testing.T) {
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

	_, err = repo.GetVulnerabilityImpactMeta(context.Background(), "CVE-2026-0002")
	if err == nil {
		t.Fatalf("expected a scan error when a raw NULL epss_score reaches the bare float64 target (the 500 path COALESCE prevents)")
	}
}
