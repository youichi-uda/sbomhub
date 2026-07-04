package repository

import (
	"testing"

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
