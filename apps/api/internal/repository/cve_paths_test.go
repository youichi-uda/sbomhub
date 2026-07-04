package repository

import (
	"testing"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// TestGroupCVEAffectedRows_RollupAndOrder pins the pure rollup step of the
// M30-A affected-component resolution (F402, #138): flat (project, component)
// rows fold into one CVEAffectedProject per project, each carries its affected
// components (with type — the field the diff match key needs beyond
// AggregateCVEImpact's name/version/purl), and the query's first-seen project
// order (ORDER BY p.name) is preserved. The SQL itself is exercised by the
// integration test; this is the real-PG-free half.
func TestGroupCVEAffectedRows_RollupAndOrder(t *testing.T) {
	pA, pB, pC := uuid.New(), uuid.New(), uuid.New()

	comp := func(name, version, purl, typ string) model.Component {
		return model.Component{Name: name, Version: version, Purl: purl, Type: typ}
	}

	rows := []cvePathsRow{
		{ProjectID: pA, ProjectName: "app-a", Component: comp("libx", "1.0", "pkg:generic/libx@1.0", "library")},
		{ProjectID: pA, ProjectName: "app-a", Component: comp("liby", "2.0", "pkg:generic/liby@2.0", "library")},
		{ProjectID: pB, ProjectName: "app-b", Component: comp("libx", "1.0", "pkg:generic/libx@1.0", "library")},
		{ProjectID: pC, ProjectName: "app-c", Component: comp("libz", "3.0", "pkg:generic/libz@3.0", "application")},
	}

	got := groupCVEAffectedRows(rows)

	if len(got) != 3 {
		t.Fatalf("expected 3 projects, got %d: %+v", len(got), got)
	}
	want := []struct {
		id    uuid.UUID
		name  string
		count int
	}{
		{pA, "app-a", 2},
		{pB, "app-b", 1},
		{pC, "app-c", 1},
	}
	for i, w := range want {
		if got[i].ProjectID != w.id {
			t.Errorf("project[%d] id = %s, want %s (order not preserved)", i, got[i].ProjectID, w.id)
		}
		if got[i].ProjectName != w.name {
			t.Errorf("project[%d] name = %q, want %q", i, got[i].ProjectName, w.name)
		}
		if len(got[i].Components) != w.count {
			t.Errorf("project[%d] len(components) = %d, want %d", i, len(got[i].Components), w.count)
		}
	}
	// Component payload preserved, including type.
	if got[0].Components[0].Purl != "pkg:generic/libx@1.0" || got[0].Components[0].Type != "library" {
		t.Errorf("component[0] = %+v, want purl=pkg:generic/libx@1.0 type=library", got[0].Components[0])
	}
	if got[2].Components[0].Type != "application" {
		t.Errorf("project C component type = %q, want application (type carried through)", got[2].Components[0].Type)
	}
}

// TestGroupCVEAffectedRows_Empty ensures a zero-affected CVE folds to an empty
// (non-nil) slice — the blast-radius-0 case rendered as a valid 200 empty
// rather than a 404.
func TestGroupCVEAffectedRows_Empty(t *testing.T) {
	got := groupCVEAffectedRows(nil)
	if got == nil {
		t.Fatalf("expected non-nil empty slice, got nil")
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 projects, got %d", len(got))
	}
}
