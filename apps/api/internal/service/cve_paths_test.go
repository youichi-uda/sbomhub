package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// ---------- in-memory fakes for the two repos GetCVEPaths consumes ----------

type fakeCVEPathsSearchRepo struct {
	meta          *model.CVEImpactMeta
	metaErr       error
	totalProjects int
	totalErr      error
	affected      []model.CVEAffectedProject
	affectedErr   error
}

func (f *fakeCVEPathsSearchRepo) GetVulnerabilityImpactMeta(_ context.Context, _ string) (*model.CVEImpactMeta, error) {
	return f.meta, f.metaErr
}
func (f *fakeCVEPathsSearchRepo) CountProjectsByTenant(_ context.Context, _ uuid.UUID) (int, error) {
	return f.totalProjects, f.totalErr
}
func (f *fakeCVEPathsSearchRepo) AggregateCVEAffectedComponents(_ context.Context, _, _ uuid.UUID) ([]model.CVEAffectedProject, error) {
	return f.affected, f.affectedErr
}

type fakeCVEPathsSbomRepo struct {
	byProject map[uuid.UUID][]model.Sbom
	listCalls map[uuid.UUID]int // per-project ListByProject call counter
}

func (f *fakeCVEPathsSbomRepo) ListByProject(_ context.Context, projectID uuid.UUID) ([]model.Sbom, error) {
	if f.listCalls == nil {
		f.listCalls = map[uuid.UUID]int{}
	}
	f.listCalls[projectID]++
	return f.byProject[projectID], nil
}

// ---------- CycloneDX fixture builders (local to the service package) ----------

type cdxComp struct {
	BOMRef  string `json:"bom-ref"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl,omitempty"`
}
type cdxDep struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}
type cdxMeta struct {
	Component *cdxComp `json:"component,omitempty"`
}
type cdxBOM struct {
	BOMFormat    string   `json:"bomFormat"`
	SpecVersion  string   `json:"specVersion"`
	Metadata     *cdxMeta `json:"metadata,omitempty"`
	Components   []cdxComp `json:"components"`
	Dependencies []cdxDep  `json:"dependencies"`
}

func mkCDX(t *testing.T, root cdxComp, comps []cdxComp, deps []cdxDep) []byte {
	t.Helper()
	b, err := json.Marshal(cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		Metadata:     &cdxMeta{Component: &root},
		Components:   comps,
		Dependencies: deps,
	})
	if err != nil {
		t.Fatalf("marshal cdx: %v", err)
	}
	return b
}

func affComp(name, version, purl string) model.Component {
	return model.Component{Name: name, Version: version, Purl: purl, Type: "library"}
}

func joinIDs(chain []model.PathNode) string {
	out := ""
	for i, n := range chain {
		if i > 0 {
			out += " -> "
		}
		out += n.ID
	}
	return out
}

// TestGetCVEPaths_MultiProjectFanout pins the core M30-A behaviour: a CVE
// affecting TWO projects yields two entries, each with the correct per-project
// entry path — a transitive path (app-a → express → qs) in project A and a
// direct path (app-b → qs) in project B — plus the metadata + counter rollup.
func TestGetCVEPaths_MultiProjectFanout(t *testing.T) {
	tenantID := uuid.New()
	projA, sbomA := uuid.New(), uuid.New()
	projB, sbomB := uuid.New(), uuid.New()

	// Project A: app-a → express → qs (qs is transitive, depth 2).
	rawA := mkCDX(t,
		cdxComp{BOMRef: "root", Type: "application", Name: "app-a", Version: "1.0.0", Purl: "pkg:npm/app-a@1.0.0"},
		[]cdxComp{
			{BOMRef: "express", Type: "library", Name: "express", Version: "4.18.0", Purl: "pkg:npm/express@4.18.0"},
			{BOMRef: "qs", Type: "library", Name: "qs", Version: "6.2.0", Purl: "pkg:npm/qs@6.2.0"},
		},
		[]cdxDep{
			{Ref: "root", DependsOn: []string{"express"}},
			{Ref: "express", DependsOn: []string{"qs"}},
		},
	)
	// Project B: app-b → qs (qs is direct).
	rawB := mkCDX(t,
		cdxComp{BOMRef: "root", Type: "application", Name: "app-b", Version: "2.0.0", Purl: "pkg:npm/app-b@2.0.0"},
		[]cdxComp{
			{BOMRef: "qs", Type: "library", Name: "qs", Version: "6.2.0", Purl: "pkg:npm/qs@6.2.0"},
		},
		[]cdxDep{
			{Ref: "root", DependsOn: []string{"qs"}},
		},
	)

	search := &fakeCVEPathsSearchRepo{
		meta: &model.CVEImpactMeta{
			VulnerabilityID: uuid.New(),
			Severity:        "HIGH", CVSSScore: 7.5, EPSSScore: 0, InKEV: true,
		},
		totalProjects: 12,
		affected: []model.CVEAffectedProject{
			{ProjectID: projA, ProjectName: "app-a", Components: []model.Component{affComp("qs", "6.2.0", "pkg:npm/qs@6.2.0")}},
			{ProjectID: projB, ProjectName: "app-b", Components: []model.Component{affComp("qs", "6.2.0", "pkg:npm/qs@6.2.0")}},
		},
	}
	sbom := &fakeCVEPathsSbomRepo{byProject: map[uuid.UUID][]model.Sbom{
		projA: {{ID: sbomA, ProjectID: projA, Format: "cyclonedx", RawData: rawA, CreatedAt: time.Now()}},
		projB: {{ID: sbomB, ProjectID: projB, Format: "cyclonedx", RawData: rawB, CreatedAt: time.Now()}},
	}}

	svc := NewCVEPathsService(search, sbom)
	got, err := svc.GetCVEPaths(context.Background(), tenantID, "cve-2024-qs")
	if err != nil {
		t.Fatalf("GetCVEPaths: %v", err)
	}
	if got == nil {
		t.Fatalf("expected non-nil response")
	}

	// Metadata + counters.
	if got.CVEID != "CVE-2024-QS" {
		t.Errorf("cve_id = %q, want CVE-2024-QS (normalised uppercase)", got.CVEID)
	}
	if got.Severity != "HIGH" || got.CVSSScore != 7.5 || !got.InKEV || got.EPSSScore != 0 {
		t.Errorf("meta rollup mismatch: sev=%q cvss=%v kev=%v epss=%v", got.Severity, got.CVSSScore, got.InKEV, got.EPSSScore)
	}
	if got.AffectedProjectCount != 2 {
		t.Errorf("affected_project_count = %d, want 2", got.AffectedProjectCount)
	}
	if got.TotalProjectCount != 12 {
		t.Errorf("total_project_count = %d, want 12", got.TotalProjectCount)
	}
	if len(got.AffectedProjects) != 2 {
		t.Fatalf("len(affected_projects) = %d, want 2", len(got.AffectedProjects))
	}

	byID := map[uuid.UUID]model.AffectedProjectPaths{}
	for _, p := range got.AffectedProjects {
		byID[p.ProjectID] = p
	}

	// Project A: transitive path app-a → express → qs, is_direct=false.
	pa := byID[projA]
	if pa.SbomID != sbomA || pa.Format != "cyclonedx" || pa.Degraded {
		t.Errorf("projA sbom/format/degraded = %s/%q/%v, want %s/cyclonedx/false", pa.SbomID, pa.Format, pa.Degraded, sbomA)
	}
	if pa.ComponentCount != 1 || len(pa.AffectedComponents) != 1 {
		t.Fatalf("projA component_count = %d (len %d), want 1", pa.ComponentCount, len(pa.AffectedComponents))
	}
	ca := pa.AffectedComponents[0]
	if !ca.InGraph || ca.IsDirect || ca.Truncated {
		t.Errorf("projA qs: in_graph=%v is_direct=%v truncated=%v, want true/false/false", ca.InGraph, ca.IsDirect, ca.Truncated)
	}
	if ca.PathCount != 1 || len(ca.Paths) != 1 {
		t.Fatalf("projA qs path_count = %d (len %d), want 1", ca.PathCount, len(ca.Paths))
	}
	if joinIDs(ca.Paths[0]) != "pkg:npm/app-a -> pkg:npm/express -> pkg:npm/qs" {
		t.Errorf("projA qs path = %q, want app-a -> express -> qs", joinIDs(ca.Paths[0]))
	}
	assertNoRevisit(t, ca.Paths[0])

	// Project B: direct path app-b → qs, is_direct=true.
	pb := byID[projB]
	if pb.SbomID != sbomB || pb.Degraded {
		t.Errorf("projB sbom/degraded = %s/%v, want %s/false", pb.SbomID, pb.Degraded, sbomB)
	}
	cb := pb.AffectedComponents[0]
	if !cb.InGraph || !cb.IsDirect {
		t.Errorf("projB qs: in_graph=%v is_direct=%v, want true/true (direct)", cb.InGraph, cb.IsDirect)
	}
	if cb.PathCount != 1 || joinIDs(cb.Paths[0]) != "pkg:npm/app-b -> pkg:npm/qs" {
		t.Errorf("projB qs path = %v, want [app-b -> qs]", cb.Paths)
	}
}

func assertNoRevisit(t *testing.T, chain []model.PathNode) {
	t.Helper()
	seen := map[string]struct{}{}
	for _, n := range chain {
		if _, dup := seen[n.ID]; dup {
			t.Errorf("path revisits node %q: %s", n.ID, joinIDs(chain))
		}
		seen[n.ID] = struct{}{}
	}
}

// TestGetCVEPaths_ParseOncePerProject pins the efficiency contract: a project
// with MULTIPLE affected components in one SBOM loads (and therefore parses)
// that SBOM EXACTLY ONCE — ListByProject is called once for the project, not
// once per component.
func TestGetCVEPaths_ParseOncePerProject(t *testing.T) {
	tenantID := uuid.New()
	projA, sbomA := uuid.New(), uuid.New()

	// app → express → qs, and app → lodash — express, qs AND lodash all affected.
	rawA := mkCDX(t,
		cdxComp{BOMRef: "root", Type: "application", Name: "app", Version: "1.0.0", Purl: "pkg:npm/app@1.0.0"},
		[]cdxComp{
			{BOMRef: "express", Type: "library", Name: "express", Version: "4.18.0", Purl: "pkg:npm/express@4.18.0"},
			{BOMRef: "qs", Type: "library", Name: "qs", Version: "6.2.0", Purl: "pkg:npm/qs@6.2.0"},
			{BOMRef: "lodash", Type: "library", Name: "lodash", Version: "4.17.21", Purl: "pkg:npm/lodash@4.17.21"},
		},
		[]cdxDep{
			{Ref: "root", DependsOn: []string{"express", "lodash"}},
			{Ref: "express", DependsOn: []string{"qs"}},
		},
	)
	search := &fakeCVEPathsSearchRepo{
		meta:          &model.CVEImpactMeta{VulnerabilityID: uuid.New(), Severity: "HIGH", CVSSScore: 7.5},
		totalProjects: 1,
		affected: []model.CVEAffectedProject{
			{ProjectID: projA, ProjectName: "app", Components: []model.Component{
				affComp("express", "4.18.0", "pkg:npm/express@4.18.0"),
				affComp("qs", "6.2.0", "pkg:npm/qs@6.2.0"),
				affComp("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
			}},
		},
	}
	sbom := &fakeCVEPathsSbomRepo{byProject: map[uuid.UUID][]model.Sbom{
		projA: {{ID: sbomA, ProjectID: projA, Format: "cyclonedx", RawData: rawA, CreatedAt: time.Now()}},
	}}

	svc := NewCVEPathsService(search, sbom)
	got, err := svc.GetCVEPaths(context.Background(), tenantID, "CVE-2024-MULTI")
	if err != nil {
		t.Fatalf("GetCVEPaths: %v", err)
	}
	if n := sbom.listCalls[projA]; n != 1 {
		t.Fatalf("PARSE-ONCE VIOLATED: ListByProject called %d times for projA with 3 affected components, want exactly 1", n)
	}
	// All three components still resolved against the single parsed graph.
	if len(got.AffectedProjects) != 1 || got.AffectedProjects[0].ComponentCount != 3 {
		t.Fatalf("want 1 project with 3 components, got %+v", got.AffectedProjects)
	}
}

// TestGetCVEPaths_DegradedSPDXProject pins the project-level degrade: a project
// whose LATEST SBOM is SPDX carries no dependency edges, so degraded=true and
// every affected component resolves in_graph=false with empty paths.
func TestGetCVEPaths_DegradedSPDXProject(t *testing.T) {
	tenantID := uuid.New()
	projX, sbomX := uuid.New(), uuid.New()
	spdx := []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"qs","versionInfo":"6.2.0"}]}`)

	search := &fakeCVEPathsSearchRepo{
		meta:          &model.CVEImpactMeta{VulnerabilityID: uuid.New(), Severity: "HIGH", CVSSScore: 7.5},
		totalProjects: 1,
		affected: []model.CVEAffectedProject{
			{ProjectID: projX, ProjectName: "spdx-app", Components: []model.Component{affComp("qs", "6.2.0", "pkg:npm/qs@6.2.0")}},
		},
	}
	sbom := &fakeCVEPathsSbomRepo{byProject: map[uuid.UUID][]model.Sbom{
		projX: {{ID: sbomX, ProjectID: projX, Format: "spdx", RawData: spdx, CreatedAt: time.Now()}},
	}}

	svc := NewCVEPathsService(search, sbom)
	got, err := svc.GetCVEPaths(context.Background(), tenantID, "CVE-2024-SPDX")
	if err != nil {
		t.Fatalf("GetCVEPaths: %v", err)
	}
	p := got.AffectedProjects[0]
	if !p.Degraded || p.Format != "spdx" {
		t.Errorf("projX degraded=%v format=%q, want true/spdx", p.Degraded, p.Format)
	}
	c := p.AffectedComponents[0]
	if c.InGraph || c.PathCount != 0 || len(c.Paths) != 0 {
		t.Errorf("degraded project component: in_graph=%v path_count=%d len=%d, want false/0/0", c.InGraph, c.PathCount, len(c.Paths))
	}
}

// TestGetCVEPaths_InGraphFalseOlderSnapshot pins the latest-SBOM semantics: a
// component affected only in an older snapshot (absent from the LATEST SBOM's
// graph) resolves in_graph=false with empty paths, while the project is NOT
// degraded (its latest SBOM is cyclonedx).
func TestGetCVEPaths_InGraphFalseOlderSnapshot(t *testing.T) {
	tenantID := uuid.New()
	projX, sbomLatest := uuid.New(), uuid.New()

	// Latest SBOM: app → express only. The affected component "oldlib" was
	// removed and is NOT present here.
	rawLatest := mkCDX(t,
		cdxComp{BOMRef: "root", Type: "application", Name: "app", Version: "2.0.0", Purl: "pkg:npm/app@2.0.0"},
		[]cdxComp{
			{BOMRef: "express", Type: "library", Name: "express", Version: "4.18.0", Purl: "pkg:npm/express@4.18.0"},
		},
		[]cdxDep{{Ref: "root", DependsOn: []string{"express"}}},
	)
	search := &fakeCVEPathsSearchRepo{
		meta:          &model.CVEImpactMeta{VulnerabilityID: uuid.New(), Severity: "HIGH", CVSSScore: 7.5},
		totalProjects: 1,
		// oldlib is affected (from an older snapshot) but absent from latest.
		affected: []model.CVEAffectedProject{
			{ProjectID: projX, ProjectName: "app", Components: []model.Component{affComp("oldlib", "1.0.0", "pkg:npm/oldlib@1.0.0")}},
		},
	}
	sbom := &fakeCVEPathsSbomRepo{byProject: map[uuid.UUID][]model.Sbom{
		projX: {{ID: sbomLatest, ProjectID: projX, Format: "cyclonedx", RawData: rawLatest, CreatedAt: time.Now()}},
	}}

	svc := NewCVEPathsService(search, sbom)
	got, err := svc.GetCVEPaths(context.Background(), tenantID, "CVE-2024-OLD")
	if err != nil {
		t.Fatalf("GetCVEPaths: %v", err)
	}
	p := got.AffectedProjects[0]
	if p.Degraded {
		t.Errorf("latest SBOM is cyclonedx; degraded must be false")
	}
	c := p.AffectedComponents[0]
	if c.InGraph {
		t.Errorf("oldlib is absent from the latest SBOM; in_graph must be false")
	}
	if c.PathCount != 0 || len(c.Paths) != 0 {
		t.Errorf("absent component paths = %d/%d, want 0/0", c.PathCount, len(c.Paths))
	}
	if c.Paths == nil {
		t.Errorf("paths must be non-nil empty slice (JSON []), got nil")
	}
}

// TestGetCVEPaths_TruncatedPropagates pins that the M29 path-cap truncation
// (maxDependencyPaths=50) flows through to the component-level truncated flag
// — a fan-in graph with 51 distinct root→target paths caps at 50 and sets
// truncated=true (silent drop forbidden).
func TestGetCVEPaths_TruncatedPropagates(t *testing.T) {
	tenantID := uuid.New()
	projX, sbomX := uuid.New(), uuid.New()

	// 51 roots each depending directly on the target → 51 distinct paths.
	const numRoots = 51
	target := cdxComp{BOMRef: "target", Type: "library", Name: "target", Version: "1.0.0", Purl: "pkg:npm/target@1.0.0"}
	comps := []cdxComp{target}
	deps := []cdxDep{}
	for i := 0; i < numRoots; i++ {
		ref := "root-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		comps = append(comps, cdxComp{BOMRef: ref, Type: "application", Name: ref, Version: "1.0.0", Purl: "pkg:npm/" + ref + "@1.0.0"})
		deps = append(deps, cdxDep{Ref: ref, DependsOn: []string{"target"}})
	}
	// Use a plain (metadata-less) BOM so no single declared root collapses the fan-in.
	rawX, err := json.Marshal(cdxBOM{BOMFormat: "CycloneDX", SpecVersion: "1.6", Components: comps, Dependencies: deps})
	if err != nil {
		t.Fatalf("marshal fan-in: %v", err)
	}

	search := &fakeCVEPathsSearchRepo{
		meta:          &model.CVEImpactMeta{VulnerabilityID: uuid.New(), Severity: "HIGH", CVSSScore: 7.5},
		totalProjects: 1,
		affected: []model.CVEAffectedProject{
			{ProjectID: projX, ProjectName: "fan", Components: []model.Component{affComp("target", "1.0.0", "pkg:npm/target@1.0.0")}},
		},
	}
	sbom := &fakeCVEPathsSbomRepo{byProject: map[uuid.UUID][]model.Sbom{
		projX: {{ID: sbomX, ProjectID: projX, Format: "cyclonedx", RawData: rawX, CreatedAt: time.Now()}},
	}}

	svc := NewCVEPathsService(search, sbom)
	got, err := svc.GetCVEPaths(context.Background(), tenantID, "CVE-2024-FAN")
	if err != nil {
		t.Fatalf("GetCVEPaths: %v", err)
	}
	c := got.AffectedProjects[0].AffectedComponents[0]
	if !c.Truncated {
		t.Errorf("51 distinct paths must hit the cap and set truncated=true")
	}
	if c.PathCount > 50 {
		t.Errorf("path_count = %d, want <= 50 (cap)", c.PathCount)
	}
}

// TestGetCVEPaths_ZeroAffected pins the blast-radius-0 contract: a known CVE
// reaching no project returns a non-nil result with count 0 and a non-nil
// empty list (JSON []), NOT nil (which the handler would map to 404).
func TestGetCVEPaths_ZeroAffected(t *testing.T) {
	search := &fakeCVEPathsSearchRepo{
		meta:          &model.CVEImpactMeta{VulnerabilityID: uuid.New(), Severity: "HIGH", CVSSScore: 7.5},
		totalProjects: 5,
		affected:      []model.CVEAffectedProject{},
	}
	sbom := &fakeCVEPathsSbomRepo{byProject: map[uuid.UUID][]model.Sbom{}}

	svc := NewCVEPathsService(search, sbom)
	got, err := svc.GetCVEPaths(context.Background(), uuid.New(), "CVE-2024-NONE")
	if err != nil {
		t.Fatalf("GetCVEPaths: %v", err)
	}
	if got == nil {
		t.Fatalf("known-but-unaffecting CVE must return non-nil (200 empty), got nil (would 404)")
	}
	if got.AffectedProjectCount != 0 || len(got.AffectedProjects) != 0 {
		t.Errorf("zero-affected: count=%d len=%d, want 0/0", got.AffectedProjectCount, len(got.AffectedProjects))
	}
	if got.AffectedProjects == nil {
		t.Errorf("affected_projects must be non-nil empty slice (JSON []), got nil")
	}
	if got.TotalProjectCount != 5 {
		t.Errorf("total_project_count = %d, want 5", got.TotalProjectCount)
	}
}

// TestGetCVEPaths_UnknownCVENil pins the unknown-CVE contract: nil meta →
// (nil, nil) so the handler answers 404 (distinct from a known-but-empty CVE).
func TestGetCVEPaths_UnknownCVENil(t *testing.T) {
	search := &fakeCVEPathsSearchRepo{meta: nil}
	sbom := &fakeCVEPathsSbomRepo{}
	svc := NewCVEPathsService(search, sbom)
	got, err := svc.GetCVEPaths(context.Background(), uuid.New(), "CVE-9999-UNKNOWN")
	if err != nil {
		t.Fatalf("GetCVEPaths: %v", err)
	}
	if got != nil {
		t.Errorf("unknown CVE must return nil (→404), got %+v", got)
	}
}
