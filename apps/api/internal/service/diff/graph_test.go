// Package diff — graph.go tests for M12-3 (#84).
//
// Strategy mirrors diff_test.go: in-memory fakes for the four repo
// interfaces, with RawData baked into the model.Sbom fixtures so the
// CycloneDX parser has something to chew on. Three groups:
//
//   1. small-fixture functional tests: add / remove / version_change
//      markers are correctly populated, edges survive the bom-ref →
//      match-key translation, single-SBOM baseline path.
//   2. F164 nil-slice protection: every slice field is `[]` not nil
//      so JSON marshalling never produces `null` (the api.ts helper
//      additionally `?? []`s, but defence in depth).
//   3. 1000-component latency sanity: the parse + merge fits well
//      inside the 1 s p99 the diff page expects (looser bound than
//      a benchmark — we just want to catch quadratic regressions).
package diff

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// ---------- fixture builders (CycloneDX raw bytes) ----------

// cdxComponent is the minimal CycloneDX 1.5 component projection used
// by the test fixtures. We marshal these directly rather than going
// through the cyclonedx-go library so the test stays a black-box
// regression on the parser path.
type cdxComponent struct {
	BOMRef  string `json:"bom-ref"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl,omitempty"`
}

type cdxDependency struct {
	Ref          string   `json:"ref"`
	Dependencies []string `json:"dependsOn,omitempty"`
}

type cdxDoc struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies"`
}

func makeCycloneDXBytes(t *testing.T, comps []cdxComponent, deps []cdxDependency) []byte {
	t.Helper()
	doc := cdxDoc{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		Components:   comps,
		Dependencies: deps,
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal cdx fixture: %v", err)
	}
	return b
}

// graphFixture builds a two-SBOM project with a parent -> {child-a,
// child-b} dependency tree where:
//
//   from:                                to:
//     root@1.0 -> lodash@4.17.20            root@1.0 -> lodash@4.17.21  (version_change)
//     root@1.0 -> axios@1.4.0               root@1.0 -> cool-pkg@2.0.0  (axios removed, cool-pkg added)
//
// Match keys for these components come from the purl normalisation
// (`pkg:npm/<name>` with the version stripped). That means lodash on
// both sides shares the same node ID (id = "pkg:npm/lodash") and lands
// in diff_status.version_changed.
func graphFixture(t *testing.T) *fixture {
	t.Helper()
	tenantID := uuid.New()
	projectID := uuid.New()
	fromID := uuid.New()
	toID := uuid.New()
	now := time.Now()

	fromBytes := makeCycloneDXBytes(t,
		[]cdxComponent{
			{BOMRef: "root@1.0", Type: "application", Name: "root", Version: "1.0", Purl: "pkg:my/root@1.0"},
			{BOMRef: "lodash@4.17.20", Type: "library", Name: "lodash", Version: "4.17.20", Purl: "pkg:npm/lodash@4.17.20"},
			{BOMRef: "axios@1.4.0", Type: "library", Name: "axios", Version: "1.4.0", Purl: "pkg:npm/axios@1.4.0"},
		},
		[]cdxDependency{
			{Ref: "root@1.0", Dependencies: []string{"lodash@4.17.20", "axios@1.4.0"}},
		},
	)
	toBytes := makeCycloneDXBytes(t,
		[]cdxComponent{
			{BOMRef: "root@1.0", Type: "application", Name: "root", Version: "1.0", Purl: "pkg:my/root@1.0"},
			{BOMRef: "lodash@4.17.21", Type: "library", Name: "lodash", Version: "4.17.21", Purl: "pkg:npm/lodash@4.17.21"},
			{BOMRef: "cool-pkg@2.0.0", Type: "library", Name: "cool-pkg", Version: "2.0.0", Purl: "pkg:npm/cool-pkg@2.0.0"},
		},
		[]cdxDependency{
			{Ref: "root@1.0", Dependencies: []string{"lodash@4.17.21", "cool-pkg@2.0.0"}},
		},
	)

	fromSbom := model.Sbom{
		ID: fromID, TenantID: tenantID, ProjectID: projectID,
		Format: "cyclonedx", Version: "1.5", RawData: fromBytes,
		CreatedAt: now.Add(-2 * time.Hour),
	}
	toSbom := model.Sbom{
		ID: toID, TenantID: tenantID, ProjectID: projectID,
		Format: "cyclonedx", Version: "1.5", RawData: toBytes,
		CreatedAt: now.Add(-1 * time.Hour),
	}

	pr := &fakeProjectRepo{projects: map[uuid.UUID]uuid.UUID{projectID: tenantID}}
	sr := &fakeSbomRepo{
		byID:      map[uuid.UUID]model.Sbom{fromID: fromSbom, toID: toSbom},
		byProject: map[uuid.UUID][]model.Sbom{projectID: {toSbom, fromSbom}}, // DESC
	}
	cr := &fakeComponentRepo{
		components: map[uuid.UUID][]model.Component{},
		vulns:      map[uuid.UUID][]model.ComponentVulnerability{},
	}
	lr := &fakeLicenseRepo{policies: map[uuid.UUID][]model.LicensePolicy{}}

	return &fixture{
		tenantID:  tenantID,
		projectID: projectID,
		fromSbom:  fromSbom,
		toSbom:    toSbom,
		service:   NewService(pr, sr, cr, lr),
	}
}

// ---------- functional tests ----------

func TestComputeGraph_TwoSbom_AllThreeMarkers(t *testing.T) {
	f := graphFixture(t)

	resp, err := f.service.ComputeGraph(context.Background(), Request{
		TenantID:   f.tenantID,
		ProjectID:  f.projectID,
		FromSbomID: f.fromSbom.ID,
		ToSbomID:   f.toSbom.ID,
	})
	if err != nil {
		t.Fatalf("ComputeGraph error: %v", err)
	}

	if resp.From == nil || resp.From.SbomID != f.fromSbom.ID {
		t.Errorf("From mismatch: %+v", resp.From)
	}
	if resp.To == nil || resp.To.SbomID != f.toSbom.ID {
		t.Errorf("To mismatch: %+v", resp.To)
	}

	// 4 distinct match keys: root, lodash, axios, cool-pkg.
	if len(resp.Nodes) != 4 {
		t.Errorf("Nodes count: got %d, want 4; %+v", len(resp.Nodes), resp.Nodes)
	}
	nodeByID := map[string]GraphNode{}
	for _, n := range resp.Nodes {
		nodeByID[n.ID] = n
	}

	wantLodash := "pkg:npm/lodash"
	wantAxios := "pkg:npm/axios"
	wantCool := "pkg:npm/cool-pkg"
	wantRoot := "pkg:my/root"

	for _, id := range []string{wantLodash, wantAxios, wantCool, wantRoot} {
		if _, ok := nodeByID[id]; !ok {
			t.Errorf("missing node id %q in %+v", id, nodeByID)
		}
	}

	// lodash node should carry the to-side version (newer projection).
	if nodeByID[wantLodash].Version != "4.17.21" {
		t.Errorf("lodash version: got %q, want 4.17.21", nodeByID[wantLodash].Version)
	}

	// Edges: 2 from + 2 to. lodash from+to share parent (root) but
	// match key normalisation makes them the same edge (root -> lodash),
	// so the union dedups to 3 distinct directed edges:
	//   root -> lodash   (present on both sides)
	//   root -> axios    (from-only / removed)
	//   root -> cool-pkg (to-only / added)
	if len(resp.Edges) != 3 {
		t.Errorf("Edges count: got %d, want 3; %+v", len(resp.Edges), resp.Edges)
	}
	edgeSet := map[string]struct{}{}
	for _, e := range resp.Edges {
		edgeSet[e.From+" -> "+e.To] = struct{}{}
	}
	for _, want := range []string{
		wantRoot + " -> " + wantLodash,
		wantRoot + " -> " + wantAxios,
		wantRoot + " -> " + wantCool,
	} {
		if _, ok := edgeSet[want]; !ok {
			t.Errorf("missing edge %q in %v", want, edgeSet)
		}
	}

	// diff_status: added = {cool-pkg}, removed = {axios},
	// version_changed = {lodash: 4.17.20 -> 4.17.21}
	if len(resp.DiffStatus.Added) != 1 || resp.DiffStatus.Added[0] != wantCool {
		t.Errorf("Added: %+v", resp.DiffStatus.Added)
	}
	if len(resp.DiffStatus.Removed) != 1 || resp.DiffStatus.Removed[0] != wantAxios {
		t.Errorf("Removed: %+v", resp.DiffStatus.Removed)
	}
	if len(resp.DiffStatus.VersionChanged) != 1 {
		t.Fatalf("VersionChanged: %+v", resp.DiffStatus.VersionChanged)
	}
	vc := resp.DiffStatus.VersionChanged[0]
	if vc.ID != wantLodash || vc.OldVersion != "4.17.20" || vc.NewVersion != "4.17.21" {
		t.Errorf("VersionChanged[0] mismatch: %+v", vc)
	}
}

func TestComputeGraph_SingleSbomBaseline_AllAdded(t *testing.T) {
	// Project with a single SBOM: every node should land in added.
	tenantID := uuid.New()
	projectID := uuid.New()
	toID := uuid.New()
	bytes := makeCycloneDXBytes(t,
		[]cdxComponent{
			{BOMRef: "root@1.0", Type: "application", Name: "root", Version: "1.0", Purl: "pkg:my/root@1.0"},
			{BOMRef: "lodash@4.17.21", Type: "library", Name: "lodash", Version: "4.17.21", Purl: "pkg:npm/lodash@4.17.21"},
		},
		[]cdxDependency{
			{Ref: "root@1.0", Dependencies: []string{"lodash@4.17.21"}},
		},
	)
	toSbom := model.Sbom{
		ID: toID, TenantID: tenantID, ProjectID: projectID,
		Format: "cyclonedx", Version: "1.5", RawData: bytes,
		CreatedAt: time.Now(),
	}
	pr := &fakeProjectRepo{projects: map[uuid.UUID]uuid.UUID{projectID: tenantID}}
	sr := &fakeSbomRepo{
		byID:      map[uuid.UUID]model.Sbom{toID: toSbom},
		byProject: map[uuid.UUID][]model.Sbom{projectID: {toSbom}},
	}
	cr := &fakeComponentRepo{components: map[uuid.UUID][]model.Component{}, vulns: map[uuid.UUID][]model.ComponentVulnerability{}}
	lr := &fakeLicenseRepo{policies: map[uuid.UUID][]model.LicensePolicy{}}
	svc := NewService(pr, sr, cr, lr)

	resp, err := svc.ComputeGraph(context.Background(), Request{TenantID: tenantID, ProjectID: projectID})
	if err != nil {
		t.Fatalf("ComputeGraph error: %v", err)
	}
	if resp.From != nil {
		t.Errorf("baseline From should be nil: %+v", resp.From)
	}
	if len(resp.Nodes) != 2 {
		t.Errorf("Nodes: %+v", resp.Nodes)
	}
	if len(resp.DiffStatus.Added) != 2 {
		t.Errorf("Added: %+v", resp.DiffStatus.Added)
	}
	if len(resp.DiffStatus.Removed) != 0 {
		t.Errorf("Removed should be empty: %+v", resp.DiffStatus.Removed)
	}
	if len(resp.DiffStatus.VersionChanged) != 0 {
		t.Errorf("VersionChanged should be empty: %+v", resp.DiffStatus.VersionChanged)
	}
	if len(resp.Edges) != 1 {
		t.Errorf("Edges: %+v", resp.Edges)
	}
}

func TestComputeGraph_NilSliceProtection_F164(t *testing.T) {
	// An empty CycloneDX with no components, no dependencies. Every
	// `[]T` field must round-trip through JSON as `[]`, not `null`,
	// so the typescript helper can rely on the typed contract.
	tenantID := uuid.New()
	projectID := uuid.New()
	toID := uuid.New()
	emptyDoc := makeCycloneDXBytes(t, []cdxComponent{}, []cdxDependency{})
	toSbom := model.Sbom{
		ID: toID, TenantID: tenantID, ProjectID: projectID,
		Format: "cyclonedx", Version: "1.5", RawData: emptyDoc,
		CreatedAt: time.Now(),
	}
	pr := &fakeProjectRepo{projects: map[uuid.UUID]uuid.UUID{projectID: tenantID}}
	sr := &fakeSbomRepo{
		byID:      map[uuid.UUID]model.Sbom{toID: toSbom},
		byProject: map[uuid.UUID][]model.Sbom{projectID: {toSbom}},
	}
	cr := &fakeComponentRepo{components: map[uuid.UUID][]model.Component{}, vulns: map[uuid.UUID][]model.ComponentVulnerability{}}
	lr := &fakeLicenseRepo{policies: map[uuid.UUID][]model.LicensePolicy{}}
	svc := NewService(pr, sr, cr, lr)

	resp, err := svc.ComputeGraph(context.Background(), Request{TenantID: tenantID, ProjectID: projectID})
	if err != nil {
		t.Fatalf("ComputeGraph error: %v", err)
	}

	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	// Re-decode into a permissive map and verify each slice field is
	// a JSON array (possibly empty), never `null`.
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	mustArray := func(path string, v interface{}) {
		if v == nil {
			t.Errorf("F164: %s is JSON null, want []", path)
		}
		if _, ok := v.([]interface{}); !ok {
			t.Errorf("F164: %s is not []: %T %+v", path, v, v)
		}
	}
	mustArray("nodes", decoded["nodes"])
	mustArray("edges", decoded["edges"])
	ds, _ := decoded["diff_status"].(map[string]interface{})
	if ds == nil {
		t.Fatalf("diff_status missing in %s", string(raw))
	}
	mustArray("diff_status.added", ds["added"])
	mustArray("diff_status.removed", ds["removed"])
	mustArray("diff_status.version_changed", ds["version_changed"])
}

func TestComputeGraph_TenantMismatch_ReturnsErrNoRows(t *testing.T) {
	f := graphFixture(t)
	wrongTenant := uuid.New()
	_, err := f.service.ComputeGraph(context.Background(), Request{
		TenantID:   wrongTenant,
		ProjectID:  f.projectID,
		FromSbomID: f.fromSbom.ID,
		ToSbomID:   f.toSbom.ID,
	})
	if err == nil {
		t.Fatalf("expected ErrNoRows-class error for wrong tenant, got nil")
	}
}

// ---------- scale / latency ----------

// TestComputeGraph_1000NodesLatency builds a CycloneDX with 1000
// components arranged as one root + 999 leaves, runs ComputeGraph
// twice (from + to, with 1 version_change), and asserts the wall
// clock is comfortably below a loose ceiling. We are catching
// quadratic regressions, not benchmarking.
func TestComputeGraph_1000NodesLatency(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	fromID := uuid.New()
	toID := uuid.New()

	build := func(verSuffix string) []byte {
		comps := make([]cdxComponent, 0, 1000)
		deps := make([]cdxDependency, 0, 1000)
		comps = append(comps, cdxComponent{
			BOMRef: "root@1.0", Type: "application", Name: "root",
			Version: "1.0", Purl: "pkg:my/root@1.0",
		})
		rootDeps := cdxDependency{Ref: "root@1.0"}
		for i := 0; i < 999; i++ {
			ref := fmt.Sprintf("lib-%d@1.0.%s", i, verSuffix)
			purl := fmt.Sprintf("pkg:npm/lib-%d@1.0.%s", i, verSuffix)
			comps = append(comps, cdxComponent{
				BOMRef: ref, Type: "library",
				Name:    fmt.Sprintf("lib-%d", i),
				Version: "1.0." + verSuffix,
				Purl:    purl,
			})
			rootDeps.Dependencies = append(rootDeps.Dependencies, ref)
		}
		deps = append(deps, rootDeps)
		return makeCycloneDXBytes(t, comps, deps)
	}

	fromBytes := build("0")
	toBytes := build("1") // every leaf is version_changed

	fromSbom := model.Sbom{
		ID: fromID, TenantID: tenantID, ProjectID: projectID,
		Format: "cyclonedx", Version: "1.5", RawData: fromBytes,
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	toSbom := model.Sbom{
		ID: toID, TenantID: tenantID, ProjectID: projectID,
		Format: "cyclonedx", Version: "1.5", RawData: toBytes,
		CreatedAt: time.Now().Add(-1 * time.Hour),
	}
	pr := &fakeProjectRepo{projects: map[uuid.UUID]uuid.UUID{projectID: tenantID}}
	sr := &fakeSbomRepo{
		byID:      map[uuid.UUID]model.Sbom{fromID: fromSbom, toID: toSbom},
		byProject: map[uuid.UUID][]model.Sbom{projectID: {toSbom, fromSbom}},
	}
	cr := &fakeComponentRepo{components: map[uuid.UUID][]model.Component{}, vulns: map[uuid.UUID][]model.ComponentVulnerability{}}
	lr := &fakeLicenseRepo{policies: map[uuid.UUID][]model.LicensePolicy{}}
	svc := NewService(pr, sr, cr, lr)

	start := time.Now()
	resp, err := svc.ComputeGraph(context.Background(), Request{
		TenantID: tenantID, ProjectID: projectID,
		FromSbomID: fromID, ToSbomID: toID,
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ComputeGraph error: %v", err)
	}
	// 1000 nodes + 999 edges should fit comfortably in well under a
	// second. The ceiling is loose so CI variance does not flap;
	// the goal is to catch a quadratic regression which would push
	// this well past 5 s.
	if elapsed > 5*time.Second {
		t.Errorf("ComputeGraph 1000-node latency too slow: %v (loose ceiling 5s)", elapsed)
	}
	t.Logf("ComputeGraph 1000-node latency: %v (nodes=%d edges=%d added=%d removed=%d changed=%d)",
		elapsed, len(resp.Nodes), len(resp.Edges),
		len(resp.DiffStatus.Added), len(resp.DiffStatus.Removed),
		len(resp.DiffStatus.VersionChanged))

	// 1 root + 999 leaves on each side, all leaves share match keys,
	// so 1000 unique nodes total and 999 directed edges (root->leaf).
	if len(resp.Nodes) != 1000 {
		t.Errorf("nodes: got %d want 1000", len(resp.Nodes))
	}
	if len(resp.Edges) != 999 {
		t.Errorf("edges: got %d want 999", len(resp.Edges))
	}
	if len(resp.DiffStatus.VersionChanged) != 999 {
		t.Errorf("version_changed: got %d want 999", len(resp.DiffStatus.VersionChanged))
	}
	if len(resp.DiffStatus.Added) != 0 {
		t.Errorf("added: got %d want 0", len(resp.DiffStatus.Added))
	}
	if len(resp.DiffStatus.Removed) != 0 {
		t.Errorf("removed: got %d want 0", len(resp.DiffStatus.Removed))
	}
}
