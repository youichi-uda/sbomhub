// Package diff — graph.go tests for M12-3 (#84).
//
// Strategy mirrors diff_test.go: in-memory fakes for the four repo
// interfaces, with RawData baked into the model.Sbom fixtures so the
// CycloneDX parser has something to chew on. Three groups:
//
//  1. small-fixture functional tests: add / remove / version_change
//     markers are correctly populated, edges survive the bom-ref →
//     match-key translation, single-SBOM baseline path.
//  2. F164 nil-slice protection: every slice field is `[]` not nil
//     so JSON marshalling never produces `null` (the api.ts helper
//     additionally `?? []`s, but defence in depth).
//  3. 1000-component latency sanity: the parse + merge fits well
//     inside the 1 s p99 the diff page expects (looser bound than
//     a benchmark — we just want to catch quadratic regressions).
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
	BOMRef     string         `json:"bom-ref"`
	Type       string         `json:"type"`
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	Purl       string         `json:"purl,omitempty"`
	Components []cdxComponent `json:"components,omitempty"`
}

type cdxDependency struct {
	Ref          string   `json:"ref"`
	Dependencies []string `json:"dependsOn,omitempty"`
}

type cdxMetadata struct {
	Component *cdxComponent `json:"component,omitempty"`
}

type cdxDoc struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	Metadata     *cdxMetadata    `json:"metadata,omitempty"`
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

// makeCycloneDXBytesWithMetadata mirrors makeCycloneDXBytes but also
// emits a `metadata.component` block — the CycloneDX 1.6 canonical
// home of the application/root node. F171 regression coverage.
func makeCycloneDXBytesWithMetadata(t *testing.T, root cdxComponent, comps []cdxComponent, deps []cdxDependency) []byte {
	t.Helper()
	doc := cdxDoc{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		Metadata:     &cdxMetadata{Component: &root},
		Components:   comps,
		Dependencies: deps,
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal cdx fixture with metadata: %v", err)
	}
	return b
}

// graphFixture builds a two-SBOM project with a parent -> {child-a,
// child-b} dependency tree where:
//
//	from:                                to:
//	  root@1.0 -> lodash@4.17.20            root@1.0 -> lodash@4.17.21  (version_change)
//	  root@1.0 -> axios@1.4.0               root@1.0 -> cool-pkg@2.0.0  (axios removed, cool-pkg added)
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

// TestComputeGraph_MetadataComponentRoot_F171 covers the Codex round-1
// finding F171: parseCycloneDXGraph used to only walk bom.Components
// for the bom-ref → match-key index, which silently dropped the
// application/root node + every edge whose `ref` pointed at it. The
// fixture below puts the root in metadata.component (per the
// CycloneDX 1.6 spec) and asserts the root node, the root → library
// edge, and the library node all survive.
func TestComputeGraph_MetadataComponentRoot_F171(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	toID := uuid.New()
	rawData := makeCycloneDXBytesWithMetadata(t,
		cdxComponent{BOMRef: "app", Type: "application", Name: "app", Version: "1.0.0", Purl: "pkg:my/app@1.0.0"},
		[]cdxComponent{
			{BOMRef: "lib", Type: "library", Name: "lib", Version: "2.0.0", Purl: "pkg:npm/lib@2.0.0"},
		},
		[]cdxDependency{
			{Ref: "app", Dependencies: []string{"lib"}},
		},
	)
	toSbom := model.Sbom{
		ID: toID, TenantID: tenantID, ProjectID: projectID,
		Format: "cyclonedx", Version: "1.6", RawData: rawData,
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

	wantApp := "pkg:my/app"
	wantLib := "pkg:npm/lib"

	// Both nodes must be present — pre-fix the app node was dropped.
	if len(resp.Nodes) != 2 {
		t.Errorf("Nodes count: got %d, want 2 (app + lib); %+v", len(resp.Nodes), resp.Nodes)
	}
	nodeByID := map[string]GraphNode{}
	for _, n := range resp.Nodes {
		nodeByID[n.ID] = n
	}
	if _, ok := nodeByID[wantApp]; !ok {
		t.Errorf("F171: metadata.component root node %q missing from graph; got nodes %+v", wantApp, nodeByID)
	}
	if _, ok := nodeByID[wantLib]; !ok {
		t.Errorf("library node %q missing from graph; got nodes %+v", wantLib, nodeByID)
	}
	if got := nodeByID[wantApp]; got.Name != "app" || got.Version != "1.0.0" || got.Type != "application" {
		t.Errorf("root node projection mismatch: %+v", got)
	}

	// Root → library edge must survive the bom-ref translation —
	// pre-fix `app` was unindexed so the edge was dropped.
	if len(resp.Edges) != 1 {
		t.Fatalf("Edges count: got %d, want 1; %+v", len(resp.Edges), resp.Edges)
	}
	e := resp.Edges[0]
	if e.From != wantApp || e.To != wantLib {
		t.Errorf("F171: edge mismatch: got %s -> %s, want %s -> %s", e.From, e.To, wantApp, wantLib)
	}

	// Single-SBOM baseline path: both nodes land in Added.
	if len(resp.DiffStatus.Added) != 2 {
		t.Errorf("Added: got %d, want 2 (app + lib); %+v", len(resp.DiffStatus.Added), resp.DiffStatus.Added)
	}
}

// TestComputeGraph_NestedSubComponents_M13_2 (#88) pins the nested
// Component.Components walk: a CycloneDX 1.6 SBOM declares a container
// component (`app`) whose sub-components (`mid` and the deeply-nested
// `leaf`) only exist under `metadata.component.components` /
// `components[].components` — they are NOT top-level entries in
// `bom.Components`. Pre-M13-2 the parser stopped at the first level,
// so dependencies[].ref pointing at `mid` / `leaf` silently dropped
// the node + every edge through it. The fixture asserts:
//
//   - all three nodes (app, mid, leaf) land in the graph
//   - the explicit dependency chain app -> mid -> leaf survives the
//     bom-ref -> match-key translation
//   - the baseline single-SBOM path reports all three under Added
//
// We assert the dependencies-array remains the canonical edge source:
// nesting alone does NOT synthesise implicit parent -> child edges
// (the test fixture wires the chain through `dependencies`).
func TestComputeGraph_NestedSubComponents_M13_2(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	toID := uuid.New()

	// metadata.component (root=app) holds an inline child component
	// (mid), which itself holds an inline child component (leaf).
	// The dependencies array describes the full chain.
	rootWithNested := cdxComponent{
		BOMRef: "app", Type: "application", Name: "app", Version: "1.0.0",
		Purl: "pkg:my/app@1.0.0",
		Components: []cdxComponent{
			{
				BOMRef: "mid", Type: "library", Name: "mid", Version: "2.0.0",
				Purl: "pkg:npm/mid@2.0.0",
				Components: []cdxComponent{
					{BOMRef: "leaf", Type: "library", Name: "leaf", Version: "3.0.0", Purl: "pkg:npm/leaf@3.0.0"},
				},
			},
		},
	}
	rawData := makeCycloneDXBytesWithMetadata(t,
		rootWithNested,
		// bom.Components is empty: every node is nested under metadata.component.
		// This makes the recursion the only path that can index `mid` and `leaf`.
		[]cdxComponent{},
		[]cdxDependency{
			{Ref: "app", Dependencies: []string{"mid"}},
			{Ref: "mid", Dependencies: []string{"leaf"}},
		},
	)
	toSbom := model.Sbom{
		ID: toID, TenantID: tenantID, ProjectID: projectID,
		Format: "cyclonedx", Version: "1.6", RawData: rawData,
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

	wantApp := "pkg:my/app"
	wantMid := "pkg:npm/mid"
	wantLeaf := "pkg:npm/leaf"

	if len(resp.Nodes) != 3 {
		t.Errorf("Nodes count: got %d, want 3 (app + mid + leaf); %+v", len(resp.Nodes), resp.Nodes)
	}
	nodeByID := map[string]GraphNode{}
	for _, n := range resp.Nodes {
		nodeByID[n.ID] = n
	}
	for _, id := range []string{wantApp, wantMid, wantLeaf} {
		if _, ok := nodeByID[id]; !ok {
			t.Errorf("M13-2: nested node %q missing; got nodes %+v", id, nodeByID)
		}
	}
	if got := nodeByID[wantMid]; got.Name != "mid" || got.Version != "2.0.0" || got.Type != "library" {
		t.Errorf("nested mid projection mismatch: %+v", got)
	}
	if got := nodeByID[wantLeaf]; got.Name != "leaf" || got.Version != "3.0.0" || got.Type != "library" {
		t.Errorf("nested leaf projection mismatch: %+v", got)
	}

	// Edges: app -> mid + mid -> leaf. Nesting alone does NOT
	// synthesise implicit edges — both must come from `dependencies`.
	if len(resp.Edges) != 2 {
		t.Fatalf("Edges count: got %d, want 2 (app->mid, mid->leaf); %+v", len(resp.Edges), resp.Edges)
	}
	edgeSet := map[string]struct{}{}
	for _, e := range resp.Edges {
		edgeSet[e.From+" -> "+e.To] = struct{}{}
	}
	for _, want := range []string{
		wantApp + " -> " + wantMid,
		wantMid + " -> " + wantLeaf,
	} {
		if _, ok := edgeSet[want]; !ok {
			t.Errorf("M13-2: chain edge %q missing; got %v", want, edgeSet)
		}
	}

	// Single-SBOM baseline: all three nodes land in Added.
	if len(resp.DiffStatus.Added) != 3 {
		t.Errorf("Added: got %d, want 3; %+v", len(resp.DiffStatus.Added), resp.DiffStatus.Added)
	}
	if len(resp.DiffStatus.Removed) != 0 {
		t.Errorf("Removed should be empty in baseline: %+v", resp.DiffStatus.Removed)
	}
	if len(resp.DiffStatus.VersionChanged) != 0 {
		t.Errorf("VersionChanged should be empty in baseline: %+v", resp.DiffStatus.VersionChanged)
	}
}

// TestComputeGraph_NestedSubComponents_VersionDiff_M13_2 covers the
// two-SBOM path with nested components: a nested `mid` library bumps
// version between `from` and `to`. The version_changed marker MUST
// be emitted on the merged node so the frontend renders the colour
// even though the component only exists under nesting.
func TestComputeGraph_NestedSubComponents_VersionDiff_M13_2(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	fromID := uuid.New()
	toID := uuid.New()

	makeNested := func(midVersion string) []byte {
		root := cdxComponent{
			BOMRef: "app", Type: "application", Name: "app", Version: "1.0.0",
			Purl: "pkg:my/app@1.0.0",
			Components: []cdxComponent{
				{BOMRef: "mid", Type: "library", Name: "mid", Version: midVersion, Purl: "pkg:npm/mid@" + midVersion},
			},
		}
		return makeCycloneDXBytesWithMetadata(t,
			root,
			[]cdxComponent{},
			[]cdxDependency{{Ref: "app", Dependencies: []string{"mid"}}},
		)
	}

	fromSbom := model.Sbom{
		ID: fromID, TenantID: tenantID, ProjectID: projectID,
		Format: "cyclonedx", Version: "1.6", RawData: makeNested("2.0.0"),
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}
	toSbom := model.Sbom{
		ID: toID, TenantID: tenantID, ProjectID: projectID,
		Format: "cyclonedx", Version: "1.6", RawData: makeNested("2.0.1"),
		CreatedAt: time.Now().Add(-1 * time.Hour),
	}
	pr := &fakeProjectRepo{projects: map[uuid.UUID]uuid.UUID{projectID: tenantID}}
	sr := &fakeSbomRepo{
		byID:      map[uuid.UUID]model.Sbom{fromID: fromSbom, toID: toSbom},
		byProject: map[uuid.UUID][]model.Sbom{projectID: {toSbom, fromSbom}}, // DESC
	}
	cr := &fakeComponentRepo{components: map[uuid.UUID][]model.Component{}, vulns: map[uuid.UUID][]model.ComponentVulnerability{}}
	lr := &fakeLicenseRepo{policies: map[uuid.UUID][]model.LicensePolicy{}}
	svc := NewService(pr, sr, cr, lr)

	resp, err := svc.ComputeGraph(context.Background(), Request{
		TenantID: tenantID, ProjectID: projectID,
		FromSbomID: fromID, ToSbomID: toID,
	})
	if err != nil {
		t.Fatalf("ComputeGraph error: %v", err)
	}

	wantMid := "pkg:npm/mid"

	if len(resp.DiffStatus.VersionChanged) != 1 {
		t.Fatalf("VersionChanged: got %d, want 1; %+v", len(resp.DiffStatus.VersionChanged), resp.DiffStatus.VersionChanged)
	}
	vc := resp.DiffStatus.VersionChanged[0]
	if vc.ID != wantMid || vc.OldVersion != "2.0.0" || vc.NewVersion != "2.0.1" {
		t.Errorf("nested VersionChanged mismatch: %+v", vc)
	}
	// app node should be unchanged (no marker).
	if len(resp.DiffStatus.Added) != 0 || len(resp.DiffStatus.Removed) != 0 {
		t.Errorf("Added/Removed should be empty for version-only nested change: added=%v removed=%v",
			resp.DiffStatus.Added, resp.DiffStatus.Removed)
	}
}

// TestComputeGraph_DeepNestedComponents_DepthLimit_F203 pins the F203
// depth cap on indexComponent recursion. An adversarial CycloneDX
// document with components nested 100 levels deep (well past the
// configured cap of 64) is parsed end-to-end through ComputeGraph; the
// fixture asserts:
//
//   - parsing completes without panicking and within a bounded latency
//     budget (10s — well below any realistic stack-blow regression);
//   - every component AT OR ABOVE the depth cap lands in the graph
//     (the closure bails at the recursion site, so the node at
//     depth == maxGraphComponentDepth is still indexed);
//   - components STRICTLY DEEPER than the cap are absent from the
//     graph (the closure stops recursing into them).
//
// Pre-F203 the recursion was unbounded; a hand-crafted SBOM with
// O(10^4-10^5) nested levels could expand the Go goroutine stack
// toward its ~1 GB hard cap and spike CPU + memory on a single
// authenticated /diff/graph request. Tenant auth gates the endpoint,
// but any authenticated user can upload an SBOM, so the DoS surface
// is real even with auth in place.
func TestComputeGraph_DeepNestedComponents_DepthLimit_F203(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	toID := uuid.New()

	// Build a 100-deep nested chain anchored at metadata.component.
	// The chain is intentionally deeper than the configured cap (64)
	// so we exercise both the "indexed under the cap" and "dropped
	// past the cap" code paths in a single fixture.
	const totalDepth = 100
	buildDeepNested := func() cdxComponent {
		// Construct innermost component first, then wrap outward so
		// the depth-0 root contains a depth-1 child contains a depth-2
		// child, etc, ending with the depth-(totalDepth-1) leaf.
		var current cdxComponent
		// Leaf at the deepest level.
		current = cdxComponent{
			BOMRef:  fmt.Sprintf("nested-%d", totalDepth-1),
			Type:    "library",
			Name:    fmt.Sprintf("nested-%d", totalDepth-1),
			Version: "1.0.0",
			Purl:    fmt.Sprintf("pkg:npm/nested-%d@1.0.0", totalDepth-1),
		}
		for i := totalDepth - 2; i >= 0; i-- {
			current = cdxComponent{
				BOMRef:     fmt.Sprintf("nested-%d", i),
				Type:       "library",
				Name:       fmt.Sprintf("nested-%d", i),
				Version:    "1.0.0",
				Purl:       fmt.Sprintf("pkg:npm/nested-%d@1.0.0", i),
				Components: []cdxComponent{current},
			}
		}
		// Wrap once more with an "app" root so metadata.component
		// itself is at depth 0 and `nested-0` starts at depth 1.
		// This matches the structure of a real container SBOM.
		return cdxComponent{
			BOMRef:     "app",
			Type:       "application",
			Name:       "app",
			Version:    "1.0.0",
			Purl:       "pkg:my/app@1.0.0",
			Components: []cdxComponent{current},
		}
	}

	rawData := makeCycloneDXBytesWithMetadata(t,
		buildDeepNested(),
		[]cdxComponent{},
		// No `dependencies` array: the test is about whether nodes
		// are indexed safely, not about edge resolution.
		[]cdxDependency{},
	)

	toSbom := model.Sbom{
		ID: toID, TenantID: tenantID, ProjectID: projectID,
		Format: "cyclonedx", Version: "1.6", RawData: rawData,
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

	start := time.Now()
	resp, err := svc.ComputeGraph(context.Background(), Request{TenantID: tenantID, ProjectID: projectID})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ComputeGraph error: %v", err)
	}
	// Loose latency ceiling — defence against a future regression
	// reintroducing unbounded recursion + accidental quadratic
	// behaviour. Real measurement of a 100-deep chain post-F203
	// completes in single-digit milliseconds.
	if elapsed > 10*time.Second {
		t.Errorf("ComputeGraph deep-nested latency too slow: %v "+
			"(loose ceiling 10s; suggests F203 cap regressed)", elapsed)
	}

	nodeByID := map[string]GraphNode{}
	for _, n := range resp.Nodes {
		nodeByID[n.ID] = n
	}

	// Root + every level UP TO AND INCLUDING the cap must be present.
	// The cap depth refers to indexComponent's `depth` parameter
	// (depth 0 = metadata.component itself). When called with depth=0
	// for `app`, depth=1 for `nested-0`, ..., depth=N for
	// `nested-(N-1)`. The depth check bails BEFORE recursing into
	// children, so the deepest indexed nested-X has depth ==
	// maxGraphComponentDepth, i.e. X == maxGraphComponentDepth - 1.
	maxIndexedNested := maxGraphComponentDepth - 1
	if _, ok := nodeByID["pkg:my/app"]; !ok {
		t.Errorf("F203: root app missing from graph; nodes=%+v", nodeByID)
	}
	for i := 0; i <= maxIndexedNested; i++ {
		id := fmt.Sprintf("pkg:npm/nested-%d", i)
		if _, ok := nodeByID[id]; !ok {
			t.Errorf("F203: nested-%d (within depth cap) missing from graph", i)
		}
	}

	// Everything strictly deeper than the cap must be ABSENT.
	for i := maxIndexedNested + 1; i < totalDepth; i++ {
		id := fmt.Sprintf("pkg:npm/nested-%d", i)
		if _, ok := nodeByID[id]; ok {
			t.Errorf("F203: nested-%d (beyond depth cap) leaked into graph; "+
				"cap is supposed to bail at depth=%d",
				i, maxGraphComponentDepth)
		}
	}

	// Sanity: the indexed count matches the cap. 1 root (app) + the
	// nested-0..nested-(maxIndexedNested) chain.
	wantNodeCount := 1 + (maxIndexedNested + 1)
	if len(resp.Nodes) != wantNodeCount {
		t.Errorf("F203: node count %d != expected %d (root + cap-1 deep chain)",
			len(resp.Nodes), wantNodeCount)
	}

	t.Logf("F203 depth-cap pin: indexed %d nodes from %d-deep fixture in %v (cap=%d)",
		len(resp.Nodes), totalDepth, elapsed, maxGraphComponentDepth)
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
