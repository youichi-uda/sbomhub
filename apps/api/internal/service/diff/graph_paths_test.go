// Package diff — graph_paths.go tests for M29-A (#136, F397).
//
// The reverse-reachability traversal is the highest-risk surface of M29
// (cycles, exponential path blow-up, root detection, ownership), so this
// file leans on the same in-memory fakes + CycloneDX fixture builders used
// by graph_test.go / diff_test.go and exercises ComputePaths end to end.
package diff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// ---------- helpers ----------

func newPathsService(t *testing.T, tenantID, projectID uuid.UUID, sbom model.Sbom, comps map[uuid.UUID]model.Component) *Service {
	t.Helper()
	pr := &fakeProjectRepo{projects: map[uuid.UUID]uuid.UUID{projectID: tenantID}}
	sr := &fakeSbomRepo{
		byID:      map[uuid.UUID]model.Sbom{sbom.ID: sbom},
		byProject: map[uuid.UUID][]model.Sbom{projectID: {sbom}},
	}
	cr := &fakeComponentRepo{
		components: map[uuid.UUID][]model.Component{},
		vulns:      map[uuid.UUID][]model.ComponentVulnerability{},
		byID:       comps,
	}
	lr := &fakeLicenseRepo{policies: map[uuid.UUID][]model.LicensePolicy{}}
	return NewService(pr, sr, cr, lr)
}

func mkComp(id, sbomID uuid.UUID, name, version, purl, typ string) model.Component {
	return model.Component{ID: id, SbomID: sbomID, Name: name, Version: version, Purl: purl, Type: typ}
}

func pathJoined(p []GraphNode) string {
	ids := make([]string, 0, len(p))
	for _, n := range p {
		ids = append(ids, n.ID)
	}
	return strings.Join(ids, " -> ")
}

func pathSet(paths [][]GraphNode) map[string]struct{} {
	out := map[string]struct{}{}
	for _, p := range paths {
		out[pathJoined(p)] = struct{}{}
	}
	return out
}

// ---------- cycle guard ----------

// TestComputePaths_CycleGuard pins the kickoff hard requirement: a
// multi-node dependency cycle (a → b → a) must NOT loop forever. The
// fixture wires root → a, a → b, b → a and queries b; the visited-set
// cycle guard must produce the single acyclic path root → a → b and stop.
func TestComputePaths_CycleGuard(t *testing.T) {
	tenantID, projectID, sbomID := uuid.New(), uuid.New(), uuid.New()
	raw := makeCycloneDXBytesWithMetadata(t,
		cdxComponent{BOMRef: "root", Type: "application", Name: "root", Version: "1.0", Purl: "pkg:my/root@1.0"},
		[]cdxComponent{
			{BOMRef: "a", Type: "library", Name: "a", Version: "1.0.0", Purl: "pkg:npm/a@1.0.0"},
			{BOMRef: "b", Type: "library", Name: "b", Version: "1.0.0", Purl: "pkg:npm/b@1.0.0"},
		},
		[]cdxDependency{
			{Ref: "root", Dependencies: []string{"a"}},
			{Ref: "a", Dependencies: []string{"b"}},
			{Ref: "b", Dependencies: []string{"a"}}, // cycle a <-> b
		},
	)
	sbom := model.Sbom{ID: sbomID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", RawData: raw, CreatedAt: time.Now()}
	compID := uuid.New()
	svc := newPathsService(t, tenantID, projectID, sbom, map[uuid.UUID]model.Component{
		compID: mkComp(compID, sbomID, "b", "1.0.0", "pkg:npm/b@1.0.0", "library"),
	})

	done := make(chan struct{})
	var resp *PathsResponse
	var err error
	go func() {
		resp, err = svc.ComputePaths(context.Background(), tenantID, projectID, compID, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ComputePaths did not terminate on a cyclic graph — cycle guard regressed")
	}
	if err != nil {
		t.Fatalf("ComputePaths error: %v", err)
	}

	if resp.Degraded {
		t.Errorf("cyclonedx should not be degraded")
	}
	if len(resp.Paths) != 1 {
		t.Fatalf("want 1 acyclic path, got %d: %v", len(resp.Paths), pathSet(resp.Paths))
	}
	if got := pathJoined(resp.Paths[0]); got != "pkg:my/root -> pkg:npm/a -> pkg:npm/b" {
		t.Errorf("path = %q, want root -> a -> b", got)
	}
	if resp.IsDirect {
		t.Errorf("b is transitive, is_direct must be false")
	}
	if resp.PathCount != 1 || resp.Truncated {
		t.Errorf("path_count=%d truncated=%v, want 1/false", resp.PathCount, resp.Truncated)
	}
}

// ---------- multi-path ----------

// TestComputePaths_MultiPath: the same target enters via two independent
// routes (root → x → z and root → y → z) — both paths must surface.
func TestComputePaths_MultiPath(t *testing.T) {
	tenantID, projectID, sbomID := uuid.New(), uuid.New(), uuid.New()
	raw := makeCycloneDXBytesWithMetadata(t,
		cdxComponent{BOMRef: "root", Type: "application", Name: "root", Version: "1.0", Purl: "pkg:my/root@1.0"},
		[]cdxComponent{
			{BOMRef: "x", Type: "library", Name: "x", Version: "1.0.0", Purl: "pkg:npm/x@1.0.0"},
			{BOMRef: "y", Type: "library", Name: "y", Version: "1.0.0", Purl: "pkg:npm/y@1.0.0"},
			{BOMRef: "z", Type: "library", Name: "z", Version: "1.0.0", Purl: "pkg:npm/z@1.0.0"},
		},
		[]cdxDependency{
			{Ref: "root", Dependencies: []string{"x", "y"}},
			{Ref: "x", Dependencies: []string{"z"}},
			{Ref: "y", Dependencies: []string{"z"}},
		},
	)
	sbom := model.Sbom{ID: sbomID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", RawData: raw, CreatedAt: time.Now()}
	compID := uuid.New()
	svc := newPathsService(t, tenantID, projectID, sbom, map[uuid.UUID]model.Component{
		compID: mkComp(compID, sbomID, "z", "1.0.0", "pkg:npm/z@1.0.0", "library"),
	})

	resp, err := svc.ComputePaths(context.Background(), tenantID, projectID, compID, nil)
	if err != nil {
		t.Fatalf("ComputePaths error: %v", err)
	}
	if len(resp.Paths) != 2 {
		t.Fatalf("want 2 paths, got %d: %v", len(resp.Paths), pathSet(resp.Paths))
	}
	set := pathSet(resp.Paths)
	for _, want := range []string{
		"pkg:my/root -> pkg:npm/x -> pkg:npm/z",
		"pkg:my/root -> pkg:npm/y -> pkg:npm/z",
	} {
		if _, ok := set[want]; !ok {
			t.Errorf("missing path %q in %v", want, set)
		}
	}
	if resp.IsDirect {
		t.Errorf("z is transitive, is_direct must be false")
	}
}

// ---------- root detection / is_direct ----------

// TestComputePaths_RootAndDirect covers the three is_direct cases against
// one graph root(app) → direct(lib) → transitive(lib):
//   - target == root  → is_direct true, path length 1 (root itself)
//   - target == direct child of root → is_direct true, path length 2
//   - target == transitive → is_direct false, path length 3
func TestComputePaths_RootAndDirect(t *testing.T) {
	tenantID, projectID, sbomID := uuid.New(), uuid.New(), uuid.New()
	raw := makeCycloneDXBytesWithMetadata(t,
		cdxComponent{BOMRef: "root", Type: "application", Name: "root", Version: "1.0", Purl: "pkg:my/root@1.0"},
		[]cdxComponent{
			{BOMRef: "direct", Type: "library", Name: "direct", Version: "1.0.0", Purl: "pkg:npm/direct@1.0.0"},
			{BOMRef: "trans", Type: "library", Name: "trans", Version: "1.0.0", Purl: "pkg:npm/trans@1.0.0"},
		},
		[]cdxDependency{
			{Ref: "root", Dependencies: []string{"direct"}},
			{Ref: "direct", Dependencies: []string{"trans"}},
		},
	)
	sbom := model.Sbom{ID: sbomID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", RawData: raw, CreatedAt: time.Now()}

	rootID, directID, transID := uuid.New(), uuid.New(), uuid.New()
	svc := newPathsService(t, tenantID, projectID, sbom, map[uuid.UUID]model.Component{
		rootID:   mkComp(rootID, sbomID, "root", "1.0", "pkg:my/root@1.0", "application"),
		directID: mkComp(directID, sbomID, "direct", "1.0.0", "pkg:npm/direct@1.0.0", "library"),
		transID:  mkComp(transID, sbomID, "trans", "1.0.0", "pkg:npm/trans@1.0.0", "library"),
	})

	cases := []struct {
		name       string
		compID     uuid.UUID
		wantDirect bool
		wantPath   string
	}{
		{"root itself", rootID, true, "pkg:my/root"},
		{"direct dependency", directID, true, "pkg:my/root -> pkg:npm/direct"},
		{"transitive dependency", transID, false, "pkg:my/root -> pkg:npm/direct -> pkg:npm/trans"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := svc.ComputePaths(context.Background(), tenantID, projectID, tc.compID, nil)
			if err != nil {
				t.Fatalf("ComputePaths error: %v", err)
			}
			if resp.IsDirect != tc.wantDirect {
				t.Errorf("is_direct = %v, want %v", resp.IsDirect, tc.wantDirect)
			}
			if len(resp.Paths) != 1 {
				t.Fatalf("want 1 path, got %d: %v", len(resp.Paths), pathSet(resp.Paths))
			}
			if got := pathJoined(resp.Paths[0]); got != tc.wantPath {
				t.Errorf("path = %q, want %q", got, tc.wantPath)
			}
		})
	}
}

// ---------- SPDX degrade ----------

// TestComputePaths_SPDXDegrades: an SPDX SBOM has no parsed edges, so the
// response is degraded=true with empty paths (graceful degrade).
func TestComputePaths_SPDXDegrades(t *testing.T) {
	tenantID, projectID, sbomID := uuid.New(), uuid.New(), uuid.New()
	spdx := []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"qs","versionInfo":"6.2.0"}]}`)
	sbom := model.Sbom{ID: sbomID, TenantID: tenantID, ProjectID: projectID, Format: "spdx", RawData: spdx, CreatedAt: time.Now()}
	compID := uuid.New()
	svc := newPathsService(t, tenantID, projectID, sbom, map[uuid.UUID]model.Component{
		compID: mkComp(compID, sbomID, "qs", "6.2.0", "", "library"),
	})

	resp, err := svc.ComputePaths(context.Background(), tenantID, projectID, compID, nil)
	if err != nil {
		t.Fatalf("ComputePaths error: %v", err)
	}
	if !resp.Degraded {
		t.Errorf("SPDX must set degraded=true")
	}
	if len(resp.Paths) != 0 || resp.PathCount != 0 {
		t.Errorf("degraded paths must be empty, got %d", len(resp.Paths))
	}
	if resp.IsDirect {
		t.Errorf("is_direct must be false when degraded")
	}
	if resp.Format != "spdx" {
		t.Errorf("format = %q, want spdx", resp.Format)
	}
	// F164: paths must marshal as [], never null.
	raw, _ := json.Marshal(resp)
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := decoded["paths"].([]interface{}); !ok {
		t.Errorf("F164: paths not a JSON array: %T", decoded["paths"])
	}
}

// ---------- cap / truncation ----------

// TestComputePaths_TruncationCap: a fan-in graph with more than
// maxDependencyPaths distinct root → target paths must return exactly the
// cap and flag truncated=true (silent drop is forbidden).
func TestComputePaths_TruncationCap(t *testing.T) {
	tenantID, projectID, sbomID := uuid.New(), uuid.New(), uuid.New()

	const fanIn = maxDependencyPaths + 10 // guarantee we exceed the cap
	comps := make([]cdxComponent, 0, fanIn+1)
	rootDeps := cdxDependency{Ref: "root"}
	deps := []cdxDependency{}
	for i := 0; i < fanIn; i++ {
		ref := fmt.Sprintf("mid-%d", i)
		comps = append(comps, cdxComponent{
			BOMRef: ref, Type: "library", Name: ref, Version: "1.0.0",
			Purl: fmt.Sprintf("pkg:npm/mid-%d@1.0.0", i),
		})
		rootDeps.Dependencies = append(rootDeps.Dependencies, ref)
		deps = append(deps, cdxDependency{Ref: ref, Dependencies: []string{"target"}})
	}
	comps = append(comps, cdxComponent{BOMRef: "target", Type: "library", Name: "target", Version: "1.0.0", Purl: "pkg:npm/target@1.0.0"})
	deps = append([]cdxDependency{rootDeps}, deps...)

	raw := makeCycloneDXBytesWithMetadata(t,
		cdxComponent{BOMRef: "root", Type: "application", Name: "root", Version: "1.0", Purl: "pkg:my/root@1.0"},
		comps, deps,
	)
	sbom := model.Sbom{ID: sbomID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", RawData: raw, CreatedAt: time.Now()}
	compID := uuid.New()
	svc := newPathsService(t, tenantID, projectID, sbom, map[uuid.UUID]model.Component{
		compID: mkComp(compID, sbomID, "target", "1.0.0", "pkg:npm/target@1.0.0", "library"),
	})

	resp, err := svc.ComputePaths(context.Background(), tenantID, projectID, compID, nil)
	if err != nil {
		t.Fatalf("ComputePaths error: %v", err)
	}
	if !resp.Truncated {
		t.Errorf("truncated must be true when the path cap is exceeded")
	}
	if len(resp.Paths) != maxDependencyPaths {
		t.Errorf("want exactly %d paths (the cap), got %d", maxDependencyPaths, len(resp.Paths))
	}
	if resp.PathCount != len(resp.Paths) {
		t.Errorf("path_count %d must equal len(paths) %d", resp.PathCount, len(resp.Paths))
	}
}

// ---------- version granularity ----------

// TestComputePaths_VersionGranularityCollapse pins the documented caveat:
// node IDs are version-stripped purls, so two versions of the same library
// collapse to ONE graph node. root depends on liba@1.0.0 AND liba@2.0.0 (two
// component entries, same purl-name); the traversal sees a single node and
// returns a single path. The node projection carries the first-indexed
// version (1.0.0) while the response `component` block keeps the queried
// version (2.0.0).
func TestComputePaths_VersionGranularityCollapse(t *testing.T) {
	tenantID, projectID, sbomID := uuid.New(), uuid.New(), uuid.New()
	raw := makeCycloneDXBytesWithMetadata(t,
		cdxComponent{BOMRef: "root", Type: "application", Name: "root", Version: "1.0", Purl: "pkg:my/root@1.0"},
		[]cdxComponent{
			{BOMRef: "liba-1", Type: "library", Name: "liba", Version: "1.0.0", Purl: "pkg:npm/liba@1.0.0"},
			{BOMRef: "liba-2", Type: "library", Name: "liba", Version: "2.0.0", Purl: "pkg:npm/liba@2.0.0"},
		},
		[]cdxDependency{
			{Ref: "root", Dependencies: []string{"liba-1", "liba-2"}},
		},
	)
	sbom := model.Sbom{ID: sbomID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", RawData: raw, CreatedAt: time.Now()}
	compID := uuid.New()
	// Query the 2.0.0 row; its match key is the version-stripped purl.
	svc := newPathsService(t, tenantID, projectID, sbom, map[uuid.UUID]model.Component{
		compID: mkComp(compID, sbomID, "liba", "2.0.0", "pkg:npm/liba@2.0.0", "library"),
	})

	resp, err := svc.ComputePaths(context.Background(), tenantID, projectID, compID, nil)
	if err != nil {
		t.Fatalf("ComputePaths error: %v", err)
	}
	// Two version entries collapse to one node → a single path, not two.
	if len(resp.Paths) != 1 {
		t.Fatalf("version collapse: want 1 path, got %d: %v", len(resp.Paths), pathSet(resp.Paths))
	}
	if got := pathJoined(resp.Paths[0]); got != "pkg:my/root -> pkg:npm/liba" {
		t.Errorf("path = %q, want root -> liba (single node)", got)
	}
	// Response component block keeps the queried version.
	if resp.Component.Version != "2.0.0" {
		t.Errorf("component.version = %q, want 2.0.0 (queried row)", resp.Component.Version)
	}
	// The collapsed node carries the first-indexed version (1.0.0).
	leaf := resp.Paths[0][len(resp.Paths[0])-1]
	if leaf.ID != "pkg:npm/liba" || leaf.Version != "1.0.0" {
		t.Errorf("collapsed node = %+v, want id=pkg:npm/liba version=1.0.0 (first-write-wins)", leaf)
	}
	if resp.IsDirect != true {
		t.Errorf("liba is a direct dependency of root, is_direct must be true")
	}
}

// ---------- component absent from graph ----------

// TestComputePaths_ComponentNotInGraph: a component that belongs to the
// project (ownership OK) but whose match key is absent from the resolved
// SBOM graph yields an empty path list — a valid answer, not an error.
func TestComputePaths_ComponentNotInGraph(t *testing.T) {
	tenantID, projectID, sbomID := uuid.New(), uuid.New(), uuid.New()
	raw := makeCycloneDXBytesWithMetadata(t,
		cdxComponent{BOMRef: "root", Type: "application", Name: "root", Version: "1.0", Purl: "pkg:my/root@1.0"},
		[]cdxComponent{{BOMRef: "a", Type: "library", Name: "a", Version: "1.0.0", Purl: "pkg:npm/a@1.0.0"}},
		[]cdxDependency{{Ref: "root", Dependencies: []string{"a"}}},
	)
	sbom := model.Sbom{ID: sbomID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", RawData: raw, CreatedAt: time.Now()}
	compID := uuid.New()
	// component owned by the sbom (ownership passes) but not present in the graph.
	svc := newPathsService(t, tenantID, projectID, sbom, map[uuid.UUID]model.Component{
		compID: mkComp(compID, sbomID, "ghost", "9.9.9", "pkg:npm/ghost@9.9.9", "library"),
	})

	resp, err := svc.ComputePaths(context.Background(), tenantID, projectID, compID, nil)
	if err != nil {
		t.Fatalf("ComputePaths error: %v", err)
	}
	if resp.Degraded {
		t.Errorf("cyclonedx (edges present) must not be degraded")
	}
	if len(resp.Paths) != 0 || resp.PathCount != 0 || resp.IsDirect || resp.Truncated {
		t.Errorf("absent component: want empty/false result, got %+v", resp)
	}
}

// ---------- ownership (F379) ----------

// TestComputePaths_Ownership covers the 404-class outcomes without leaking
// existence: unknown component id, cross-project component id, cross-project
// ?sbom, and a wrong-tenant project.
func TestComputePaths_Ownership(t *testing.T) {
	tenantID, projectID, sbomID := uuid.New(), uuid.New(), uuid.New()
	raw := makeCycloneDXBytesWithMetadata(t,
		cdxComponent{BOMRef: "root", Type: "application", Name: "root", Version: "1.0", Purl: "pkg:my/root@1.0"},
		[]cdxComponent{{BOMRef: "a", Type: "library", Name: "a", Version: "1.0.0", Purl: "pkg:npm/a@1.0.0"}},
		[]cdxDependency{{Ref: "root", Dependencies: []string{"a"}}},
	)
	sbom := model.Sbom{ID: sbomID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", RawData: raw, CreatedAt: time.Now()}

	// A second project (same tenant) with its own SBOM + component — used
	// for the cross-project checks.
	otherProjectID, otherSbomID := uuid.New(), uuid.New()
	otherSbom := model.Sbom{ID: otherSbomID, TenantID: tenantID, ProjectID: otherProjectID, Format: "cyclonedx", RawData: raw, CreatedAt: time.Now()}
	crossCompID := uuid.New()

	pr := &fakeProjectRepo{projects: map[uuid.UUID]uuid.UUID{projectID: tenantID, otherProjectID: tenantID}}
	sr := &fakeSbomRepo{
		byID:      map[uuid.UUID]model.Sbom{sbomID: sbom, otherSbomID: otherSbom},
		byProject: map[uuid.UUID][]model.Sbom{projectID: {sbom}, otherProjectID: {otherSbom}},
	}
	cr := &fakeComponentRepo{
		components: map[uuid.UUID][]model.Component{},
		vulns:      map[uuid.UUID][]model.ComponentVulnerability{},
		byID: map[uuid.UUID]model.Component{
			// belongs to otherProject's sbom.
			crossCompID: mkComp(crossCompID, otherSbomID, "a", "1.0.0", "pkg:npm/a@1.0.0", "library"),
		},
	}
	lr := &fakeLicenseRepo{policies: map[uuid.UUID][]model.LicensePolicy{}}
	svc := NewService(pr, sr, cr, lr)

	t.Run("unknown component id -> ErrComponentNotFound", func(t *testing.T) {
		_, err := svc.ComputePaths(context.Background(), tenantID, projectID, uuid.New(), nil)
		if !errors.Is(err, ErrComponentNotFound) {
			t.Fatalf("err = %v, want ErrComponentNotFound", err)
		}
	})

	t.Run("cross-project component id -> ErrComponentNotFound (no leak)", func(t *testing.T) {
		_, err := svc.ComputePaths(context.Background(), tenantID, projectID, crossCompID, nil)
		if !errors.Is(err, ErrComponentNotFound) {
			t.Fatalf("err = %v, want ErrComponentNotFound", err)
		}
	})

	t.Run("cross-project ?sbom -> ErrSbomNotInProject", func(t *testing.T) {
		// component legitimately in projectID, but ?sbom points at other project.
		localComp := uuid.New()
		cr.byID[localComp] = mkComp(localComp, sbomID, "a", "1.0.0", "pkg:npm/a@1.0.0", "library")
		other := otherSbomID
		_, err := svc.ComputePaths(context.Background(), tenantID, projectID, localComp, &other)
		if !errors.Is(err, ErrSbomNotInProject) {
			t.Fatalf("err = %v, want ErrSbomNotInProject", err)
		}
	})

	t.Run("wrong tenant -> ErrNoRows-class (project not found)", func(t *testing.T) {
		localComp := uuid.New()
		cr.byID[localComp] = mkComp(localComp, sbomID, "a", "1.0.0", "pkg:npm/a@1.0.0", "library")
		_, err := svc.ComputePaths(context.Background(), uuid.New(), projectID, localComp, nil)
		if err == nil {
			t.Fatalf("want error for wrong tenant, got nil")
		}
	})
}

// TestComputePaths_ExplicitSbomParam: passing ?sbom resolves that SBOM's
// graph (not the latest) and reports its id in the response.
func TestComputePaths_ExplicitSbomParam(t *testing.T) {
	tenantID, projectID, sbomID := uuid.New(), uuid.New(), uuid.New()
	raw := makeCycloneDXBytesWithMetadata(t,
		cdxComponent{BOMRef: "root", Type: "application", Name: "root", Version: "1.0", Purl: "pkg:my/root@1.0"},
		[]cdxComponent{{BOMRef: "a", Type: "library", Name: "a", Version: "1.0.0", Purl: "pkg:npm/a@1.0.0"}},
		[]cdxDependency{{Ref: "root", Dependencies: []string{"a"}}},
	)
	sbom := model.Sbom{ID: sbomID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", RawData: raw, CreatedAt: time.Now()}
	compID := uuid.New()
	svc := newPathsService(t, tenantID, projectID, sbom, map[uuid.UUID]model.Component{
		compID: mkComp(compID, sbomID, "a", "1.0.0", "pkg:npm/a@1.0.0", "library"),
	})

	explicit := sbomID
	resp, err := svc.ComputePaths(context.Background(), tenantID, projectID, compID, &explicit)
	if err != nil {
		t.Fatalf("ComputePaths error: %v", err)
	}
	if resp.SbomID != sbomID {
		t.Errorf("sbom_id = %s, want %s", resp.SbomID, sbomID)
	}
	if !resp.IsDirect || len(resp.Paths) != 1 {
		t.Errorf("want direct dep with 1 path, got is_direct=%v paths=%d", resp.IsDirect, len(resp.Paths))
	}
}
