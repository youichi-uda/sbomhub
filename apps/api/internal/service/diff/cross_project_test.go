// Package diff — cross_project.go tests for M30-A (#138, F402).
//
// These pin the exported reverse-reachability surface (ParseReachabilityGraph
// / ReachabilityGraph.PathsTo) that service/cve_paths.go reuses. The heavy
// traversal correctness (cycles / caps / DFS / roots) is already covered by
// graph_paths_test.go against ComputePaths; because PathsTo calls the SAME
// unexported primitives, these tests focus on the export contract: parse
// once → query many, degraded short-circuit, in-graph vs absent, and that
// is_direct / truncated / path ordering flow through unchanged.
package diff

import (
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

// crossFixtureRaw builds a CycloneDX SBOM with:
//
//	root(app) → express → qs        (qs is transitive, depth 2)
//	root(app) → lodash              (lodash is direct)
//
// so a single parsed ReachabilityGraph can answer several PathsTo queries.
func crossFixtureRaw(t *testing.T) []byte {
	t.Helper()
	return makeCycloneDXBytesWithMetadata(t,
		cdxComponent{BOMRef: "root", Type: "application", Name: "app", Version: "1.0.0", Purl: "pkg:npm/app@1.0.0"},
		[]cdxComponent{
			{BOMRef: "express", Type: "library", Name: "express", Version: "4.18.0", Purl: "pkg:npm/express@4.18.0"},
			{BOMRef: "qs", Type: "library", Name: "qs", Version: "6.2.0", Purl: "pkg:npm/qs@6.2.0"},
			{BOMRef: "lodash", Type: "library", Name: "lodash", Version: "4.17.21", Purl: "pkg:npm/lodash@4.17.21"},
		},
		[]cdxDependency{
			{Ref: "root", Dependencies: []string{"express", "lodash"}},
			{Ref: "express", Dependencies: []string{"qs"}},
		},
	)
}

func comp(name, version, purl, typ string) model.Component {
	return model.Component{Name: name, Version: version, Purl: purl, Type: typ}
}

// TestParseReachabilityGraph_ParseOnceQueryMany pins the efficiency contract:
// one ParseReachabilityGraph call produces a handle that answers many
// PathsTo queries — the transitive component (qs) resolves to the full
// root→express→qs chain, and the direct component (lodash) resolves with
// is_direct=true — all without re-parsing the raw bytes.
func TestParseReachabilityGraph_ParseOnceQueryMany(t *testing.T) {
	g, degraded := ParseReachabilityGraph(crossFixtureRaw(t), "cyclonedx")
	if degraded {
		t.Fatalf("cyclonedx SBOM must not be degraded")
	}

	// --- transitive component qs: root → express → qs ---
	qs := g.PathsTo(comp("qs", "6.2.0", "pkg:npm/qs@6.2.0", "library"))
	if !qs.InGraph {
		t.Fatalf("qs must be in graph")
	}
	if qs.IsDirect {
		t.Errorf("qs is transitive (depth 2), is_direct must be false")
	}
	if qs.Truncated {
		t.Errorf("qs enumeration must not be truncated for a 1-path graph")
	}
	if len(qs.Paths) != 1 {
		t.Fatalf("qs path count = %d, want 1", len(qs.Paths))
	}
	got := pathJoined(qs.Paths[0])
	if want := "pkg:npm/app -> pkg:npm/express -> pkg:npm/qs"; got != want {
		t.Errorf("qs path = %q, want %q", got, want)
	}
	// No revisits: each node id appears once.
	seen := map[string]int{}
	for _, n := range qs.Paths[0] {
		seen[n.ID]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("node %q appears %d times in path (revisit)", id, n)
		}
	}

	// --- direct component lodash: root → lodash, is_direct=true ---
	lodash := g.PathsTo(comp("lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "library"))
	if !lodash.InGraph {
		t.Fatalf("lodash must be in graph")
	}
	if !lodash.IsDirect {
		t.Errorf("lodash is a direct child of the root, is_direct must be true")
	}
	if len(lodash.Paths) != 1 || pathJoined(lodash.Paths[0]) != "pkg:npm/app -> pkg:npm/lodash" {
		t.Errorf("lodash path = %v, want [pkg:npm/app -> pkg:npm/lodash]", lodash.Paths)
	}

	// --- the declared root itself is direct (path length 1) ---
	root := g.PathsTo(comp("app", "1.0.0", "pkg:npm/app@1.0.0", "application"))
	if !root.InGraph || !root.IsDirect {
		t.Errorf("root app must be in-graph + direct, got in_graph=%v is_direct=%v", root.InGraph, root.IsDirect)
	}
}

// TestPathsTo_AbsentComponent pins the honest-empty answer: a component whose
// match key is not in the parsed graph (e.g. it lives only in an older
// snapshot than the latest traversed one) returns in_graph=false with a
// non-nil empty path slice — not an error, not a fabricated path.
func TestPathsTo_AbsentComponent(t *testing.T) {
	g, _ := ParseReachabilityGraph(crossFixtureRaw(t), "cyclonedx")
	got := g.PathsTo(comp("ghost", "9.9.9", "pkg:npm/ghost@9.9.9", "library"))
	if got.InGraph {
		t.Errorf("absent component must report in_graph=false")
	}
	if got.IsDirect || got.Truncated {
		t.Errorf("absent component must have is_direct=false truncated=false, got %+v", got)
	}
	if got.Paths == nil {
		t.Errorf("paths must be a non-nil empty slice (JSON []), got nil")
	}
	if len(got.Paths) != 0 {
		t.Errorf("absent component path count = %d, want 0", len(got.Paths))
	}
}

// TestParseReachabilityGraph_DegradedSPDX pins the project-level degrade:
// an SPDX (or any non-cyclonedx) SBOM carries no dependency edges, so
// ParseReachabilityGraph reports degraded=true and PathsTo answers every
// component in-graph=false with empty paths — even a package name that DOES
// appear in the SPDX nodes-only projection (proving the degraded
// short-circuit fires before any nodes-only graph could fabricate a
// single-node "direct" path).
func TestParseReachabilityGraph_DegradedSPDX(t *testing.T) {
	spdx := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"packages": [
			{"name": "openssl", "versionInfo": "3.0.0"},
			{"name": "zlib", "versionInfo": "1.2.13"}
		]
	}`)
	g, degraded := ParseReachabilityGraph(spdx, "spdx")
	if !degraded {
		t.Fatalf("spdx SBOM must be degraded (no edge support)")
	}
	// openssl is present in the SPDX packages list, yet a degraded graph must
	// NOT surface it as in-graph with a bogus path.
	got := g.PathsTo(comp("openssl", "3.0.0", "", "library"))
	if got.InGraph {
		t.Errorf("degraded graph must report in_graph=false even for a listed package")
	}
	if len(got.Paths) != 0 {
		t.Errorf("degraded graph path count = %d, want 0", len(got.Paths))
	}
}

// TestParseReachabilityGraph_UnknownFormatDegraded pins that an unknown /
// empty format is treated as degraded (never parsed as cyclonedx).
func TestParseReachabilityGraph_UnknownFormatDegraded(t *testing.T) {
	for _, f := range []string{"", "unknown", "SPDX", "CycloneDX-but-typo"} {
		g, degraded := ParseReachabilityGraph([]byte(`{}`), f)
		if !degraded {
			t.Errorf("format %q must be degraded", f)
		}
		if got := g.PathsTo(comp("x", "1", "pkg:npm/x@1", "library")); got.InGraph {
			t.Errorf("format %q: degraded PathsTo must be in_graph=false", f)
		}
	}
}

// TestPathsTo_EmptyMatchKey pins that a component with neither purl nor name
// (empty match key) never resolves in-graph.
func TestPathsTo_EmptyMatchKey(t *testing.T) {
	g, _ := ParseReachabilityGraph(crossFixtureRaw(t), "cyclonedx")
	got := g.PathsTo(comp("", "", "", ""))
	if got.InGraph || len(got.Paths) != 0 {
		t.Errorf("empty-key component must be in_graph=false with 0 paths, got %+v", got)
	}
}

// TestParseReachabilityGraph_CycleGuardInherited is a smoke check that the
// export path inherits the M29 per-path cycle guard (a → b → a must not loop
// forever and yields the single acyclic root → a → b chain). The exhaustive
// guard coverage lives in graph_paths_test.go; this just confirms PathsTo
// reaches the same enumeratePaths.
func TestParseReachabilityGraph_CycleGuardInherited(t *testing.T) {
	raw := makeCycloneDXBytesWithMetadata(t,
		cdxComponent{BOMRef: "root", Type: "application", Name: "root", Version: "1.0", Purl: "pkg:my/root@1.0"},
		[]cdxComponent{
			{BOMRef: "a", Type: "library", Name: "a", Version: "1.0.0", Purl: "pkg:npm/a@1.0.0"},
			{BOMRef: "b", Type: "library", Name: "b", Version: "1.0.0", Purl: "pkg:npm/b@1.0.0"},
		},
		[]cdxDependency{
			{Ref: "root", Dependencies: []string{"a"}},
			{Ref: "a", Dependencies: []string{"b"}},
			{Ref: "b", Dependencies: []string{"a"}}, // cycle
		},
	)
	g, _ := ParseReachabilityGraph(raw, "cyclonedx")
	got := g.PathsTo(comp("b", "1.0.0", "pkg:npm/b@1.0.0", "library"))
	if !got.InGraph {
		t.Fatalf("b must be in graph")
	}
	if len(got.Paths) != 1 || pathJoined(got.Paths[0]) != "pkg:my/root -> pkg:npm/a -> pkg:npm/b" {
		t.Errorf("cycle-guarded path = %v, want [pkg:my/root -> pkg:npm/a -> pkg:npm/b]", got.Paths)
	}
}
