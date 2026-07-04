// Package diff — cross-project reverse-reachability export for M30-A
// (#138, F402).
//
// M29-A (graph_paths.go) answers "how does this component get pulled into
// THIS project's SBOM" by parsing one SBOM on demand and walking its
// CycloneDX dependency graph backwards (target → roots). M30-A fuses that
// per-SBOM traversal with M28's cross-project blast radius: for a single
// CVE it walks EVERY affected project's latest SBOM so an auditor sees, per
// project, the entry path(s) each vulnerable component arrives through.
//
// That cross-project loop lives in package service (service/cve_paths.go),
// which cannot reach the unexported M29 traversal primitives
// (parseSbomGraph / buildReverseAdjacency / findRoots / isDirectDependency /
// enumeratePaths) directly. This file is the thin export surface that lets
// it reuse them WITHOUT re-implementing (or forking) any traversal logic —
// every guard the M29 kickoff pinned (F399 DFS, per-path cycle guard,
// maxDependencyPaths=50 cap, maxPathEnumerationSteps=20000 budget,
// shortest-first sort, F401 declared-root) is inherited verbatim because we
// call the exact same functions ComputePaths does.
//
// Efficiency contract (M30 kickoff): a project's SBOM is parsed into a
// ReachabilityGraph ONCE (ParseReachabilityGraph), then PathsTo is invoked
// per affected component against that single parsed handle — never
// re-parsing the raw bytes once per component.
package diff

import (
	"strings"

	"github.com/sbomhub/sbomhub/internal/model"
)

// ReachabilityGraph is a parse-once handle over a single SBOM's reverse
// reachability graph. It caches the parsed node/edge graph, the inverted
// child→parents adjacency and the root set so PathsTo can be called for
// many target components without re-parsing the raw SBOM bytes.
//
// It is produced by ParseReachabilityGraph and consumed by PathsTo; the
// fields are unexported so the only supported use is "parse once, query
// many". degraded records that the source SBOM carried no dependency edges
// (SPDX / unknown / unparseable) — mirroring ComputePaths, a degraded graph
// answers every PathsTo as in-graph=false with empty paths rather than
// fabricating a single-node path from the nodes-only projection.
type ReachabilityGraph struct {
	graph          sbomGraph
	childToParents map[string][]string
	roots          map[string]struct{}
	degraded       bool
}

// ComponentPaths is the per-component reverse-reachability answer PathsTo
// returns. It is the graft point the service maps into the JSON response:
//
//   - InGraph   — the component's match key exists in this SBOM's graph
//     (false when the component lives only in an older snapshot than the
//     latest traversed one, or when the graph is degraded).
//   - IsDirect  — the component is a root or a direct child of a root.
//   - Truncated — enumeration hit the M29 path cap / step budget (the
//     silent-truncation-forbidden flag is propagated, never dropped).
//   - Paths     — root → … → target chains (make([][]GraphNode, 0), so a
//     component with no path serialises as [] not null, F164).
type ComponentPaths struct {
	InGraph   bool
	IsDirect  bool
	Truncated bool
	Paths     [][]GraphNode
}

// ParseReachabilityGraph parses a single SBOM's raw bytes into a
// reverse-reachability handle and reports whether the SBOM is degraded (no
// dependency edges). The bool return mirrors the project-level `degraded`
// flag in the M30 response contract.
//
// It calls the EXISTING unexported parseSbomGraph → buildReverseAdjacency →
// findRoots ONCE, exactly as ComputePaths does for the single-project view.
// Non-CycloneDX inputs short-circuit to a degraded, empty handle BEFORE any
// graph is built — identical to ComputePaths, which sets degraded + empty
// paths before parseSbomGraph for SPDX/unknown. Building a nodes-only SPDX
// graph and letting findRoots mark every node a root would otherwise emit a
// bogus single-node "direct" path for any nodes-only match, so the
// short-circuit is load-bearing for honest degraded output.
func ParseReachabilityGraph(rawData []byte, format string) (*ReachabilityGraph, bool) {
	if model.SbomFormat(strings.ToLower(strings.TrimSpace(format))) != model.FormatCycloneDX {
		return &ReachabilityGraph{degraded: true, graph: emptySbomGraph()}, true
	}
	// parseSbomGraph dispatches on the (already-checked cyclonedx) format;
	// a synthetic *model.Sbom lets us reuse the exact dispatch + best-effort
	// empty-graph-on-malformed behaviour rather than calling
	// parseCycloneDXGraph directly.
	g := parseSbomGraph(&model.Sbom{Format: format, RawData: rawData})
	return &ReachabilityGraph{
		graph:          g,
		childToParents: buildReverseAdjacency(g),
		roots:          findRoots(g),
	}, false
}

// PathsTo enumerates the root → … → comp dependency paths for one affected
// component against this pre-parsed graph. It computes comp's deterministic
// match key (componentMatchKey, version-stripped — same identity M29 uses,
// so two versions of a library collapse to one node) and:
//
//   - degraded graph OR empty/unresolvable key OR key absent from the graph
//     → {InGraph:false} with empty paths (a valid honest answer — the
//     component is not present in the latest SBOM's dependency graph);
//   - otherwise → isDirectDependency + enumeratePaths (the F399 DFS with the
//     per-path cycle guard, path cap, step budget and shortest-first sort)
//     exactly as ComputePaths, returning {InGraph:true, IsDirect, Truncated,
//     Paths}.
func (g *ReachabilityGraph) PathsTo(comp model.Component) ComponentPaths {
	out := ComponentPaths{Paths: make([][]GraphNode, 0)}
	if g.degraded {
		return out
	}
	targetID := componentMatchKey(comp)
	if targetID == "" {
		return out
	}
	if _, inGraph := g.graph.nodes[targetID]; !inGraph {
		return out
	}
	out.InGraph = true
	out.IsDirect = isDirectDependency(g.childToParents, g.roots, targetID)
	paths, truncated := enumeratePaths(g.graph, g.childToParents, g.roots, targetID)
	out.Paths = paths
	out.Truncated = truncated
	return out
}
