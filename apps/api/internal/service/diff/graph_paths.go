// Package diff — dependency path-to-root traversal for M29-A (#136, F397).
//
// ComputePaths answers "how does this (usually transitive, usually
// vulnerable) component get pulled into the project?" by reconstructing
// the CycloneDX dependency graph of a single SBOM on demand and walking
// it BACKWARDS — from the target component up through its parents to the
// graph roots. The developer then sees, for each entry path:
//
//	root → express → body-parser → qs (vuln)
//
// so they can decide what to upgrade (the direct dependency, or — for a
// transitive — which parent to bump).
//
// Why re-parse the raw SBOM here (rather than a materialised edge table):
// the same rationale as graph.go — the parent → child edges only live in
// the CycloneDX `dependencies` block, which the M10-6 ingest discards, and
// re-parsing per request is acceptable for this lightly-trafficked auditor
// surface. A materialised `sbom_dependencies` table (Path B) is deferred to
// M30+ (cross-project transitive / extreme scale only).
//
// Format coverage:
//   - cyclonedx: full reverse reachability via the `dependencies` edges.
//   - spdx / spdx3 / unknown: no edges (parseSbomGraph yields nodes-only),
//     so paths are empty and `degraded` is set — the frontend renders a
//     "dependency edges unavailable for this format" state.
//
// Safety (kickoff-pinned, MUST hold — see M29_KICKOFF_PROMPT.md):
//   - cycle guard: enumeratePaths carries a per-path visited set so a
//     multi-node dependency cycle (A → B → A) cannot loop forever. The
//     parse-time maxGraphComponentDepth cap (F203) protects only nested
//     Component.Components recursion, NOT graph traversal, so the visited
//     set here is the sole guard against traversal cycles.
//   - path-count cap: at most maxDependencyPaths paths are enumerated;
//     hitting the cap sets truncated=true (silent drop is forbidden).
//   - work budget: a bounded expansion budget (maxPathEnumerationSteps)
//     guards against exponential path blow-up in adversarial diamond
//     graphs even before the path cap is reached; hitting it also sets
//     truncated=true.
//
// Traversal order (F399): enumeratePaths walks depth-first, not
// breadth-first. A BFS enumerator emits shortest-paths-first, but on a
// deep AND wide (reconverging) graph the number of shallow partial paths
// is exponential, so the maxPathEnumerationSteps budget is exhausted
// popping shallow partials before ANY partial reaches the (deep) root —
// returning zero paths for a genuinely reachable component. DFS instead
// completes a full target → root path within ~depth pops, so real paths
// are always returned within budget. The collected paths are then sorted
// (length ascending, then lexicographically by node-id sequence) so the
// "shortest paths first" presentation and deterministic output are
// preserved regardless of DFS discovery order.
//
// F164 (Go nil slice → JSON null) is enforced: Paths is make([][]..., 0).
package diff

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// maxDependencyPaths caps how many distinct root → target paths are
// enumerated for a single request. Real-world SBOMs surface a handful of
// entry paths for any given transitive component; 50 is a generous ceiling
// that still bounds the response size and traversal work. When the cap is
// reached the response sets truncated=true so the caller knows more paths
// exist (silent truncation is forbidden — kickoff hard requirement).
const maxDependencyPaths = 50

// maxPathEnumerationSteps bounds the total number of partial-path
// expansions (stack pops) during enumeration. The per-path visited set
// prevents cycles, but a wide DAG (e.g. a chain of "diamonds") can still
// contain an exponential number of distinct simple paths; without a work
// budget the traversal could expand exponentially many partials before the
// path-count cap is reached. Hitting this budget sets truncated=true.
// 20000 is far above what any legitimate SBOM reaches (shallow DAGs of a
// few thousand components) while keeping the worst case bounded. Because
// enumeration is depth-first (F399), complete root paths are found within
// ~depth pops, so this budget truncates the *tail* of a huge path set
// rather than starving before the first path is emitted.
const maxPathEnumerationSteps = 20000

// ErrComponentNotFound is returned by ComputePaths when the component_id
// does not exist OR belongs to a different project (F379 ownership: we do
// NOT leak the distinction — both map to 404 at the handler).
var ErrComponentNotFound = errors.New("component not found in project")

// PathComponent is the small projection of the queried component carried
// in the response `component` field. Version is the real (DB) version, so
// the caller can render "qs 6.2.0" even though the graph node ID is the
// version-stripped match key.
type PathComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl,omitempty"`
}

// PathsResponse is the JSON payload returned by
// GET /api/v1/projects/:id/components/:component_id/paths.
//
// Paths is a list of root → ... → target node chains. Each chain element
// is a GraphNode (id = version-stripped match key, plus name/version/type).
// PathCount == len(Paths) (the number of paths RETURNED); when Truncated is
// true there are additional paths not enumerated.
type PathsResponse struct {
	ComponentID uuid.UUID     `json:"component_id"`
	Component   PathComponent `json:"component"`
	SbomID      uuid.UUID     `json:"sbom_id"`
	Format      string        `json:"format"`
	Degraded    bool          `json:"degraded"`
	IsDirect    bool          `json:"is_direct"`
	Paths       [][]GraphNode `json:"paths"`
	PathCount   int           `json:"path_count"`
	Truncated   bool          `json:"truncated"`
}

// ComputePaths reconstructs the dependency graph of the project's SBOM
// (latest, or the one named by sbomID) and enumerates the root → target
// dependency paths for the given component.
//
// Ownership / tenant scoping (all before any traversal):
//  1. projectRepo.GetByTenant confirms the tenant owns the project
//     (sql.ErrNoRows → 404 at the handler).
//  2. the component is loaded by id and its owning SBOM must belong to
//     THIS project (F379). A missing component OR a cross-project
//     component both surface ErrComponentNotFound (no existence leak).
//  3. the graph SBOM (explicit sbomID or latest) must belong to the
//     project (ErrSbomNotInProject).
//
// A component whose match key is absent from the resolved graph (e.g. it
// lives in an older SBOM than the latest) yields an empty path list with
// is_direct=false — a valid answer, not an error.
func (s *Service) ComputePaths(ctx context.Context, tenantID, projectID, componentID uuid.UUID, sbomID *uuid.UUID) (*PathsResponse, error) {
	// (1) tenant owns project.
	if _, err := s.projectRepo.GetByTenant(ctx, tenantID, projectID); err != nil {
		return nil, err
	}

	// (2) component exists + belongs to this project (via its SBOM).
	component, err := s.componentRepo.GetByID(ctx, componentID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrComponentNotFound
		}
		return nil, fmt.Errorf("get component %s: %w", componentID, err)
	}
	ownerSbom, err := s.sbomRepo.GetByID(ctx, component.SbomID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrComponentNotFound
		}
		return nil, fmt.Errorf("get component sbom %s: %w", component.SbomID, err)
	}
	if ownerSbom.ProjectID != projectID {
		// Cross-project component_id (same tenant, different project).
		// F379: 404 without leaking that the id exists elsewhere.
		return nil, ErrComponentNotFound
	}

	// (3) resolve the graph SBOM (explicit ?sbom or project latest).
	graphSbom, err := s.resolvePathSbom(ctx, projectID, sbomID)
	if err != nil {
		return nil, err
	}

	resp := &PathsResponse{
		ComponentID: componentID,
		Component: PathComponent{
			Name:    component.Name,
			Version: component.Version,
			Purl:    component.Purl,
		},
		SbomID: graphSbom.ID,
		Format: graphSbom.Format,
		Paths:  make([][]GraphNode, 0),
	}

	// SPDX / unknown formats have no edge support (parseSbomGraph returns
	// nodes-only). Report degraded + empty paths; is_direct is
	// indeterminate without edges, so false.
	if model.SbomFormat(strings.ToLower(graphSbom.Format)) != model.FormatCycloneDX {
		resp.Degraded = true
		return resp, nil
	}

	graph := parseSbomGraph(graphSbom)
	targetID := componentMatchKey(*component)

	// Target absent from this SBOM's graph: honest empty result.
	if _, inGraph := graph.nodes[targetID]; targetID == "" || !inGraph {
		return resp, nil
	}

	childToParents := buildReverseAdjacency(graph)
	roots := findRoots(graph)

	resp.IsDirect = isDirectDependency(childToParents, roots, targetID)
	paths, truncated := enumeratePaths(graph, childToParents, roots, targetID)
	resp.Paths = paths
	resp.PathCount = len(paths)
	resp.Truncated = truncated
	return resp, nil
}

// resolvePathSbom picks the SBOM whose graph is traversed: the explicit
// sbomID (verified to belong to the project) or the project's latest.
func (s *Service) resolvePathSbom(ctx context.Context, projectID uuid.UUID, sbomID *uuid.UUID) (*model.Sbom, error) {
	if sbomID != nil {
		got, err := s.sbomRepo.GetByID(ctx, *sbomID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrSbomNotInProject
			}
			return nil, fmt.Errorf("get sbom %s: %w", *sbomID, err)
		}
		if got.ProjectID != projectID {
			return nil, ErrSbomNotInProject
		}
		return got, nil
	}
	sboms, err := s.sbomRepo.ListByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("list project sboms: %w", err)
	}
	if len(sboms) == 0 {
		return nil, ErrNoSboms
	}
	// ListByProject is newest-first.
	latest := sboms[0]
	return &latest, nil
}

// buildReverseAdjacency inverts the parent → child edges into a
// child → parents map used by the reverse (target → root) walk. Parent
// lists are de-duplicated and sorted so enumeration is deterministic.
func buildReverseAdjacency(g sbomGraph) map[string][]string {
	seen := map[string]map[string]struct{}{}
	rev := map[string][]string{}
	for _, e := range g.edges {
		if e.From == "" || e.To == "" || e.From == e.To {
			continue // defensive: parser already drops self-loops
		}
		if seen[e.To] == nil {
			seen[e.To] = map[string]struct{}{}
		}
		if _, dup := seen[e.To][e.From]; dup {
			continue
		}
		seen[e.To][e.From] = struct{}{}
		rev[e.To] = append(rev[e.To], e.From)
	}
	for child := range rev {
		sort.Strings(rev[child])
	}
	return rev
}

// findRoots returns the set of node IDs treated as dependency-graph roots:
// every node with in-degree 0 (nothing depends on it) plus the declared
// application/root node at orderedIDs[0] (metadata.component, per the
// CycloneDX 1.6 contract — see parseCycloneDXGraph). Including the declared
// root explicitly bounds traversal even if a malformed SBOM records an
// inbound edge to it.
func findRoots(g sbomGraph) map[string]struct{} {
	inDegree := make(map[string]int, len(g.nodes))
	for id := range g.nodes {
		inDegree[id] = 0
	}
	for _, e := range g.edges {
		if _, ok := g.nodes[e.To]; ok {
			inDegree[e.To]++
		}
	}
	roots := map[string]struct{}{}
	for id, d := range inDegree {
		if d == 0 {
			roots[id] = struct{}{}
		}
	}
	if len(g.orderedIDs) > 0 {
		roots[g.orderedIDs[0]] = struct{}{}
	}
	return roots
}

// isDirectDependency reports whether the target is a direct/root-level
// dependency: it is itself a root (path length 1) or a direct child of a
// root (path length 2). Computed independently of enumeration so it stays
// correct even when path enumeration is truncated.
func isDirectDependency(childToParents map[string][]string, roots map[string]struct{}, targetID string) bool {
	if _, ok := roots[targetID]; ok {
		return true
	}
	for _, p := range childToParents[targetID] {
		if _, ok := roots[p]; ok {
			return true
		}
	}
	return false
}

// enumeratePaths walks child → parent edges from the target up to the
// graph roots depth-first (F399) and returns each discovered path ordered
// root → ... → target. Because DFS completes a full path within ~depth
// pops, real paths are always returned within the work budget even on a
// deep, exponentially-wide graph where a breadth-first walk would starve
// (see the package doc for the failure mode). The collected paths are
// sorted before returning — length ascending, then lexicographically by
// node-id sequence — so the "shortest paths first" presentation and
// deterministic output hold regardless of DFS discovery order.
//
// Cycle guard: each partial carries its own node set (a path may not
// revisit a node), so cyclic dependencies terminate. Caps: at most
// maxDependencyPaths paths are returned and at most maxPathEnumerationSteps
// stack pops are performed; hitting either bound sets truncated=true.
func enumeratePaths(g sbomGraph, childToParents map[string][]string, roots map[string]struct{}, targetID string) (paths [][]GraphNode, truncated bool) {
	paths = make([][]GraphNode, 0)
	if _, ok := g.nodes[targetID]; !ok {
		return paths, false
	}

	// Each stack item is a reverse path (target-first, walking upward).
	// LIFO ordering makes the walk depth-first: a partial is fully driven
	// to a root before its siblings are expanded, so a complete path is
	// emitted within ~depth pops rather than after the entire shallow
	// frontier (the BFS starvation fixed by F399).
	stack := [][]string{{targetID}}
	steps := 0
	for len(stack) > 0 {
		steps++
		if steps > maxPathEnumerationSteps {
			truncated = true
			break
		}
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		tail := cur[len(cur)-1]

		if _, isRoot := roots[tail]; isRoot {
			if len(paths) >= maxDependencyPaths {
				// A further complete path exists beyond the cap.
				truncated = true
				break
			}
			// Emit root → ... → target (reverse of the walk order).
			ordered := make([]GraphNode, 0, len(cur))
			for i := len(cur) - 1; i >= 0; i-- {
				ordered = append(ordered, g.nodes[cur[i]])
			}
			paths = append(paths, ordered)
			continue
		}

		for _, parent := range childToParents[tail] {
			if pathContains(cur, parent) {
				continue // cycle guard: no repeated node within a path
			}
			next := make([]string, len(cur)+1)
			copy(next, cur)
			next[len(cur)] = parent
			stack = append(stack, next)
		}
	}

	// Deterministic, shortest-first presentation independent of DFS
	// discovery order: sort by length, then lexicographically by the
	// node-id sequence.
	sort.SliceStable(paths, func(i, j int) bool {
		a, b := paths[i], paths[j]
		if len(a) != len(b) {
			return len(a) < len(b)
		}
		for k := range a {
			if a[k].ID != b[k].ID {
				return a[k].ID < b[k].ID
			}
		}
		return false
	})
	return paths, truncated
}

// pathContains reports whether id already appears in the partial path.
// Paths are short (bounded by graph depth), so a linear scan is cheaper
// than maintaining a per-path map.
func pathContains(path []string, id string) bool {
	for _, p := range path {
		if p == id {
			return true
		}
	}
	return false
}
