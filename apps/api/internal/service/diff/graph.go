// Package diff — dependency-graph view for M12-3 (#84).
//
// ComputeGraph parses the CycloneDX `dependencies` array of two SBOMs
// (from + to), merges them into a single node/edge graph keyed by the
// shared componentMatchKey identity used by the M10-6 component diff,
// and annotates each node with a diff status (added / removed /
// version_changed / unchanged) so the frontend can render coloured
// react-flow nodes.
//
// Why parse the raw SBOM here (instead of the components table):
//   - components are stored normalised (one row per component) but the
//     parent → child edges live only in the CycloneDX `dependencies`
//     block, which the M10-6 ingestion path discards. Re-parsing the
//     raw JSON per request is acceptable because (a) the diff page is
//     a lightly-trafficked auditor surface, (b) the SBOM raw bytes are
//     already loaded by sbomRepo.GetByID, (c) we only parse twice per
//     request (from + to), and (d) the alternative (a sbom_dependencies
//     table backfilled at ingest time) is an M13+ optimisation.
//
// Format coverage:
//   - cyclonedx: full edge support via the `dependencies` array
//   - spdx / spdx3 / unknown: nodes only, no edges (graceful degrade;
//     the frontend still renders the diff colours on a force-layout)
//
// F164 (Go nil slice → JSON null) is enforced throughout: every
// `[]T` field is `make([]T, 0)`-initialised so the typescript helper
// in apps/web/src/lib/api.ts can additionally `?? []` without ever
// hitting a real null.
package diff

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// GraphNode is the projection of a component for the dependency-graph view.
// ID is the deterministic match key (purl-normalised, falling back to
// `name|type`) so the same library has the same node ID across both
// SBOMs — that is what lets the frontend overlay added / removed /
// version_changed markers on a single merged graph.
type GraphNode struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// GraphEdge is a directed parent → child dependency edge. From/To are
// node IDs (i.e. the deterministic match keys above).
type GraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// GraphVersionChange records a component that exists on both sides
// with a different version. Mirrors ComponentVersionChange but uses
// the graph node ID (match key) so the frontend can colour the node
// without re-running the component match.
type GraphVersionChange struct {
	ID         string `json:"id"`
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`
}

// GraphDiffStatus enumerates the per-node diff markers. Nodes whose ID
// appears in none of the three slices are unchanged (the frontend
// renders them in grey).
type GraphDiffStatus struct {
	Added          []string             `json:"added"`
	Removed        []string             `json:"removed"`
	VersionChanged []GraphVersionChange `json:"version_changed"`
}

// GraphResponse is the JSON payload returned by
// GET /api/v1/projects/:id/diff/graph.
type GraphResponse struct {
	ProjectID  uuid.UUID       `json:"project_id"`
	From       *SbomRef        `json:"from"`
	To         *SbomRef        `json:"to"`
	Nodes      []GraphNode     `json:"nodes"`
	Edges      []GraphEdge     `json:"edges"`
	DiffStatus GraphDiffStatus `json:"diff_status"`
}

// ComputeGraph runs the dependency-graph diff. Tenant scoping +
// SBOM resolution semantics mirror Compute (the flat-list diff above):
// the same Request shape, the same auto-newest defaults, the same
// errors (ErrNoSboms / ErrSbomNotInProject / ErrNoNewerSbom).
//
// Single-SBOM (initial baseline) path: every node in the `to` graph
// lands in DiffStatus.Added; edges are taken verbatim from `to`.
func (s *Service) ComputeGraph(ctx context.Context, req Request) (*GraphResponse, error) {
	if _, err := s.projectRepo.GetByTenant(ctx, req.TenantID, req.ProjectID); err != nil {
		return nil, err
	}

	sboms, err := s.sbomRepo.ListByProject(ctx, req.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("list project sboms: %w", err)
	}
	if len(sboms) == 0 {
		return nil, ErrNoSboms
	}

	fromSbom, toSbom, err := s.resolveSboms(ctx, req, sboms)
	if err != nil {
		return nil, err
	}

	if fromSbom == nil {
		return computeGraphBaseline(req.ProjectID, toSbom), nil
	}

	// Re-fetch from/to via GetByID so that the in-memory copies in
	// `sboms` (which ListByProject already loaded with RawData) are
	// used directly when present. The pickPredecessor / pickSuccessor
	// helpers already return slice copies; the resolveSboms lookup()
	// closure may also call GetByID for explicit (from, to) ids that
	// happen to be in the list.  In every path the returned *model.Sbom
	// has RawData populated (both ListByProject and GetByID scan the
	// raw_data column — see apps/api/internal/repository/sbom.go).
	return computeGraphPair(req.ProjectID, fromSbom, toSbom), nil
}

// computeGraphBaseline mirrors Service.computeBaseline: every node in
// `to` is reported as added, removed/version_changed are empty.
func computeGraphBaseline(projectID uuid.UUID, to *model.Sbom) *GraphResponse {
	toGraph := parseSbomGraph(to)

	nodes := make([]GraphNode, 0, len(toGraph.nodes))
	added := make([]string, 0, len(toGraph.nodes))
	for _, id := range toGraph.orderedIDs {
		n := toGraph.nodes[id]
		nodes = append(nodes, n)
		added = append(added, id)
	}

	return &GraphResponse{
		ProjectID: projectID,
		From:      nil,
		To:        sbomToRef(to),
		Nodes:     nodes,
		Edges:     copyEdges(toGraph.edges),
		DiffStatus: GraphDiffStatus{
			Added:          added,
			Removed:        []string{},
			VersionChanged: []GraphVersionChange{},
		},
	}
}

// computeGraphPair merges two parsed SBOM graphs into a single node
// list with diff markers. Edges are the union of from edges + to
// edges (deduped); unchanged edges show in both, removed-only and
// added-only edges are still rendered so the auditor can see the
// dependency churn even when a node itself did not change.
func computeGraphPair(projectID uuid.UUID, from, to *model.Sbom) *GraphResponse {
	fromGraph := parseSbomGraph(from)
	toGraph := parseSbomGraph(to)

	// Deterministic node ordering: from-set first (preserves the from
	// SBOM's declaration order), then to-only nodes (preserves the to
	// SBOM's declaration order). Stable across re-renders.
	mergedNodes := make([]GraphNode, 0, len(fromGraph.nodes)+len(toGraph.nodes))
	seen := map[string]struct{}{}
	added := make([]string, 0)
	removed := make([]string, 0)
	versionChanged := make([]GraphVersionChange, 0)

	for _, id := range fromGraph.orderedIDs {
		fn := fromGraph.nodes[id]
		tn, inTo := toGraph.nodes[id]
		if inTo {
			// Prefer the `to` projection (newer name casing / type).
			mergedNodes = append(mergedNodes, tn)
			seen[id] = struct{}{}
			fv := strings.TrimSpace(fn.Version)
			tv := strings.TrimSpace(tn.Version)
			if fv != tv {
				versionChanged = append(versionChanged, GraphVersionChange{
					ID:         id,
					OldVersion: fn.Version,
					NewVersion: tn.Version,
				})
			}
		} else {
			mergedNodes = append(mergedNodes, fn)
			seen[id] = struct{}{}
			removed = append(removed, id)
		}
	}
	for _, id := range toGraph.orderedIDs {
		if _, ok := seen[id]; ok {
			continue
		}
		mergedNodes = append(mergedNodes, toGraph.nodes[id])
		seen[id] = struct{}{}
		added = append(added, id)
	}

	// Edge union with stable ordering (from-edges first, then any
	// new-to-only edges). Deterministic for tests + UI stability.
	edgeSet := map[string]struct{}{}
	mergedEdges := make([]GraphEdge, 0, len(fromGraph.edges)+len(toGraph.edges))
	edgeKey := func(e GraphEdge) string { return e.From + "\x00" + e.To }
	for _, e := range fromGraph.edges {
		k := edgeKey(e)
		if _, ok := edgeSet[k]; ok {
			continue
		}
		edgeSet[k] = struct{}{}
		mergedEdges = append(mergedEdges, e)
	}
	for _, e := range toGraph.edges {
		k := edgeKey(e)
		if _, ok := edgeSet[k]; ok {
			continue
		}
		edgeSet[k] = struct{}{}
		mergedEdges = append(mergedEdges, e)
	}

	// F164: sort added/removed for deterministic JSON; map iteration
	// order in the from-loop above is already deterministic (slice-
	// driven) but defence-in-depth never hurts.
	sort.Strings(added)
	sort.Strings(removed)
	sort.Slice(versionChanged, func(i, j int) bool {
		return versionChanged[i].ID < versionChanged[j].ID
	})

	return &GraphResponse{
		ProjectID: projectID,
		From:      sbomToRef(from),
		To:        sbomToRef(to),
		Nodes:     mergedNodes,
		Edges:     mergedEdges,
		DiffStatus: GraphDiffStatus{
			Added:          added,
			Removed:        removed,
			VersionChanged: versionChanged,
		},
	}
}

// ---------- per-SBOM raw parsing ----------

// sbomGraph is the intermediate representation produced by
// parseSbomGraph: a node map keyed by the deterministic match key, an
// ordered list of those keys (preserves declaration order for stable
// frontend layout), and the edge list already translated from
// bom-refs to match keys.
type sbomGraph struct {
	nodes      map[string]GraphNode
	orderedIDs []string
	edges      []GraphEdge
}

func emptySbomGraph() sbomGraph {
	return sbomGraph{
		nodes:      map[string]GraphNode{},
		orderedIDs: []string{},
		edges:      []GraphEdge{},
	}
}

// parseSbomGraph extracts nodes + edges from the raw SBOM bytes. Best
// effort: a malformed SBOM (or one without RawData) yields an empty
// graph rather than erroring so the diff endpoint stays usable even
// on partially-corrupt ingestion histories.
func parseSbomGraph(s *model.Sbom) sbomGraph {
	if s == nil || len(s.RawData) == 0 {
		return emptySbomGraph()
	}
	switch model.SbomFormat(strings.ToLower(s.Format)) {
	case model.FormatCycloneDX:
		return parseCycloneDXGraph(s.RawData)
	case model.FormatSPDX:
		// SPDX `relationships` parse is intentionally deferred (M13+);
		// degrade to nodes-only. The diff colours still render.
		return parseSPDXNodesOnly(s.RawData)
	default:
		return emptySbomGraph()
	}
}

// parseCycloneDXGraph walks bom.Components + bom.Dependencies and
// produces a (matchKey-id'd) node/edge graph. Components missing a
// bom-ref are still emitted as nodes (degenerate identity, no edges
// resolvable), so a graph of components-only SBOMs still renders.
func parseCycloneDXGraph(data []byte) sbomGraph {
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return emptySbomGraph()
	}

	out := emptySbomGraph()

	// bomRef → matchKey index for edge translation. A bom-ref that
	// does not resolve to a known component is skipped (CycloneDX
	// permits dangling refs; we drop them rather than synthesising
	// orphan nodes that would confuse the diff colours).
	refToKey := map[string]string{}

	// indexComponent is the shared add-node-to-graph logic used for
	// both bom.Metadata.Component (the application/root node, per the
	// CycloneDX 1.6 metadata.component contract) and bom.Components
	// (libraries / files / etc). F171: previously only bom.Components
	// was indexed, which silently dropped the root node + any edges
	// whose `ref` pointed at the metadata.component bom-ref.
	//
	// M13-2 (#88): the closure recurses into Component.Components so
	// nested sub-components (CycloneDX 1.6 supports nesting
	// components — e.g. a container component declaring its constituent
	// libraries inline) are also indexed. Without recursion the
	// dependencies[].ref pointing at a nested bom-ref silently dropped
	// the edge AND the node, leaving the auditor with a partial graph
	// that did not match the on-disk SBOM.
	//
	// Edge inference for nested components follows the CycloneDX
	// 1.6 spec contract: the `dependencies` array is the canonical
	// source of edges. Nesting alone does NOT synthesize an implicit
	// parent → child edge; auditors who want the parent → nested-child
	// edge visualised should declare it in `dependencies` (cyclonedx
	// tooling such as syft/trivy does this consistently). This stays
	// consistent with the existing M12-3 contract and avoids inventing
	// edges that are not in the SBOM bytes.
	var indexComponent func(c cdx.Component)
	indexComponent = func(c cdx.Component) {
		comp := model.Component{
			Name:    c.Name,
			Version: c.Version,
			Type:    string(c.Type),
			Purl:    c.PackageURL,
		}
		key := componentMatchKey(comp)
		if key != "" {
			if _, dup := out.nodes[key]; !dup {
				out.nodes[key] = GraphNode{
					ID:      key,
					Name:    c.Name,
					Version: c.Version,
					Type:    string(c.Type),
				}
				out.orderedIDs = append(out.orderedIDs, key)
			}
			if c.BOMRef != "" {
				// First-write-wins: keep the metadata.component mapping
				// when a duplicate bom-ref shows up under components, so
				// the root edge still resolves.
				if _, exists := refToKey[c.BOMRef]; !exists {
					refToKey[c.BOMRef] = key
				}
			}
		}
		// M13-2 (#88): walk nested sub-components even when the parent
		// itself has no usable identity (a bom-ref-only wrapper with no
		// name/purl is legal but rare). The children may still carry
		// match keys and need to be indexed so edge resolution works.
		if c.Components != nil {
			for _, sub := range *c.Components {
				indexComponent(sub)
			}
		}
	}

	// F171: metadata.component is the canonical root in CycloneDX 1.6
	// (application, framework, container, etc). Index it BEFORE
	// bom.Components so the root node lands at orderedIDs[0] and any
	// dependencies[].ref pointing at the root bom-ref resolves.
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		indexComponent(*bom.Metadata.Component)
	}

	if bom.Components != nil {
		for _, c := range *bom.Components {
			indexComponent(c)
		}
	}

	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			parentKey, ok := refToKey[dep.Ref]
			if !ok {
				continue
			}
			if dep.Dependencies == nil {
				continue
			}
			for _, childRef := range *dep.Dependencies {
				childKey, ok := refToKey[childRef]
				if !ok {
					continue
				}
				if parentKey == childKey {
					continue // skip self-loops
				}
				out.edges = append(out.edges, GraphEdge{From: parentKey, To: childKey})
			}
		}
	}

	return out
}

// parseSPDXNodesOnly extracts packages from an SPDX 2.x JSON document
// (and SPDX 3.x best-effort) so the graph can render coloured nodes
// even when the dependency edges are not parsed. M13+ may add full
// relationships support.
func parseSPDXNodesOnly(data []byte) sbomGraph {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return emptySbomGraph()
	}
	out := emptySbomGraph()
	if packages, ok := raw["packages"].([]interface{}); ok {
		for _, pkg := range packages {
			p, ok := pkg.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := p["name"].(string)
			version, _ := p["versionInfo"].(string)
			comp := model.Component{
				Name:    name,
				Version: version,
				Type:    "library",
			}
			key := componentMatchKey(comp)
			if key == "" {
				continue
			}
			if _, dup := out.nodes[key]; !dup {
				out.nodes[key] = GraphNode{
					ID:      key,
					Name:    name,
					Version: version,
					Type:    "library",
				}
				out.orderedIDs = append(out.orderedIDs, key)
			}
		}
	}
	return out
}

func copyEdges(in []GraphEdge) []GraphEdge {
	out := make([]GraphEdge, len(in))
	copy(out, in)
	return out
}
