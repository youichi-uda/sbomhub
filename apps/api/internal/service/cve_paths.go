package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service/diff"
)

// cvePathsSearchRepo is the read-only slice of SearchRepository the
// cross-project transitive-paths view needs. Declared as an interface so the
// service assembly is unit-testable with in-memory fakes (no Postgres).
type cvePathsSearchRepo interface {
	GetVulnerabilityImpactMeta(ctx context.Context, cveID string) (*model.CVEImpactMeta, error)
	CountProjectsByTenant(ctx context.Context, tenantID uuid.UUID) (int, error)
	AggregateCVEAffectedComponents(ctx context.Context, tenantID, vulnID uuid.UUID) ([]model.CVEAffectedProject, error)
}

// cvePathsSbomRepo is the read-only slice of SbomRepository the view needs to
// resolve + load each affected project's latest SBOM. ListByProject is
// newest-first and already scans raw_data, so [0] is the latest SBOM with its
// bytes populated — the single load per project (efficiency contract: parse
// once per SBOM, not once per component). This mirrors M29's resolvePathSbom,
// which also takes ListByProject[0] for the latest, so no extra GetByID round
// trip is issued.
type cvePathsSbomRepo interface {
	ListByProject(ctx context.Context, projectID uuid.UUID) ([]model.Sbom, error)
}

// CVEPathsService assembles the cross-project transitive dependency-path view
// (M30-A / F402, issue #138): M28's blast radius fused with M29's per-SBOM
// reverse reachability, computed on demand. Read-only — no new table, no
// ingest change, no new audit action (a read-only GET; the request middleware
// chain is sufficient and F271 audit parity is intentionally not triggered).
type CVEPathsService struct {
	searchRepo cvePathsSearchRepo
	sbomRepo   cvePathsSbomRepo
}

// NewCVEPathsService wires the paths service. Both repositories are required.
func NewCVEPathsService(searchRepo cvePathsSearchRepo, sbomRepo cvePathsSbomRepo) *CVEPathsService {
	return &CVEPathsService{searchRepo: searchRepo, sbomRepo: sbomRepo}
}

// GetCVEPaths resolves the vulnerability metadata, the tenant's affected
// projects/components, and — per affected project — the transitive entry
// paths of each affected component against the project's LATEST SBOM.
//
// Return contract (identical shape to GetCVEImpact so the handler maps them
// the same way):
//   - unknown CVE            -> (nil, nil)   (handler answers 404)
//   - known CVE, 0 affected  -> (&CVEPathsResponse{count:0, projects:[]}, nil) (200)
//   - known CVE, N affected  -> (&CVEPathsResponse{...}, nil)
//
// Everything is tenant-scoped (RLS braces + explicit tenant_id belt); the
// caller must run inside a TenantTx so project_id is crossed but tenant_id
// never is.
//
// Efficiency contract (tested): for each affected project the latest SBOM is
// loaded and parsed into a diff.ReachabilityGraph EXACTLY ONCE (outside the
// per-component loop), then PathsTo is called per affected component against
// that single handle — the raw SBOM bytes are never re-parsed per component.
func (s *CVEPathsService) GetCVEPaths(ctx context.Context, tenantID uuid.UUID, cveID string) (*model.CVEPathsResponse, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))

	meta, err := s.searchRepo.GetVulnerabilityImpactMeta(ctx, cveID)
	if err != nil {
		return nil, fmt.Errorf("resolve vulnerability meta for %s: %w", cveID, err)
	}
	if meta == nil {
		// Unknown CVE — handler returns 404. (A known CVE affecting zero
		// projects is handled below as a non-nil, empty 200 result.)
		return nil, nil
	}

	affected, err := s.searchRepo.AggregateCVEAffectedComponents(ctx, tenantID, meta.VulnerabilityID)
	if err != nil {
		return nil, fmt.Errorf("aggregate cve affected components for %s: %w", cveID, err)
	}

	totalProjects, err := s.searchRepo.CountProjectsByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("count tenant projects: %w", err)
	}

	projects := make([]model.AffectedProjectPaths, 0, len(affected))
	for _, ap := range affected {
		proj, err := s.buildProjectPaths(ctx, ap)
		if err != nil {
			return nil, err
		}
		projects = append(projects, proj)
	}

	return &model.CVEPathsResponse{
		CVEID:                cveID,
		Severity:             meta.Severity,
		CVSSScore:            meta.CVSSScore,
		EPSSScore:            meta.EPSSScore,
		InKEV:                meta.InKEV,
		AffectedProjectCount: len(projects),
		TotalProjectCount:    totalProjects,
		AffectedProjects:     projects,
	}, nil
}

// buildProjectPaths loads the project's latest SBOM ONCE, parses it into a
// reverse-reachability graph ONCE, and computes each affected component's
// entry paths against that single handle.
func (s *CVEPathsService) buildProjectPaths(ctx context.Context, ap model.CVEAffectedProject) (model.AffectedProjectPaths, error) {
	sboms, err := s.sbomRepo.ListByProject(ctx, ap.ProjectID)
	if err != nil {
		return model.AffectedProjectPaths{}, fmt.Errorf("list sboms for project %s: %w", ap.ProjectID, err)
	}

	// ListByProject is newest-first; [0] is the latest SBOM with raw_data
	// already loaded. A project with affected components necessarily has at
	// least one SBOM (FK integrity), but if the list is empty we fall back to
	// a zero SBOM whose empty format ParseReachabilityGraph treats as degraded
	// — every component then resolves in_graph=false rather than crashing.
	var latest model.Sbom
	if len(sboms) > 0 {
		latest = sboms[0]
	}

	// PARSE ONCE per project (outside the component loop — the efficiency
	// contract). degraded is project-level: the latest SBOM is SPDX / unknown
	// / unparseable (no dependency edges).
	graph, degraded := diff.ParseReachabilityGraph(latest.RawData, latest.Format)

	components := make([]model.AffectedComponentPaths, 0, len(ap.Components))
	for _, comp := range ap.Components {
		cp := graph.PathsTo(comp)
		components = append(components, model.AffectedComponentPaths{
			Name:      comp.Name,
			Version:   comp.Version,
			Purl:      comp.Purl,
			InGraph:   cp.InGraph,
			IsDirect:  cp.IsDirect,
			Truncated: cp.Truncated,
			PathCount: len(cp.Paths),
			Paths:     toPathNodes(cp.Paths),
		})
	}

	return model.AffectedProjectPaths{
		ProjectID:          ap.ProjectID,
		ProjectName:        ap.ProjectName,
		SbomID:             latest.ID,
		Format:             latest.Format,
		Degraded:           degraded,
		ComponentCount:     len(components),
		AffectedComponents: components,
	}, nil
}

// toPathNodes maps the diff package's [][]GraphNode into the model's
// [][]PathNode (identical wire shape) so CVEPathsResponse carries no import
// dependency on the diff package. Always returns a non-nil outer slice
// (F164: nil → JSON null defence).
func toPathNodes(paths [][]diff.GraphNode) [][]model.PathNode {
	out := make([][]model.PathNode, 0, len(paths))
	for _, p := range paths {
		chain := make([]model.PathNode, 0, len(p))
		for _, n := range p {
			chain = append(chain, model.PathNode{
				ID:      n.ID,
				Name:    n.Name,
				Version: n.Version,
				Type:    n.Type,
			})
		}
		out = append(out, chain)
	}
	return out
}
