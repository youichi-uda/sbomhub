package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// FormatInfo contains the detected SBOM format and version
type FormatInfo struct {
	Format  model.SbomFormat
	Version string
}

type SbomService struct {
	sbomRepo      *repository.SbomRepository
	componentRepo *repository.ComponentRepository
}

func NewSbomService(sr *repository.SbomRepository, cr *repository.ComponentRepository) *SbomService {
	return &SbomService{sbomRepo: sr, componentRepo: cr}
}

func (s *SbomService) Import(ctx context.Context, projectID uuid.UUID, data []byte) (*model.Sbom, error) {
	info, err := detectFormatAndVersion(data)
	if err != nil {
		return nil, fmt.Errorf("failed to detect SBOM format: %w", err)
	}

	// Resolve the tenant_id of the parent project so that both the new sbom
	// row and the components belonging to it are tagged with the correct
	// tenant. Without this, the FORCE RLS WITH CHECK clause on `sboms` (see
	// migration 023) rejects the INSERT and the NOT NULL constraint added in
	// 027 rejects it at the schema layer as well.
	tenantID, err := s.sbomRepo.LookupProjectTenantID(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve project tenant: %w", err)
	}

	sbom := &model.Sbom{
		ID:        uuid.New(),
		TenantID:  tenantID,
		ProjectID: projectID,
		Format:    string(info.Format),
		Version:   info.Version,
		RawData:   data,
		CreatedAt: time.Now(),
	}

	if err := s.sbomRepo.Create(ctx, sbom); err != nil {
		return nil, fmt.Errorf("failed to save SBOM: %w", err)
	}

	components, err := parseComponents(data, info.Format, info.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to parse components: %w", err)
	}

	for _, comp := range components {
		comp.SbomID = sbom.ID
		comp.TenantID = sbom.TenantID
		if err := s.componentRepo.Create(ctx, &comp); err != nil {
			return nil, fmt.Errorf("failed to save component: %w", err)
		}
	}

	return sbom, nil
}

func (s *SbomService) GetLatest(ctx context.Context, projectID uuid.UUID) (*model.Sbom, error) {
	return s.sbomRepo.GetLatest(ctx, projectID)
}

func (s *SbomService) ListByProject(ctx context.Context, projectID uuid.UUID) ([]model.Sbom, error) {
	return s.sbomRepo.ListByProject(ctx, projectID)
}

func (s *SbomService) GetComponents(ctx context.Context, projectID uuid.UUID) ([]model.Component, error) {
	sbom, err := s.sbomRepo.GetLatest(ctx, projectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []model.Component{}, nil
		}
		return nil, err
	}
	return s.componentRepo.ListBySbom(ctx, sbom.ID)
}

func (s *SbomService) GetVulnerabilities(ctx context.Context, projectID uuid.UUID) ([]model.Vulnerability, error) {
	sbom, err := s.sbomRepo.GetLatest(ctx, projectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []model.Vulnerability{}, nil
		}
		return nil, err
	}
	return s.componentRepo.GetVulnerabilities(ctx, sbom.ID)
}

// GetVulnerabilitiesPaginated returns a single page of the latest
// SBOM's matched vulnerabilities. M1 Codex review #F26: the canonical
// route GET /api/v1/projects/:id/vulnerabilities is reachable from the
// CLI's read-scoped API-key auth path (#F20), so the response shape
// MUST be bounded — without a per-request page the underlying SQL
// scanned + materialised every matching row inside the request
// goroutine and forced the CLI to io.ReadAll the whole body.
//
// Contract:
//   - limit > 0 issues a paginated query with SQL LIMIT/OFFSET; the
//     handler clamps to [1, MaxListLimit] before calling.
//   - limit <= 0 reuses the existing un-paginated GetVulnerabilities
//     path. Reserved for internal aggregators that need every row in
//     one shot (none currently exist on this method — every external
//     call site routes through the handler's clamp).
//   - sbom.ErrNoRows on the "no SBOM yet" branch is mapped to an empty
//     slice to mirror GetVulnerabilities' historical behaviour (the
//     CLI's triage loop short-circuits on len==0 with a "脆弱性は検出
//     されませんでした" message rather than treating it as an error).
func (s *SbomService) GetVulnerabilitiesPaginated(ctx context.Context, projectID uuid.UUID, limit, offset int) ([]model.Vulnerability, error) {
	sbom, err := s.sbomRepo.GetLatest(ctx, projectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []model.Vulnerability{}, nil
		}
		return nil, err
	}
	return s.componentRepo.GetVulnerabilitiesPaginated(ctx, sbom.ID, limit, offset)
}

// CountVulnerabilities returns the total number of vulnerabilities
// matched for the project's latest SBOM. M1 Codex review #F28: the
// /vulnerabilities route emits this as X-Total-Count so the Web UI
// can render an accurate "N / total" indicator + warning banner when
// the total exceeds the default page size — without it the UI
// treated the first 100 rows as the complete set and silently
// truncated the tab counter / workflow actions for later rows.
//
// Behaviour mirrors GetVulnerabilities for the "no SBOM yet" branch:
// sql.ErrNoRows collapses to (0, nil) so the handler does not need a
// separate 404 path when a freshly-created project has yet to receive
// its first upload.
func (s *SbomService) CountVulnerabilities(ctx context.Context, projectID uuid.UUID) (int, error) {
	sbom, err := s.sbomRepo.GetLatest(ctx, projectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	return s.componentRepo.CountVulnerabilities(ctx, sbom.ID)
}

// GetVulnerabilitiesBySbom returns the vulnerabilities matched for one
// specific SBOM. Unlike GetVulnerabilities (which resolves the "latest" SBOM
// for the project), this preserves the caller-supplied sbom_id so polling a
// specific upload's scan progress is not corrupted by a sibling upload that
// happens to land between poll iterations.
//
// Codex R2 P2: the scan-status handler used to call GetVulnerabilities and
// thereby read whichever SBOM happened to be latest at the moment of the
// poll. Two parallel uploads (sbom1, then sbom2) would cause status(sbom1)
// to report sbom2's counts, racing the CLI's --fail-on threshold.
//
// The sbom_id is verified to belong to projectID before any vulnerability
// query is issued. A mismatch (or a missing sbom) returns sql.ErrNoRows so
// the handler can map it to 404 cleanly without leaking whether the row
// exists in another project.
func (s *SbomService) GetVulnerabilitiesBySbom(ctx context.Context, projectID, sbomID uuid.UUID) ([]model.Vulnerability, error) {
	sbom, err := s.sbomRepo.GetByID(ctx, sbomID)
	if err != nil {
		return nil, err
	}
	if sbom.ProjectID != projectID {
		// Do not differentiate "wrong project" from "not found" — that
		// would let a caller probe sbom_id existence across projects.
		return nil, sql.ErrNoRows
	}
	return s.componentRepo.GetVulnerabilities(ctx, sbomID)
}

// detectFormat is deprecated, use detectFormatAndVersion instead
func detectFormat(data []byte) (model.SbomFormat, error) {
	info, err := detectFormatAndVersion(data)
	if err != nil {
		return "", err
	}
	return info.Format, nil
}

// detectFormatAndVersion detects the SBOM format and extracts the spec version
func detectFormatAndVersion(data []byte) (*FormatInfo, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// CycloneDX: check "bomFormat" + extract "specVersion"
	if _, ok := raw["bomFormat"]; ok {
		version, _ := raw["specVersion"].(string)
		return &FormatInfo{Format: model.FormatCycloneDX, Version: version}, nil
	}

	// SPDX 2.x: check "spdxVersion" (e.g., "SPDX-2.3")
	if spdxVer, ok := raw["spdxVersion"].(string); ok {
		version := strings.TrimPrefix(spdxVer, "SPDX-")
		return &FormatInfo{Format: model.FormatSPDX, Version: version}, nil
	}

	// SPDX 3.0: check "@context" contains "spdx.org/rdf/3.0"
	if ctx, ok := raw["@context"].(string); ok {
		if strings.Contains(ctx, "spdx.org/rdf/3.0") {
			version := extractSPDX3Version(ctx)
			return &FormatInfo{Format: model.FormatSPDX, Version: version}, nil
		}
	}

	return nil, fmt.Errorf("unknown SBOM format")
}

// extractSPDX3Version extracts the SPDX 3.x version from the @context URL
func extractSPDX3Version(ctx string) string {
	// Handle patterns like "https://spdx.org/rdf/3.0.1/terms/Core"
	// or "https://spdx.org/rdf/3.0/terms/Core"
	if strings.Contains(ctx, "spdx.org/rdf/3.0.1") {
		return "3.0.1"
	}
	if strings.Contains(ctx, "spdx.org/rdf/3.0") {
		return "3.0"
	}
	return "3.0" // default to 3.0
}

func parseComponents(data []byte, format model.SbomFormat, version string) ([]model.Component, error) {
	switch format {
	case model.FormatCycloneDX:
		return parseCycloneDX(data)
	case model.FormatSPDX:
		if strings.HasPrefix(version, "3.") {
			return parseSPDX3(data)
		}
		return parseSPDX(data)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

func parseCycloneDX(data []byte) ([]model.Component, error) {
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, err
	}

	var components []model.Component
	if bom.Components != nil {
		for _, c := range *bom.Components {
			comp := model.Component{
				ID:        uuid.New(),
				Name:      c.Name,
				Version:   c.Version,
				Type:      string(c.Type),
				CreatedAt: time.Now(),
			}
			if c.PackageURL != "" {
				comp.Purl = c.PackageURL
			}
			if c.Licenses != nil && len(*c.Licenses) > 0 {
				for _, lic := range *c.Licenses {
					if lic.License != nil && lic.License.ID != "" {
						comp.License = lic.License.ID
						break
					}
				}
			}
			components = append(components, comp)
		}
	}

	return components, nil
}

func parseSPDX(data []byte) ([]model.Component, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	var components []model.Component
	if packages, ok := raw["packages"].([]interface{}); ok {
		for _, pkg := range packages {
			if p, ok := pkg.(map[string]interface{}); ok {
				comp := model.Component{
					ID:        uuid.New(),
					Name:      getString(p, "name"),
					Version:   getString(p, "versionInfo"),
					Type:      "library",
					CreatedAt: time.Now(),
				}
				if purl := getString(p, "externalRefs"); purl != "" {
					comp.Purl = purl
				}
				components = append(components, comp)
			}
		}
	}

	return components, nil
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// parseSPDX3 parses SPDX 3.0/3.0.1 format documents
func parseSPDX3(data []byte) ([]model.Component, error) {
	var doc model.SPDX3Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	var components []model.Component
	for _, elem := range doc.Graph {
		// Only process Package types
		if !strings.Contains(elem.Type, "Package") && !strings.Contains(elem.Type, "software_Package") {
			continue
		}

		comp := model.Component{
			ID:        uuid.New(),
			Name:      elem.Name,
			Version:   elem.PackageVersion,
			Type:      "library",
			CreatedAt: time.Now(),
		}

		// Check for direct packageUrl field first
		if elem.PackageUrl != "" {
			comp.Purl = elem.PackageUrl
		}

		// Extract PURL from externalIdentifier array
		for _, ext := range elem.ExternalIdentifier {
			if ext.ExternalIDType == "packageUrl" || ext.ExternalIDType == "purl" {
				comp.Purl = ext.Identifier
				break
			}
		}

		// Extract license if available
		if elem.DeclaredLicense != "" {
			comp.License = elem.DeclaredLicense
		}

		components = append(components, comp)
	}

	return components, nil
}
