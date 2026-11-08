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

// SbomInProject reports whether sbomID is an SBOM of the given
// (tenant, project). It is the service-level entry point to the M47 W1
// ownership predicate so callers outside this package never have to reach
// for the repository directly.
//
// The one consumer today is POST /api/v1/projects/:id/scan, whose
// `?sbom_id=` parameter was previously handed straight to the NVD / JVN
// scanners; see handler.VulnerabilityHandler.Scan for what that enabled.
func (s *SbomService) SbomInProject(ctx context.Context, tenantID, projectID, sbomID uuid.UUID) (bool, error) {
	return s.sbomRepo.SbomInProject(ctx, tenantID, projectID, sbomID)
}

func (s *SbomService) Import(ctx context.Context, projectID uuid.UUID, data []byte) (*model.Sbom, error) {
	info, err := detectFormatAndVersion(data)
	if err != nil {
		// F443: format-detection failure is caller-fixable feedback about a
		// malformed upload (bad JSON / unknown SBOM shape). The parser error
		// text is safe + helpful, so surface it at 400 via ErrValidation.
		// %v inlines the parser message — the goal is errors.Is(ErrValidation)
		// + a clean message, not to preserve the %w chain.
		return nil, ValidationErrorf("failed to parse SBOM: %v", err)
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
		// F443: component parse failure is likewise caller-fixable feedback
		// about a malformed upload; surface it at 400 via ErrValidation.
		return nil, ValidationErrorf("failed to parse SBOM: %v", err)
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
	// Default (unpaginated) path keeps the historical CVSS-descending order.
	return s.componentRepo.GetVulnerabilities(ctx, sbom.ID, "cvss")
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
//   - sortBy selects the ORDER BY column (F446 / M38): "epss" sorts by
//     exploitation probability descending, any other value (incl. "" /
//     "cvss") keeps the historical CVSS-descending order. The handler
//     validates it to {"", "cvss", "epss"} before calling.
func (s *SbomService) GetVulnerabilitiesPaginated(ctx context.Context, projectID uuid.UUID, limit, offset int, sortBy string) ([]model.Vulnerability, error) {
	sbom, err := s.sbomRepo.GetLatest(ctx, projectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []model.Vulnerability{}, nil
		}
		return nil, err
	}
	return s.componentRepo.GetVulnerabilitiesPaginated(ctx, sbom.ID, limit, offset, sortBy)
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
	// Scan-status / per-SBOM lookups keep the historical CVSS-descending order.
	return s.componentRepo.GetVulnerabilities(ctx, sbomID, "cvss")
}

// detectFormat is deprecated, use detectFormatAndVersion instead
func detectFormat(data []byte) (model.SbomFormat, error) {
	info, err := detectFormatAndVersion(data)
	if err != nil {
		return "", err
	}
	return info.Format, nil
}

// ErrUnsupportedSpecVersion marks an upload whose format was recognised but
// whose spec version this server cannot parse (or that has none). Callers
// wrap detection failures in ValidationErrorf, so it is answered 400.
var ErrUnsupportedSpecVersion = errors.New("unsupported SBOM spec version")

// supportedCycloneDXVersions lists, in order, the CycloneDX spec versions the
// linked cyclonedx-go accepts — read from the library rather than written
// down here, so a library upgrade that adds a version is picked up without a
// second edit (it is the library that parses the document).
var supportedCycloneDXVersions = func() []string {
	var out []string
	for v := cdx.SpecVersion1_0; ; v++ {
		var probe cdx.SpecVersion
		b, _ := json.Marshal(v.String())
		if probe.UnmarshalJSON(b) != nil || probe != v {
			return out
		}
		out = append(out, v.String())
	}
}()

// supportedSPDX2Versions are the SPDX 2.x "spdxVersion" values parseSPDX
// reads. Its reader only uses fields shared by every 2.x JSON document
// (packages[].name / versionInfo / externalRefs).
var supportedSPDX2Versions = []string{"2.0", "2.1", "2.2", "2.3"}

// supportedSPDX3Versions are the SPDX 3 releases whose JSON-LD @context
// parseSPDX3 is written against.
var supportedSPDX3Versions = []string{"3.0", "3.0.1"}

// detectFormatAndVersion detects the SBOM format and its spec version, and
// refuses a version this server does not support (ErrUnsupportedSpecVersion)
// rather than storing the upload and parsing it on a guess.
//
// It runs before the SBOM row is written, so an unsupported upload leaves
// nothing behind.
func detectFormatAndVersion(data []byte) (*FormatInfo, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// CycloneDX: "bomFormat" present; "specVersion" is required by every
	// CycloneDX JSON schema and decides what the document may contain.
	if _, ok := raw["bomFormat"]; ok {
		version, ok := jsonString(raw["specVersion"])
		if !ok || !containsString(supportedCycloneDXVersions, version) {
			return nil, unsupportedVersionError("CycloneDX", "specVersion", raw["specVersion"], supportedCycloneDXVersions)
		}
		return &FormatInfo{Format: model.FormatCycloneDX, Version: version}, nil
	}

	// SPDX 2.x: "spdxVersion" is "SPDX-2.<minor>". SPDX 3 documents are
	// JSON-LD and do not carry this key, so an "SPDX-3.x" value here is not a
	// document parseSPDX3 can read.
	if rawVer, ok := raw["spdxVersion"]; ok {
		spdxVer, isString := jsonString(rawVer)
		version, hasPrefix := strings.CutPrefix(spdxVer, "SPDX-")
		if !isString || !hasPrefix || !containsString(supportedSPDX2Versions, version) {
			return nil, unsupportedVersionError("SPDX", "spdxVersion", rawVer, prefixAll("SPDX-", supportedSPDX2Versions))
		}
		return &FormatInfo{Format: model.FormatSPDX, Version: version}, nil
	}

	// SPDX 3: "@context" points into spdx.org/rdf/3.<...>/.
	if ctx, ok := jsonString(raw["@context"]); ok && strings.Contains(ctx, "spdx.org/rdf/3") {
		version, ok := extractSPDX3Version(ctx)
		if !ok {
			return nil, unsupportedVersionError("SPDX 3", "@context", raw["@context"], supportedSPDX3Versions)
		}
		return &FormatInfo{Format: model.FormatSPDX, Version: version}, nil
	}

	return nil, fmt.Errorf("unknown SBOM format")
}

// unsupportedVersionError is the 400 text for an unsupported version. The
// offending value is quoted (and truncated) so a client sees what it sent.
func unsupportedVersionError(format, field string, got json.RawMessage, supported []string) error {
	shown := "missing"
	if len(got) > 0 {
		shown = string(got)
		if len(shown) > 40 {
			shown = shown[:40] + "..."
		}
	}
	return fmt.Errorf("%w: %s %s %s (supported: %s)",
		ErrUnsupportedSpecVersion, format, field, shown, strings.Join(supported, ", "))
}

// jsonString decodes a JSON string value; anything else (absent, null,
// number, object) reports false.
func jsonString(v json.RawMessage) (string, bool) {
	if len(v) == 0 {
		return "", false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", false
	}
	return s, true
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func prefixAll(prefix string, list []string) []string {
	out := make([]string, len(list))
	for i, v := range list {
		out[i] = prefix + v
	}
	return out
}

// extractSPDX3Version reads the release from an SPDX 3 @context URL
// ("https://spdx.org/rdf/3.0.1/terms/Core" → "3.0.1") and reports whether it
// is one this server supports. The release is the whole path segment after
// "spdx.org/rdf/", so "3.0.2" is not mistaken for "3.0".
func extractSPDX3Version(ctx string) (string, bool) {
	const marker = "spdx.org/rdf/"
	i := strings.Index(ctx, marker)
	if i < 0 {
		return "", false
	}
	rest := ctx[i+len(marker):]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	return rest, containsString(supportedSPDX3Versions, rest)
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
			// M60: `cpe` is the primary CPE; Syft writes its remaining
			// candidates as `syft:cpe23` properties, in order.
			cpes := []string{c.CPE}
			if c.Properties != nil {
				for _, p := range *c.Properties {
					if p.Name == "syft:cpe23" {
						cpes = append(cpes, p.Value)
					}
				}
			}
			comp.CPEs = normaliseSBOMCPEs(cpes, comp.Version, comp.Purl)
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
				// M60: externalRefs is an ARRAY in SPDX 2.x JSON. The code
				// here used to read it with getString, which only accepts a
				// string, so every SPDX 2 purl was silently dropped.
				comp.Purl, comp.CPEs = spdx2ExternalRefs(p, comp.Version)
				components = append(components, comp)
			}
		}
	}

	return components, nil
}

// spdx2ExternalRefs reads the purl and the CPE names from an SPDX 2.x
// package's externalRefs array (M60). The first purl wins; CPEs keep document
// order (Syft lists its candidates most-specific first).
func spdx2ExternalRefs(pkg map[string]interface{}, version string) (purl string, cpes []string) {
	refs, _ := pkg["externalRefs"].([]interface{})
	var raw []string
	for _, r := range refs {
		ref, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		loc := strings.TrimSpace(getString(ref, "referenceLocator"))
		switch getString(ref, "referenceType") {
		case "purl":
			if purl == "" {
				purl = loc
			}
		case "cpe23Type", "cpe22Type":
			raw = append(raw, loc)
		}
	}
	return purl, normaliseSBOMCPEs(raw, version, purl)
}

// maxStoredCPEsPerComponent bounds the CPE list kept per component. Syft
// emits up to 18 candidates for one Debian kernel package (measured
// 2026-11-08); the scanner only ever tries the first few, and the column is
// uploaded data, so it is capped rather than stored unbounded.
const maxStoredCPEsPerComponent = 16

// maxStoredCPELength rejects strings that cannot be a sane CPE name.
const maxStoredCPELength = 512

// normaliseSBOMCPEs trims, keeps only strings shaped like a CPE 2.3 formatted
// string or a CPE 2.2 URI, drops duplicates (first occurrence wins, so the
// SBOM's order is preserved) and caps the list. It returns nil when nothing
// survives, so a component without CPEs is stored as NULL.
//
// compVersion is the component's version: without one, a CPE whose own
// version is not concrete can never become a candidate (cpeCandidates), so it
// is not stored and does not use up the cap (Codex M60 R14 Low).
func normaliseSBOMCPEs(in []string, compVersion, purl string) []string {
	var out []string
	seen := make(map[string]struct{}, len(in))
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" || len(c) > maxStoredCPELength {
			continue
		}
		// Only a CPE the scanner can USE is stored, judged by the scanner's
		// own rule — cpeCandidates with this component's version and purl —
		// so storage and scanning cannot disagree (Codex M60 R5/R7/R14/R18).
		cands := cpeCandidates([]string{c}, compVersion, purl)
		if len(cands) == 0 {
			continue
		}
		// Dedupe on the product identity the scanner uses: it only ever
		// tries the first usable CPE of a product, so case variants, other
		// versions and CPEs that differ in ignored attributes neither shadow
		// a usable CPE nor use up the cap (Codex M60 R4/R10/R11/R16).
		key := cands[0].productKey()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
		if len(out) == maxStoredCPEsPerComponent {
			break
		}
	}
	return out
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
		// M60: CPE external identifiers, in document order.
		var cpes []string
		for _, ext := range elem.ExternalIdentifier {
			if ext.ExternalIDType == "cpe23" || ext.ExternalIDType == "cpe22" {
				cpes = append(cpes, ext.Identifier)
			}
		}
		comp.CPEs = normaliseSBOMCPEs(cpes, comp.Version, comp.Purl)

		// Extract license if available
		if elem.DeclaredLicense != "" {
			comp.License = elem.DeclaredLicense
		}

		components = append(components, comp)
	}

	return components, nil
}
