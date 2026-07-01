// Package diff implements the supply-chain churn observability service
// for M10-6 (issue #74). Given a project and two SBOMs in that project
// it computes the flat-list diff of components, vulnerabilities and
// license-policy violations between the two revisions.
//
// The "diff between two SBOMs" surface is intentionally mechanical:
//
//   - components are matched on normalised purl when present, otherwise
//     on (lower-cased name, type). The version is the "what changed"
//     axis, so a component appearing in both base and target with
//     different versions lands in version_changed; if either side cannot
//     be matched at all the component lands in added or removed.
//   - vulnerabilities are matched on cve_id. A CVE present in target
//     but not base is added; present in base but not target is resolved;
//     present in both with a different severity is severity_changed.
//   - license-policy violations are computed per-SBOM by intersecting
//     the project's denied license_policies with the component licenses
//     in the SBOM. The diff is the set difference of (component, license,
//     policy) tuples.
//
// No AI is involved. The diff is deterministic on the (base components,
// target components, project license_policies) inputs.
//
// M10-6 phase 1 scope: flat lists only. Graph / dependency-tree diff,
// AI summarisation, diff export, webhook on threshold are explicitly
// deferred to M11+.
package diff

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// sbomLister is the slice of SbomRepository used by the diff service.
// Narrowing the surface makes the service unit-testable with a small
// fake instead of standing up Postgres + sqlmock.
type sbomLister interface {
	ListByProject(ctx context.Context, projectID uuid.UUID) ([]model.Sbom, error)
	GetByID(ctx context.Context, sbomID uuid.UUID) (*model.Sbom, error)
}

// componentReader is the slice of ComponentRepository used here.
type componentReader interface {
	ListBySbom(ctx context.Context, sbomID uuid.UUID) ([]model.Component, error)
	ListComponentVulnerabilitiesBySbom(ctx context.Context, sbomID uuid.UUID) ([]model.ComponentVulnerability, error)
}

// licensePolicyReader is the slice of LicensePolicyRepository used here.
type licensePolicyReader interface {
	ListByProject(ctx context.Context, projectID uuid.UUID) ([]model.LicensePolicy, error)
}

// projectScoper verifies (tenant, project) ownership before any query
// fans out. Returns the project (with tenant_id stripped) on success;
// sql.ErrNoRows when the tenant does not own the project.
type projectScoper interface {
	GetByTenant(ctx context.Context, tenantID, projectID uuid.UUID) (*model.Project, error)
}

// Service computes the flat-list diff between two SBOMs in the same
// project. Construction is via NewService; the zero value is not usable.
type Service struct {
	projectRepo   projectScoper
	sbomRepo      sbomLister
	componentRepo componentReader
	licenseRepo   licensePolicyReader
}

// NewService wires the diff service. All four repositories are required.
func NewService(p projectScoper, s sbomLister, c componentReader, l licensePolicyReader) *Service {
	return &Service{
		projectRepo:   p,
		sbomRepo:      s,
		componentRepo: c,
		licenseRepo:   l,
	}
}

// Request bundles the inputs to Compute.
//
// FromSbomID / ToSbomID are optional. When both are zero, the service
// auto-selects the two most-recent SBOMs (newest -> ToSbomID, previous
// -> FromSbomID). When only one is set the other side defaults the same
// way. When the project has exactly one SBOM and From is unresolvable,
// the result represents the initial baseline: every component in To
// lands in components.added, removed and version_changed are empty.
//
// Tenant scoping is enforced server-side via projectRepo.GetByTenant —
// passing a TenantID + ProjectID outside the caller's scope returns
// sql.ErrNoRows before any SBOM query runs.
type Request struct {
	TenantID   uuid.UUID
	ProjectID  uuid.UUID
	FromSbomID uuid.UUID
	ToSbomID   uuid.UUID
}

// SbomRef is the small projection of model.Sbom carried in the response.
// The full RawData payload is intentionally omitted (the diff endpoint
// MUST NOT egress raw SBOM bytes — the project /sbom endpoints already
// own that path with their own auth chain).
type SbomRef struct {
	SbomID    uuid.UUID `json:"sbom_id"`
	Format    string    `json:"format"`
	Version   string    `json:"version,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ComponentChange is the shape for components.added and components.removed.
type ComponentChange struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl,omitempty"`
	License string `json:"license,omitempty"`
}

// ComponentVersionChange is the shape for components.version_changed.
type ComponentVersionChange struct {
	Name        string `json:"name"`
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
	Purl        string `json:"purl,omitempty"`
}

// VulnerabilityAdded is the shape for vulnerabilities.added.
type VulnerabilityAdded struct {
	CVEID            string `json:"cve_id"`
	Severity         string `json:"severity"`
	ComponentName    string `json:"component_name"`
	ComponentVersion string `json:"component_version"`
}

// VulnerabilityResolved is the shape for vulnerabilities.resolved.
type VulnerabilityResolved struct {
	CVEID    string `json:"cve_id"`
	Severity string `json:"severity"`
}

// VulnerabilitySeverityChange is the shape for vulnerabilities.severity_changed.
type VulnerabilitySeverityChange struct {
	CVEID        string `json:"cve_id"`
	FromSeverity string `json:"from_severity"`
	ToSeverity   string `json:"to_severity"`
}

// LicensePolicyViolation is the shape for licenses.added_policy_violations
// and licenses.removed_policy_violations.
type LicensePolicyViolation struct {
	ComponentName string `json:"component_name"`
	License       string `json:"license"`
	PolicyName    string `json:"policy_name"`
}

// ComponentsDiff is the components.* envelope.
type ComponentsDiff struct {
	Added          []ComponentChange        `json:"added"`
	Removed        []ComponentChange        `json:"removed"`
	VersionChanged []ComponentVersionChange `json:"version_changed"`
}

// VulnerabilitiesDiff is the vulnerabilities.* envelope.
type VulnerabilitiesDiff struct {
	Added           []VulnerabilityAdded          `json:"added"`
	Resolved        []VulnerabilityResolved       `json:"resolved"`
	SeverityChanged []VulnerabilitySeverityChange `json:"severity_changed"`
}

// LicensesDiff is the licenses.* envelope.
type LicensesDiff struct {
	AddedPolicyViolations   []LicensePolicyViolation `json:"added_policy_violations"`
	RemovedPolicyViolations []LicensePolicyViolation `json:"removed_policy_violations"`
}

// Response is the JSON payload returned by GET /api/v1/projects/:id/diff.
type Response struct {
	ProjectID       uuid.UUID           `json:"project_id"`
	From            *SbomRef            `json:"from"`
	To              *SbomRef            `json:"to"`
	Components      ComponentsDiff      `json:"components"`
	Vulnerabilities VulnerabilitiesDiff `json:"vulnerabilities"`
	Licenses        LicensesDiff        `json:"licenses"`
}

// ErrNoSboms is returned when the project has no SBOM ingests at all.
// The handler maps this to 404 — there is genuinely nothing to diff.
var ErrNoSboms = fmt.Errorf("project has no SBOM ingests")

// ErrSbomNotInProject is returned when a caller-supplied sbom_id is not
// owned by the requested project (or has been deleted). Maps to 404.
var ErrSbomNotInProject = fmt.Errorf("sbom does not belong to project")

// ErrNoNewerSbom is returned when the caller passes only `from` and that
// SBOM is already the newest revision in the project — there is nothing
// strictly after it to use as the default `to`. The handler maps this to
// 400 (the request itself is structurally fine; the project state just
// has no successor) so the UI can render a clean "already the most
// recent revision" empty state without hitting the 500-class branch.
// F166: previously this returned a generic fmt.Errorf that fell through
// to the handler's 500 path.
var ErrNoNewerSbom = fmt.Errorf("from sbom is already the newest in the project")

// Compute runs the full diff. See Request godoc for the semantics of
// optional From / To.
func (s *Service) Compute(ctx context.Context, req Request) (*Response, error) {
	// Tenant scope: confirm the project is owned by the tenant before any
	// downstream query fans out. This is belt + braces with the ambient
	// TenantTx middleware that bound `SET LOCAL app.current_tenant_id`
	// on the request's Postgres tx.
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

	// Single-SBOM baseline path: To is set, From is nil. The "initial
	// baseline" semantic is documented in the issue — every component in
	// To is reported as added, removed/version_changed are empty, and so
	// is resolved/severity_changed.
	if fromSbom == nil {
		return s.computeBaseline(ctx, req.ProjectID, toSbom)
	}

	return s.computePair(ctx, req.ProjectID, fromSbom, toSbom)
}

// resolveSboms picks the (From, To) pair from the project's sbom list +
// the caller's hints. ListByProject returns newest first.
func (s *Service) resolveSboms(ctx context.Context, req Request, sboms []model.Sbom) (*model.Sbom, *model.Sbom, error) {
	// helper: lookup a specific SBOM and verify it lives in this project.
	lookup := func(id uuid.UUID) (*model.Sbom, error) {
		// scan the in-memory list first so we don't issue a second SELECT
		// when the SBOM is already in the result of ListByProject.
		for i := range sboms {
			if sboms[i].ID == id {
				cp := sboms[i]
				return &cp, nil
			}
		}
		got, err := s.sbomRepo.GetByID(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("get sbom %s: %w", id, err)
		}
		if got.ProjectID != req.ProjectID {
			return nil, ErrSbomNotInProject
		}
		return got, nil
	}

	hasFrom := req.FromSbomID != uuid.Nil
	hasTo := req.ToSbomID != uuid.Nil

	switch {
	case hasFrom && hasTo:
		from, err := lookup(req.FromSbomID)
		if err != nil {
			return nil, nil, err
		}
		to, err := lookup(req.ToSbomID)
		if err != nil {
			return nil, nil, err
		}
		return from, to, nil
	case !hasFrom && hasTo:
		to, err := lookup(req.ToSbomID)
		if err != nil {
			return nil, nil, err
		}
		// Default From = the sbom immediately preceding To by created_at.
		from := pickPredecessor(sboms, to)
		return from, to, nil
	case hasFrom && !hasTo:
		from, err := lookup(req.FromSbomID)
		if err != nil {
			return nil, nil, err
		}
		// Default To = the newest sbom strictly after From.
		to := pickSuccessor(sboms, from)
		if to == nil {
			// From is already the newest; nothing newer to diff against.
			// Surface ErrNoNewerSbom (F166) so the handler maps to 400
			// and the UI can show a clean "already the most recent
			// revision" empty state instead of a 500.
			return nil, nil, ErrNoNewerSbom
		}
		return from, to, nil
	default:
		// Neither set: pick the 2 newest.
		to := &sboms[0]
		if len(sboms) == 1 {
			return nil, to, nil
		}
		from := &sboms[1]
		return from, to, nil
	}
}

// pickPredecessor returns the SBOM in sboms that is the immediate
// predecessor of target by created_at. Returns nil if target is the
// oldest SBOM in the project.
func pickPredecessor(sboms []model.Sbom, target *model.Sbom) *model.Sbom {
	// ListByProject returns DESC by created_at. The predecessor is the
	// next row after target in that order.
	for i := range sboms {
		if sboms[i].ID == target.ID {
			if i+1 < len(sboms) {
				cp := sboms[i+1]
				return &cp
			}
			return nil
		}
	}
	// Target is not in the project's list (e.g. a stale sbom_id that was
	// deleted) — treat as initial baseline.
	return nil
}

// pickSuccessor returns the SBOM in sboms that is the latest SBOM
// strictly newer than target. Returns nil if target is the newest.
func pickSuccessor(sboms []model.Sbom, target *model.Sbom) *model.Sbom {
	// ListByProject is DESC by created_at, so target's successor is the
	// row immediately before it in the slice.
	for i := range sboms {
		if sboms[i].ID == target.ID {
			if i > 0 {
				cp := sboms[i-1]
				return &cp
			}
			return nil
		}
	}
	return nil
}

func (s *Service) computeBaseline(ctx context.Context, projectID uuid.UUID, to *model.Sbom) (*Response, error) {
	toComps, err := s.componentRepo.ListBySbom(ctx, to.ID)
	if err != nil {
		return nil, fmt.Errorf("list to components: %w", err)
	}
	toVulns, err := s.componentRepo.ListComponentVulnerabilitiesBySbom(ctx, to.ID)
	if err != nil {
		return nil, fmt.Errorf("list to vulnerabilities: %w", err)
	}
	policies, err := s.licenseRepo.ListByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("list license policies: %w", err)
	}

	added := make([]ComponentChange, 0, len(toComps))
	for _, c := range toComps {
		added = append(added, componentToChange(c))
	}

	vulnsAdded := make([]VulnerabilityAdded, 0, len(toVulns))
	seenCVE := map[string]struct{}{}
	for _, v := range toVulns {
		key := strings.ToUpper(v.CVEID) + "|" + componentNameKey(v.ComponentName) + "|" + strings.TrimSpace(v.ComponentVersion)
		if _, ok := seenCVE[key]; ok {
			continue
		}
		seenCVE[key] = struct{}{}
		vulnsAdded = append(vulnsAdded, VulnerabilityAdded{
			CVEID:            v.CVEID,
			Severity:         v.Severity,
			ComponentName:    v.ComponentName,
			ComponentVersion: v.ComponentVersion,
		})
	}

	violations := componentLicenseViolations(toComps, policies)

	return &Response{
		ProjectID: projectID,
		From:      nil,
		To:        sbomToRef(to),
		Components: ComponentsDiff{
			Added:          added,
			Removed:        []ComponentChange{},
			VersionChanged: []ComponentVersionChange{},
		},
		Vulnerabilities: VulnerabilitiesDiff{
			Added:           vulnsAdded,
			Resolved:        []VulnerabilityResolved{},
			SeverityChanged: []VulnerabilitySeverityChange{},
		},
		Licenses: LicensesDiff{
			AddedPolicyViolations:   violations,
			RemovedPolicyViolations: []LicensePolicyViolation{},
		},
	}, nil
}

func (s *Service) computePair(ctx context.Context, projectID uuid.UUID, from, to *model.Sbom) (*Response, error) {
	fromComps, err := s.componentRepo.ListBySbom(ctx, from.ID)
	if err != nil {
		return nil, fmt.Errorf("list from components: %w", err)
	}
	toComps, err := s.componentRepo.ListBySbom(ctx, to.ID)
	if err != nil {
		return nil, fmt.Errorf("list to components: %w", err)
	}
	fromVulns, err := s.componentRepo.ListComponentVulnerabilitiesBySbom(ctx, from.ID)
	if err != nil {
		return nil, fmt.Errorf("list from vulnerabilities: %w", err)
	}
	toVulns, err := s.componentRepo.ListComponentVulnerabilitiesBySbom(ctx, to.ID)
	if err != nil {
		return nil, fmt.Errorf("list to vulnerabilities: %w", err)
	}
	policies, err := s.licenseRepo.ListByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("list license policies: %w", err)
	}

	componentsDiff := diffComponents(fromComps, toComps)
	vulnsDiff := diffVulnerabilities(fromVulns, toVulns)
	licensesDiff := diffLicenseViolations(fromComps, toComps, policies)

	return &Response{
		ProjectID:       projectID,
		From:            sbomToRef(from),
		To:              sbomToRef(to),
		Components:      componentsDiff,
		Vulnerabilities: vulnsDiff,
		Licenses:        licensesDiff,
	}, nil
}

// ---------- pure helpers (exercised directly by diff_test.go) ----------

func componentToChange(c model.Component) ComponentChange {
	return ComponentChange{
		Name:    c.Name,
		Version: c.Version,
		Purl:    c.Purl,
		License: c.License,
	}
}

func sbomToRef(s *model.Sbom) *SbomRef {
	if s == nil {
		return nil
	}
	return &SbomRef{
		SbomID:    s.ID,
		Format:    s.Format,
		Version:   s.Version,
		CreatedAt: s.CreatedAt,
	}
}

// diffComponents matches base/target components and emits the three
// sub-buckets. Matching strategy is "purl when present, else
// (lower-cased name, type)". Version is the change axis: if a match
// has different versions it is a version_change, otherwise it is
// reported in neither added nor removed.
//
// Components with neither a purl nor a name on either side are skipped
// from version_changed (they fall back to the unique-id key path which
// produces no match — they would just appear as added + removed, which
// is the most honest representation given the missing identity).
func diffComponents(fromComps, toComps []model.Component) ComponentsDiff {
	type idx struct {
		comp model.Component
		used bool
	}

	fromByID := map[string]*idx{}
	toByID := map[string]*idx{}
	for i := range fromComps {
		c := fromComps[i]
		k := componentMatchKey(c)
		if k == "" {
			continue
		}
		fromByID[k] = &idx{comp: c}
	}
	for i := range toComps {
		c := toComps[i]
		k := componentMatchKey(c)
		if k == "" {
			continue
		}
		toByID[k] = &idx{comp: c}
	}

	versionChanged := make([]ComponentVersionChange, 0)
	added := make([]ComponentChange, 0)
	removed := make([]ComponentChange, 0)

	// version-change pass.
	for k, fi := range fromByID {
		ti, ok := toByID[k]
		if !ok {
			continue
		}
		fi.used = true
		ti.used = true
		fv := strings.TrimSpace(fi.comp.Version)
		tv := strings.TrimSpace(ti.comp.Version)
		if fv == tv {
			continue
		}
		versionChanged = append(versionChanged, ComponentVersionChange{
			Name:        ti.comp.Name,
			FromVersion: fi.comp.Version,
			ToVersion:   ti.comp.Version,
			Purl:        coalescePurl(ti.comp.Purl, fi.comp.Purl),
		})
	}

	// added pass: anything in to without a from match.
	for _, ti := range toByID {
		if ti.used {
			continue
		}
		added = append(added, componentToChange(ti.comp))
	}

	// removed pass: anything in from without a to match.
	for _, fi := range fromByID {
		if fi.used {
			continue
		}
		removed = append(removed, componentToChange(fi.comp))
	}

	// Components without an identity (no purl AND no name) fall through to
	// here. They cannot be reliably matched, so the honest representation
	// is to treat each side as a discrete add/remove. We append them with
	// nil-safe defaults so the response still serialises.
	for _, c := range fromComps {
		if componentMatchKey(c) == "" {
			removed = append(removed, componentToChange(c))
		}
	}
	for _, c := range toComps {
		if componentMatchKey(c) == "" {
			added = append(added, componentToChange(c))
		}
	}

	return ComponentsDiff{
		Added:          added,
		Removed:        removed,
		VersionChanged: versionChanged,
	}
}

// diffVulnerabilities computes added / resolved / severity_changed by
// matching on (CVE id, component name, component version) tuple for
// added/resolved and on cve_id alone for severity_changed. We track
// severity per-CVE (one entry per CVE) since the canonical severity
// lives on the vulnerabilities row (a single CVE has one severity).
func diffVulnerabilities(fromVulns, toVulns []model.ComponentVulnerability) VulnerabilitiesDiff {
	type cvKey struct {
		cveUpper      string
		componentName string
		version       string
	}
	mkKey := func(v model.ComponentVulnerability) cvKey {
		return cvKey{
			cveUpper:      strings.ToUpper(strings.TrimSpace(v.CVEID)),
			componentName: componentNameKey(v.ComponentName),
			version:       strings.TrimSpace(v.ComponentVersion),
		}
	}

	fromSet := map[cvKey]model.ComponentVulnerability{}
	toSet := map[cvKey]model.ComponentVulnerability{}
	fromSeverityByCVE := map[string]string{} // cveUpper -> severity (first seen)
	toSeverityByCVE := map[string]string{}

	for _, v := range fromVulns {
		k := mkKey(v)
		if _, ok := fromSet[k]; !ok {
			fromSet[k] = v
		}
		if _, ok := fromSeverityByCVE[k.cveUpper]; !ok {
			fromSeverityByCVE[k.cveUpper] = v.Severity
		}
	}
	for _, v := range toVulns {
		k := mkKey(v)
		if _, ok := toSet[k]; !ok {
			toSet[k] = v
		}
		if _, ok := toSeverityByCVE[k.cveUpper]; !ok {
			toSeverityByCVE[k.cveUpper] = v.Severity
		}
	}

	added := make([]VulnerabilityAdded, 0)
	resolved := make([]VulnerabilityResolved, 0)
	for k, v := range toSet {
		if _, ok := fromSet[k]; ok {
			continue
		}
		added = append(added, VulnerabilityAdded{
			CVEID:            v.CVEID,
			Severity:         v.Severity,
			ComponentName:    v.ComponentName,
			ComponentVersion: v.ComponentVersion,
		})
	}
	for k, v := range fromSet {
		if _, ok := toSet[k]; ok {
			continue
		}
		resolved = append(resolved, VulnerabilityResolved{
			CVEID:    v.CVEID,
			Severity: v.Severity,
		})
	}

	severityChanged := make([]VulnerabilitySeverityChange, 0)
	for cveUpper, fromSev := range fromSeverityByCVE {
		toSev, ok := toSeverityByCVE[cveUpper]
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(fromSev), strings.TrimSpace(toSev)) {
			continue
		}
		// Recover the original-case CVE id (whichever side has it).
		cveID := cveUpper
		for _, v := range fromVulns {
			if strings.EqualFold(v.CVEID, cveUpper) {
				cveID = v.CVEID
				break
			}
		}
		severityChanged = append(severityChanged, VulnerabilitySeverityChange{
			CVEID:        cveID,
			FromSeverity: fromSev,
			ToSeverity:   toSev,
		})
	}

	return VulnerabilitiesDiff{
		Added:           added,
		Resolved:        resolved,
		SeverityChanged: severityChanged,
	}
}

// diffLicenseViolations intersects (project denied policies) with
// (component licenses in each SBOM) and returns the set difference.
// A "violation" is a tuple of (component_name, license, policy_name).
func diffLicenseViolations(fromComps, toComps []model.Component, policies []model.LicensePolicy) LicensesDiff {
	denied := map[string]string{} // license_id (lower) -> policy display name
	for _, p := range policies {
		if p.PolicyType != model.LicensePolicyDenied {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(p.LicenseID))
		if key == "" {
			continue
		}
		name := p.LicenseName
		if name == "" {
			name = p.LicenseID
		}
		denied[key] = name
	}

	fromViolations := componentLicenseViolationsWithDenied(fromComps, denied)
	toViolations := componentLicenseViolationsWithDenied(toComps, denied)

	mkKey := func(v LicensePolicyViolation) string {
		return componentNameKey(v.ComponentName) + "|" + strings.ToLower(strings.TrimSpace(v.License))
	}
	fromKeys := map[string]struct{}{}
	for _, v := range fromViolations {
		fromKeys[mkKey(v)] = struct{}{}
	}
	toKeys := map[string]struct{}{}
	for _, v := range toViolations {
		toKeys[mkKey(v)] = struct{}{}
	}

	added := make([]LicensePolicyViolation, 0)
	removed := make([]LicensePolicyViolation, 0)
	for _, v := range toViolations {
		if _, ok := fromKeys[mkKey(v)]; ok {
			continue
		}
		added = append(added, v)
	}
	for _, v := range fromViolations {
		if _, ok := toKeys[mkKey(v)]; ok {
			continue
		}
		removed = append(removed, v)
	}

	return LicensesDiff{
		AddedPolicyViolations:   added,
		RemovedPolicyViolations: removed,
	}
}

// componentLicenseViolations is the public helper that builds the list
// of violations for a single SBOM given the full set of policies (it
// filters to denied internally). Used by computeBaseline (which only
// has one SBOM).
func componentLicenseViolations(comps []model.Component, policies []model.LicensePolicy) []LicensePolicyViolation {
	denied := map[string]string{}
	for _, p := range policies {
		if p.PolicyType != model.LicensePolicyDenied {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(p.LicenseID))
		if key == "" {
			continue
		}
		name := p.LicenseName
		if name == "" {
			name = p.LicenseID
		}
		denied[key] = name
	}
	return componentLicenseViolationsWithDenied(comps, denied)
}

func componentLicenseViolationsWithDenied(comps []model.Component, denied map[string]string) []LicensePolicyViolation {
	if len(denied) == 0 {
		return nil
	}
	out := make([]LicensePolicyViolation, 0)
	for _, c := range comps {
		lic := strings.TrimSpace(c.License)
		if lic == "" {
			continue
		}
		key := strings.ToLower(lic)
		policyName, ok := denied[key]
		if !ok {
			continue
		}
		out = append(out, LicensePolicyViolation{
			ComponentName: c.Name,
			License:       c.License,
			PolicyName:    policyName,
		})
	}
	return out
}

// ---------- component identity normalisation ----------

// componentMatchKey returns a stable identity key for matching a
// component across two SBOMs. Prefers purl (normalised: lowercased,
// version stripped) so version_changed catches version churn on the
// same purl-identified library. Falls back to (lower-cased name, type)
// when purl is absent. Returns "" when neither dimension is usable —
// the caller treats those rows as opaque add/remove.
func componentMatchKey(c model.Component) string {
	if p := normalizePurl(c.Purl); p != "" {
		return p
	}
	n := componentNameKey(c.Name)
	if n == "" {
		return ""
	}
	t := strings.ToLower(strings.TrimSpace(c.Type))
	return n + "|" + t
}

var nameNormRegex = regexp.MustCompile(`[^a-z0-9]+`)

func componentNameKey(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = nameNormRegex.ReplaceAllString(name, " ")
	return strings.TrimSpace(name)
}

func normalizePurl(p string) string {
	p = strings.TrimSpace(strings.ToLower(p))
	if p == "" {
		return ""
	}
	// purl version segment is "@<ver>" preceded by the canonical part.
	// Strip everything from "@" onward so two SBOMs that differ only in
	// version share the same key.
	if at := strings.Index(p, "@"); at > 0 {
		p = p[:at]
	}
	// Also strip any qualifiers ("?key=value...") for stability.
	if q := strings.Index(p, "?"); q > 0 {
		p = p[:q]
	}
	return p
}

func coalescePurl(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
