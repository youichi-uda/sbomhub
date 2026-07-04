// Package diff — unit tests for the M10-6 supply-chain churn diff
// service. The matrix exercises every public path of Compute through
// purpose-built in-memory fakes for the four repository dependencies.
//
// Why fakes (not sqlmock): the diff service is purely about set
// arithmetic on the repo results. Wrapping the matrix in sqlmock SQL
// regex assertions would lock us to repo SQL strings we do not own
// from this package, while adding zero confidence in the diff logic.
// Repository SQL is already pinned by repository/*_test.go.
package diff

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// ---------- in-memory fakes ----------

type fakeProjectRepo struct {
	projects map[uuid.UUID]uuid.UUID // projectID -> tenantID
}

func (f *fakeProjectRepo) GetByTenant(_ context.Context, tenantID, projectID uuid.UUID) (*model.Project, error) {
	if owner, ok := f.projects[projectID]; ok && owner == tenantID {
		return &model.Project{ID: projectID, Name: "test"}, nil
	}
	return nil, sql.ErrNoRows
}

type fakeSbomRepo struct {
	byID      map[uuid.UUID]model.Sbom
	byProject map[uuid.UUID][]model.Sbom // newest-first like the real repo
}

func (f *fakeSbomRepo) ListByProject(_ context.Context, projectID uuid.UUID) ([]model.Sbom, error) {
	out := make([]model.Sbom, len(f.byProject[projectID]))
	copy(out, f.byProject[projectID])
	return out, nil
}

func (f *fakeSbomRepo) GetByID(_ context.Context, id uuid.UUID) (*model.Sbom, error) {
	if s, ok := f.byID[id]; ok {
		cp := s
		return &cp, nil
	}
	return nil, sql.ErrNoRows
}

type fakeComponentRepo struct {
	components map[uuid.UUID][]model.Component
	vulns      map[uuid.UUID][]model.ComponentVulnerability
	byID       map[uuid.UUID]model.Component // optional: for GetByID (M29-A paths)
}

func (f *fakeComponentRepo) ListBySbom(_ context.Context, sbomID uuid.UUID) ([]model.Component, error) {
	out := make([]model.Component, len(f.components[sbomID]))
	copy(out, f.components[sbomID])
	return out, nil
}

// GetByID resolves a component by id — first from the explicit byID map,
// then by scanning the per-SBOM components map. Returns sql.ErrNoRows when
// unknown (mirrors ComponentRepository.GetByID). Added for M29-A (F397)
// ComputePaths, which resolves the target component's identity.
func (f *fakeComponentRepo) GetByID(_ context.Context, id uuid.UUID) (*model.Component, error) {
	if c, ok := f.byID[id]; ok {
		cp := c
		return &cp, nil
	}
	for _, comps := range f.components {
		for _, c := range comps {
			if c.ID == id {
				cp := c
				return &cp, nil
			}
		}
	}
	return nil, sql.ErrNoRows
}

func (f *fakeComponentRepo) ListComponentVulnerabilitiesBySbom(_ context.Context, sbomID uuid.UUID) ([]model.ComponentVulnerability, error) {
	out := make([]model.ComponentVulnerability, len(f.vulns[sbomID]))
	copy(out, f.vulns[sbomID])
	return out, nil
}

type fakeLicenseRepo struct {
	policies map[uuid.UUID][]model.LicensePolicy
}

func (f *fakeLicenseRepo) ListByProject(_ context.Context, projectID uuid.UUID) ([]model.LicensePolicy, error) {
	out := make([]model.LicensePolicy, len(f.policies[projectID]))
	copy(out, f.policies[projectID])
	return out, nil
}

// ---------- fixture builders ----------

type fixture struct {
	tenantID  uuid.UUID
	projectID uuid.UUID
	fromSbom  model.Sbom
	toSbom    model.Sbom
	service   *Service
}

// twoSbomFixture builds a two-SBOM project with all 3 component
// cases + all 3 vuln cases + license-policy violations on both sides.
//
//	from:                       to:
//	  lodash@4.17.20 (MIT)         lodash@4.17.21 (MIT)        version_changed
//	  axios@1.4.0 (MIT)            -                            removed
//	  -                            cool-pkg@2.0.0 (GPL-3.0)    added + license violation (added)
//	  badgpl@1.0.0 (GPL-3.0)       -                            removed + license violation (removed)
//	  shared-mit@1.0.0 (MIT)       shared-mit@1.0.0 (MIT)       no change
//
// vulnerabilities:
//
//	from:  CVE-2020-AAAA (HIGH)   on lodash@4.17.20    -> resolved
//	from:  CVE-2021-BBBB (HIGH)   on shared-mit@1.0.0  -> severity_changed -> CRITICAL
//	to:    CVE-2021-BBBB (CRITICAL) on shared-mit@1.0.0
//	to:    CVE-2024-CCCC (MEDIUM) on cool-pkg@2.0.0   -> added
func twoSbomFixture(t *testing.T) *fixture {
	t.Helper()

	tenantID := uuid.New()
	projectID := uuid.New()
	fromID := uuid.New()
	toID := uuid.New()

	now := time.Now()
	fromTime := now.Add(-2 * time.Hour)
	toTime := now.Add(-1 * time.Hour)

	fromSbom := model.Sbom{ID: fromID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", Version: "1.5", CreatedAt: fromTime}
	toSbom := model.Sbom{ID: toID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", Version: "1.5", CreatedAt: toTime}

	fromComps := []model.Component{
		{ID: uuid.New(), Name: "lodash", Version: "4.17.20", Type: "library", Purl: "pkg:npm/lodash@4.17.20", License: "MIT"},
		{ID: uuid.New(), Name: "axios", Version: "1.4.0", Type: "library", Purl: "pkg:npm/axios@1.4.0", License: "MIT"},
		{ID: uuid.New(), Name: "badgpl", Version: "1.0.0", Type: "library", Purl: "pkg:npm/badgpl@1.0.0", License: "GPL-3.0-only"},
		{ID: uuid.New(), Name: "shared-mit", Version: "1.0.0", Type: "library", Purl: "pkg:npm/shared-mit@1.0.0", License: "MIT"},
	}
	toComps := []model.Component{
		{ID: uuid.New(), Name: "lodash", Version: "4.17.21", Type: "library", Purl: "pkg:npm/lodash@4.17.21", License: "MIT"},
		{ID: uuid.New(), Name: "cool-pkg", Version: "2.0.0", Type: "library", Purl: "pkg:npm/cool-pkg@2.0.0", License: "GPL-3.0-only"},
		{ID: uuid.New(), Name: "shared-mit", Version: "1.0.0", Type: "library", Purl: "pkg:npm/shared-mit@1.0.0", License: "MIT"},
	}

	fromVulns := []model.ComponentVulnerability{
		{ComponentID: fromComps[0].ID, ComponentName: "lodash", ComponentVersion: "4.17.20", ComponentPurl: "pkg:npm/lodash@4.17.20", CVEID: "CVE-2020-AAAA", Severity: "HIGH"},
		{ComponentID: fromComps[3].ID, ComponentName: "shared-mit", ComponentVersion: "1.0.0", ComponentPurl: "pkg:npm/shared-mit@1.0.0", CVEID: "CVE-2021-BBBB", Severity: "HIGH"},
	}
	toVulns := []model.ComponentVulnerability{
		{ComponentID: toComps[2].ID, ComponentName: "shared-mit", ComponentVersion: "1.0.0", ComponentPurl: "pkg:npm/shared-mit@1.0.0", CVEID: "CVE-2021-BBBB", Severity: "CRITICAL"},
		{ComponentID: toComps[1].ID, ComponentName: "cool-pkg", ComponentVersion: "2.0.0", ComponentPurl: "pkg:npm/cool-pkg@2.0.0", CVEID: "CVE-2024-CCCC", Severity: "MEDIUM"},
	}

	policies := []model.LicensePolicy{
		{ID: uuid.New(), ProjectID: projectID, LicenseID: "GPL-3.0-only", LicenseName: "GPL-3.0 (denied)", PolicyType: model.LicensePolicyDenied},
		{ID: uuid.New(), ProjectID: projectID, LicenseID: "MIT", LicenseName: "MIT (allowed)", PolicyType: model.LicensePolicyAllowed},
	}

	pr := &fakeProjectRepo{projects: map[uuid.UUID]uuid.UUID{projectID: tenantID}}
	sr := &fakeSbomRepo{
		byID:      map[uuid.UUID]model.Sbom{fromID: fromSbom, toID: toSbom},
		byProject: map[uuid.UUID][]model.Sbom{projectID: {toSbom, fromSbom}}, // DESC
	}
	cr := &fakeComponentRepo{
		components: map[uuid.UUID][]model.Component{fromID: fromComps, toID: toComps},
		vulns:      map[uuid.UUID][]model.ComponentVulnerability{fromID: fromVulns, toID: toVulns},
	}
	lr := &fakeLicenseRepo{policies: map[uuid.UUID][]model.LicensePolicy{projectID: policies}}

	return &fixture{
		tenantID:  tenantID,
		projectID: projectID,
		fromSbom:  fromSbom,
		toSbom:    toSbom,
		service:   NewService(pr, sr, cr, lr),
	}
}

// ---------- tests ----------

func TestCompute_TwoSbom_AllThreeComponentBuckets(t *testing.T) {
	f := twoSbomFixture(t)

	resp, err := f.service.Compute(context.Background(), Request{
		TenantID:   f.tenantID,
		ProjectID:  f.projectID,
		FromSbomID: f.fromSbom.ID,
		ToSbomID:   f.toSbom.ID,
	})
	if err != nil {
		t.Fatalf("Compute() error: %v", err)
	}

	if resp.From == nil || resp.From.SbomID != f.fromSbom.ID {
		t.Errorf("From mismatch: %+v", resp.From)
	}
	if resp.To == nil || resp.To.SbomID != f.toSbom.ID {
		t.Errorf("To mismatch: %+v", resp.To)
	}

	// version_changed: lodash 4.17.20 -> 4.17.21
	if len(resp.Components.VersionChanged) != 1 {
		t.Fatalf("VersionChanged count: got %d, want 1; %+v", len(resp.Components.VersionChanged), resp.Components.VersionChanged)
	}
	vc := resp.Components.VersionChanged[0]
	if vc.Name != "lodash" || vc.FromVersion != "4.17.20" || vc.ToVersion != "4.17.21" {
		t.Errorf("VersionChanged[0] mismatch: %+v", vc)
	}

	// added: cool-pkg
	if !hasComponent(resp.Components.Added, "cool-pkg", "2.0.0") {
		t.Errorf("Added missing cool-pkg@2.0.0: %+v", resp.Components.Added)
	}
	// removed: axios + badgpl
	if !hasComponent(resp.Components.Removed, "axios", "1.4.0") {
		t.Errorf("Removed missing axios@1.4.0: %+v", resp.Components.Removed)
	}
	if !hasComponent(resp.Components.Removed, "badgpl", "1.0.0") {
		t.Errorf("Removed missing badgpl@1.0.0: %+v", resp.Components.Removed)
	}
	// shared-mit should NOT appear in any component bucket (identical both sides)
	if hasComponent(resp.Components.Added, "shared-mit", "1.0.0") ||
		hasComponent(resp.Components.Removed, "shared-mit", "1.0.0") {
		t.Errorf("shared-mit should not appear in added/removed; got added=%+v removed=%+v",
			resp.Components.Added, resp.Components.Removed)
	}
}

func TestCompute_TwoSbom_AllThreeVulnerabilityBuckets(t *testing.T) {
	f := twoSbomFixture(t)

	resp, err := f.service.Compute(context.Background(), Request{
		TenantID:   f.tenantID,
		ProjectID:  f.projectID,
		FromSbomID: f.fromSbom.ID,
		ToSbomID:   f.toSbom.ID,
	})
	if err != nil {
		t.Fatalf("Compute() error: %v", err)
	}

	// added: CVE-2024-CCCC on cool-pkg
	if len(resp.Vulnerabilities.Added) != 1 {
		t.Fatalf("Vulns.Added count: got %d, want 1; %+v", len(resp.Vulnerabilities.Added), resp.Vulnerabilities.Added)
	}
	if resp.Vulnerabilities.Added[0].CVEID != "CVE-2024-CCCC" {
		t.Errorf("Vulns.Added[0].CVEID: got %s, want CVE-2024-CCCC", resp.Vulnerabilities.Added[0].CVEID)
	}
	if resp.Vulnerabilities.Added[0].ComponentName != "cool-pkg" {
		t.Errorf("Vulns.Added[0].ComponentName: got %s, want cool-pkg", resp.Vulnerabilities.Added[0].ComponentName)
	}

	// resolved: CVE-2020-AAAA on lodash@4.17.20 (lodash version changed so
	// the (cve, component_name, version) tuple no longer matches in `to`)
	if len(resp.Vulnerabilities.Resolved) != 1 {
		t.Fatalf("Vulns.Resolved count: got %d, want 1; %+v", len(resp.Vulnerabilities.Resolved), resp.Vulnerabilities.Resolved)
	}
	if resp.Vulnerabilities.Resolved[0].CVEID != "CVE-2020-AAAA" {
		t.Errorf("Vulns.Resolved[0].CVEID: got %s, want CVE-2020-AAAA", resp.Vulnerabilities.Resolved[0].CVEID)
	}

	// severity_changed: CVE-2021-BBBB HIGH -> CRITICAL
	if len(resp.Vulnerabilities.SeverityChanged) != 1 {
		t.Fatalf("Vulns.SeverityChanged count: got %d, want 1; %+v", len(resp.Vulnerabilities.SeverityChanged), resp.Vulnerabilities.SeverityChanged)
	}
	sc := resp.Vulnerabilities.SeverityChanged[0]
	if sc.CVEID != "CVE-2021-BBBB" || sc.FromSeverity != "HIGH" || sc.ToSeverity != "CRITICAL" {
		t.Errorf("SeverityChanged[0] mismatch: %+v", sc)
	}
}

func TestCompute_TwoSbom_LicensePolicyBuckets(t *testing.T) {
	f := twoSbomFixture(t)

	resp, err := f.service.Compute(context.Background(), Request{
		TenantID:   f.tenantID,
		ProjectID:  f.projectID,
		FromSbomID: f.fromSbom.ID,
		ToSbomID:   f.toSbom.ID,
	})
	if err != nil {
		t.Fatalf("Compute() error: %v", err)
	}

	// added violation: cool-pkg/GPL-3.0
	if len(resp.Licenses.AddedPolicyViolations) != 1 {
		t.Fatalf("AddedPolicyViolations count: got %d, want 1; %+v", len(resp.Licenses.AddedPolicyViolations), resp.Licenses.AddedPolicyViolations)
	}
	av := resp.Licenses.AddedPolicyViolations[0]
	if av.ComponentName != "cool-pkg" || av.License != "GPL-3.0-only" || av.PolicyName != "GPL-3.0 (denied)" {
		t.Errorf("AddedPolicyViolations[0] mismatch: %+v", av)
	}

	// removed violation: badgpl/GPL-3.0
	if len(resp.Licenses.RemovedPolicyViolations) != 1 {
		t.Fatalf("RemovedPolicyViolations count: got %d, want 1; %+v", len(resp.Licenses.RemovedPolicyViolations), resp.Licenses.RemovedPolicyViolations)
	}
	rv := resp.Licenses.RemovedPolicyViolations[0]
	if rv.ComponentName != "badgpl" || rv.License != "GPL-3.0-only" {
		t.Errorf("RemovedPolicyViolations[0] mismatch: %+v", rv)
	}
}

// Default behaviour: no from/to => pick the 2 newest SBOMs.
func TestCompute_DefaultsToTwoNewest(t *testing.T) {
	f := twoSbomFixture(t)

	resp, err := f.service.Compute(context.Background(), Request{
		TenantID:  f.tenantID,
		ProjectID: f.projectID,
	})
	if err != nil {
		t.Fatalf("Compute() error: %v", err)
	}
	if resp.From == nil || resp.From.SbomID != f.fromSbom.ID {
		t.Errorf("default From should be older sbom; got %+v", resp.From)
	}
	if resp.To == nil || resp.To.SbomID != f.toSbom.ID {
		t.Errorf("default To should be newest sbom; got %+v", resp.To)
	}
}

// Single-SBOM baseline: everything is "added", removed/version_changed
// are empty.
func TestCompute_SingleSbom_Baseline(t *testing.T) {
	f := twoSbomFixture(t)
	// surgically reduce to one sbom
	soleID := f.toSbom.ID
	pr := &fakeProjectRepo{projects: map[uuid.UUID]uuid.UUID{f.projectID: f.tenantID}}
	sr := &fakeSbomRepo{
		byID:      map[uuid.UUID]model.Sbom{soleID: f.toSbom},
		byProject: map[uuid.UUID][]model.Sbom{f.projectID: {f.toSbom}},
	}
	cr := &fakeComponentRepo{
		components: map[uuid.UUID][]model.Component{
			soleID: {
				{Name: "lodash", Version: "4.17.21", Type: "library", Purl: "pkg:npm/lodash@4.17.21", License: "MIT"},
				{Name: "bad", Version: "1.0.0", Type: "library", Purl: "pkg:npm/bad@1.0.0", License: "GPL-3.0-only"},
			},
		},
		vulns: map[uuid.UUID][]model.ComponentVulnerability{
			soleID: {{ComponentName: "lodash", ComponentVersion: "4.17.21", CVEID: "CVE-2024-XXXX", Severity: "HIGH"}},
		},
	}
	lr := &fakeLicenseRepo{policies: map[uuid.UUID][]model.LicensePolicy{
		f.projectID: {{ProjectID: f.projectID, LicenseID: "GPL-3.0-only", LicenseName: "GPL-3.0", PolicyType: model.LicensePolicyDenied}},
	}}
	svc := NewService(pr, sr, cr, lr)

	resp, err := svc.Compute(context.Background(), Request{TenantID: f.tenantID, ProjectID: f.projectID})
	if err != nil {
		t.Fatalf("Compute() error: %v", err)
	}
	if resp.From != nil {
		t.Errorf("expected nil From in baseline path; got %+v", resp.From)
	}
	if len(resp.Components.Added) != 2 {
		t.Errorf("Added count: got %d, want 2 (all components in baseline)", len(resp.Components.Added))
	}
	if len(resp.Components.Removed) != 0 || len(resp.Components.VersionChanged) != 0 {
		t.Errorf("baseline must have empty removed/version_changed; got %+v / %+v",
			resp.Components.Removed, resp.Components.VersionChanged)
	}
	if len(resp.Vulnerabilities.Added) != 1 || len(resp.Vulnerabilities.Resolved) != 0 || len(resp.Vulnerabilities.SeverityChanged) != 0 {
		t.Errorf("baseline vuln buckets wrong: added=%d resolved=%d severity_changed=%d",
			len(resp.Vulnerabilities.Added), len(resp.Vulnerabilities.Resolved), len(resp.Vulnerabilities.SeverityChanged))
	}
	if len(resp.Licenses.AddedPolicyViolations) != 1 || len(resp.Licenses.RemovedPolicyViolations) != 0 {
		t.Errorf("baseline license buckets wrong: added=%d removed=%d",
			len(resp.Licenses.AddedPolicyViolations), len(resp.Licenses.RemovedPolicyViolations))
	}
}

// Tenant isolation: project owned by another tenant must return ErrNoRows.
func TestCompute_RejectsCrossTenant(t *testing.T) {
	f := twoSbomFixture(t)
	otherTenant := uuid.New()

	_, err := f.service.Compute(context.Background(), Request{
		TenantID:  otherTenant,
		ProjectID: f.projectID,
	})
	if err == nil {
		t.Fatal("expected error for cross-tenant access; got nil")
	}
}

// Empty project returns ErrNoSboms.
func TestCompute_NoSboms_ReturnsErrNoSboms(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	svc := NewService(
		&fakeProjectRepo{projects: map[uuid.UUID]uuid.UUID{projectID: tenantID}},
		&fakeSbomRepo{byProject: map[uuid.UUID][]model.Sbom{projectID: nil}},
		&fakeComponentRepo{},
		&fakeLicenseRepo{},
	)
	_, err := svc.Compute(context.Background(), Request{TenantID: tenantID, ProjectID: projectID})
	if err != ErrNoSboms {
		t.Errorf("expected ErrNoSboms, got %v", err)
	}
}

// F166: when only `from` is set AND from is already the newest SBOM,
// the service must return ErrNoNewerSbom (not a generic fmt.Errorf).
// The handler maps this to 400, not 500.
func TestCompute_FromIsNewest_ReturnsErrNoNewerSbom(t *testing.T) {
	f := twoSbomFixture(t)

	// twoSbomFixture has from at -2h and to at -1h. Pass `to` (the
	// newest) as `from` with no explicit `to`. Default resolution
	// should not find a successor.
	_, err := f.service.Compute(context.Background(), Request{
		TenantID:   f.tenantID,
		ProjectID:  f.projectID,
		FromSbomID: f.toSbom.ID,
	})
	if !errors.Is(err, ErrNoNewerSbom) {
		t.Errorf("expected ErrNoNewerSbom, got %v", err)
	}
}

// SBOM from another project (or deleted) maps to ErrSbomNotInProject.
func TestCompute_SbomNotInProject(t *testing.T) {
	f := twoSbomFixture(t)
	foreignSbomID := uuid.New()
	otherProject := uuid.New()
	// register the foreign sbom under a different project
	f.service.sbomRepo.(*fakeSbomRepo).byID[foreignSbomID] = model.Sbom{ID: foreignSbomID, ProjectID: otherProject}

	_, err := f.service.Compute(context.Background(), Request{
		TenantID:  f.tenantID,
		ProjectID: f.projectID,
		ToSbomID:  foreignSbomID,
	})
	if err != ErrSbomNotInProject {
		t.Errorf("expected ErrSbomNotInProject, got %v", err)
	}
}

// componentMatchKey: purl present -> normalised purl
func TestComponentMatchKey_WithPurl(t *testing.T) {
	got := componentMatchKey(model.Component{Name: "x", Type: "library", Purl: "PKG:NPM/Lodash@4.17.21"})
	if got != "pkg:npm/lodash" {
		t.Errorf("got %q, want pkg:npm/lodash", got)
	}
}

// componentMatchKey: no purl -> (name, type)
func TestComponentMatchKey_NoPurl(t *testing.T) {
	got := componentMatchKey(model.Component{Name: "My Lib!", Type: "Library", Purl: ""})
	if got != "my lib|library" {
		t.Errorf("got %q, want \"my lib|library\"", got)
	}
}

// componentMatchKey: no purl AND no name -> empty (opaque add/remove path)
func TestComponentMatchKey_NoIdentity(t *testing.T) {
	got := componentMatchKey(model.Component{Name: "", Type: "", Purl: ""})
	if got != "" {
		t.Errorf("got %q, want empty (opaque component)", got)
	}
}

// normalizePurl: version + qualifiers stripped, case-folded.
func TestNormalizePurl(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/lodash@4.17.21":             "pkg:npm/lodash",
		"PKG:NPM/Express":                    "pkg:npm/express",
		"pkg:maven/org.x/y@1?type=jar":       "pkg:maven/org.x/y",
		"":                                   "",
		"  ":                                 "",
		"pkg:pypi/requests@2.28.0?extras=ws": "pkg:pypi/requests",
	}
	for in, want := range cases {
		if got := normalizePurl(in); got != want {
			t.Errorf("normalizePurl(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---------- helpers ----------

func hasComponent(list []ComponentChange, name, version string) bool {
	for _, c := range list {
		if c.Name == name && c.Version == version {
			return true
		}
	}
	return false
}
