package diff_export

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service/diff"
)

// ---------- in-memory fakes mirroring diff/diff_test.go ----------

type fakeProjectRepo struct {
	owner map[uuid.UUID]uuid.UUID
}

func (f *fakeProjectRepo) GetByTenant(_ context.Context, t, p uuid.UUID) (*model.Project, error) {
	if o, ok := f.owner[p]; ok && o == t {
		return &model.Project{ID: p, Name: "t"}, nil
	}
	return nil, errors.New("sql: no rows in result set")
}

type fakeSbomRepo struct {
	byID      map[uuid.UUID]model.Sbom
	byProject map[uuid.UUID][]model.Sbom
}

func (f *fakeSbomRepo) ListByProject(_ context.Context, p uuid.UUID) ([]model.Sbom, error) {
	out := make([]model.Sbom, len(f.byProject[p]))
	copy(out, f.byProject[p])
	return out, nil
}
func (f *fakeSbomRepo) GetByID(_ context.Context, id uuid.UUID) (*model.Sbom, error) {
	if s, ok := f.byID[id]; ok {
		cp := s
		return &cp, nil
	}
	return nil, errors.New("sql: no rows in result set")
}

type fakeComponentRepo struct {
	components map[uuid.UUID][]model.Component
	vulns      map[uuid.UUID][]model.ComponentVulnerability
}

func (f *fakeComponentRepo) ListBySbom(_ context.Context, id uuid.UUID) ([]model.Component, error) {
	out := make([]model.Component, len(f.components[id]))
	copy(out, f.components[id])
	return out, nil
}
func (f *fakeComponentRepo) ListComponentVulnerabilitiesBySbom(_ context.Context, id uuid.UUID) ([]model.ComponentVulnerability, error) {
	out := make([]model.ComponentVulnerability, len(f.vulns[id]))
	copy(out, f.vulns[id])
	return out, nil
}

type fakeLicenseRepo struct {
	policies map[uuid.UUID][]model.LicensePolicy
}

func (f *fakeLicenseRepo) ListByProject(_ context.Context, p uuid.UUID) ([]model.LicensePolicy, error) {
	out := make([]model.LicensePolicy, len(f.policies[p]))
	copy(out, f.policies[p])
	return out, nil
}

func twoSbomFixture(t *testing.T) (uuid.UUID, uuid.UUID, *diff.Service, uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID := uuid.New()
	projectID := uuid.New()
	fromID := uuid.New()
	toID := uuid.New()
	now := time.Now()
	fromSbom := model.Sbom{ID: fromID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", Version: "1.5", CreatedAt: now.Add(-2 * time.Hour)}
	toSbom := model.Sbom{ID: toID, TenantID: tenantID, ProjectID: projectID, Format: "cyclonedx", Version: "1.5", CreatedAt: now.Add(-1 * time.Hour)}
	fromComps := []model.Component{
		{ID: uuid.New(), Name: "lodash", Version: "4.17.20", Type: "library", Purl: "pkg:npm/lodash@4.17.20", License: "MIT"},
		{ID: uuid.New(), Name: "badgpl", Version: "1.0.0", Type: "library", Purl: "pkg:npm/badgpl@1.0.0", License: "GPL-3.0-only"},
	}
	toComps := []model.Component{
		{ID: uuid.New(), Name: "lodash", Version: "4.17.21", Type: "library", Purl: "pkg:npm/lodash@4.17.21", License: "MIT"},
		{ID: uuid.New(), Name: "axios", Version: "1.6.0", Type: "library", Purl: "pkg:npm/axios@1.6.0", License: "MIT"},
		// Added GPL component so the license_policy_violation:added bucket is non-empty.
		{ID: uuid.New(), Name: "newgpl", Version: "2.0.0", Type: "library", Purl: "pkg:npm/newgpl@2.0.0", License: "GPL-3.0-only"},
	}
	fromVulns := []model.ComponentVulnerability{
		{ComponentID: fromComps[0].ID, ComponentName: "lodash", ComponentVersion: "4.17.20", CVEID: "CVE-2020-AAAA", Severity: "HIGH"},
	}
	toVulns := []model.ComponentVulnerability{
		{ComponentID: toComps[1].ID, ComponentName: "axios", ComponentVersion: "1.6.0", CVEID: "CVE-2024-BBBB", Severity: "MEDIUM"},
	}
	policies := []model.LicensePolicy{
		{ID: uuid.New(), ProjectID: projectID, LicenseID: "GPL-3.0-only", LicenseName: "GPL-3.0", PolicyType: model.LicensePolicyDenied},
	}
	pr := &fakeProjectRepo{owner: map[uuid.UUID]uuid.UUID{projectID: tenantID}}
	sr := &fakeSbomRepo{
		byID:      map[uuid.UUID]model.Sbom{fromID: fromSbom, toID: toSbom},
		byProject: map[uuid.UUID][]model.Sbom{projectID: {toSbom, fromSbom}},
	}
	cr := &fakeComponentRepo{
		components: map[uuid.UUID][]model.Component{fromID: fromComps, toID: toComps},
		vulns:      map[uuid.UUID][]model.ComponentVulnerability{fromID: fromVulns, toID: toVulns},
	}
	lr := &fakeLicenseRepo{policies: map[uuid.UUID][]model.LicensePolicy{projectID: policies}}
	return tenantID, projectID, diff.NewService(pr, sr, cr, lr), fromID, toID
}

func TestRenderCSV_ContainsAllBuckets(t *testing.T) {
	tenantID, projectID, diffSvc, fromID, toID := twoSbomFixture(t)
	svc := NewService(diffSvc)

	data, name, err := svc.RenderCSV(context.Background(), Request{
		TenantID: tenantID, ProjectID: projectID,
		FromSbomID: fromID, ToSbomID: toID,
	})
	if err != nil {
		t.Fatalf("RenderCSV: %v", err)
	}
	if !strings.HasSuffix(name, ".csv") {
		t.Errorf("filename should end .csv; got %q", name)
	}
	r := csv.NewReader(bytes.NewReader(data))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v", err)
	}
	if len(rows) < 2 {
		t.Fatalf("expected header + body; got %d rows", len(rows))
	}
	header := rows[0]
	if header[0] != "type" || header[1] != "kind" {
		t.Errorf("header schema mismatch: %v", header)
	}
	got := map[string]int{}
	for _, r := range rows[1:] {
		got[r[0]+":"+r[1]]++
	}
	must := []string{
		"component:added",
		"component:removed",
		"component:version_changed",
		"vulnerability:added",
		"vulnerability:resolved",
		"license_policy_violation:added",
		"license_policy_violation:removed",
	}
	for _, k := range must {
		if got[k] == 0 {
			t.Errorf("CSV missing row for %s; counts=%v", k, got)
		}
	}
}

func TestRenderPDF_ReturnsPDFBytes(t *testing.T) {
	tenantID, projectID, diffSvc, fromID, toID := twoSbomFixture(t)
	svc := NewService(diffSvc)

	data, name, err := svc.RenderPDF(context.Background(), Request{
		TenantID: tenantID, ProjectID: projectID,
		FromSbomID: fromID, ToSbomID: toID,
		Lang: "ja",
	})
	if err != nil {
		t.Fatalf("RenderPDF: %v", err)
	}
	if !strings.HasSuffix(name, ".pdf") {
		t.Errorf("filename should end .pdf; got %q", name)
	}
	if len(data) < 100 {
		t.Errorf("expected non-trivial PDF body; got %d bytes", len(data))
	}
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		t.Errorf("output not a PDF (no %%PDF- header)")
	}
}

func TestRenderCSV_RejectsCrossTenant(t *testing.T) {
	_, projectID, diffSvc, fromID, toID := twoSbomFixture(t)
	svc := NewService(diffSvc)
	_, _, err := svc.RenderCSV(context.Background(), Request{
		TenantID: uuid.New(), ProjectID: projectID,
		FromSbomID: fromID, ToSbomID: toID,
	})
	if err == nil {
		t.Fatal("expected cross-tenant access to error")
	}
}
