package criteria

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// fakeDeps is the per-criterion test fake. Every field defaults to a
// zero / empty value so tests only fill in the fields the criterion
// under test actually touches; unused fields stay nil and surface a
// panic if a criterion accidentally reads them (which is the right
// test-failure shape — silent ignore would hide the bug).
type fakeDeps struct {
	latestSbom   *model.Sbom
	sbomList     []model.Sbom
	components   map[uuid.UUID][]model.Component
	vulns        []model.Vulnerability
	vexDrafts    []repository.VEXDraft
	craReports   []repository.CRAReport
	publicLinks  []model.PublicLink
	policies     []model.LicensePolicy
	eolSummary   *model.EOLSummary
	kevSettings  *model.KEVSyncSettings
	auditLogsN   int
	auditLogsErr error

	// Failure injection — tests pin these to assert error propagation.
	getLatestErr     error
	listSbomsErr     error
	listComponentsEr error
}

func (f *fakeDeps) GetLatestSbom(_ context.Context, _ uuid.UUID) (*model.Sbom, error) {
	if f.getLatestErr != nil {
		return nil, f.getLatestErr
	}
	return f.latestSbom, nil
}
func (f *fakeDeps) ListSbomsByProject(_ context.Context, _ uuid.UUID) ([]model.Sbom, error) {
	if f.listSbomsErr != nil {
		return nil, f.listSbomsErr
	}
	return f.sbomList, nil
}
func (f *fakeDeps) ListComponentsBySbom(_ context.Context, sbomID uuid.UUID) ([]model.Component, error) {
	if f.listComponentsEr != nil {
		return nil, f.listComponentsEr
	}
	if f.components == nil {
		return nil, nil
	}
	return f.components[sbomID], nil
}
func (f *fakeDeps) ListVulnerabilitiesByProject(_ context.Context, _ uuid.UUID) ([]model.Vulnerability, error) {
	return f.vulns, nil
}
func (f *fakeDeps) ListVEXDraftsByProject(_ context.Context, _, _ uuid.UUID) ([]repository.VEXDraft, error) {
	return f.vexDrafts, nil
}
func (f *fakeDeps) ListCRAReportsByProject(_ context.Context, _, _ uuid.UUID) ([]repository.CRAReport, error) {
	return f.craReports, nil
}
func (f *fakeDeps) ListPublicLinksByProject(_ context.Context, _, _ uuid.UUID) ([]model.PublicLink, error) {
	return f.publicLinks, nil
}
func (f *fakeDeps) ListLicensePoliciesByProject(_ context.Context, _ uuid.UUID) ([]model.LicensePolicy, error) {
	return f.policies, nil
}
func (f *fakeDeps) GetEOLSummary(_ context.Context, _ uuid.UUID) (*model.EOLSummary, error) {
	return f.eolSummary, nil
}
func (f *fakeDeps) GetKEVSyncSettings(_ context.Context) (*model.KEVSyncSettings, error) {
	return f.kevSettings, nil
}
func (f *fakeDeps) CountAuditLogsForTenant(_ context.Context, _ uuid.UUID) (int, error) {
	return f.auditLogsN, f.auditLogsErr
}

// jsonContains is a small assertion helper: parses the evidence
// rawmessage and checks that it is a syntactically valid JSON array
// (matching the meti_assessments DB CHECK) and that the textual form
// contains `needle` — keeps tests readable without unmarshalling
// into ad-hoc types.
func jsonContainsArray(t *testing.T, raw json.RawMessage, needle string) {
	t.Helper()
	require.NotEmpty(t, raw, "evidence must not be nil")
	var arr []json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &arr), "evidence must be a JSON array")
	assert.Contains(t, string(raw), needle, "evidence should mention %q; got %s", needle, string(raw))
}

// helperTenantProject keeps tests tidy.
func helperTenantProject() (uuid.UUID, uuid.UUID) {
	return uuid.New(), uuid.New()
}

// helperSBOM constructs a minimal model.Sbom with a deterministic
// timestamp so the cadence tests are not racy.
func helperSBOM(id uuid.UUID, format, version string, createdAt time.Time, raw []byte) *model.Sbom {
	return &model.Sbom{
		ID:        id,
		Format:    format,
		Version:   version,
		RawData:   raw,
		CreatedAt: createdAt,
	}
}

// =============================================================================
// env_setup phase
// =============================================================================

func TestEnvSetup01_AlwaysNeedsReview(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateEnvSetup01(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
	assert.NotEmpty(t, res.ImprovementAction)
}

func TestEnvSetup02_AchievedWhenPurlEcosystemsPresent(t *testing.T) {
	tenant, project := helperTenantProject()
	sbomID := uuid.New()
	deps := &fakeDeps{
		latestSbom: helperSBOM(sbomID, "cyclonedx", "1.5", time.Now(), nil),
		components: map[uuid.UUID][]model.Component{
			sbomID: {
				{Name: "react", Version: "19.0.0", Purl: "pkg:npm/react@19.0.0"},
				{Name: "express", Version: "4.18.0", Purl: "pkg:npm/express@4.18.0"},
				{Name: "guava", Version: "32.0", Purl: "pkg:maven/com.google.guava/guava@32.0"},
			},
		},
	}
	res, err := EvaluateEnvSetup02(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
	jsonContainsArray(t, res.Evidence, "pkg:npm")
	jsonContainsArray(t, res.Evidence, "pkg:maven")
}

func TestEnvSetup02_NeedsReviewWhenNoSBOM(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateEnvSetup02(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestEnvSetup02_NeedsReviewWhenComponentsHaveNoPurl(t *testing.T) {
	tenant, project := helperTenantProject()
	sbomID := uuid.New()
	deps := &fakeDeps{
		latestSbom: helperSBOM(sbomID, "cyclonedx", "1.5", time.Now(), nil),
		components: map[uuid.UUID][]model.Component{
			sbomID: {
				{Name: "foo", Version: "1.0.0"},
			},
		},
	}
	res, err := EvaluateEnvSetup02(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestEnvSetup03_AlwaysNeedsReview(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateEnvSetup03(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestEnvSetup04_AchievedWhenCRAReportsExist(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{
		craReports: []repository.CRAReport{{ID: uuid.New(), ReportType: "early_warning"}},
	}
	res, err := EvaluateEnvSetup04(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestEnvSetup04_NeedsReviewWhenNoCRA(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateEnvSetup04(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestEnvSetup05_AchievedWhenPublicLinkExists(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{
		publicLinks: []model.PublicLink{{ID: uuid.New(), Token: "abc"}},
	}
	res, err := EvaluateEnvSetup05(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestEnvSetup05_NeedsReviewWhenNoLinks(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateEnvSetup05(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestEnvSetup06_AlwaysNeedsReview(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateEnvSetup06(context.Background(), &fakeDeps{sbomList: []model.Sbom{{ID: uuid.New()}}}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestEnvSetup07_AchievedWhenSBOMsExist(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{sbomList: []model.Sbom{
		{ID: uuid.New(), Format: "CycloneDX", CreatedAt: time.Now()},
	}}
	res, err := EvaluateEnvSetup07(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestEnvSetup07_NotAchievedWhenNoSBOMs(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateEnvSetup07(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNotAchieved, res.Status)
}

func TestEnvSetup08_AlwaysNeedsReview(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateEnvSetup08(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

// =============================================================================
// sbom_creation phase
// =============================================================================

func TestSBOMCreation01_AchievedWhenRecent(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{
		sbomList: []model.Sbom{
			{ID: uuid.New(), CreatedAt: time.Now().Add(-3 * 24 * time.Hour)},
		},
	}
	res, err := EvaluateSBOMCreation01(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMCreation01_NeedsReviewWhenAllStale(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{
		sbomList: []model.Sbom{
			{ID: uuid.New(), CreatedAt: time.Now().Add(-90 * 24 * time.Hour)},
		},
	}
	res, err := EvaluateSBOMCreation01(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestSBOMCreation01_NotAchievedWhenNoSBOMs(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateSBOMCreation01(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNotAchieved, res.Status)
}

func TestSBOMCreation02_AchievedCycloneDX(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{latestSbom: helperSBOM(uuid.New(), "CycloneDX", "1.5", time.Now(), nil)}
	res, err := EvaluateSBOMCreation02(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMCreation02_AchievedSPDX(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{latestSbom: helperSBOM(uuid.New(), "spdx", "2.3", time.Now(), nil)}
	res, err := EvaluateSBOMCreation02(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMCreation02_NotAchievedUnknownFormat(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{latestSbom: helperSBOM(uuid.New(), "swid", "1.0", time.Now(), nil)}
	res, err := EvaluateSBOMCreation02(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNotAchieved, res.Status)
}

func TestSBOMCreation03_AchievedWhenComponentsPresent(t *testing.T) {
	tenant, project := helperTenantProject()
	sbomID := uuid.New()
	deps := &fakeDeps{
		latestSbom: helperSBOM(sbomID, "cyclonedx", "1.5", time.Now(), nil),
		components: map[uuid.UUID][]model.Component{
			sbomID: {{Name: "a", Version: "1.0", Purl: "pkg:npm/a@1.0"}},
		},
	}
	res, err := EvaluateSBOMCreation03(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMCreation03_NotAchievedWhenNoComponents(t *testing.T) {
	tenant, project := helperTenantProject()
	sbomID := uuid.New()
	deps := &fakeDeps{
		latestSbom: helperSBOM(sbomID, "cyclonedx", "1.5", time.Now(), nil),
		components: map[uuid.UUID][]model.Component{sbomID: {}},
	}
	res, err := EvaluateSBOMCreation03(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNotAchieved, res.Status)
}

func TestSBOMCreation04_AchievedWhenNoUnknownVersions(t *testing.T) {
	tenant, project := helperTenantProject()
	sbomID := uuid.New()
	deps := &fakeDeps{
		latestSbom: helperSBOM(sbomID, "cyclonedx", "1.5", time.Now(), nil),
		components: map[uuid.UUID][]model.Component{sbomID: {
			{Name: "a", Version: "1.0"},
			{Name: "b", Version: "2.0"},
		}},
	}
	res, err := EvaluateSBOMCreation04(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMCreation04_NotAchievedWhenUnknownVersionsExist(t *testing.T) {
	tenant, project := helperTenantProject()
	sbomID := uuid.New()
	deps := &fakeDeps{
		latestSbom: helperSBOM(sbomID, "cyclonedx", "1.5", time.Now(), nil),
		components: map[uuid.UUID][]model.Component{sbomID: {
			{Name: "a", Version: "1.0"},
			{Name: "b", Version: ""},
			{Name: "c", Version: "unknown"},
		}},
	}
	res, err := EvaluateSBOMCreation04(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNotAchieved, res.Status)
	jsonContainsArray(t, res.Evidence, "unknown_version_count")
}

func TestSBOMCreation05_AlwaysNeedsReview(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateSBOMCreation05(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestSBOMCreation06_AchievedFullElements(t *testing.T) {
	tenant, project := helperTenantProject()
	sbomID := uuid.New()
	rawCDX := []byte(`{
		"metadata": {"timestamp": "2026-01-01T00:00:00Z", "tools": [{"name":"syft"}]},
		"dependencies": [{"ref": "x"}]
	}`)
	deps := &fakeDeps{
		latestSbom: helperSBOM(sbomID, "cyclonedx", "1.5", time.Now(), rawCDX),
		components: map[uuid.UUID][]model.Component{sbomID: {
			{Name: "react", Version: "19.0", Purl: "pkg:npm/facebook/react@19.0"},
			{Name: "express", Version: "4.18", Purl: "pkg:npm/expressjs/express@4.18"},
			{Name: "guava", Version: "32.0", Purl: "pkg:maven/com.google.guava/guava@32.0"},
			{Name: "jackson", Version: "2.16", Purl: "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.16"},
			{Name: "log4j", Version: "2.22", Purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.22"},
		}},
	}
	res, err := EvaluateSBOMCreation06(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMCreation06_NotAchievedWhenMissingElements(t *testing.T) {
	tenant, project := helperTenantProject()
	sbomID := uuid.New()
	// Empty raw data -> dependency_relationship / sbom_author / timestamp fail.
	deps := &fakeDeps{
		latestSbom: helperSBOM(sbomID, "cyclonedx", "1.5", time.Now(), []byte(`{}`)),
		components: map[uuid.UUID][]model.Component{sbomID: {
			{Name: "react", Version: "19.0", Purl: "pkg:npm/react@19.0"},
		}},
	}
	res, err := EvaluateSBOMCreation06(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNotAchieved, res.Status)
}

func TestSBOMCreation07_AchievedWhenPublicLinkExists(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{publicLinks: []model.PublicLink{{ID: uuid.New()}}}
	res, err := EvaluateSBOMCreation07(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMCreation07_NeedsReviewWhenNoLinks(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateSBOMCreation07(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestSBOMCreation08_AchievedWhenMultipleVersions(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{sbomList: []model.Sbom{{ID: uuid.New()}, {ID: uuid.New()}}}
	res, err := EvaluateSBOMCreation08(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMCreation08_NeedsReviewWhenSingleSBOM(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{sbomList: []model.Sbom{{ID: uuid.New()}}}
	res, err := EvaluateSBOMCreation08(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestSBOMCreation09_AlwaysNeedsReview(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateSBOMCreation09(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

// =============================================================================
// sbom_operation phase
// =============================================================================

func TestSBOMOperation01_AchievedWhenVulnsMatched(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{vulns: []model.Vulnerability{{ID: uuid.New(), CVEID: "CVE-2025-0001"}}}
	res, err := EvaluateSBOMOperation01(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMOperation01_NeedsReviewWhenZeroVulns(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateSBOMOperation01(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestSBOMOperation02_AchievedWhenKEVRecent(t *testing.T) {
	tenant, project := helperTenantProject()
	now := time.Now()
	deps := &fakeDeps{
		kevSettings: &model.KEVSyncSettings{
			Enabled:      true,
			LastSyncAt:   &now,
			TotalEntries: 1100,
		},
	}
	res, err := EvaluateSBOMOperation02(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMOperation02_NeedsReviewWhenKEVStale(t *testing.T) {
	tenant, project := helperTenantProject()
	stale := time.Now().Add(-5 * 24 * time.Hour)
	deps := &fakeDeps{
		kevSettings: &model.KEVSyncSettings{
			Enabled:    true,
			LastSyncAt: &stale,
		},
	}
	res, err := EvaluateSBOMOperation02(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestSBOMOperation02_NeedsReviewWhenKEVNil(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateSBOMOperation02(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestSBOMOperation03_AchievedWhenEPSSScorePresent(t *testing.T) {
	tenant, project := helperTenantProject()
	score := 0.42
	deps := &fakeDeps{vulns: []model.Vulnerability{
		{ID: uuid.New(), CVEID: "CVE-2025-0001", EPSSScore: &score},
	}}
	res, err := EvaluateSBOMOperation03(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMOperation03_AchievedWhenKEVFlagged(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{vulns: []model.Vulnerability{
		{ID: uuid.New(), CVEID: "CVE-2025-0001", InKEV: true},
	}}
	res, err := EvaluateSBOMOperation03(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMOperation03_NeedsReviewWhenNeither(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{vulns: []model.Vulnerability{{ID: uuid.New(), CVEID: "CVE-2025-0001"}}}
	res, err := EvaluateSBOMOperation03(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestSBOMOperation04_AchievedWhenApprovedDraft(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{vexDrafts: []repository.VEXDraft{{ID: uuid.New(), Decision: "approved"}}}
	res, err := EvaluateSBOMOperation04(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMOperation04_NeedsReviewWhenOnlyPending(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{vexDrafts: []repository.VEXDraft{{ID: uuid.New(), Decision: "pending"}}}
	res, err := EvaluateSBOMOperation04(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestSBOMOperation04_NotAchievedWhenNoDrafts(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateSBOMOperation04(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNotAchieved, res.Status)
}

func TestSBOMOperation05_AchievedWhenPolicyExists(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{policies: []model.LicensePolicy{{ID: uuid.New(), LicenseID: "GPL-3.0"}}}
	res, err := EvaluateSBOMOperation05(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMOperation05_NeedsReviewWhenNoPolicy(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateSBOMOperation05(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestSBOMOperation06_AchievedWhenEOLSummary(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{eolSummary: &model.EOLSummary{TotalComponents: 5, EOL: 1, Active: 4}}
	res, err := EvaluateSBOMOperation06(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMOperation06_NotApplicableWhenNoEOL(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateSBOMOperation06(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNotApplicable, res.Status)
}

func TestSBOMOperation07_AchievedWhenAuditLogsExist(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{auditLogsN: 42}
	res, err := EvaluateSBOMOperation07(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMOperation07_NeedsReviewWhenNoAudit(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateSBOMOperation07(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestSBOMOperation08_AchievedWhenCRAReports(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{craReports: []repository.CRAReport{
		{ID: uuid.New(), ReportType: "early_warning"},
		{ID: uuid.New(), ReportType: "detailed_notification"},
	}}
	res, err := EvaluateSBOMOperation08(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMOperation08_NeedsReviewWhenNoCRA(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateSBOMOperation08(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNeedsReview, res.Status)
}

func TestSBOMOperation09_AchievedWhenRecentSBOM(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{latestSbom: helperSBOM(uuid.New(), "cyclonedx", "1.5", time.Now().Add(-1*24*time.Hour), nil)}
	res, err := EvaluateSBOMOperation09(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMOperation09_NotAchievedWhenStaleSBOM(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{latestSbom: helperSBOM(uuid.New(), "cyclonedx", "1.5", time.Now().Add(-90*24*time.Hour), nil)}
	res, err := EvaluateSBOMOperation09(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNotAchieved, res.Status)
}

func TestSBOMOperation09_NotAchievedWhenNoSBOM(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateSBOMOperation09(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNotAchieved, res.Status)
}

func TestSBOMOperation10_AchievedWhenAuditLogsExist(t *testing.T) {
	tenant, project := helperTenantProject()
	deps := &fakeDeps{auditLogsN: 100}
	res, err := EvaluateSBOMOperation10(context.Background(), deps, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusAchieved, res.Status)
}

func TestSBOMOperation10_NotAchievedWhenEmpty(t *testing.T) {
	tenant, project := helperTenantProject()
	res, err := EvaluateSBOMOperation10(context.Background(), &fakeDeps{}, tenant, project)
	require.NoError(t, err)
	assert.Equal(t, StatusNotAchieved, res.Status)
}

// =============================================================================
// helpers
// =============================================================================

// TestDistinctPurlPrefixes_DedupesAndIgnoresEmpties pins the small
// PURL-parser helper used by env_setup.02 so a regression in the
// prefix extraction is caught independently of the criterion path.
func TestDistinctPurlPrefixes_DedupesAndIgnoresEmpties(t *testing.T) {
	got := distinctPurlPrefixes([]model.Component{
		{Purl: "pkg:npm/react@19.0"},
		{Purl: "pkg:npm/express@4.18"},
		{Purl: "pkg:maven/com.google.guava/guava@32.0"},
		{Purl: ""}, // ignored
		{Purl: "not-a-purl"},
		{Purl: "pkg:golang/github.com/google/uuid@v1.6.0"},
	})
	assert.ElementsMatch(t, []string{"pkg:npm", "pkg:maven", "pkg:golang"}, got)
}

// TestRegistry_AllStatusesAreFromAllowList catches a per-criterion
// typo (e.g. "achived") that the meti_assessments DB CHECK would
// reject only at handler-write time. Asserts every function in the
// registry returns one of the four allow-list values for the
// empty-deps fixture.
func TestRegistry_AllStatusesAreFromAllowList(t *testing.T) {
	tenant, project := helperTenantProject()
	allowed := map[string]struct{}{
		StatusAchieved: {}, StatusNotAchieved: {}, StatusNeedsReview: {}, StatusNotApplicable: {},
	}
	for id, fn := range Registry {
		res, err := fn(context.Background(), &fakeDeps{}, tenant, project)
		require.NoError(t, err, "evaluator %s returned unexpected error", id)
		_, ok := allowed[res.Status]
		assert.True(t, ok, "evaluator %s returned non-allowlist status %q", id, res.Status)
		// Evidence must always be a JSON array.
		var arr []json.RawMessage
		assert.NoError(t, json.Unmarshal(res.Evidence, &arr), "evaluator %s evidence is not a JSON array: %s", id, string(res.Evidence))
	}
}
