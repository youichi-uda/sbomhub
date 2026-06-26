package evidence_pack

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/meti"
)

// ----------------------------------------------------------------------------
// In-memory fakes (no Postgres) — mirror the pattern used by
// handler/vex_drafts_test.go and triage/runner_test.go.
// ----------------------------------------------------------------------------

type fakeVEXReader struct {
	rows    []repository.VEXDraft
	err     error
	gotFilt repository.VEXDraftListFilter
}

func (f *fakeVEXReader) ListByProject(_ context.Context, _, _ uuid.UUID, filter repository.VEXDraftListFilter) ([]repository.VEXDraft, error) {
	f.gotFilt = filter
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

type fakeCRAReader struct {
	rows    []repository.CRAReport
	err     error
	gotFilt repository.CRAReportListFilter
}

func (f *fakeCRAReader) ListByProject(_ context.Context, _, _ uuid.UUID, filter repository.CRAReportListFilter) ([]repository.CRAReport, error) {
	f.gotFilt = filter
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

type fakeProjectReader struct {
	project *model.Project
	err     error
}

func (f *fakeProjectReader) GetByTenant(_ context.Context, _, _ uuid.UUID) (*model.Project, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.project, nil
}

// fakeMETIReader stubs repository.MetiAssessmentsRepository.ListByProject
// for the M3-6 builder tests. Captures the filter so the test can pin
// the limit-clamp behaviour.
type fakeMETIReader struct {
	rows    []repository.MetiAssessment
	err     error
	gotFilt repository.MetiAssessmentListFilter
}

func (f *fakeMETIReader) ListByProject(_ context.Context, _, _ uuid.UUID, filter repository.MetiAssessmentListFilter) ([]repository.MetiAssessment, error) {
	f.gotFilt = filter
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

// fakeCatalog stubs the M3-3 catalog. byID is consulted by
// GetCriterion; phases is the ordered phase list (defaults to the
// real catalog's chronological ordering env_setup → sbom_creation →
// sbom_operation when nil).
type fakeCatalog struct {
	byID   map[string]meti.Criterion
	phases []meti.Phase
}

func (f *fakeCatalog) GetCriterion(id string) (*meti.Criterion, bool) {
	c, ok := f.byID[id]
	if !ok {
		return nil, false
	}
	cp := c
	return &cp, true
}

func (f *fakeCatalog) Phases() []meti.Phase {
	if f.phases != nil {
		return f.phases
	}
	return []meti.Phase{meti.PhaseEnvSetup, meti.PhaseSBOMCreation, meti.PhaseSBOMOperation}
}

// newFakeCatalogForTest returns a catalog populated with the
// criteria used across the M3-6 builder tests. Centralised so the
// catalog wiring is consistent between tests.
func newFakeCatalogForTest() *fakeCatalog {
	return &fakeCatalog{byID: map[string]meti.Criterion{
		"meti.env_setup.01": {
			ID:            "meti.env_setup.01",
			Phase:         meti.PhaseEnvSetup,
			TitleJA:       "SBOM ポリシー策定",
			TitleEN:       "Define SBOM policy",
			DescriptionJA: "...",
			DescriptionEN: "...",
			EvaluatorHint: "...",
		},
		"meti.sbom_creation.01": {
			ID:            "meti.sbom_creation.01",
			Phase:         meti.PhaseSBOMCreation,
			TitleJA:       "SBOM 生成ツール導入",
			TitleEN:       "Adopt SBOM generation tooling",
			DescriptionJA: "...",
			DescriptionEN: "...",
			EvaluatorHint: "...",
		},
		"meti.sbom_operation.01": {
			ID:            "meti.sbom_operation.01",
			Phase:         meti.PhaseSBOMOperation,
			TitleJA:       "脆弱性マッチング運用",
			TitleEN:       "Operate vulnerability matching",
			DescriptionJA: "...",
			DescriptionEN: "...",
			EvaluatorHint: "...",
		},
	}}
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

func TestBuilder_Build_HappyPath(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	approver := uuid.New()
	now := time.Date(2026, 6, 25, 12, 30, 45, 0, time.UTC)
	approvedAt := now.Add(-1 * time.Hour)

	conf := 0.92
	vexRow := repository.VEXDraft{
		ID:              uuid.New(),
		TenantID:        tenantID,
		ProjectID:       projectID,
		ComponentID:     uuid.New(),
		VulnerabilityID: uuid.New(),
		CVEID:           "CVE-2026-0001",
		State:           "not_affected",
		Justification:   "code_not_reachable",
		Detail:          "The vulnerable function is not reachable from any entrypoint.",
		Confidence:      &conf,
		Provider:        "openai",
		Model:           "gpt-5",
		PromptHash:      "abc123",
		ResponseHash:    "def456",
		Evidence:        json.RawMessage(`[{"kind":"reachability","ref":"reach_id_1"}]`),
		Decision:        "approved",
		DecisionBy:      &approver,
		DecisionAt:      &approvedAt,
		DecisionNote:    "verified by reviewer",
		CreatedAt:       now.Add(-2 * time.Hour),
		UpdatedAt:       approvedAt,
	}
	craRow := repository.CRAReport{
		ID:               uuid.New(),
		TenantID:         tenantID,
		ProjectID:        projectID,
		VulnerabilityID:  uuid.New(),
		CVEID:            "CVE-2026-0002",
		ReportType:       "early_warning",
		Lang:             "ja",
		State:            "approved",
		DraftText:        "## 24時間早期警告\n\n対象 CVE: CVE-2026-0002\n",
		Provider:         "anthropic",
		Model:            "claude-opus-4-7",
		PromptHash:       "ph",
		ResponseHash:     "rh",
		Evidence:         json.RawMessage(`[{"kind":"vex","ref":"draft_id_1"}]`),
		Decision:         "approved",
		DecisionBy:       &approver,
		DecisionAt:       &approvedAt,
		SourceVEXDraftID: &vexRow.ID,
		CreatedAt:        now.Add(-2 * time.Hour),
		UpdatedAt:        approvedAt,
	}

	vexFake := &fakeVEXReader{rows: []repository.VEXDraft{vexRow}}
	craFake := &fakeCRAReader{rows: []repository.CRAReport{craRow}}
	projFake := &fakeProjectReader{project: &model.Project{
		ID:          projectID,
		Name:        "demo-product",
		Description: "Demo IoT firmware",
	}}
	metiFake := &fakeMETIReader{rows: []repository.MetiAssessment{
		{
			ID:                uuid.New(),
			TenantID:          tenantID,
			ProjectID:         projectID,
			CriterionID:       "meti.env_setup.01",
			CriterionPhase:    string(meti.PhaseEnvSetup),
			Status:            "achieved",
			Evidence:          json.RawMessage(`[{"kind":"settings","ref":"sbom_policy"}]`),
			ImprovementAction: "",
			CreatedAt:         now,
			UpdatedAt:         now,
		},
	}}

	b := NewBuilder(vexFake, craFake, projFake, metiFake, newFakeCatalogForTest())
	res, err := b.Build(context.Background(), BuildInput{
		TenantID:              tenantID,
		ProjectID:             projectID,
		IncludeVEXApproved:    true,
		IncludeCRAApproved:    true,
		IncludeMETIAssessment: true,
		Format:                FormatMarkdown,
		Now:                   now,
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if res == nil {
		t.Fatal("Build returned nil result")
	}
	if res.Format != FormatMarkdown {
		t.Errorf("Format = %q, want %q", res.Format, FormatMarkdown)
	}
	if res.VEXApprovedCount != 1 {
		t.Errorf("VEXApprovedCount = %d, want 1", res.VEXApprovedCount)
	}
	if res.CRAApprovedCount != 1 {
		t.Errorf("CRAApprovedCount = %d, want 1", res.CRAApprovedCount)
	}
	if !res.METIIncluded {
		t.Error("METIIncluded = false, want true")
	}
	if res.METIRowCount != 1 {
		t.Errorf("METIRowCount = %d, want 1", res.METIRowCount)
	}
	if res.METIAchievedCount != 1 {
		t.Errorf("METIAchievedCount = %d, want 1", res.METIAchievedCount)
	}
	if !res.BuiltAt.Equal(now) {
		t.Errorf("BuiltAt = %v, want %v", res.BuiltAt, now)
	}

	// Filename must include the short project id + timestamp.
	if !strings.HasPrefix(res.Filename, "evidence-pack-") || !strings.HasSuffix(res.Filename, ".md") {
		t.Errorf("Filename = %q, want evidence-pack-*.md", res.Filename)
	}
	if !strings.Contains(res.Filename, "20260625-123045") {
		t.Errorf("Filename = %q, want timestamp 20260625-123045", res.Filename)
	}

	body := string(res.ContentBytes)

	// Header presence.
	for _, want := range []string{
		"# SBOMHub AI Compliance Evidence Pack",
		"demo-product",
		"Demo IoT firmware",
		"## 法的免責 / Legal Disclaimer",
		"PRODUCT_REBOOT_PLAN.md §8.5",
		"## Table of Contents",
		"## 1. Approved VEX Statements",
		"CVE-2026-0001",
		"not\\_affected", // escapeMD escapes underscore
		"code\\_not\\_reachable",
		"## 2. Approved CRA Reports",
		"CVE-2026-0002",
		"early\\_warning",
		"## 3. METI 自己評価 / METI Self-Assessment",
		// Phase sub-header (catalog Phases() iteration order).
		"### 3.1 Phase: env\\_setup",
		// Table header for the per-phase Markdown table.
		"| Criterion | Title (JA / EN) | Status | Evidence | Improvement Action |",
		// Criterion row content.
		"`meti.env\\_setup.01`",
		"SBOM ポリシー策定",
		"Define SBOM policy",
		"`achieved`",
		// Evidence summary (1 item, kind=settings).
		"1 items: settings",
		// Improvement actions subsection.
		"### 3.Z Improvement Actions",
		"_No outstanding improvement actions",
		"## Bundle Summary",
		"included (1 criteria; 1 achieved)",
		"End of Evidence Pack.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}

	// Repository filters must request decision='approved' for VEX/CRA.
	if vexFake.gotFilt.Decision != "approved" {
		t.Errorf("vex filter Decision = %q, want approved", vexFake.gotFilt.Decision)
	}
	if craFake.gotFilt.Decision != "approved" {
		t.Errorf("cra filter Decision = %q, want approved", craFake.gotFilt.Decision)
	}
	// METI filter must request the repository cap so the builder is
	// the place a future paging change has to happen.
	if metiFake.gotFilt.Limit != 500 {
		t.Errorf("meti filter Limit = %d, want 500", metiFake.gotFilt.Limit)
	}
}

func TestBuilder_Build_EmptySections(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()

	vexFake := &fakeVEXReader{rows: nil}
	craFake := &fakeCRAReader{rows: nil}
	projFake := &fakeProjectReader{project: &model.Project{
		ID:   projectID,
		Name: "empty-product",
	}}
	metiFake := &fakeMETIReader{rows: nil}
	b := NewBuilder(vexFake, craFake, projFake, metiFake, newFakeCatalogForTest())
	res, err := b.Build(context.Background(), BuildInput{
		TenantID:              tenantID,
		ProjectID:             projectID,
		IncludeVEXApproved:    true,
		IncludeCRAApproved:    true,
		IncludeMETIAssessment: true,
		Format:                FormatMarkdown,
		Now:                   time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	body := string(res.ContentBytes)
	if !strings.Contains(body, "_No approved VEX drafts found for this project._") {
		t.Errorf("body missing VEX empty marker; body=%q", body)
	}
	if !strings.Contains(body, "_No approved CRA reports found for this project._") {
		t.Errorf("body missing CRA empty marker")
	}
	if !strings.Contains(body, "_No METI self-assessment rows found for this project.") {
		t.Errorf("body missing METI empty marker")
	}
	if res.VEXApprovedCount != 0 || res.CRAApprovedCount != 0 || res.METIRowCount != 0 {
		t.Errorf("counts wrong: vex=%d cra=%d meti=%d", res.VEXApprovedCount, res.CRAApprovedCount, res.METIRowCount)
	}
}

func TestBuilder_Build_SectionToggles(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	vexFake := &fakeVEXReader{rows: nil}
	craFake := &fakeCRAReader{rows: nil}
	projFake := &fakeProjectReader{project: &model.Project{ID: projectID, Name: "p"}}

	b := NewBuilder(vexFake, craFake, projFake, &fakeMETIReader{}, newFakeCatalogForTest())
	res, err := b.Build(context.Background(), BuildInput{
		TenantID:              tenantID,
		ProjectID:             projectID,
		IncludeVEXApproved:    false,
		IncludeCRAApproved:    false,
		IncludeMETIAssessment: false,
		Format:                FormatMarkdown,
		Now:                   time.Now(),
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	body := string(res.ContentBytes)
	for _, unwanted := range []string{
		"## 1. Approved VEX Statements",
		"## 2. Approved CRA Reports",
		"## 3. METI",
	} {
		if strings.Contains(body, unwanted) {
			t.Errorf("body contains disabled section %q", unwanted)
		}
	}
	if !strings.Contains(body, "omitted from this bundle") {
		t.Errorf("body missing METI omitted footer line; body=%q", body)
	}
}

func TestBuilder_Build_RejectsMissingTenant(t *testing.T) {
	b := NewBuilder(&fakeVEXReader{}, &fakeCRAReader{}, &fakeProjectReader{}, &fakeMETIReader{}, newFakeCatalogForTest())
	_, err := b.Build(context.Background(), BuildInput{
		ProjectID: uuid.New(),
	})
	if err == nil || !strings.Contains(err.Error(), "tenant_id is required") {
		t.Fatalf("want tenant_id-required error, got %v", err)
	}
}

func TestBuilder_Build_RejectsMissingProject(t *testing.T) {
	b := NewBuilder(&fakeVEXReader{}, &fakeCRAReader{}, &fakeProjectReader{}, &fakeMETIReader{}, newFakeCatalogForTest())
	_, err := b.Build(context.Background(), BuildInput{
		TenantID: uuid.New(),
	})
	if err == nil || !strings.Contains(err.Error(), "project_id is required") {
		t.Fatalf("want project_id-required error, got %v", err)
	}
}

func TestBuilder_Build_RejectsUnsupportedFormat(t *testing.T) {
	b := NewBuilder(&fakeVEXReader{}, &fakeCRAReader{}, &fakeProjectReader{}, &fakeMETIReader{}, newFakeCatalogForTest())
	_, err := b.Build(context.Background(), BuildInput{
		TenantID:  uuid.New(),
		ProjectID: uuid.New(),
		Format:    "pdf",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Fatalf("want unsupported-format error, got %v", err)
	}
}

func TestBuilder_Build_ProjectNotFound(t *testing.T) {
	b := NewBuilder(&fakeVEXReader{}, &fakeCRAReader{}, &fakeProjectReader{err: sql.ErrNoRows}, &fakeMETIReader{}, newFakeCatalogForTest())
	_, err := b.Build(context.Background(), BuildInput{
		TenantID:  uuid.New(),
		ProjectID: uuid.New(),
		Format:    FormatMarkdown,
	})
	if err == nil {
		t.Fatal("want error for missing project, got nil")
	}
	// errors.Is must succeed so the handler can map to 404.
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("err = %v, want errors.Is(_, sql.ErrNoRows)", err)
	}
}

func TestBuilder_Build_RepositoryError(t *testing.T) {
	stub := errors.New("db boom")
	b := NewBuilder(
		&fakeVEXReader{err: stub},
		&fakeCRAReader{},
		&fakeProjectReader{project: &model.Project{ID: uuid.New(), Name: "p"}},
		&fakeMETIReader{},
		newFakeCatalogForTest(),
	)
	_, err := b.Build(context.Background(), BuildInput{
		TenantID:           uuid.New(),
		ProjectID:          uuid.New(),
		IncludeVEXApproved: true,
		Format:             FormatMarkdown,
	})
	if err == nil || !errors.Is(err, stub) {
		t.Fatalf("want wrapped repository error, got %v", err)
	}
}

func TestBuilder_Build_DefaultsNowAndFormat(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	projFake := &fakeProjectReader{project: &model.Project{ID: projectID, Name: "p"}}
	b := NewBuilder(&fakeVEXReader{}, &fakeCRAReader{}, projFake, &fakeMETIReader{}, newFakeCatalogForTest())
	before := time.Now().UTC().Add(-time.Second)
	res, err := b.Build(context.Background(), BuildInput{
		TenantID:  tenantID,
		ProjectID: projectID,
		// Format intentionally empty — should default to markdown.
		// Now intentionally zero — should default to time.Now().UTC().
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if res.Format != FormatMarkdown {
		t.Errorf("Format = %q, want default markdown", res.Format)
	}
	after := time.Now().UTC().Add(time.Second)
	if res.BuiltAt.Before(before) || res.BuiltAt.After(after) {
		t.Errorf("BuiltAt = %v not within [%v, %v]", res.BuiltAt, before, after)
	}
}

func TestBuildFilename(t *testing.T) {
	id := uuid.MustParse("11112222-3333-4444-5555-666677778888")
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	got := buildFilename(id, now)
	const want = "evidence-pack-11112222-20260102-030405.md"
	if got != want {
		t.Errorf("buildFilename = %q, want %q", got, want)
	}
}

func TestEscapeMD(t *testing.T) {
	cases := map[string]string{
		"":                  "",
		"plain":             "plain",
		"under_score":       "under\\_score",
		"a*b":               "a\\*b",
		"`code`":            "\\`code\\`",
		"pipe|sep":          "pipe\\|sep",
		"back\\slash":       "back\\\\slash",
		"all_*_|`_combined": "all\\_\\*\\_\\|\\`\\_combined",
	}
	for in, want := range cases {
		got := escapeMD(in)
		if got != want {
			t.Errorf("escapeMD(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuilder_Build_OrdersRowsDeterministically(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mid := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	newt := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	mk := func(cve string, created time.Time) repository.VEXDraft {
		return repository.VEXDraft{
			ID:              uuid.New(),
			TenantID:        tenantID,
			ProjectID:       projectID,
			ComponentID:     uuid.New(),
			VulnerabilityID: uuid.New(),
			CVEID:           cve,
			State:           "not_affected",
			Evidence:        json.RawMessage(`[{"kind":"x","ref":"y"}]`),
			Decision:        "approved",
			CreatedAt:       created,
			UpdatedAt:       created,
		}
	}

	// Insert out of order.
	rows := []repository.VEXDraft{mk("CVE-OLD", old), mk("CVE-NEW", newt), mk("CVE-MID", mid)}
	b := NewBuilder(
		&fakeVEXReader{rows: rows},
		&fakeCRAReader{},
		&fakeProjectReader{project: &model.Project{ID: projectID, Name: "p"}},
		&fakeMETIReader{},
		newFakeCatalogForTest(),
	)
	res, err := b.Build(context.Background(), BuildInput{
		TenantID:           tenantID,
		ProjectID:          projectID,
		IncludeVEXApproved: true,
		Format:             FormatMarkdown,
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	body := string(res.ContentBytes)
	// newest first → CVE-NEW must appear before CVE-MID before CVE-OLD.
	iNew := strings.Index(body, "CVE-NEW")
	iMid := strings.Index(body, "CVE-MID")
	iOld := strings.Index(body, "CVE-OLD")
	if !(iNew >= 0 && iMid >= 0 && iOld >= 0 && iNew < iMid && iMid < iOld) {
		t.Errorf("ordering wrong: NEW=%d MID=%d OLD=%d", iNew, iMid, iOld)
	}
}

// ----------------------------------------------------------------------------
// M3-6 (issue #42) — METI section regression tests
// ----------------------------------------------------------------------------

// TestBuilder_Build_METISection_PhaseGroupingAndOrder pins the
// per-phase grouping + the chronological phase iteration order
// (env_setup → sbom_creation → sbom_operation) even when the input
// rows arrive in arbitrary order.
func TestBuilder_Build_METISection_PhaseGroupingAndOrder(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	now := time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC)

	mk := func(id string, phase meti.Phase, status string) repository.MetiAssessment {
		return repository.MetiAssessment{
			ID:             uuid.New(),
			TenantID:       tenantID,
			ProjectID:      projectID,
			CriterionID:    id,
			CriterionPhase: string(phase),
			Status:         status,
			Evidence:       json.RawMessage(`[]`),
			CreatedAt:      now,
			UpdatedAt:      now,
		}
	}
	// Out-of-order: operation, env, creation.
	rows := []repository.MetiAssessment{
		mk("meti.sbom_operation.01", meti.PhaseSBOMOperation, "achieved"),
		mk("meti.env_setup.01", meti.PhaseEnvSetup, "achieved"),
		mk("meti.sbom_creation.01", meti.PhaseSBOMCreation, "needs_review"),
	}

	b := NewBuilder(
		&fakeVEXReader{}, &fakeCRAReader{},
		&fakeProjectReader{project: &model.Project{ID: projectID, Name: "p"}},
		&fakeMETIReader{rows: rows},
		newFakeCatalogForTest(),
	)
	res, err := b.Build(context.Background(), BuildInput{
		TenantID:              tenantID,
		ProjectID:             projectID,
		IncludeMETIAssessment: true,
		Format:                FormatMarkdown,
		Now:                   now,
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	body := string(res.ContentBytes)

	// Phase headers in chronological order.
	iEnv := strings.Index(body, "### 3.1 Phase: env\\_setup")
	iCre := strings.Index(body, "### 3.2 Phase: sbom\\_creation")
	iOpe := strings.Index(body, "### 3.3 Phase: sbom\\_operation")
	if !(iEnv >= 0 && iCre >= 0 && iOpe >= 0 && iEnv < iCre && iCre < iOpe) {
		t.Errorf("phase order wrong: env=%d cre=%d ope=%d (body=...%s...)", iEnv, iCre, iOpe, body[:min(len(body), 400)])
	}

	// achieved-count and totals.
	if res.METIRowCount != 3 {
		t.Errorf("METIRowCount = %d, want 3", res.METIRowCount)
	}
	if res.METIAchievedCount != 2 {
		t.Errorf("METIAchievedCount = %d, want 2", res.METIAchievedCount)
	}
}

// TestBuilder_Build_METISection_OverridePrecedence pins that the
// operator override beats the evaluator status in the Status cell,
// the achieved-count, and the Improvement Actions subsection.
func TestBuilder_Build_METISection_OverridePrecedence(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	overrider := uuid.New()
	overrideAt := time.Date(2026, 6, 25, 1, 0, 0, 0, time.UTC)

	// Evaluator says needs_review; operator overrides to achieved.
	overridden := repository.MetiAssessment{
		ID:             uuid.New(),
		TenantID:       tenantID,
		ProjectID:      projectID,
		CriterionID:    "meti.env_setup.01",
		CriterionPhase: string(meti.PhaseEnvSetup),
		Status:         "needs_review",
		OverrideStatus: "achieved",
		OverrideBy:     &overrider,
		OverrideAt:     &overrideAt,
		OverrideNote:   "manually verified by QA",
		Evidence:       json.RawMessage(`[{"kind":"settings","ref":"sbom_policy"}]`),
		CreatedAt:      overrideAt,
		UpdatedAt:      overrideAt,
	}
	// Evaluator says achieved; no override.
	clean := repository.MetiAssessment{
		ID:             uuid.New(),
		TenantID:       tenantID,
		ProjectID:      projectID,
		CriterionID:    "meti.sbom_creation.01",
		CriterionPhase: string(meti.PhaseSBOMCreation),
		Status:         "achieved",
		Evidence:       json.RawMessage(`[{"kind":"sbom","ref":"sbom_count"}]`),
		CreatedAt:      overrideAt,
		UpdatedAt:      overrideAt,
	}
	// Evaluator says not_achieved; no override; carries an operator
	// improvement-action plan.
	gap := repository.MetiAssessment{
		ID:                uuid.New(),
		TenantID:          tenantID,
		ProjectID:         projectID,
		CriterionID:       "meti.sbom_operation.01",
		CriterionPhase:    string(meti.PhaseSBOMOperation),
		Status:            "not_achieved",
		Evidence:          json.RawMessage(`[]`),
		ImprovementAction: "Enable automated vulnerability matching in CI",
		CreatedAt:         overrideAt,
		UpdatedAt:         overrideAt,
	}

	b := NewBuilder(
		&fakeVEXReader{}, &fakeCRAReader{},
		&fakeProjectReader{project: &model.Project{ID: projectID, Name: "p"}},
		&fakeMETIReader{rows: []repository.MetiAssessment{overridden, clean, gap}},
		newFakeCatalogForTest(),
	)
	res, err := b.Build(context.Background(), BuildInput{
		TenantID:              tenantID,
		ProjectID:             projectID,
		IncludeMETIAssessment: true,
		Format:                FormatMarkdown,
		Now:                   overrideAt,
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	body := string(res.ContentBytes)

	// Status cell renders override + evaluator-original side by side.
	if !strings.Contains(body, "`achieved` (override; evaluator: `needs\\_review`)") {
		t.Errorf("body missing override status cell; body=%q", body)
	}

	// Achieved count uses effective status: overridden(achieved=1) +
	// clean(achieved=1) + gap(not_achieved=0) = 2.
	if res.METIAchievedCount != 2 {
		t.Errorf("METIAchievedCount = %d, want 2", res.METIAchievedCount)
	}

	// Improvement Actions: gap row appears, clean + overridden do not.
	improveStart := strings.Index(body, "### 3.Z Improvement Actions")
	if improveStart < 0 {
		t.Fatal("Improvement Actions section missing")
	}
	tail := body[improveStart:]
	if !strings.Contains(tail, "`meti.sbom\\_operation.01`") {
		t.Errorf("Improvement Actions missing gap row; tail=%q", tail)
	}
	if !strings.Contains(tail, "Enable automated vulnerability matching in CI") {
		t.Errorf("Improvement Actions missing operator plan text")
	}
	if strings.Contains(tail, "`meti.env\\_setup.01`") {
		t.Errorf("Improvement Actions should NOT list overridden-to-achieved row")
	}
	if strings.Contains(tail, "`meti.sbom\\_creation.01`") {
		t.Errorf("Improvement Actions should NOT list a row whose evaluator status is achieved")
	}
}

// TestBuilder_Build_METISection_UnknownCriterion exercises the
// stale-catalog branch: a meti_assessments row whose criterion_id is
// not in the catalog still renders (with a fallback title) so a
// catalog rotation cannot silently drop attested rows.
func TestBuilder_Build_METISection_UnknownCriterion(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()

	stale := repository.MetiAssessment{
		ID:             uuid.New(),
		TenantID:       tenantID,
		ProjectID:      projectID,
		CriterionID:    "meti.env_setup.99-retired",
		CriterionPhase: string(meti.PhaseEnvSetup),
		Status:         "achieved",
		Evidence:       json.RawMessage(`[]`),
	}

	b := NewBuilder(
		&fakeVEXReader{}, &fakeCRAReader{},
		&fakeProjectReader{project: &model.Project{ID: projectID, Name: "p"}},
		&fakeMETIReader{rows: []repository.MetiAssessment{stale}},
		newFakeCatalogForTest(), // does not contain the .99-retired id
	)
	res, err := b.Build(context.Background(), BuildInput{
		TenantID:              tenantID,
		ProjectID:             projectID,
		IncludeMETIAssessment: true,
		Format:                FormatMarkdown,
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	body := string(res.ContentBytes)
	if !strings.Contains(body, "`meti.env\\_setup.99-retired`") {
		t.Errorf("body missing stale criterion row")
	}
	if !strings.Contains(body, "(unknown criterion)") {
		t.Errorf("body missing unknown-criterion fallback label")
	}
}

// TestBuilder_Build_METISection_RejectsNilDeps pins that requesting
// the METI section without the reader/catalog wired surfaces a clear
// configuration error rather than silently producing an empty
// section.
func TestBuilder_Build_METISection_RejectsNilDeps(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	b := NewBuilder(
		&fakeVEXReader{}, &fakeCRAReader{},
		&fakeProjectReader{project: &model.Project{ID: projectID, Name: "p"}},
		nil, nil,
	)
	_, err := b.Build(context.Background(), BuildInput{
		TenantID:              tenantID,
		ProjectID:             projectID,
		IncludeMETIAssessment: true,
		Format:                FormatMarkdown,
	})
	if err == nil || !strings.Contains(err.Error(), "reader/catalog not wired") {
		t.Fatalf("want configuration error, got %v", err)
	}
}

// TestBuilder_Build_METISection_RepositoryError pins that a
// meti_assessments repo failure surfaces wrapped through Build (the
// handler maps it to 500).
func TestBuilder_Build_METISection_RepositoryError(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	stub := errors.New("meti db boom")
	b := NewBuilder(
		&fakeVEXReader{}, &fakeCRAReader{},
		&fakeProjectReader{project: &model.Project{ID: projectID, Name: "p"}},
		&fakeMETIReader{err: stub},
		newFakeCatalogForTest(),
	)
	_, err := b.Build(context.Background(), BuildInput{
		TenantID:              tenantID,
		ProjectID:             projectID,
		IncludeMETIAssessment: true,
		Format:                FormatMarkdown,
	})
	if err == nil || !errors.Is(err, stub) {
		t.Fatalf("want wrapped meti repository error, got %v", err)
	}
}

// TestBuilder_Build_METISection_DeterministicBytes pins that two
// builds with identical inputs produce byte-identical output (the
// audit-friendliness invariant the rest of the bundle already
// satisfies — extending it to the METI section).
func TestBuilder_Build_METISection_DeterministicBytes(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	now := time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC)

	rows := []repository.MetiAssessment{
		{
			ID:             uuid.New(),
			TenantID:       tenantID,
			ProjectID:      projectID,
			CriterionID:    "meti.sbom_creation.01",
			CriterionPhase: string(meti.PhaseSBOMCreation),
			Status:         "achieved",
			Evidence:       json.RawMessage(`[{"kind":"sbom","ref":"r1"},{"kind":"settings","ref":"r2"}]`),
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		{
			ID:             uuid.New(),
			TenantID:       tenantID,
			ProjectID:      projectID,
			CriterionID:    "meti.env_setup.01",
			CriterionPhase: string(meti.PhaseEnvSetup),
			Status:         "achieved",
			Evidence:       json.RawMessage(`[{"kind":"settings","ref":"r3"}]`),
			CreatedAt:      now,
			UpdatedAt:      now,
		},
	}

	build := func() []byte {
		b := NewBuilder(
			&fakeVEXReader{}, &fakeCRAReader{},
			&fakeProjectReader{project: &model.Project{ID: projectID, Name: "p"}},
			&fakeMETIReader{rows: append([]repository.MetiAssessment(nil), rows...)},
			newFakeCatalogForTest(),
		)
		res, err := b.Build(context.Background(), BuildInput{
			TenantID:              tenantID,
			ProjectID:             projectID,
			IncludeMETIAssessment: true,
			Format:                FormatMarkdown,
			Now:                   now,
		})
		if err != nil {
			t.Fatalf("Build returned error: %v", err)
		}
		return res.ContentBytes
	}
	a := build()
	b := build()
	if string(a) != string(b) {
		t.Errorf("Build output not deterministic (METI section bytes differ)")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
