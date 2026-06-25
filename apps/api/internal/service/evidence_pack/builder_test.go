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

	b := NewBuilder(vexFake, craFake, projFake)
	res, err := b.Build(context.Background(), BuildInput{
		TenantID:               tenantID,
		ProjectID:              projectID,
		IncludeVEXApproved:     true,
		IncludeCRAApproved:     true,
		IncludeMETIPlaceholder: true,
		Format:                 FormatMarkdown,
		Now:                    now,
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
		"## 3. METI 自己評価 / METI Self-Assessment (placeholder)",
		"(M3 で実装予定)",
		"## Bundle Summary",
		"End of Evidence Pack.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}

	// Repository filters must request decision='approved'.
	if vexFake.gotFilt.Decision != "approved" {
		t.Errorf("vex filter Decision = %q, want approved", vexFake.gotFilt.Decision)
	}
	if craFake.gotFilt.Decision != "approved" {
		t.Errorf("cra filter Decision = %q, want approved", craFake.gotFilt.Decision)
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
	b := NewBuilder(vexFake, craFake, projFake)
	res, err := b.Build(context.Background(), BuildInput{
		TenantID:               tenantID,
		ProjectID:              projectID,
		IncludeVEXApproved:     true,
		IncludeCRAApproved:     true,
		IncludeMETIPlaceholder: true,
		Format:                 FormatMarkdown,
		Now:                    time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC),
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
	if res.VEXApprovedCount != 0 || res.CRAApprovedCount != 0 {
		t.Errorf("counts wrong: vex=%d cra=%d", res.VEXApprovedCount, res.CRAApprovedCount)
	}
}

func TestBuilder_Build_SectionToggles(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	vexFake := &fakeVEXReader{rows: nil}
	craFake := &fakeCRAReader{rows: nil}
	projFake := &fakeProjectReader{project: &model.Project{ID: projectID, Name: "p"}}

	b := NewBuilder(vexFake, craFake, projFake)
	res, err := b.Build(context.Background(), BuildInput{
		TenantID:               tenantID,
		ProjectID:              projectID,
		IncludeVEXApproved:     false,
		IncludeCRAApproved:     false,
		IncludeMETIPlaceholder: false,
		Format:                 FormatMarkdown,
		Now:                    time.Now(),
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
}

func TestBuilder_Build_RejectsMissingTenant(t *testing.T) {
	b := NewBuilder(&fakeVEXReader{}, &fakeCRAReader{}, &fakeProjectReader{})
	_, err := b.Build(context.Background(), BuildInput{
		ProjectID: uuid.New(),
	})
	if err == nil || !strings.Contains(err.Error(), "tenant_id is required") {
		t.Fatalf("want tenant_id-required error, got %v", err)
	}
}

func TestBuilder_Build_RejectsMissingProject(t *testing.T) {
	b := NewBuilder(&fakeVEXReader{}, &fakeCRAReader{}, &fakeProjectReader{})
	_, err := b.Build(context.Background(), BuildInput{
		TenantID: uuid.New(),
	})
	if err == nil || !strings.Contains(err.Error(), "project_id is required") {
		t.Fatalf("want project_id-required error, got %v", err)
	}
}

func TestBuilder_Build_RejectsUnsupportedFormat(t *testing.T) {
	b := NewBuilder(&fakeVEXReader{}, &fakeCRAReader{}, &fakeProjectReader{})
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
	b := NewBuilder(&fakeVEXReader{}, &fakeCRAReader{}, &fakeProjectReader{err: sql.ErrNoRows})
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
	b := NewBuilder(&fakeVEXReader{err: stub}, &fakeCRAReader{}, &fakeProjectReader{project: &model.Project{ID: uuid.New(), Name: "p"}})
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
	b := NewBuilder(&fakeVEXReader{}, &fakeCRAReader{}, projFake)
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
		"":                      "",
		"plain":                 "plain",
		"under_score":           "under\\_score",
		"a*b":                   "a\\*b",
		"`code`":                "\\`code\\`",
		"pipe|sep":              "pipe\\|sep",
		"back\\slash":           "back\\\\slash",
		"all_*_|`_combined":     "all\\_\\*\\_\\|\\`\\_combined",
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
