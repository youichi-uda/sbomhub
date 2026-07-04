package evidence_pack

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/meti"
)

// ----------------------------------------------------------------------------
// F405 / M31 (#140) — zip render target tests.
// ----------------------------------------------------------------------------

// fakeVEXExporter returns fixed bytes so tests that only care about the
// presence/plumbing of vex.cdx.json stay simple. The determinism of the
// timestamp path (F408) is exercised separately by clockVEXExporter, which
// stamps the ts the builder passes — the real exporter
// (service.VEXService.ExportCycloneDXVEXAt) does the same with the pack's
// BuildInput.Now, so the bundled vex.cdx.json is byte-reproducible.
type fakeVEXExporter struct {
	data       []byte
	err        error
	calls      int
	gotProject uuid.UUID
	gotTS      time.Time
}

func (f *fakeVEXExporter) ExportCycloneDXVEXAt(_ context.Context, projectID uuid.UUID, ts time.Time) ([]byte, error) {
	f.calls++
	f.gotProject = projectID
	f.gotTS = ts
	if f.err != nil {
		return nil, f.err
	}
	return f.data, nil
}

// unzip reads a zip archive into a path->bytes map.
func unzip(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		out[f.Name] = b
	}
	return out
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// zipFixture builds a Builder + fakes covering all sections, including a
// deliberate CRA (report_type, lang) collision to exercise deterministic
// disambiguation.
func zipFixture(t *testing.T) (*Builder, *fakeVEXExporter, uuid.UUID, uuid.UUID, time.Time) {
	t.Helper()
	tenantID := uuid.New()
	projectID := uuid.New()
	now := time.Date(2026, 7, 4, 9, 8, 7, 0, time.UTC)
	approver := uuid.New()
	approvedAt := now.Add(-time.Hour)
	conf := 0.91

	vexRow := repository.VEXDraft{
		ID:              uuid.New(),
		TenantID:        tenantID,
		ProjectID:       projectID,
		ComponentID:     uuid.New(),
		VulnerabilityID: uuid.New(),
		CVEID:           "CVE-2026-1000",
		State:           "not_affected",
		Justification:   "code_not_reachable",
		Detail:          "not reachable",
		Confidence:      &conf,
		Provider:        "openai",
		Model:           "gpt-5",
		Evidence:        json.RawMessage(`[{"kind":"reachability","ref":"r1"}]`),
		Decision:        "approved",
		DecisionBy:      &approver,
		DecisionAt:      &approvedAt,
		CreatedAt:       now.Add(-2 * time.Hour),
		UpdatedAt:       approvedAt,
	}

	mkCRA := func(cve, rtype, lang, text string, created time.Time) repository.CRAReport {
		return repository.CRAReport{
			ID:              uuid.New(),
			TenantID:        tenantID,
			ProjectID:       projectID,
			VulnerabilityID: uuid.New(),
			CVEID:           cve,
			ReportType:      rtype,
			Lang:            lang,
			State:           "approved",
			DraftText:       text,
			Provider:        "anthropic",
			Model:           "claude-opus-4-7",
			Evidence:        json.RawMessage(`[{"kind":"vex","ref":"d1"}]`),
			Decision:        "approved",
			DecisionBy:      &approver,
			DecisionAt:      &approvedAt,
			CreatedAt:       created,
			UpdatedAt:       created,
		}
	}
	craRows := []repository.CRAReport{
		mkCRA("CVE-2026-1000", "early_warning", "ja", "## 24h EW A\n", now.Add(-3*time.Hour)),
		mkCRA("CVE-2026-1000", "final_report", "en", "## Final EN\n", now.Add(-2*time.Hour)),
		// Collision on (early_warning, ja): must NOT clobber the first.
		mkCRA("CVE-2026-1001", "early_warning", "ja", "## 24h EW B\n", now.Add(-1*time.Hour)),
	}

	metiRows := []repository.MetiAssessment{
		{
			ID:             uuid.New(),
			TenantID:       tenantID,
			ProjectID:      projectID,
			CriterionID:    "meti.env_setup.01",
			CriterionPhase: string(meti.PhaseEnvSetup),
			Status:         "needs_review",
			OverrideStatus: "achieved",
			Evidence:       json.RawMessage(`[{"kind":"settings","ref":"sbom_policy"}]`),
			CreatedAt:      now,
			UpdatedAt:      now,
		},
		{
			ID:             uuid.New(),
			TenantID:       tenantID,
			ProjectID:      projectID,
			CriterionID:    "meti.sbom_creation.01",
			CriterionPhase: string(meti.PhaseSBOMCreation),
			Status:         "achieved",
			Evidence:       json.RawMessage(`[{"kind":"sbom","ref":"sbom_count"}]`),
			CreatedAt:      now,
			UpdatedAt:      now,
		},
	}

	b := NewBuilder(
		&fakeVEXReader{rows: []repository.VEXDraft{vexRow}},
		&fakeCRAReader{rows: craRows},
		&fakeProjectReader{project: &model.Project{ID: projectID, Name: "zip-demo", Description: "d"}},
		&fakeMETIReader{rows: metiRows},
		newFakeCatalogForTest(),
	)
	exporter := &fakeVEXExporter{data: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`)}
	b.WithVEXExporter(exporter)
	return b, exporter, tenantID, projectID, now
}

func fullZipInput(tenantID, projectID uuid.UUID, now time.Time) BuildInput {
	return BuildInput{
		TenantID:              tenantID,
		ProjectID:             projectID,
		IncludeVEXApproved:    true,
		IncludeCRAApproved:    true,
		IncludeMETIAssessment: true,
		Format:                FormatZip,
		Now:                   now,
	}
}

func TestBuilder_BuildZip_Contents(t *testing.T) {
	b, exporter, tenantID, projectID, now := zipFixture(t)

	// Markdown build (same input, markdown format) to assert report.md is
	// the verbatim Markdown output.
	mdIn := fullZipInput(tenantID, projectID, now)
	mdIn.Format = FormatMarkdown
	mdRes, err := b.Build(context.Background(), mdIn)
	if err != nil {
		t.Fatalf("markdown Build error: %v", err)
	}

	res, err := b.Build(context.Background(), fullZipInput(tenantID, projectID, now))
	if err != nil {
		t.Fatalf("zip Build error: %v", err)
	}
	if res.Format != FormatZip {
		t.Errorf("Format = %q, want %q", res.Format, FormatZip)
	}
	if !bytes.HasPrefix([]byte(res.Filename), []byte("evidence-pack-")) || !bytes.HasSuffix([]byte(res.Filename), []byte(".zip")) {
		t.Errorf("Filename = %q, want evidence-pack-*.zip", res.Filename)
	}
	if res.VEXApprovedCount != 1 || res.CRAApprovedCount != 3 || res.METIRowCount != 2 {
		t.Errorf("counts vex=%d cra=%d meti=%d, want 1/3/2", res.VEXApprovedCount, res.CRAApprovedCount, res.METIRowCount)
	}
	// override wins → env_setup achieved + creation achieved = 2.
	if res.METIAchievedCount != 2 {
		t.Errorf("METIAchievedCount = %d, want 2", res.METIAchievedCount)
	}

	files := unzip(t, res.ContentBytes)

	wantPaths := []string{
		"cra/early_warning.ja.2.md",
		"cra/early_warning.ja.md",
		"cra/final_report.en.md",
		"manifest.json",
		"meti-assessment.json",
		"report.md",
		"vex.cdx.json",
	}
	got := sortedKeys(files)
	if len(got) != len(wantPaths) {
		t.Fatalf("zip entries = %v, want %v", got, wantPaths)
	}
	for i := range wantPaths {
		if got[i] != wantPaths[i] {
			t.Errorf("zip entry[%d] = %q, want %q (all: %v)", i, got[i], wantPaths[i], got)
		}
	}

	// report.md == verbatim Markdown output.
	if !bytes.Equal(files["report.md"], mdRes.ContentBytes) {
		t.Errorf("report.md is not the verbatim Markdown output")
	}
	// vex.cdx.json == exporter bytes; exporter called once with projectID.
	if !bytes.Equal(files["vex.cdx.json"], exporter.data) {
		t.Errorf("vex.cdx.json = %q, want exporter data", files["vex.cdx.json"])
	}
	if exporter.calls != 1 {
		t.Errorf("exporter calls = %d, want 1", exporter.calls)
	}
	if exporter.gotProject != projectID {
		t.Errorf("exporter got project %v, want %v", exporter.gotProject, projectID)
	}
	// CRA collision: both early_warning.ja bodies survive, distinct. Rows
	// sort created_at DESC, so the NEWEST (EW B, now-1h) takes the base
	// name and the older (EW A, now-3h) gets the .2 suffix — deterministic.
	if string(files["cra/early_warning.ja.md"]) != "## 24h EW B\n" {
		t.Errorf("cra/early_warning.ja.md = %q, want EW B (newest)", files["cra/early_warning.ja.md"])
	}
	if string(files["cra/early_warning.ja.2.md"]) != "## 24h EW A\n" {
		t.Errorf("cra/early_warning.ja.2.md = %q, want EW A (older)", files["cra/early_warning.ja.2.md"])
	}

	// ---- manifest.json ----
	var mf manifest
	if err := json.Unmarshal(files["manifest.json"], &mf); err != nil {
		t.Fatalf("manifest not json: %v", err)
	}
	if mf.Schema != manifestSchema {
		t.Errorf("manifest.schema = %q, want %q", mf.Schema, manifestSchema)
	}
	if mf.GeneratedAt != now.UTC().Format(time.RFC3339) {
		t.Errorf("manifest.generated_at = %q, want %q", mf.GeneratedAt, now.UTC().Format(time.RFC3339))
	}
	if mf.GeneratedBy.Provider != generatorProvider || mf.GeneratedBy.Model != generatorModel {
		t.Errorf("manifest.generated_by = %+v, want provider=%q model=%q", mf.GeneratedBy, generatorProvider, generatorModel)
	}
	if mf.TenantID != tenantID.String() || mf.ProjectID != projectID.String() {
		t.Errorf("manifest tenant/project = %q/%q, want %q/%q", mf.TenantID, mf.ProjectID, tenantID.String(), projectID.String())
	}
	if mf.Disclaimer != manifestDisclaimer {
		t.Errorf("manifest.disclaimer = %q, want pinned disclaimer", mf.Disclaimer)
	}

	// files[] lists every entry EXCEPT manifest.json, each sha256 matches
	// the actual entry bytes, and paths are sorted.
	if len(mf.Files) != len(files)-1 {
		t.Errorf("manifest lists %d files, want %d (all entries except manifest.json)", len(mf.Files), len(files)-1)
	}
	prev := ""
	for _, mfile := range mf.Files {
		if mfile.Path == "manifest.json" {
			t.Errorf("manifest must not list itself")
		}
		if mfile.Path < prev {
			t.Errorf("manifest.files not path-sorted: %q after %q", mfile.Path, prev)
		}
		prev = mfile.Path
		entry, ok := files[mfile.Path]
		if !ok {
			t.Errorf("manifest lists %q but zip has no such entry", mfile.Path)
			continue
		}
		sum := sha256.Sum256(entry)
		if mfile.SHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("manifest sha256 for %q = %q, want %q", mfile.Path, mfile.SHA256, hex.EncodeToString(sum[:]))
		}
		if mfile.Bytes != len(entry) {
			t.Errorf("manifest bytes for %q = %d, want %d", mfile.Path, mfile.Bytes, len(entry))
		}
	}
}

func TestBuilder_BuildZip_ByteDeterministic(t *testing.T) {
	// Pin tenant/project/now across both builds (fixed uuids so the only
	// candidate for divergence is internal non-determinism).
	tenantID := uuid.New()
	projectID := uuid.New()
	now := time.Date(2026, 7, 4, 1, 2, 3, 0, time.UTC)
	mk := func() []byte {
		b := NewBuilder(
			&fakeVEXReader{rows: []repository.VEXDraft{{
				ID: uuid.Nil, ProjectID: projectID, CVEID: "CVE-2026-2000", State: "affected",
				Evidence: json.RawMessage(`[{"kind":"x","ref":"y"}]`), Decision: "approved",
				CreatedAt: now, UpdatedAt: now,
			}}},
			&fakeCRAReader{rows: []repository.CRAReport{{
				ID: uuid.Nil, ProjectID: projectID, CVEID: "CVE-2026-2000", ReportType: "final_report",
				Lang: "en", State: "approved", DraftText: "body\n",
				Evidence: json.RawMessage(`[{"kind":"vex","ref":"d"}]`), Decision: "approved",
				CreatedAt: now, UpdatedAt: now,
			}}},
			&fakeProjectReader{project: &model.Project{ID: projectID, Name: "p"}},
			&fakeMETIReader{rows: []repository.MetiAssessment{{
				ID: uuid.Nil, ProjectID: projectID, CriterionID: "meti.env_setup.01",
				CriterionPhase: string(meti.PhaseEnvSetup), Status: "achieved",
				Evidence: json.RawMessage(`[{"kind":"settings","ref":"z"}]`), CreatedAt: now, UpdatedAt: now,
			}}},
			newFakeCatalogForTest(),
		).WithVEXExporter(&fakeVEXExporter{data: []byte(`{"bomFormat":"CycloneDX"}`)})
		res, err := b.Build(context.Background(), fullZipInput(tenantID, projectID, now))
		if err != nil {
			t.Fatalf("zip Build error: %v", err)
		}
		return res.ContentBytes
	}
	a := mk()
	c := mk()
	if !bytes.Equal(a, c) {
		t.Errorf("zip not byte-deterministic: len(a)=%d len(c)=%d", len(a), len(c))
	}
}

// clockVEXExporter mirrors the PRODUCTION exporter
// (service.VEXService.ExportCycloneDXVEXAt): it stamps the SUPPLIED timestamp
// into metadata.timestamp instead of a fixed blob or a live clock. This is
// what makes the determinism assertion below load-bearing for F408 — the
// bug was that the builder ignored z.now and the real exporter used
// time.Now(), so two builds with identical BuildInput.Now embedded different
// vex.cdx.json timestamps → different zip bytes.
type clockVEXExporter struct{}

func (clockVEXExporter) ExportCycloneDXVEXAt(_ context.Context, _ uuid.UUID, ts time.Time) ([]byte, error) {
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"timestamp":"` +
		ts.UTC().Format(time.RFC3339) + `"}}`), nil
}

// TestBuilder_BuildZip_VEXTimestampDeterministic pins F408 (#140): the zip is
// byte-identical across re-builds with the same BuildInput.Now even when the
// VEX exporter stamps a timestamp — because the builder threads z.now into
// ExportCycloneDXVEXAt rather than letting the exporter read a live clock.
//
// Before the fix (builder calling ExportCycloneDXVEX → real exporter's
// time.Now()) this would diverge on vex.cdx.json and thus the manifest SHA
// and the whole zip. It exercises the REAL timestamp path, not a fixed-bytes
// fake.
func TestBuilder_BuildZip_VEXTimestampDeterministic(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	now := time.Date(2026, 7, 4, 1, 2, 3, 0, time.UTC)
	mk := func() []byte {
		b := NewBuilder(
			&fakeVEXReader{rows: []repository.VEXDraft{{
				ID: uuid.Nil, ProjectID: projectID, CVEID: "CVE-2026-2000", State: "affected",
				Evidence: json.RawMessage(`[{"kind":"x","ref":"y"}]`), Decision: "approved",
				CreatedAt: now, UpdatedAt: now,
			}}},
			&fakeCRAReader{rows: []repository.CRAReport{}},
			&fakeProjectReader{project: &model.Project{ID: projectID, Name: "p"}},
			&fakeMETIReader{rows: []repository.MetiAssessment{{
				ID: uuid.Nil, ProjectID: projectID, CriterionID: "meti.env_setup.01",
				CriterionPhase: string(meti.PhaseEnvSetup), Status: "achieved",
				Evidence: json.RawMessage(`[{"kind":"settings","ref":"z"}]`), CreatedAt: now, UpdatedAt: now,
			}}},
			newFakeCatalogForTest(),
		).WithVEXExporter(clockVEXExporter{})
		res, err := b.Build(context.Background(), fullZipInput(tenantID, projectID, now))
		if err != nil {
			t.Fatalf("zip Build error: %v", err)
		}
		return res.ContentBytes
	}
	a := mk()
	c := mk()
	if !bytes.Equal(a, c) {
		t.Fatalf("zip not byte-deterministic with a timestamp-stamping VEX exporter: len(a)=%d len(c)=%d", len(a), len(c))
	}

	// Lock the mechanism, not just the accidental equality: vex.cdx.json's
	// metadata.timestamp must be the pack timestamp (z.now), NOT a live clock.
	files := unzip(t, a)
	vexJSON, ok := files["vex.cdx.json"]
	if !ok {
		t.Fatal("vex.cdx.json missing from zip")
	}
	wantTS := now.UTC().Format(time.RFC3339)
	if !bytes.Contains(vexJSON, []byte(`"timestamp":"`+wantTS+`"`)) {
		t.Errorf("vex.cdx.json timestamp is not the pack timestamp %q; got %s", wantTS, vexJSON)
	}
}

func TestBuilder_BuildZip_METIAssessmentJSON(t *testing.T) {
	b, _, tenantID, projectID, now := zipFixture(t)
	res, err := b.Build(context.Background(), fullZipInput(tenantID, projectID, now))
	if err != nil {
		t.Fatalf("zip Build error: %v", err)
	}
	files := unzip(t, res.ContentBytes)
	var doc metiAssessmentDoc
	if err := json.Unmarshal(files["meti-assessment.json"], &doc); err != nil {
		t.Fatalf("meti-assessment.json not json: %v", err)
	}
	if doc.Schema != metiAssessmentSchema {
		t.Errorf("meti schema = %q, want %q", doc.Schema, metiAssessmentSchema)
	}
	if doc.Total != 2 || doc.Achieved != 2 {
		t.Errorf("meti total/achieved = %d/%d, want 2/2", doc.Total, doc.Achieved)
	}
	// Sorted by (phase, criterion_id): env_setup before sbom_creation.
	if len(doc.Criteria) != 2 {
		t.Fatalf("criteria len = %d, want 2", len(doc.Criteria))
	}
	if doc.Criteria[0].CriterionID != "meti.env_setup.01" {
		t.Errorf("criteria[0] = %q, want meti.env_setup.01", doc.Criteria[0].CriterionID)
	}
	// override precedence surfaced honestly: effective=achieved, evaluator=needs_review.
	if doc.Criteria[0].Status != "achieved" || doc.Criteria[0].EvaluatorStatus != "needs_review" || doc.Criteria[0].OverrideStatus != "achieved" {
		t.Errorf("criteria[0] status/evaluator/override = %q/%q/%q, want achieved/needs_review/achieved",
			doc.Criteria[0].Status, doc.Criteria[0].EvaluatorStatus, doc.Criteria[0].OverrideStatus)
	}
}

func TestBuilder_BuildZip_TogglesOmitEntries(t *testing.T) {
	b, _, tenantID, projectID, now := zipFixture(t)
	in := fullZipInput(tenantID, projectID, now)
	in.IncludeVEXApproved = false
	in.IncludeCRAApproved = false
	in.IncludeMETIAssessment = false
	res, err := b.Build(context.Background(), in)
	if err != nil {
		t.Fatalf("zip Build error: %v", err)
	}
	files := unzip(t, res.ContentBytes)
	// Only report.md + manifest.json remain.
	if _, ok := files["vex.cdx.json"]; ok {
		t.Errorf("vex.cdx.json present despite IncludeVEXApproved=false")
	}
	for name := range files {
		if len(name) >= 4 && name[:4] == "cra/" {
			t.Errorf("cra entry %q present despite IncludeCRAApproved=false", name)
		}
	}
	if _, ok := files["meti-assessment.json"]; ok {
		t.Errorf("meti-assessment.json present despite IncludeMETIAssessment=false")
	}
	if _, ok := files["report.md"]; !ok {
		t.Errorf("report.md missing")
	}
	if _, ok := files["manifest.json"]; !ok {
		t.Errorf("manifest.json missing")
	}
}

func TestBuilder_BuildZip_VEXExporterRequired(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	// Builder WITHOUT WithVEXExporter, VEX section requested.
	b := NewBuilder(
		&fakeVEXReader{},
		&fakeCRAReader{},
		&fakeProjectReader{project: &model.Project{ID: projectID, Name: "p"}},
		&fakeMETIReader{},
		newFakeCatalogForTest(),
	)
	_, err := b.Build(context.Background(), fullZipInput(tenantID, projectID, time.Now()))
	if err == nil || !contains(err.Error(), "VEX exporter not wired") {
		t.Fatalf("want VEX-exporter-not-wired error, got %v", err)
	}
}

func TestBuilder_BuildZip_ExporterError(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	boom := errors.New("cdx boom")
	b := NewBuilder(
		&fakeVEXReader{},
		&fakeCRAReader{},
		&fakeProjectReader{project: &model.Project{ID: projectID, Name: "p"}},
		&fakeMETIReader{},
		newFakeCatalogForTest(),
	).WithVEXExporter(&fakeVEXExporter{err: boom})
	_, err := b.Build(context.Background(), fullZipInput(tenantID, projectID, time.Now()))
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("want wrapped exporter error, got %v", err)
	}
}

func TestBuilder_BuildZip_VEXOmittedNeedsNoExporter(t *testing.T) {
	// With the VEX section off, a zip must build even when no exporter is
	// wired (the exporter is only consulted for vex.cdx.json).
	tenantID := uuid.New()
	projectID := uuid.New()
	b := NewBuilder(
		&fakeVEXReader{},
		&fakeCRAReader{},
		&fakeProjectReader{project: &model.Project{ID: projectID, Name: "p"}},
		&fakeMETIReader{},
		newFakeCatalogForTest(),
	)
	in := fullZipInput(tenantID, projectID, time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC))
	in.IncludeVEXApproved = false
	res, err := b.Build(context.Background(), in)
	if err != nil {
		t.Fatalf("zip Build error: %v", err)
	}
	files := unzip(t, res.ContentBytes)
	if _, ok := files["vex.cdx.json"]; ok {
		t.Errorf("vex.cdx.json present with VEX section off")
	}
}

func TestSanitizePathSegment(t *testing.T) {
	cases := map[string]string{
		"early_warning": "early_warning",
		"ja":            "ja",
		"":              "unknown",
		"../etc/passwd": "___etc_passwd",
		"a.b":           "a_b",
		"UP-1":          "UP-1",
	}
	for in, want := range cases {
		if got := sanitizePathSegment(in); got != want {
			t.Errorf("sanitizePathSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

// contains is a tiny strings.Contains shim kept local so this test file
// does not need an extra import beyond the ones already used.
func contains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}
