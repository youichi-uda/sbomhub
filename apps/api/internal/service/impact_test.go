package service

import (
	"testing"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// TestBuildCVEImpact_RollupAndMeta pins the pure assembly step of the
// blast-radius view (M28-A / F388, #134): affected_project_count derives from
// the affected list length, total_project_count is passed through, and the
// vulnerability metadata (severity / CVSS / EPSS / KEV) is copied verbatim from
// the resolved meta.
func TestBuildCVEImpact_RollupAndMeta(t *testing.T) {
	meta := &model.CVEImpactMeta{
		VulnerabilityID: uuid.New(),
		Severity:        "CRITICAL",
		CVSSScore:       9.8,
		EPSSScore:       0, // EPSS fixed at 0 until 006_epss (see repository docstring)
		InKEV:           true,
	}
	affected := []model.ImpactProject{
		{ProjectID: uuid.New(), ProjectName: "app-a", ComponentCount: 3,
			AffectedComponents: []model.ImpactComponent{{Name: "log4j", Version: "2.14.0", Purl: "pkg:maven/log4j@2.14.0"}}},
		{ProjectID: uuid.New(), ProjectName: "app-b", ComponentCount: 1,
			AffectedComponents: []model.ImpactComponent{{Name: "log4j", Version: "2.14.0", Purl: "pkg:maven/log4j@2.14.0"}}},
	}

	got := buildCVEImpact("CVE-2024-1234", meta, affected, 12)

	if got.CVEID != "CVE-2024-1234" {
		t.Errorf("cve_id = %q, want CVE-2024-1234", got.CVEID)
	}
	if got.Severity != "CRITICAL" || got.CVSSScore != 9.8 || !got.InKEV {
		t.Errorf("meta rollup mismatch: severity=%q cvss=%v in_kev=%v", got.Severity, got.CVSSScore, got.InKEV)
	}
	if got.AffectedProjectCount != 2 {
		t.Errorf("affected_project_count = %d, want 2", got.AffectedProjectCount)
	}
	if got.TotalProjectCount != 12 {
		t.Errorf("total_project_count = %d, want 12", got.TotalProjectCount)
	}
	if len(got.AffectedProjects) != 2 {
		t.Errorf("len(affected_projects) = %d, want 2", len(got.AffectedProjects))
	}
}

// TestBuildCVEImpact_ZeroAffected pins the blast-radius-0 contract: a known CVE
// that reaches no project yields a non-nil result with count 0 and a non-nil
// empty affected list (which JSON-encodes as [] rather than null), NOT a 404.
func TestBuildCVEImpact_ZeroAffected(t *testing.T) {
	meta := &model.CVEImpactMeta{
		VulnerabilityID: uuid.New(),
		Severity:        "HIGH",
		CVSSScore:       7.5,
	}

	// nil affected must be normalised to an empty (non-nil) slice.
	got := buildCVEImpact("CVE-2024-9999", meta, nil, 5)

	if got == nil {
		t.Fatalf("expected non-nil result for a known-but-unaffecting CVE")
	}
	if got.AffectedProjectCount != 0 {
		t.Errorf("affected_project_count = %d, want 0", got.AffectedProjectCount)
	}
	if got.TotalProjectCount != 5 {
		t.Errorf("total_project_count = %d, want 5", got.TotalProjectCount)
	}
	if got.AffectedProjects == nil {
		t.Errorf("affected_projects must be a non-nil empty slice (JSON []), got nil")
	}
	if len(got.AffectedProjects) != 0 {
		t.Errorf("len(affected_projects) = %d, want 0", len(got.AffectedProjects))
	}
}
