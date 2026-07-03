package service

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// TestAssembleSuggestions_ExclusionAndMatchType pins the pure business
// logic of the cross-project VEX aggregation (M26-A / F375, issue #130)
// without a live DB. The repository query returns raw candidates —
// including self-project rows and rows the target has already triaged —
// and assembleSuggestions is responsible for dropping those and deriving
// match_type. This test is the unit-level guard the kickoff calls for.
func TestAssembleSuggestions_ExclusionAndMatchType(t *testing.T) {
	targetProject := uuid.New()
	otherProjectA := uuid.New()
	otherProjectB := uuid.New()
	sourceComp := uuid.New()

	vulnPurl := uuid.New()
	vulnAgnostic := uuid.New()
	vulnSelf := uuid.New()
	vulnTriaged := uuid.New()

	now := time.Now().UTC()

	candidates := []model.VEXSuggestionCandidate{
		// 1. purl match from another project → kept, match_type "purl".
		{
			VulnerabilityID:   vulnPurl,
			CVEID:             "CVE-2026-1000",
			TargetComponentID: uuid.New(),
			ComponentName:     "libfoo",
			ComponentVersion:  "1.2.3",
			ComponentPurl:     "pkg:golang/libfoo@1.2.3",
			SourceProjectID:   otherProjectA,
			SourceProjectName: "Project A",
			SourceComponentID: &sourceComp, // non-nil → purl
			StatementID:       uuid.New(),
			Status:            "not_affected",
			Justification:     "vulnerable_code_not_present",
			ImpactStatement:   "not reachable",
			ActionStatement:   "",
			CreatedAt:         now,
		},
		// 2. vulnerability-only match from another project → kept,
		//    match_type "vulnerability_only".
		{
			VulnerabilityID:   vulnAgnostic,
			CVEID:             "CVE-2026-2000",
			TargetComponentID: uuid.New(),
			ComponentName:     "libbar",
			ComponentVersion:  "0.9.0",
			ComponentPurl:     "pkg:npm/libbar@0.9.0",
			SourceProjectID:   otherProjectB,
			SourceProjectName: "Project B",
			SourceComponentID: nil, // nil → vulnerability_only
			StatementID:       uuid.New(),
			Status:            "affected",
			CreatedAt:         now,
		},
		// 3. self-project candidate → dropped.
		{
			VulnerabilityID:   vulnSelf,
			CVEID:             "CVE-2026-3000",
			TargetComponentID: uuid.New(),
			ComponentName:     "libself",
			SourceProjectID:   targetProject, // self → drop
			SourceProjectName: "Target",
			SourceComponentID: &sourceComp,
			StatementID:       uuid.New(),
			Status:            "not_affected",
			CreatedAt:         now,
		},
		// 4. already-triaged in target → dropped even though it's from
		//    another project.
		{
			VulnerabilityID:      vulnTriaged,
			CVEID:                "CVE-2026-4000",
			TargetComponentID:    uuid.New(),
			ComponentName:        "libtriaged",
			SourceProjectID:      otherProjectA,
			SourceProjectName:    "Project A",
			SourceComponentID:    &sourceComp,
			StatementID:          uuid.New(),
			Status:               "not_affected",
			CreatedAt:            now,
			TargetAlreadyTriaged: true, // → drop
		},
	}

	got := assembleSuggestions(candidates, targetProject)

	if len(got) != 2 {
		t.Fatalf("expected 2 surviving suggestions (self + already-triaged dropped), got %d: %+v", len(got), got)
	}

	// Result 1: purl match preserved with full source provenance.
	if got[0].MatchType != model.VEXMatchTypePurl {
		t.Errorf("suggestion[0] match_type = %q, want %q", got[0].MatchType, model.VEXMatchTypePurl)
	}
	if got[0].CVEID != "CVE-2026-1000" {
		t.Errorf("suggestion[0] cve = %q, want CVE-2026-1000", got[0].CVEID)
	}
	if got[0].Source.ProjectID != otherProjectA || got[0].Source.ProjectName != "Project A" {
		t.Errorf("suggestion[0] source provenance mismatch: %+v", got[0].Source)
	}
	if got[0].Component.Purl != "pkg:golang/libfoo@1.2.3" {
		t.Errorf("suggestion[0] component purl = %q", got[0].Component.Purl)
	}

	// Result 2: vulnerability_only match.
	if got[1].MatchType != model.VEXMatchTypeVulnerabilityOnly {
		t.Errorf("suggestion[1] match_type = %q, want %q", got[1].MatchType, model.VEXMatchTypeVulnerabilityOnly)
	}
	if got[1].CVEID != "CVE-2026-2000" {
		t.Errorf("suggestion[1] cve = %q, want CVE-2026-2000", got[1].CVEID)
	}

	// Neither dropped CVE may appear in the output.
	for _, s := range got {
		if s.CVEID == "CVE-2026-3000" {
			t.Errorf("self-project suggestion (CVE-2026-3000) must be dropped")
		}
		if s.CVEID == "CVE-2026-4000" {
			t.Errorf("already-triaged suggestion (CVE-2026-4000) must be dropped")
		}
	}
}

// TestAssembleSuggestions_EmptyIsNonNil guards the handler contract: an
// empty candidate set must serialise as `[]`, not `null`.
func TestAssembleSuggestions_EmptyIsNonNil(t *testing.T) {
	got := assembleSuggestions(nil, uuid.New())
	if got == nil {
		t.Fatalf("assembleSuggestions must return a non-nil slice for the empty case")
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 suggestions, got %d", len(got))
	}
}
