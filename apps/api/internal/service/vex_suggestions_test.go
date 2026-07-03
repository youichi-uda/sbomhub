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

	// Target component ids captured so the test can assert the response
	// carries the TARGET component's id (F377, issue #131), not the source's.
	purlTargetComp := uuid.New()
	agnosticTargetComp := uuid.New()

	now := time.Now().UTC()

	candidates := []model.VEXSuggestionCandidate{
		// 1. purl match from another project → kept, match_type "purl".
		{
			VulnerabilityID:   vulnPurl,
			CVEID:             "CVE-2026-1000",
			TargetComponentID: purlTargetComp,
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
			TargetComponentID: agnosticTargetComp,
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
	// F377: the suggestion must carry the TARGET component's id, not the
	// source statement's component id (sourceComp).
	if got[0].Component.ComponentID != purlTargetComp {
		t.Errorf("suggestion[0] component_id = %s, want target %s (not source %s)",
			got[0].Component.ComponentID, purlTargetComp, sourceComp)
	}

	// Result 2: vulnerability_only match.
	if got[1].MatchType != model.VEXMatchTypeVulnerabilityOnly {
		t.Errorf("suggestion[1] match_type = %q, want %q", got[1].MatchType, model.VEXMatchTypeVulnerabilityOnly)
	}
	if got[1].CVEID != "CVE-2026-2000" {
		t.Errorf("suggestion[1] cve = %q, want CVE-2026-2000", got[1].CVEID)
	}
	if got[1].Component.ComponentID != agnosticTargetComp {
		t.Errorf("suggestion[1] component_id = %s, want target %s", got[1].Component.ComponentID, agnosticTargetComp)
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

// TestAssembleSuggestions_VulnerabilityOnlyFanOutDistinctComponentIDs pins
// the F377 invariant (issue #131): one component-agnostic source statement
// (SourceComponentID nil) fans out across every target component the
// vulnerability touches. Those fan-out rows share the SAME source
// statement_id and vulnerability_id, and — because a target may hold two
// component rows with the identical (name, version, purl) triple — the
// component name/version/purl are NOT sufficient to tell them apart. The
// only field that distinguishes them is the target Component.ComponentID,
// which the web list keys on to avoid duplicate React keys. This test proves
// assembleSuggestions surfaces a distinct component_id per fan-out row.
func TestAssembleSuggestions_VulnerabilityOnlyFanOutDistinctComponentIDs(t *testing.T) {
	targetProject := uuid.New()
	sourceProject := uuid.New()
	vuln := uuid.New()
	sharedStmt := uuid.New()

	// Two DISTINCT target components with the identical (name, version, purl)
	// triple — the worst case the old {statement_id, vulnerability_id} key
	// could not distinguish.
	compA := uuid.New()
	compB := uuid.New()
	now := time.Now().UTC()

	mk := func(targetComp uuid.UUID) model.VEXSuggestionCandidate {
		return model.VEXSuggestionCandidate{
			VulnerabilityID:   vuln,
			CVEID:             "CVE-2026-9000",
			TargetComponentID: targetComp,
			ComponentName:     "libdup",
			ComponentVersion:  "1.0.0",
			ComponentPurl:     "pkg:npm/libdup@1.0.0",
			SourceProjectID:   sourceProject,
			SourceProjectName: "Source",
			SourceComponentID: nil, // agnostic → vulnerability_only fan-out
			StatementID:       sharedStmt,
			Status:            "not_affected",
			CreatedAt:         now,
		}
	}

	got := assembleSuggestions([]model.VEXSuggestionCandidate{mk(compA), mk(compB)}, targetProject)
	if len(got) != 2 {
		t.Fatalf("expected 2 fan-out suggestions, got %d", len(got))
	}

	// Both rows share the source statement + vulnerability (the old key)…
	if got[0].Source.StatementID != got[1].Source.StatementID || got[0].VulnerabilityID != got[1].VulnerabilityID {
		t.Fatalf("fan-out rows should share statement_id + vulnerability_id")
	}
	// …and the name/version/purl (so those cannot disambiguate)…
	if got[0].Component.Purl != got[1].Component.Purl {
		t.Fatalf("fan-out rows should share the component purl in this worst case")
	}
	// …but component_id must be distinct, giving the client a unique key.
	if got[0].Component.ComponentID == got[1].Component.ComponentID {
		t.Fatalf("F377 regression: fan-out rows share component_id %s — web key would collide",
			got[0].Component.ComponentID)
	}
	seen := map[uuid.UUID]bool{compA: false, compB: false}
	for _, s := range got {
		if _, ok := seen[s.Component.ComponentID]; !ok {
			t.Errorf("unexpected component_id %s (want one of the two target components)", s.Component.ComponentID)
		}
		seen[s.Component.ComponentID] = true
	}
	if !seen[compA] || !seen[compB] {
		t.Errorf("both target component ids must appear exactly once: %+v", seen)
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
