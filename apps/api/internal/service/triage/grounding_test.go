package triage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// ----------------------------------------------------------------------------
// M32 Wave B (P2) — grounding guard tests
// ----------------------------------------------------------------------------
//
// These tests pin the hardening described in guards.go: ValidateEvidence
// only checks evidence SHAPE, so before this guard the LLM could fabricate
// evidence pointers (an advisory_excerpt with a Description it wrote itself)
// that flowed straight through to the human approver as a confident VEX.
// The runner now cross-checks the LLM's self-reported evidence against the
// advisory / reachability rows actually loaded, clamping ungrounded drafts.

// groundingResp is a small builder for an LLM triage response whose evidence
// we fully control (so a test can fabricate or ground pointers at will).
func groundingResp(t *testing.T, state, just string, conf float64, evidence []map[string]interface{}) string {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"state":         state,
		"justification": just,
		"confidence":    conf,
		"detail":        "grounding-guard test rationale",
		"evidence":      evidence,
	})
	if err != nil {
		t.Fatalf("groundingResp marshal: %v", err)
	}
	return string(body)
}

func decodeEvidence(t *testing.T, raw json.RawMessage) []EvidencePointer {
	t.Helper()
	var evs []EvidencePointer
	if err := json.Unmarshal(raw, &evs); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	return evs
}

// Test 1 — zero-grounding clamp (MANDATORY). No advisory / reachability rows
// were loaded, yet the LLM returns a confident not_affected. The persisted
// draft must be forced to under_investigation, confidence clamped below the
// threshold, and a synthetic ungrounded note must preserve the AI's proposal.
func TestRunner_Run_ZeroGrounding_ClampsToUnderInvestigation(t *testing.T) {
	componentID := uuid.New()
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: groundingResp(t,
		"not_affected", "code_not_reachable", 0.95,
		[]map[string]interface{}{
			{
				"kind":        "advisory_excerpt",
				"raw_snippet": "Totally fabricated excerpt that was never loaded into any table.",
				"source":      "advisory_parser",
			},
		},
	)}}
	drafts := &fakeVexDraftStore{}
	r := NewRunner(RunnerConfig{
		Drafts:                   drafts,
		Advisories:               &fakeAdvisoryReader{},     // empty → no grounding
		Reachability:             &fakeReachabilityReader{}, // empty → no grounding
		LLMCalls:                 &fakeLLMCallWriter{},
		Audit:                    &fakeAuditWriter{},
		Provider:                 stub,
		Threshold:                0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0700"),
	})

	res, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0700",
		ComponentID: &componentID,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	// Draft is saved, not dropped.
	if got := len(drafts.inserted); got != 1 {
		t.Fatalf("expected 1 saved draft (never dropped), got %d", got)
	}
	d := drafts.inserted[0]

	if d.State != string(StateUnderInvestigation) {
		t.Errorf("ungrounded confident draft must clamp to under_investigation, got %q", d.State)
	}
	if d.Confidence == nil || *d.Confidence >= 0.7 {
		t.Errorf("confidence must be clamped below threshold 0.7, got %v", d.Confidence)
	}
	if !res.Clamped {
		t.Errorf("expected RunResult.Clamped=true for an ungrounded draft")
	}

	// Synthetic ungrounded note present + preserves the AI's original proposal.
	evs := decodeEvidence(t, d.Evidence)
	var found bool
	for _, ev := range evs {
		if ev.Kind == EvidenceKindAnalyzerError && ev.Note == UngroundedNoteTag {
			found = true
			if !strings.Contains(ev.Description, "not_affected") || !strings.Contains(ev.Description, "0.95") {
				t.Errorf("synthetic note must preserve original proposal (state@confidence), got %q", ev.Description)
			}
			if !strings.Contains(ev.Description, "ungrounded") {
				t.Errorf("synthetic note must state it is ungrounded, got %q", ev.Description)
			}
		}
	}
	if !found {
		t.Errorf("expected a synthetic ungrounded analyzer_error note, evidence=%+v", evs)
	}
}

// Test 2 — grounded regression (no over-clamp). With a matching advisory
// excerpt and a matching reachability symbol loaded, a confident draft must
// NOT be clamped, and the advisory / reachability FKs must still be set
// (protects the happy-path FK contract in runner_test.go).
func TestRunner_Run_GroundedEvidence_NotClamped(t *testing.T) {
	componentID := uuid.New()
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: groundingResp(t,
		"not_affected", "code_not_reachable", 0.9,
		[]map[string]interface{}{
			{"kind": "advisory_excerpt", "raw_snippet": "func Parse mishandles nested anchors", "source": "advisory_parser"},
			{"kind": "symbol_ref", "symbol": "yaml.Parse", "source": "reachability"},
		},
	)}}
	advisories := &fakeAdvisoryReader{rows: []AdvisoryExcerptRow{{
		ID: uuid.New(), CVEID: "CVE-2026-0701", Source: "ghsa",
		RawExcerpt: "GHSA-yaml: func Parse mishandles nested anchors leading to unbounded recursion.",
	}}}
	reach := &fakeReachabilityReader{rows: []ReachabilityRow{{
		ID: uuid.New(), ComponentID: componentID, CVEID: "CVE-2026-0701",
		Ecosystem: "go", Status: "reachable",
		Evidence: json.RawMessage(`{"symbol":"yaml.Parse","path":["main","yaml.Parse"]}`),
	}}}
	drafts := &fakeVexDraftStore{}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: advisories, Reachability: reach,
		LLMCalls: &fakeLLMCallWriter{}, Audit: &fakeAuditWriter{},
		Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0701"),
	})

	res, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0701",
		ComponentID: &componentID,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if got := len(drafts.inserted); got != 1 {
		t.Fatalf("expected 1 draft, got %d", got)
	}
	d := drafts.inserted[0]
	if d.State != "not_affected" {
		t.Errorf("fully grounded confident draft must NOT be clamped, got state %q", d.State)
	}
	if d.Confidence == nil || *d.Confidence != 0.9 {
		t.Errorf("grounded draft confidence must be preserved, got %v", d.Confidence)
	}
	if res.Clamped {
		t.Errorf("did not expect a clamp for a fully grounded draft")
	}
	if d.AdvisoryExcerptID == nil {
		t.Errorf("expected advisory_excerpt_id FK to be set")
	}
	if d.ReachabilityResultID == nil {
		t.Errorf("expected reachability_result_id FK to be set")
	}
	// No pointer should be flagged unverified.
	for _, ev := range decodeEvidence(t, d.Evidence) {
		if strings.Contains(ev.Note, UnverifiedGroundingTag) {
			t.Errorf("grounded pointer wrongly flagged unverified: %+v", ev)
		}
	}
}

// Test 3 — fabrication catch (Tier 2). A loaded advisory row is present but
// the LLM's advisory_excerpt snippet is NOT a substring of any loaded
// RawExcerpt. The pointer must be marked unverified and confidence clamped,
// the draft still saved (never dropped). With no grounded pointer matching,
// the draft collapses to under_investigation (Tier-1 escalation).
func TestRunner_Run_FabricatedAdvisoryExcerpt_FlaggedAndClamped(t *testing.T) {
	componentID := uuid.New()
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: groundingResp(t,
		"not_affected", "code_not_present", 0.92,
		[]map[string]interface{}{
			{
				"kind":        "advisory_excerpt",
				"raw_snippet": "Fabricated: the CVE only affects the Windows named-pipe transport.",
				"source":      "advisory_parser",
			},
		},
	)}}
	advisories := &fakeAdvisoryReader{rows: []AdvisoryExcerptRow{{
		ID: uuid.New(), CVEID: "CVE-2026-0702", Source: "nvd",
		RawExcerpt: "NVD: heap overflow in the TLS record parser when handling oversized fragments.",
	}}}
	drafts := &fakeVexDraftStore{}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: advisories,
		Reachability: &fakeReachabilityReader{}, // no reach rows
		LLMCalls:     &fakeLLMCallWriter{}, Audit: &fakeAuditWriter{},
		Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0702"),
	})

	res, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0702",
		ComponentID: &componentID,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if got := len(drafts.inserted); got != 1 {
		t.Fatalf("expected the draft to still be saved (flag, never drop), got %d", got)
	}
	d := drafts.inserted[0]

	if d.Confidence == nil || *d.Confidence >= 0.7 {
		t.Errorf("fabricated citation must clamp confidence below threshold, got %v", d.Confidence)
	}
	if !res.Clamped {
		t.Errorf("expected RunResult.Clamped=true")
	}
	if d.State != string(StateUnderInvestigation) {
		t.Errorf("draft with no verified grounding must collapse to under_investigation, got %q", d.State)
	}

	evs := decodeEvidence(t, d.Evidence)
	var flagged bool
	for _, ev := range evs {
		if ev.Kind == EvidenceKindAdvisoryExcerpt && strings.Contains(ev.Note, UnverifiedGroundingTag) {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("fabricated advisory_excerpt must be marked unverified, evidence=%+v", evs)
	}
}

// Test 3b — partial grounding (lenient Tier-2). One pointer matches a loaded
// row and another does not. The matched pointer keeps the verdict alive so
// the state is preserved (NOT clamped to under_investigation), while the
// unmatched pointer is flagged and confidence is clamped below threshold.
func TestRunner_Run_PartialGrounding_KeepsStateClampsConfidence(t *testing.T) {
	componentID := uuid.New()
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: groundingResp(t,
		"not_affected", "code_not_reachable", 0.9,
		[]map[string]interface{}{
			// Grounded: matches the reachability Evidence below.
			{"kind": "symbol_ref", "symbol": "pkg.DoWork", "source": "reachability"},
			// Fabricated: not present in the loaded advisory.
			{"kind": "advisory_excerpt", "raw_snippet": "invented advisory text nowhere in the row", "source": "advisory_parser"},
		},
	)}}
	advisories := &fakeAdvisoryReader{rows: []AdvisoryExcerptRow{{
		ID: uuid.New(), CVEID: "CVE-2026-0703", Source: "ghsa",
		RawExcerpt: "GHSA: DoWork is exploitable only when debug logging is enabled.",
	}}}
	reach := &fakeReachabilityReader{rows: []ReachabilityRow{{
		ID: uuid.New(), ComponentID: componentID, CVEID: "CVE-2026-0703",
		Ecosystem: "go", Status: "import_only",
		Evidence: json.RawMessage(`{"symbol":"pkg.DoWork","status":"import_only"}`),
	}}}
	drafts := &fakeVexDraftStore{}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: advisories, Reachability: reach,
		LLMCalls: &fakeLLMCallWriter{}, Audit: &fakeAuditWriter{},
		Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0703"),
	})

	res, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0703",
		ComponentID: &componentID,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if got := len(drafts.inserted); got != 1 {
		t.Fatalf("expected 1 draft, got %d", got)
	}
	d := drafts.inserted[0]

	// At least one pointer matched → the verdict survives (state preserved).
	if d.State != "not_affected" {
		t.Errorf("partially grounded draft should keep its state, got %q", d.State)
	}
	// ...but confidence is clamped below threshold because a pointer was unverified.
	if d.Confidence == nil || *d.Confidence >= 0.7 {
		t.Errorf("partial grounding must clamp confidence below threshold, got %v", d.Confidence)
	}
	if !res.Clamped {
		t.Errorf("expected RunResult.Clamped=true when a pointer is unverified")
	}

	evs := decodeEvidence(t, d.Evidence)
	var symbolOK, advisoryFlagged bool
	for _, ev := range evs {
		switch ev.Kind {
		case EvidenceKindSymbolRef:
			if !strings.Contains(ev.Note, UnverifiedGroundingTag) {
				symbolOK = true
			}
		case EvidenceKindAdvisoryExcerpt:
			if strings.Contains(ev.Note, UnverifiedGroundingTag) {
				advisoryFlagged = true
			}
		}
	}
	if !symbolOK {
		t.Errorf("matched symbol_ref must NOT be flagged")
	}
	if !advisoryFlagged {
		t.Errorf("unmatched advisory_excerpt must be flagged unverified")
	}
}

// Test 4 — ValidateGrounding unit coverage.
func TestValidateGrounding(t *testing.T) {
	advisories := []AdvisoryExcerptRow{{
		ID: uuid.New(), CVEID: "CVE-X",
		RawExcerpt: "The Parse function is vulnerable to injection via crafted input.",
		VulnFuncs:  json.RawMessage(`["Parse","Unmarshal"]`),
	}}
	reach := []ReachabilityRow{{
		ID: uuid.New(), CVEID: "CVE-X", Status: "reachable",
		Evidence: json.RawMessage(`{"symbol":"pkg.Parse","import_path":"github.com/x/pkg"}`),
	}}

	t.Run("matching advisory_excerpt passes (substring of RawExcerpt)", func(t *testing.T) {
		ev := []EvidencePointer{{Kind: EvidenceKindAdvisoryExcerpt, RawSnippet: "Parse function is vulnerable to injection"}}
		res := ValidateGrounding(ev, advisories, reach)
		if res.Matched != 1 || res.Unverified != 0 || res.GroundedKinds != 1 {
			t.Fatalf("expected matched advisory, got %+v", res)
		}
		if strings.Contains(ev[0].Note, UnverifiedGroundingTag) {
			t.Errorf("matched pointer must not be flagged")
		}
	})

	t.Run("advisory match is case-insensitive", func(t *testing.T) {
		ev := []EvidencePointer{{Kind: EvidenceKindAdvisoryExcerpt, RawSnippet: "PARSE FUNCTION IS VULNERABLE"}}
		if res := ValidateGrounding(ev, advisories, reach); res.Matched != 1 {
			t.Fatalf("expected case-insensitive match, got %+v", res)
		}
	})

	t.Run("advisory match against a structured field (VulnFuncs)", func(t *testing.T) {
		ev := []EvidencePointer{{Kind: EvidenceKindAdvisoryExcerpt, Description: "Unmarshal"}}
		if res := ValidateGrounding(ev, advisories, reach); res.Matched != 1 {
			t.Fatalf("expected VulnFuncs structured-field match, got %+v", res)
		}
	})

	t.Run("non-matching advisory_excerpt flagged (not dropped)", func(t *testing.T) {
		ev := []EvidencePointer{{Kind: EvidenceKindAdvisoryExcerpt, RawSnippet: "totally invented text not present anywhere"}}
		res := ValidateGrounding(ev, advisories, reach)
		if res.Unverified != 1 || res.Matched != 0 {
			t.Fatalf("expected unverified, got %+v", res)
		}
		if len(ev) != 1 {
			t.Fatalf("pointer must not be dropped, len=%d", len(ev))
		}
		if !strings.Contains(ev[0].Note, UnverifiedGroundingTag) {
			t.Errorf("non-matching pointer must be flagged, note=%q", ev[0].Note)
		}
	})

	t.Run("matching symbol_ref passes (in reach Evidence)", func(t *testing.T) {
		ev := []EvidencePointer{{Kind: EvidenceKindSymbolRef, Symbol: "pkg.Parse"}}
		if res := ValidateGrounding(ev, advisories, reach); res.Matched != 1 {
			t.Fatalf("expected symbol match, got %+v", res)
		}
	})

	t.Run("non-matching import_path flagged", func(t *testing.T) {
		ev := []EvidencePointer{{Kind: EvidenceKindImportPath, ImportPath: "github.com/unrelated/lib"}}
		res := ValidateGrounding(ev, advisories, reach)
		if res.Unverified != 1 {
			t.Fatalf("expected import_path flagged, got %+v", res)
		}
		if !strings.Contains(ev[0].Note, UnverifiedGroundingTag) {
			t.Errorf("expected flag on unmatched import_path")
		}
	})

	t.Run("llm_rationale and analyzer_error are always exempt", func(t *testing.T) {
		ev := []EvidencePointer{
			{Kind: EvidenceKindLLMRationale, Description: "model reasoning"},
			{Kind: EvidenceKindAnalyzerError, Description: "analyzer downgraded", Note: UngroundedNoteTag},
		}
		res := ValidateGrounding(ev, nil, nil) // no data at all
		if res.Exempt != 2 || res.GroundedKinds != 0 || res.Unverified != 0 {
			t.Fatalf("exempt kinds must never be checked/flagged, got %+v", res)
		}
		if strings.Contains(ev[0].Note, UnverifiedGroundingTag) || strings.Contains(ev[1].Note, UnverifiedGroundingTag) {
			t.Errorf("exempt pointers must not be flagged: %+v", ev)
		}
		// The Tier-1 synthetic note (analyzer_error) is preserved intact.
		if ev[1].Note != UngroundedNoteTag {
			t.Errorf("synthetic note tag mutated: %q", ev[1].Note)
		}
	})

	t.Run("flagging preserves an existing Note", func(t *testing.T) {
		ev := []EvidencePointer{{Kind: EvidenceKindSymbolRef, Symbol: "nope.Nothing", Note: "import_only"}}
		ValidateGrounding(ev, advisories, reach)
		if !strings.Contains(ev[0].Note, "import_only") || !strings.Contains(ev[0].Note, UnverifiedGroundingTag) {
			t.Errorf("flagging must preserve the existing note, got %q", ev[0].Note)
		}
	})
}

func TestIsUngrounded(t *testing.T) {
	if !IsUngrounded(nil, nil) {
		t.Errorf("nil/nil must be ungrounded")
	}
	if IsUngrounded([]AdvisoryExcerptRow{{}}, nil) {
		t.Errorf("advisory present must be grounded")
	}
	if IsUngrounded(nil, []ReachabilityRow{{}}) {
		t.Errorf("reachability present must be grounded")
	}
}

func TestUngroundedConfidenceCeiling(t *testing.T) {
	if c := UngroundedConfidenceCeiling(0.7); c < 0 || c >= 0.7 {
		t.Errorf("ceiling must be in [0,0.7), got %v", c)
	}
	if c := UngroundedConfidenceCeiling(0); c != 0 {
		t.Errorf("threshold 0 → 0, got %v", c)
	}
	if c := UngroundedConfidenceCeiling(2); c >= 1 {
		t.Errorf("threshold > 1 must be clamped, got %v", c)
	}
}

func TestUngroundedNote_PreservesProposal(t *testing.T) {
	n := UngroundedNote("not_affected", 0.93)
	if n.Kind != EvidenceKindAnalyzerError {
		t.Errorf("synthetic note kind must be analyzer_error (exempt), got %q", n.Kind)
	}
	if n.Note != UngroundedNoteTag {
		t.Errorf("synthetic note tag mismatch: %q", n.Note)
	}
	if !strings.Contains(n.Description, "not_affected") || !strings.Contains(n.Description, "0.93") {
		t.Errorf("synthetic note must preserve the original proposal, got %q", n.Description)
	}
}
