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

	// --- Codex F416: trivial-substring bypass must NOT verify. ---

	t.Run("trivial advisory RawSnippet 'a' stays unverified", func(t *testing.T) {
		// 'a' is a substring of nearly any excerpt (and appears in VulnFuncs
		// text), but is below the meaningful-length floor and is not an exact
		// structured-array element → must be flagged.
		ev := []EvidencePointer{{Kind: EvidenceKindAdvisoryExcerpt, RawSnippet: "a"}}
		res := ValidateGrounding(ev, advisories, reach)
		if res.Matched != 0 || res.Unverified != 1 {
			t.Fatalf("trivial 'a' must stay unverified, got %+v", res)
		}
		if !strings.Contains(ev[0].Note, UnverifiedGroundingTag) {
			t.Errorf("expected flag on trivial advisory snippet")
		}
	})

	t.Run("short common word substring stays unverified", func(t *testing.T) {
		// "input" really appears in RawExcerpt ("...via crafted input.") but
		// is < minGroundingMatchLen and not a structured element → unverified.
		ev := []EvidencePointer{{Kind: EvidenceKindAdvisoryExcerpt, RawSnippet: "input"}}
		if res := ValidateGrounding(ev, advisories, reach); res.Matched != 0 || res.Unverified != 1 {
			t.Fatalf("short common word must stay unverified, got %+v", res)
		}
	})

	t.Run("trivial symbol 'a' stays unverified", func(t *testing.T) {
		// Old behaviour raw-substring-searched the Evidence JSON, so 'a'
		// (present in "pkg.parse") would have verified. Structured matching
		// with a length floor keeps it unverified.
		ev := []EvidencePointer{{Kind: EvidenceKindSymbolRef, Symbol: "a"}}
		res := ValidateGrounding(ev, advisories, reach)
		if res.Matched != 0 || res.Unverified != 1 {
			t.Fatalf("trivial symbol 'a' must stay unverified, got %+v", res)
		}
		if !strings.Contains(ev[0].Note, UnverifiedGroundingTag) {
			t.Errorf("expected flag on trivial symbol")
		}
	})

	t.Run("meaningful snippet really in RawExcerpt stays verified", func(t *testing.T) {
		// Positive control: a long snippet that genuinely appears in the
		// free-text excerpt is still accepted (no over-flagging from F416).
		ev := []EvidencePointer{{Kind: EvidenceKindAdvisoryExcerpt, RawSnippet: "vulnerable to injection via crafted input"}}
		if res := ValidateGrounding(ev, advisories, reach); res.Matched != 1 || res.Unverified != 0 {
			t.Fatalf("meaningful long snippet must verify, got %+v", res)
		}
	})

	t.Run("symbol matched via segment of a callgraph node", func(t *testing.T) {
		// Evidence with an ad-hoc {"callgraph_nodes":[...]} shape: the symbol
		// must match a structured field value (segment), not raw JSON text.
		cg := []ReachabilityRow{{
			ID: uuid.New(), CVEID: "CVE-X", Status: "reachable",
			Evidence: json.RawMessage(`{"callgraph_nodes":["main -> pkg/foo.Bar"]}`),
		}}
		ev := []EvidencePointer{{Kind: EvidenceKindSymbolRef, Symbol: "pkg/foo.Bar"}}
		if res := ValidateGrounding(ev, nil, cg); res.Matched != 1 {
			t.Fatalf("expected callgraph-node segment match, got %+v", res)
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

// ----------------------------------------------------------------------------
// Codex F416 — trivial-substring citations must not verify (end-to-end)
// ----------------------------------------------------------------------------

// A confident verdict whose only cited advisory_excerpt is a trivial token
// ("a") must NOT be treated as grounded: the pointer is flagged unverified
// and the draft is clamped (here to under_investigation, since no grounded
// pointer verified). Regresses the trivial-substring bypass.
func TestRunner_Run_TrivialSubstringCitation_FlaggedAndClamped(t *testing.T) {
	componentID := uuid.New()
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: groundingResp(t,
		"not_affected", "code_not_reachable", 0.95,
		[]map[string]interface{}{
			{"kind": "advisory_excerpt", "raw_snippet": "a", "source": "advisory_parser"},
		},
	)}}
	advisories := &fakeAdvisoryReader{rows: []AdvisoryExcerptRow{{
		ID: uuid.New(), CVEID: "CVE-2026-0704", Source: "ghsa",
		RawExcerpt: "GHSA: a heap overflow allows remote attackers to crash the parser.",
	}}}
	drafts := &fakeVexDraftStore{}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: advisories,
		Reachability: &fakeReachabilityReader{},
		LLMCalls:     &fakeLLMCallWriter{}, Audit: &fakeAuditWriter{},
		Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0704"),
	})

	res, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0704",
		ComponentID: &componentID,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if got := len(drafts.inserted); got != 1 {
		t.Fatalf("expected the draft to be saved (flag, never drop), got %d", got)
	}
	d := drafts.inserted[0]
	if d.State != string(StateUnderInvestigation) {
		t.Errorf("trivial-citation draft with no verified grounding must clamp, got %q", d.State)
	}
	if d.Confidence == nil || *d.Confidence >= 0.7 {
		t.Errorf("confidence must be clamped below threshold, got %v", d.Confidence)
	}
	if !res.Clamped {
		t.Errorf("expected RunResult.Clamped=true")
	}
	var flagged bool
	for _, ev := range decodeEvidence(t, d.Evidence) {
		if ev.Kind == EvidenceKindAdvisoryExcerpt && strings.Contains(ev.Note, UnverifiedGroundingTag) {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("trivial advisory_excerpt must be marked unverified")
	}
}

// ----------------------------------------------------------------------------
// R1 #3 — confident strong verdict citing ZERO grounded-kind pointers
// (despite loaded grounding rows) must be clamped
// ----------------------------------------------------------------------------

func TestRunner_Run_StrongVerdictNoGroundedCite_Clamped(t *testing.T) {
	componentID := uuid.New()
	// Confident not_affected, but the ONLY evidence pointer is an
	// llm_rationale (exempt kind) — zero grounded-kind pointers cited.
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: groundingResp(t,
		"not_affected", "code_not_reachable", 0.9,
		[]map[string]interface{}{
			{"kind": "llm_rationale", "description": "The model is confident based on general knowledge.", "source": "llm"},
		},
	)}}
	// Grounding data WAS available (an advisory row is loaded) — the LLM just
	// did not cite any of it.
	advisories := &fakeAdvisoryReader{rows: []AdvisoryExcerptRow{{
		ID: uuid.New(), CVEID: "CVE-2026-0705", Source: "nvd",
		RawExcerpt: "NVD: use-after-free in the session handler under concurrent close.",
	}}}
	drafts := &fakeVexDraftStore{}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: advisories,
		Reachability: &fakeReachabilityReader{},
		LLMCalls:     &fakeLLMCallWriter{}, Audit: &fakeAuditWriter{},
		Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0705"),
	})

	res, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0705",
		ComponentID: &componentID,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if got := len(drafts.inserted); got != 1 {
		t.Fatalf("expected 1 draft, got %d", got)
	}
	d := drafts.inserted[0]
	if d.State != string(StateUnderInvestigation) {
		t.Errorf("strong verdict citing no grounded evidence must clamp to under_investigation, got %q", d.State)
	}
	if d.Confidence == nil || *d.Confidence >= 0.7 {
		t.Errorf("confidence must be clamped below threshold, got %v", d.Confidence)
	}
	if !res.Clamped {
		t.Errorf("expected RunResult.Clamped=true")
	}
	// A distinct synthetic note explaining the uncited strong verdict must
	// be present (and preserve the original proposal).
	var found bool
	for _, ev := range decodeEvidence(t, d.Evidence) {
		if ev.Kind == EvidenceKindAnalyzerError && ev.Note == UngroundedNoteTag {
			if strings.Contains(ev.Description, "grounded-kind") &&
				strings.Contains(ev.Description, "not_affected") &&
				strings.Contains(ev.Description, "0.90") {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected an uncited-strong-verdict synthetic note preserving the proposal, evidence=%+v", decodeEvidence(t, d.Evidence))
	}
}

// Negative control: a fallbackDecision draft (malformed LLM JSON → parse
// fallback) must NOT be newly clamped/annotated by the R1 #3 strong-verdict
// rule — it is already under_investigation / confidence 0.
func TestRunner_Run_FallbackDraft_NotClampedByUncitedRule(t *testing.T) {
	componentID := uuid.New()
	// Malformed JSON → ParseLLMResponse returns fallbackDecision
	// (under_investigation, confidence 0, single llm_rationale pointer).
	stub := &stubProvider{resp: &llm.CompleteResponse{Content: `{not valid json at all`}}
	advisories := &fakeAdvisoryReader{rows: []AdvisoryExcerptRow{{
		ID: uuid.New(), CVEID: "CVE-2026-0706", Source: "ghsa",
		RawExcerpt: "GHSA: loaded advisory that the fallback path never cites.",
	}}}
	drafts := &fakeVexDraftStore{}
	r := NewRunner(RunnerConfig{
		Drafts: drafts, Advisories: advisories,
		Reachability: &fakeReachabilityReader{},
		LLMCalls:     &fakeLLMCallWriter{}, Audit: &fakeAuditWriter{},
		Provider: stub, Threshold: 0.7,
		ComponentVulnerabilities: &fakeComponentVulnResolver{ids: []uuid.UUID{componentID}},
		VulnerabilityCVE:         okVulnCVE("CVE-2026-0706"),
	})

	_, err := r.Run(context.Background(), RunInput{
		TenantID: uuid.New(), ProjectID: uuid.New(),
		VulnerabilityID: uuid.New(), CVEID: "CVE-2026-0706",
		ComponentID: &componentID,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if got := len(drafts.inserted); got != 1 {
		t.Fatalf("expected 1 fallback draft, got %d", got)
	}
	d := drafts.inserted[0]
	// Fallback is already under_investigation — unchanged.
	if d.State != string(StateUnderInvestigation) {
		t.Errorf("fallback draft state should be under_investigation, got %q", d.State)
	}
	// Confidence stays 0 — the strong-verdict rule did NOT run its clamp
	// (which would have set it to UngroundedConfidenceCeiling = 0.35).
	if d.Confidence == nil || *d.Confidence != 0 {
		t.Errorf("fallback confidence must stay 0 (not newly clamped), got %v", d.Confidence)
	}
	// No uncited-strong-verdict synthetic note must have been appended: the
	// only pointer is the original parse_error llm_rationale.
	evs := decodeEvidence(t, d.Evidence)
	for _, ev := range evs {
		if ev.Kind == EvidenceKindAnalyzerError && ev.Note == UngroundedNoteTag {
			t.Errorf("fallback draft must NOT get an ungrounded/strong-verdict note, evidence=%+v", evs)
		}
	}
	if len(evs) != 1 || evs[0].Kind != EvidenceKindLLMRationale {
		t.Errorf("fallback evidence should remain the single llm_rationale pointer, got %+v", evs)
	}
}
