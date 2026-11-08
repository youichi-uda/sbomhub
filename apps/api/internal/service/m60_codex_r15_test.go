package service

import "testing"

// Codex M60 R15 High: a CPE that pins an update keeps it even when its
// version attribute is ANY ("widget:*:beta" + component version 2.0): the
// candidate is 2.0 + beta — not plain — so nothing may be excluded by
// comparison.
func TestM60R15_UpdateIsKeptWhenCPEVersionIsAny(t *testing.T) {
	cs := cpeCandidates([]string{"cpe:2.3:a:acme:widget:*:beta:*:*:*:*:*:*"}, "2.0", "")
	if len(cs) != 1 || cs[0].update != "beta" || cs[0].plain() {
		t.Fatalf("candidate = %+v, want update beta, not plain", cs)
	}
	m := NVDCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", VersionEndExcluding: "2.0"}
	crit, _ := parseCPE(m.Criteria)
	if got := criterionContains(crit, m, cs[0]); got != cpeUndecidable {
		t.Errorf("2.0:beta vs (,2.0) = %v, want undecidable", got)
	}
	na := cpeCandidates([]string{"cpe:2.3:a:acme:widget:*:-:*:*:*:*:*:*"}, "2.0", "")
	if len(na) != 1 || !na[0].updateNA {
		t.Errorf("NA update lost for a version-ANY CPE: %+v", na)
	}
}

// Codex M60 R15 Medium: an unbounded criterion restricted to the final
// release ("widget:*:-") does not prove that a candidate pinning an update
// (2.0:beta) is affected.
func TestM60R15_UnboundedNACriterionVsPinnedUpdateIsUndecidable(t *testing.T) {
	c := cpeCandidate{part: "a", vendor: "acme", product: "widget", version: "2.0", update: "beta", raw: "2.0"}
	m := NVDCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:acme:widget:*:-:*:*:*:*:*:*"}
	crit, _ := parseCPE(m.Criteria)
	if got := criterionContains(crit, m, c); got != cpeUndecidable {
		t.Errorf("*:- vs 2.0:beta = %v, want undecidable", got)
	}
	plainC := cpeCandidate{part: "a", vendor: "acme", product: "widget", version: "2.0", raw: "2.0"}
	if got := criterionContains(crit, m, plainC); got != cpeMatched {
		t.Errorf("*:- vs plain 2.0 = %v, want matched", got)
	}
}
