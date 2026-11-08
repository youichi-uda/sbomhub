package service

import "testing"

// Codex M60 R24 Medium: whether a non-plain version ("2.0-beta9") is a FINAL
// release is not decidable, so an unbounded criterion restricted to final
// releases ("widget:*:-") cannot verify it — undecidable, kept unverified.
// Plain and explicitly-NA candidates still match.
func TestM60R24_NACriterionCannotVerifyANonPlainCandidate(t *testing.T) {
	m := NVDCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:acme:widget:*:-:*:*:*:*:*:*"}
	crit, _ := parseCPE(m.Criteria)
	for _, tc := range []struct {
		c    cpeCandidate
		want cpeVerdict
	}{
		{cpeCandidate{part: "a", vendor: "acme", product: "widget", version: "2.0-beta9", raw: "2.0-beta9"}, cpeUndecidable},
		{cpeCandidate{part: "a", vendor: "acme", product: "widget", version: "1.1.1k", raw: "1.1.1k-1"}, cpeUndecidable},
		{cpeCandidate{part: "a", vendor: "acme", product: "widget", version: "2.0", raw: "2.0"}, cpeMatched},
		{cpeCandidate{part: "a", vendor: "acme", product: "widget", version: "2.0-beta9", raw: "2.0-beta9", updateNA: true}, cpeMatched},
	} {
		if got := criterionContains(crit, m, tc.c); got != tc.want {
			t.Errorf("*:- vs %+v = %v, want %v", tc.c, got, tc.want)
		}
	}
}
