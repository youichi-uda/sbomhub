package service

import "testing"

// Codex M60 R18 High: a vulnerable criterion under a NEGATED node is not
// evidence that the product has CVEs of its own (verification ignores it
// too), so it must not make a platform-only answer "decided".
func TestM60R18_NegatedCriteriaAreNotEvidence(t *testing.T) {
	cve := NVDCVE{Configurations: []NVDConfiguration{{Operator: "AND", Nodes: []NVDConfigNode{
		{Negate: true, CpeMatch: []NVDCPEMatch{{Vulnerable: true, Criteria: "cpe:2.3:a:wrong:guess:*:*:*:*:*:*:*:*"}}},
		{CpeMatch: []NVDCPEMatch{{Vulnerable: false, Criteria: "cpe:2.3:a:wrong:guess:*:*:*:*:*:*:*:*"}}},
	}}, {Negate: true, Nodes: []NVDConfigNode{
		{CpeMatch: []NVDCPEMatch{{Vulnerable: true, Criteria: "cpe:2.3:a:wrong:guess:*:*:*:*:*:*:*:*"}}},
	}}}}
	c := cpeCandidate{part: "a", vendor: "wrong", product: "guess", version: "1.0", raw: "1.0"}
	if productHasVulnerableEvidence(cve, c) {
		t.Errorf("negated vulnerable criteria counted as product evidence")
	}
}

// Codex M60 R18 Low: storage applies the scanner's own usability rule
// (cpeCandidates, purl included) before product dedupe and the cap: a CPE
// whose version normalises to nothing must not shadow a usable one.
func TestM60R18_StorageUsesTheScannersUsabilityRule(t *testing.T) {
	in := []string{
		`cpe:2.3:a:apache:log4j:\+meta:*:*:*:*:*:*:*`, // normalises to "" -> unusable
		"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
	}
	got := normaliseSBOMCPEs(in, "", "")
	if len(got) != 1 || got[0] != in[1] {
		t.Errorf("normaliseSBOMCPEs = %q, want only the usable CPE", got)
	}
}
