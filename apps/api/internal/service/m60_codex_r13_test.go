package service

import "testing"

// Codex M60 R13 Medium: a CPE 2.3 formatted string has no empty attributes.
func TestM60R13_EmptyCPE23AttributeIsRejected(t *testing.T) {
	if _, ok := parseCPE("cpe:2.3:a:acme:widget::*:*:*:*:*:*:*"); ok {
		t.Errorf("parseCPE accepted an empty version attribute")
	}
	cve := NVDCVE{Configurations: []NVDConfiguration{{Nodes: []NVDConfigNode{{CpeMatch: []NVDCPEMatch{
		{Vulnerable: true, Criteria: "cpe:2.3:a:acme:widget::*:*:*:*:*:*:*"},
	}}}}}}
	if got := verifyCPEMatch(cve, cpeCandidate{part: "a", vendor: "acme", product: "widget", version: "1.0", raw: "1.0"}); got == cpeMatched {
		t.Errorf("malformed criterion verified as a match")
	}
	if _, ok := parseCPE("cpe:/a:acme:widget"); !ok {
		t.Errorf("CPE 2.2 with omitted trailing fields must stay valid")
	}
}
