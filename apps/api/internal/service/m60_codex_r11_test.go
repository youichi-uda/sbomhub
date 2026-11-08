package service

import (
	"reflect"
	"testing"
)

// Codex M60 R11 High: a candidate whose CPE update is ANY ("2.0:*", Syft's
// default) is not "the final release": against a criterion pinning an update
// of the same version ("2.0:sp1") it is undecidable — kept, unverified, not
// cached. Since M60 decision 1 (option B) a criterion that pins an update is
// never plain, so it is undecidable for EVERY candidate (even "2.0:-" or a
// different base version: a vendor may label 2.0 SP1 as 2.0.1).
func TestM60R11_CandidateUpdateAnyIsNotFinalOnly(t *testing.T) {
	cve := NVDCVE{Configurations: []NVDConfiguration{{Nodes: []NVDConfigNode{{CpeMatch: []NVDCPEMatch{
		{Vulnerable: true, Criteria: "cpe:2.3:a:v:widget:2.0:sp1:*:*:*:*:*:*"},
	}}}}}}
	anyUpd := cpeCandidates([]string{"cpe:2.3:a:v:widget:2.0:*:*:*:*:*:*:*"}, "", "")
	na := cpeCandidates([]string{"cpe:2.3:a:v:widget:2.0:-:*:*:*:*:*:*"}, "", "")
	other := cpeCandidates([]string{"cpe:2.3:a:v:widget:2.1:*:*:*:*:*:*:*"}, "", "")
	if len(anyUpd) != 1 || len(na) != 1 || len(other) != 1 {
		t.Fatalf("candidates: %v %v %v", anyUpd, na, other)
	}
	if got := verifyCPEMatch(cve, anyUpd[0]); got != cpeUndecidable {
		t.Errorf("2.0:* vs criterion 2.0:sp1 = %v, want undecidable", got)
	}
	if got := verifyCPEMatch(cve, na[0]); got != cpeUndecidable {
		t.Errorf("2.0:- (final) vs criterion 2.0:sp1 = %v, want undecidable", got)
	}
	if got := verifyCPEMatch(cve, other[0]); got != cpeUndecidable {
		t.Errorf("2.1:* vs criterion 2.0:sp1 = %v, want undecidable", got)
	}
	// Log4Shell lists log4j 2.0:- and 2.0:beta9 ...: a plain "2.0" component
	// still MATCHES (via 2.0:-), so the change costs nothing there.
	r := m60NVDFixture(t, "p01_cpename_log4j")
	for _, e := range r.entries() {
		if e.CVE.ID == "CVE-2021-44228" {
			c := cpeCandidates([]string{"cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"}, "", "")[0]
			if got := verifyCPEMatch(e.CVE, c); got != cpeMatched {
				t.Errorf("log4j 2.0 vs CVE-2021-44228 = %v, want matched", got)
			}
		}
	}
}

// Codex M60 R11 Medium: storage dedupe must not let a version-less CPE of a
// product shadow a versioned CPE of the same product (with no component
// version, only the versioned one is usable).
func TestM60R11_VersionlessCPEDoesNotShadowVersionedOne(t *testing.T) {
	in := []string{"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
	if got := normaliseSBOMCPEs(in, "1.0"); !reflect.DeepEqual(got, in) {
		t.Fatalf("normaliseSBOMCPEs = %q, want both", got)
	}
	cs := cpeCandidates(in, "", "")
	if len(cs) != 1 || cs[0].version != "2.14.1" {
		t.Errorf("candidates = %v, want log4j@2.14.1", cs)
	}
}
