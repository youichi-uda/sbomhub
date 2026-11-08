package service

import (
	"strings"
	"testing"
)

// Codex M60 R1 High-1: a CPE's `update` attribute is part of the release it
// names (NVD writes log4j 2.0-beta9 as `log4j:2.0:beta9`). Dropping it turned
// a beta9 component into "2.0", which matches final-2.0-only CVEs and misses
// beta-only ones. The update is carried into the query; since M60 decision 1
// (option B) a pinned update is not plain, so local verification keeps every
// such CVE as undecidable rather than deciding it.
func TestM60R1_CPEUpdateAttributeIsPartOfTheVersion(t *testing.T) {
	cs := cpeCandidates([]string{"cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*"}, "", "")
	if len(cs) != 1 {
		t.Fatalf("candidates = %v", cs)
	}
	c := cs[0]
	if !strings.Contains(c.query(), ":log4j:2.0:beta9:") {
		t.Errorf("query %q does not carry the update attribute", c.query())
	}
	r := m60NVDFixture(t, "p01_cpename_log4j")
	for _, e := range r.entries() {
		if e.CVE.ID == "CVE-2021-44228" {
			if got := verifyCPEMatch(e.CVE, c); got != cpeUndecidable {
				t.Errorf("2.0:beta9 vs CVE-2021-44228 (lists log4j:2.0:beta9) = %v, want undecidable (kept)", got)
			}
		}
	}
	// update NA ("-") names the final release; ANY ("*") adds nothing.
	for _, tc := range []struct{ cpe, wantVersion string }{
		{"cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*", "2.0"},
		{"cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", "2.0"},
		{"cpe:/a:apache:log4j:2.0:rc1", "2.0-rc1"},
	} {
		cs := cpeCandidates([]string{tc.cpe}, "", "")
		if len(cs) != 1 || cs[0].effectiveVersion() != tc.wantVersion {
			t.Errorf("%s -> %+v, want effective version %q", tc.cpe, cs, tc.wantVersion)
		}
	}
}

// Codex M60 R1 High-2: a CVE whose configurations are missing (a mirror that
// drops them, or a record NVD has not finished configuring) cannot be
// verified. Rejecting it — then caching the empty answer — reported the
// component clean. Rejection needs POSITIVE evidence: a criterion for the
// product that is not vulnerable or does not cover the version.
func TestM60R1_MissingConfigurationIsUnverifiableNotRejected(t *testing.T) {
	c := cpeCandidate{part: "a", vendor: "apache", product: "log4j", version: "2.14.1", raw: "2.14.1"}
	if got := verifyCPEMatch(NVDCVE{ID: "CVE-2021-44228"}, c); got != cpeUndecidable {
		t.Errorf("no configurations at all = %v, want undecidable (kept)", got)
	}
	other := NVDCVE{ID: "CVE-2099-0001", Configurations: []NVDConfiguration{{Nodes: []NVDConfigNode{{CpeMatch: []NVDCPEMatch{
		{Vulnerable: true, Criteria: "cpe:2.3:a:someone:else:*:*:*:*:*:*:*:*"},
	}}}}}}
	if got := verifyCPEMatch(other, c); got != cpeUndecidable {
		t.Errorf("configurations that never mention the product = %v, want undecidable (kept)", got)
	}
	// Positive evidence still rejects: platform-only, and out of range.
	platform := NVDCVE{Configurations: []NVDConfiguration{{Nodes: []NVDConfigNode{{CpeMatch: []NVDCPEMatch{
		{Vulnerable: false, Criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"},
	}}}}}}
	if got := verifyCPEMatch(platform, c); got != cpeRejected {
		t.Errorf("platform-only = %v, want rejected", got)
	}
	outOfRange := NVDCVE{Configurations: []NVDConfiguration{{Nodes: []NVDConfigNode{{CpeMatch: []NVDCPEMatch{
		{Vulnerable: true, Criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", VersionEndExcluding: "2.0"},
	}}}}}}
	if got := verifyCPEMatch(outOfRange, c); got != cpeRejected {
		t.Errorf("out of range = %v, want rejected", got)
	}
}
