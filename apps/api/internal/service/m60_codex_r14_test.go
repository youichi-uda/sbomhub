package service

import (
	"encoding/json"
	"strings"
	"testing"
)

// Codex M60 R14 High-1: whether a comparison may exclude depends on the RAW
// version (option B), so plain "2.31" and distro "2.31-13" — same query —
// must not share a cache entry or a work item: the plain one may cache a
// narrower verified answer than the distro one is entitled to.
func TestM60R14_IdentityIncludesComparisonMode(t *testing.T) {
	plainC := cpeCandidates([]string{"cpe:2.3:a:gnu:glibc:*:*:*:*:*:*:*:*"}, "2.31", "pkg:generic/glibc@2.31")[0]
	distroC := cpeCandidates([]string{"cpe:2.3:a:gnu:glibc:*:*:*:*:*:*:*:*"}, "2.31-13", "pkg:deb/debian/libc6@2.31-13")[0]
	if plainC.query() != distroC.query() {
		t.Fatalf("precondition: same query expected (%q / %q)", plainC.query(), distroC.query())
	}
	if nvdCPECacheName(plainC) == nvdCPECacheName(distroC) {
		t.Errorf("plain and non-plain candidates share a cache key")
	}
	cpes := []string{"cpe:2.3:a:gnu:glibc:*:*:*:*:*:*:*:*"}
	if nvdWorkKey("glibc", "2.31", cpes, "pkg:generic/glibc@2.31") == nvdWorkKey("glibc", "2.31-13", cpes, "pkg:generic/glibc@2.31-13") {
		t.Errorf("plain and non-plain components share a work item")
	}
}

// Codex M60 R14 High-2: only an EXPLICIT vulnerable=false is the platform
// evidence that may drop a CVE. A criterion whose `vulnerable` is absent (a
// malformed mirror answer) is not evidence: undecidable, kept.
func TestM60R14_AbsentVulnerableIsNotPlatformEvidence(t *testing.T) {
	var cve NVDCVE
	if err := json.Unmarshal([]byte(`{"id":"CVE-2099-0001","configurations":[{"nodes":[{"cpeMatch":[
		{"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*","versionEndExcluding":"9.0"}]}]}]}`), &cve); err != nil {
		t.Fatal(err)
	}
	c := cpeCandidate{part: "a", vendor: "acme", product: "widget", version: "1.0", raw: "1.0"}
	if got := verifyCPEMatch(cve, c); got != cpeUndecidable {
		t.Errorf("criterion without `vulnerable` = %v, want undecidable", got)
	}
	var explicit NVDCVE
	if err := json.Unmarshal([]byte(`{"id":"CVE-2099-0002","configurations":[{"nodes":[{"cpeMatch":[
		{"vulnerable":false,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}]}]}]}`), &explicit); err != nil {
		t.Fatal(err)
	}
	if got := verifyCPEMatch(explicit, c); got != cpeRejected {
		t.Errorf("explicit vulnerable=false = %v, want rejected (platform-only)", got)
	}
}

// Codex M60 R14 Medium: a criterion that pins an update is undecidable
// whatever its version attribute — including "*" with or without bounds.
func TestM60R14_PinnedUpdateOnWildcardVersionIsUndecidable(t *testing.T) {
	c := cpeCandidate{part: "a", vendor: "acme", product: "widget", version: "5.0", raw: "5.0"}
	for _, m := range []NVDCPEMatch{
		{Vulnerable: true, Criteria: "cpe:2.3:a:acme:widget:*:beta:*:*:*:*:*:*"},
		{Vulnerable: true, Criteria: "cpe:2.3:a:acme:widget:*:beta:*:*:*:*:*:*", VersionEndExcluding: "2.0"},
	} {
		crit, _ := parseCPE(m.Criteria)
		if got := criterionContains(crit, m, c); got != cpeUndecidable {
			t.Errorf("%s %+v = %v, want undecidable", m.Criteria, m, got)
		}
	}
}

// Codex M60 R14 Low: with no component version a version-less CPE can never
// become a candidate, so it must not use up the storage cap.
func TestM60R14_UnusableWildcardCPEsDoNotUseTheCap(t *testing.T) {
	var in []string
	for i := 0; i < maxStoredCPEsPerComponent; i++ {
		in = append(in, "cpe:2.3:a:acme:w"+strings.Repeat("x", i)+":*:*:*:*:*:*:*:*")
	}
	in = append(in, "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	got := normaliseSBOMCPEs(in, "", "")
	if len(got) != 1 || got[0] != "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" {
		t.Errorf("no component version: kept %q, want only the versioned CPE", got)
	}
	if got := normaliseSBOMCPEs(in, "1.0", ""); len(got) != maxStoredCPEsPerComponent {
		t.Errorf("with a component version the wildcard CPEs are usable: kept %d, want the cap", len(got))
	}
}
