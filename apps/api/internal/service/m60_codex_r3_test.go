package service

import (
	"testing"
)

// Codex M60 R3 High: shorthand pre-releases ("1.0a1", "1.0b1", PEP 440 /
// Maven style) were read as post-releases, so "1.0a1" fell outside a
// `versionEndExcluding: 1.0` range and the empty answer was cacheable. And an
// alphabetic suffix the comparator does not know must be UNDECIDABLE (kept,
// labelled nvd_cpe_unverified, not cached) rather than guessed.
func TestM60R3_ShorthandPreReleasesAndUnknownSuffixes(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.0a1", "1.0", -1, true},
		{"1.0b1", "1.0", -1, true},
		{"1.0a1", "1.0b1", -1, true},
		{"1.0b2", "1.0rc1", -1, true},
		{"1.0rc1", "1.0", -1, true},
		{"1.1.1k", "1.1.1", 1, true}, // OpenSSL: a bare letter is a patch release (a/b: see R6)
		{"1.1.1za", "1.1.1z", 1, true},
		{"4.1.100.Final", "4.1.100", 0, true}, // Maven release marker
		{"4.1.108.Final", "4.1.100", 1, true},
		{"5.3.18.RELEASE", "5.3.18", 0, true},
		{"1.0.post1", "1.0", 0, false},   // unknown qualifier: not guessed
		{"1.2.3+dfsg", "1.2.3", 0, true}, // SemVer build metadata (Codex M60 R5)
		{"2.0-final2", "2.0", 0, false},
	} {
		got, ok := compareVersions(tc.a, tc.b)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("compareVersions(%q,%q) = %d,%v want %d,%v", tc.a, tc.b, got, ok, tc.want, tc.ok)
		}
	}
	vs := []string{"0.9", "1.0a1", "1.0a2", "1.0b1", "1.0-beta2", "1.0rc1", "1.0", "1.0.Final", "1.0.0", "1.0a", "1.0.1",
		"1.1.1", "1.1.1a", "1.1.1k", "1.1.1m", "1.1.1za", "9.0.0.M1", "9.0.0.M2", "9.0.0"}
	for i := range vs {
		for j := range vs {
			// A pair may be undecidable ("1.0a" vs "1.0.1": a patch letter
			// against a number), but then in BOTH directions; decided pairs
			// must be antisymmetric and decided triples transitive.
			c1, ok1 := compareVersions(vs[i], vs[j])
			c2, ok2 := compareVersions(vs[j], vs[i])
			if ok1 != ok2 || (ok1 && c1 != -c2) {
				t.Errorf("not antisymmetric: %q vs %q = %d,%v / %d,%v", vs[i], vs[j], c1, ok1, c2, ok2)
				continue
			}
			if !ok1 {
				continue
			}
			for k := range vs {
				c3, ok3 := compareVersions(vs[j], vs[k])
				c4, ok4 := compareVersions(vs[i], vs[k])
				if ok3 && ok4 && c1 < 0 && c3 < 0 && c4 >= 0 {
					t.Errorf("not transitive: %q < %q < %q but %q !< %q", vs[i], vs[j], vs[k], vs[i], vs[k])
				}
			}
		}
	}

	m := NVDCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionEndExcluding: "1.0"}
	crit, _ := parseCPE(m.Criteria)
	if got := criterionContains(crit, m, cpeCandidate{part: "a", vendor: "v", product: "p", version: "1.0a1"}); got != cpeMatched {
		t.Errorf("1.0a1 in (,1.0) = %v, want matched", got)
	}
	if got := criterionContains(crit, m, cpeCandidate{part: "a", vendor: "v", product: "p", version: "1.0.post1"}); got != cpeUndecidable {
		t.Errorf("1.0.post1 in (,1.0) = %v, want undecidable", got)
	}
}

// Codex M60 R3 Low: when no CPE candidate survives, the lookup is the plain
// keyword search whatever the purl says, so distro-ness must not split the
// work item (two identical keyword walks on a cold cache).
func TestM60R3_DistroDoesNotSplitKeywordOnlyWork(t *testing.T) {
	a := nvdWorkKey("openssl", "1.1.1k", nil, "pkg:deb/debian/openssl@1.1.1k")
	b := nvdWorkKey("openssl", "1.1.1k", nil, "pkg:generic/openssl@1.1.1k")
	if a != b {
		t.Errorf("keyword-only items split by distro-ness: %+v vs %+v", a, b)
	}
	cpe := []string{"cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"}
	if nvdWorkKey("openssl", "1.1.1k", cpe, "pkg:deb/debian/openssl@1.1.1k") ==
		nvdWorkKey("openssl", "1.1.1k", cpe, "pkg:generic/openssl@1.1.1k") {
		t.Errorf("CPE items with different labels (distro vs not) share a key")
	}
}
