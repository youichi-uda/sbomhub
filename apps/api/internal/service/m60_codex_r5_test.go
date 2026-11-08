package service

import (
	"strings"
	"testing"
)

// Codex M60 R5 High: separators carry meaning the tokenizer threw away.
//   - "+" starts SemVer build metadata, which does not take part in ordering
//     ("1.0.0+1" == "1.0.0").
//   - a NUMBER after "-" is a SemVer pre-release ("1.0.0-1" < "1.0.0") but a
//     revision in other schemes (Debian/RPM — stripped earlier for distro
//     packages, but not for everything else). When the order depends on that
//     reading it is undecidable, never guessed.
func TestM60R5_SeparatorsThatChangeTheOrder(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.0.0+1", "1.0.0", 0, true},
		{"1.0.0+build.5", "1.0.1", -1, true},
		{"1.2.3+dfsg", "1.2.3", 0, true},
		{"1.0.0-1", "1.0.0", 0, false},
		{"1.0.0", "1.0.0-1", 0, false},
		{"1.0.0-1", "1.0.0.1", 0, false},
		{"1.0.0-1", "1.0.0-2", -1, true}, // same reading on both sides
		{"1.0.0-1", "1.0.1", -1, true},   // decided before the suffix matters
		{"2.0-beta9", "2.0", -1, true},
		{"2.0-rc1", "2.0-beta9", 1, true},
	} {
		got, ok := compareVersions(tc.a, tc.b)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("compareVersions(%q,%q) = %d,%v want %d,%v", tc.a, tc.b, got, ok, tc.want, tc.ok)
		}
	}
	m := NVDCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionEndExcluding: "1.0.0"}
	crit, _ := parseCPE(m.Criteria)
	if got := criterionContains(crit, m, cpeCandidate{part: "a", vendor: "v", product: "p", version: "1.0.0-1"}); got != cpeUndecidable {
		t.Errorf("1.0.0-1 in (,1.0.0) = %v, want undecidable (kept, not cached)", got)
	}
}

// Codex M60 R5 Low: only strings that PARSE as a usable CPE count toward the
// storage cap; malformed ones with a valid-looking prefix must not push a real
// candidate out.
func TestM60R5_MalformedCPEsDoNotUseTheCap(t *testing.T) {
	var in []string
	for i := 0; i < maxStoredCPEsPerComponent; i++ {
		in = append(in, "cpe:2.3:x:bad"+strings.Repeat("y", i)) // invalid part
	}
	in = append(in, "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	got := normaliseSBOMCPEs(in)
	if len(got) != 1 || got[0] != "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" {
		t.Errorf("normaliseSBOMCPEs = %q, want only the valid CPE", got)
	}
}
