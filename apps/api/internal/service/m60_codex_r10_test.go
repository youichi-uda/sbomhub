package service

import (
	"strings"
	"testing"
)

// Codex M60 R10 High-2: tokens that are equal in value but structured
// differently are not equal versions — SemVer orders "rc.1" (two
// identifiers) before "rc1" (one). Corresponding tokens joined by different
// separators make the comparison undecidable ('_' is read as '.').
func TestM60R10_SeparatorStructureMustMatch(t *testing.T) {
	for _, tc := range []struct{ a, b string }{
		{"1.0.0-rc.1", "1.0.0-rc1"},
		{"1.0.0-rc.3", "1.0.0-rc2"},
		{"2.0-beta.1", "2.0-beta1"},
	} {
		if c, ok := compareVersions(tc.a, tc.b); ok {
			t.Errorf("compareVersions(%q,%q) = %d decided; want undecidable", tc.a, tc.b, c)
		}
	}
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1_2_3", "1.2.3", 0},
		{"1.0.0-rc.1", "1.0.0-rc.2", -1},
		{"2.14.1", "2.15.0", -1},
	} {
		if c, ok := compareVersions(tc.a, tc.b); !ok || c != tc.want {
			t.Errorf("compareVersions(%q,%q) = %d,%v want %d", tc.a, tc.b, c, ok, tc.want)
		}
	}
	m := NVDCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionEndExcluding: "1.0.0-rc1"}
	crit, _ := parseCPE(m.Criteria)
	if got := criterionContains(crit, m, cpeCandidate{part: "a", vendor: "v", product: "p", version: "1.0.0-rc.1"}); got != cpeUndecidable {
		t.Errorf("1.0.0-rc.1 in (,1.0.0-rc1) = %v, want undecidable", got)
	}
}

// Codex M60 R10 Medium: storage dedupe uses the scanner's product identity,
// so CPEs for one product that differ only in attributes the scanner ignores
// do not use up the cap and push a different product out.
func TestM60R10_StoredCPEsDedupeByProduct(t *testing.T) {
	var in []string
	for i := 0; i < maxStoredCPEsPerComponent; i++ {
		in = append(in, "cpe:2.3:a:acme:widget:1.0:*:*:*:*:t"+strings.Repeat("x", i)+":*:*")
	}
	in = append(in, "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	got := normaliseSBOMCPEs(in)
	if len(got) != 2 || got[0] != in[0] || got[1] != in[len(in)-1] {
		t.Errorf("normaliseSBOMCPEs = %q, want the first acme CPE and the log4j one", got)
	}
}
