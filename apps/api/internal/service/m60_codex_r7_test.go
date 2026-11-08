package service

import (
	"strings"
	"testing"
)

// Codex M60 R7 High: separators other than '.', '-', '_' (and '+', whose
// tail is build metadata) carry scheme-specific meaning — PEP 440's epoch
// "1!2.0", Debian's pre-release "1.0~1", RPM's "^" — that the tokenizer
// cannot honour. Any comparison involving one is undecidable, so a CVE whose
// range depends on it is kept as nvd_cpe_unverified and not cached.
func TestM60R7_UnsupportedSeparatorsAreUndecidable(t *testing.T) {
	for _, tc := range []struct{ a, b string }{
		{"1!2.0", "2.1"},
		{"1.0~1", "1.0.1"},
		{"1.0^20210101", "1.0"},
		{"2.1", "1!2.0"},
		{"1.0 beta", "1.0"},
	} {
		if c, ok := compareVersions(tc.a, tc.b); ok {
			t.Errorf("compareVersions(%q,%q) = %d decided; want undecidable", tc.a, tc.b, c)
		}
	}
	for _, tc := range []struct{ a, b string }{{"1_2_3", "1_2_4"}, {"2.0-beta9", "2.0"}, {"1.0.0+build~x", "1.0.1"}} {
		if _, ok := compareVersions(tc.a, tc.b); !ok {
			t.Errorf("compareVersions(%q,%q) undecidable; want decided", tc.a, tc.b)
		}
	}
	m := NVDCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionStartIncluding: "2.1"}
	crit, _ := parseCPE(m.Criteria)
	if got := criterionContains(crit, m, cpeCandidate{part: "a", vendor: "v", product: "p", version: "1!2.0"}); got != cpeUndecidable {
		t.Errorf("1!2.0 in [2.1,) = %v, want undecidable", got)
	}
}

// Codex M60 R7 Low: a CPE whose version is NA can never become a candidate
// (R6), so it must not use up the storage cap.
func TestM60R7_VersionNACPEsDoNotUseTheCap(t *testing.T) {
	var in []string
	for i := 0; i < maxStoredCPEsPerComponent; i++ {
		in = append(in, "cpe:2.3:a:acme:w"+strings.Repeat("x", i)+":-:*:*:*:*:*:*:*")
	}
	in = append(in, "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	got := normaliseSBOMCPEs(in)
	if len(got) != 1 || got[0] != "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" {
		t.Errorf("normaliseSBOMCPEs = %q, want only the usable CPE", got)
	}
}
