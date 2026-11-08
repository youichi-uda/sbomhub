package service

import "testing"

// Codex M60 R9 High-1: build metadata is ignored when comparing, so it must
// not be sent in the cpeName query either — "2.0.0+incompatible" names no
// CPE in NVD, the query answers 0, the probe finds the product, and a clean
// answer is cached without any comparison happening.
func TestM60R9_BuildMetadataIsNotQueried(t *testing.T) {
	cs := cpeCandidates([]string{"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}, "v2.0.0+incompatible", "pkg:golang/example.com/widget@v2.0.0+incompatible")
	if len(cs) != 1 || cs[0].version != "2.0.0" {
		t.Fatalf("candidates = %+v, want version 2.0.0", cs)
	}
	if got, want := cs[0].query(), "cpe:2.3:a:acme:widget:2.0.0:*:*:*:*:*:*:*"; got != want {
		t.Errorf("query = %q, want %q", got, want)
	}
	if got := normaliseCPEVersion("1.0+dfsg-2", true); got != "1.0" {
		t.Errorf("distro 1.0+dfsg-2 -> %q, want 1.0", got)
	}
}

// Codex M60 R9 High-2: a release marker is dropped only after '.', as the R8
// comment said; "_final" and an appended "final" are not decided.
func TestM60R9_ReleaseMarkerOnlyAfterDot(t *testing.T) {
	if c, ok := compareVersions("4.1.100.Final", "4.1.100"); !ok || c != 0 {
		t.Errorf("4.1.100.Final vs 4.1.100 = %d,%v want 0", c, ok)
	}
	for _, tc := range []struct{ a, b string }{{"1.0_final", "1.0"}, {"1.0final", "1.0"}, {"1.0", "1.0_ga"}} {
		if c, ok := compareVersions(tc.a, tc.b); ok {
			t.Errorf("compareVersions(%q,%q) = %d decided; want undecidable", tc.a, tc.b, c)
		}
	}
}
