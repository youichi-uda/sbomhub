package service

import "testing"

// Codex M60 R13 High: "dev", "pre", "preview" are ordered differently by the
// supported schemes (Maven: an unknown qualifier sorts AFTER the release;
// PEP 440: dev before, pre/preview = rc), and a bare "c" is PEP 440's rc but
// an OpenSSL patch letter. Against the release they are undecidable.
func TestM60R13_SchemeDependentQualifiersAreUndecidable(t *testing.T) {
	for _, tc := range []struct{ a, b string }{
		{"1.0-dev", "1.0"}, {"1.0-pre1", "1.0"}, {"1.0-preview", "1.0"}, {"1.0c", "1.0"}, {"1.0.2c", "1.0.2"},
	} {
		if c, ok := compareVersions(tc.a, tc.b); ok {
			t.Errorf("compareVersions(%q,%q) = %d decided; want undecidable", tc.a, tc.b, c)
		}
	}
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0-alpha1", "1.0", -1}, {"1.0-rc1", "1.0", -1}, {"1.0c1", "1.0", -1}, {"9.0.0.M1", "9.0.0", -1},
		{"1.0-SNAPSHOT", "1.0", -1}, {"1.0.2d", "1.0.2", 1}, {"1.1.1k", "1.1.1", 1},
	} {
		if c, ok := compareVersions(tc.a, tc.b); !ok || c != tc.want {
			t.Errorf("compareVersions(%q,%q) = %d,%v want %d", tc.a, tc.b, c, ok, tc.want)
		}
	}
	m := NVDCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionStartIncluding: "1.0"}
	crit, _ := parseCPE(m.Criteria)
	if got := criterionContains(crit, m, cpeCandidate{part: "a", vendor: "v", product: "p", version: "1.0-dev"}); got != cpeUndecidable {
		t.Errorf("1.0-dev in [1.0,) = %v, want undecidable", got)
	}
}

// Codex M60 R13 Medium: a CPE 2.3 formatted string has no empty attributes.
func TestM60R13_EmptyCPE23AttributeIsRejected(t *testing.T) {
	if _, ok := parseCPE("cpe:2.3:a:acme:widget::*:*:*:*:*:*:*"); ok {
		t.Errorf("parseCPE accepted an empty version attribute")
	}
	cve := NVDCVE{Configurations: []NVDConfiguration{{Nodes: []NVDConfigNode{{CpeMatch: []NVDCPEMatch{
		{Vulnerable: true, Criteria: "cpe:2.3:a:acme:widget::*:*:*:*:*:*:*"},
	}}}}}}
	if got := verifyCPEMatch(cve, cpeCandidate{part: "a", vendor: "acme", product: "widget", version: "1.0"}); got == cpeMatched {
		t.Errorf("malformed criterion verified as a match")
	}
	if _, ok := parseCPE("cpe:/a:acme:widget"); !ok {
		t.Errorf("CPE 2.2 with omitted trailing fields must stay valid")
	}
}
