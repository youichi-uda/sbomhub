package service

import (
	"strings"
	"testing"
)

// Codex M60 R16 Medium: a criterion may name a concrete version AND carry
// range bounds; every version it involves counts, so it is undecidable
// rather than decided on the version attribute alone.
func TestM60R16_ConcreteVersionWithBoundsIsUndecidable(t *testing.T) {
	c := cpeCandidate{part: "a", vendor: "acme", product: "widget", version: "1.0", raw: "1.0"}
	for _, m := range []NVDCPEMatch{
		{Vulnerable: true, Criteria: "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", VersionEndExcluding: "1.0-beta9"},
		{Vulnerable: true, Criteria: "cpe:2.3:a:acme:widget:2.0:*:*:*:*:*:*:*", VersionStartIncluding: "0.9"},
	} {
		crit, _ := parseCPE(m.Criteria)
		if got := criterionContains(crit, m, c); got != cpeUndecidable {
			t.Errorf("%s %+v = %v, want undecidable", m.Criteria, m, got)
		}
	}
}

// Codex M60 R16 Low: storage dedupes on the same product identity the
// scanner uses (it only ever tries the first usable CPE of a product), so
// many versions of one product cannot push another product out.
func TestM60R16_StorageDedupesByProductLikeTheScanner(t *testing.T) {
	var in []string
	for i := 0; i < maxStoredCPEsPerComponent; i++ {
		in = append(in, "cpe:2.3:a:acme:widget:1."+strings.Repeat("1", i+1)+":*:*:*:*:*:*:*")
	}
	in = append(in, "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	got := normaliseSBOMCPEs(in, "1.0")
	if len(got) != 2 || got[0] != in[0] || got[1] != in[len(in)-1] {
		t.Errorf("normaliseSBOMCPEs = %q, want the first acme CPE and log4j", got)
	}
}
