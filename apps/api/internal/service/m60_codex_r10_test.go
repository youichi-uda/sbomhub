package service

import (
	"strings"
	"testing"
)

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
