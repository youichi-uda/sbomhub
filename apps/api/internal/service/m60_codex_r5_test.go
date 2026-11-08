package service

import (
	"strings"
	"testing"
)

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
