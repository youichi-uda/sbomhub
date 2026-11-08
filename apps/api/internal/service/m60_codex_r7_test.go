package service

import (
	"strings"
	"testing"
)

// Codex M60 R7 Low: a CPE whose version is NA can never become a candidate
// (R6), so it must not use up the storage cap.
func TestM60R7_VersionNACPEsDoNotUseTheCap(t *testing.T) {
	var in []string
	for i := 0; i < maxStoredCPEsPerComponent; i++ {
		in = append(in, "cpe:2.3:a:acme:w"+strings.Repeat("x", i)+":-:*:*:*:*:*:*:*")
	}
	in = append(in, "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	got := normaliseSBOMCPEs(in, "1.0", "")
	if len(got) != 1 || got[0] != "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" {
		t.Errorf("normaliseSBOMCPEs = %q, want only the usable CPE", got)
	}
}
