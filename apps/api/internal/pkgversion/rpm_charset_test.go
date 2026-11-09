package pkgversion

import "testing"

// Codex M70 R20 High-1: an EVR's version and release use RPM's character set
// only — letters, digits, '.', '_', '+', '~', '^' (rpm-version(7)). Anything
// else would be compared as a separator ("1>9" == "1.9") instead of refused.
func TestParseRPMEVR_CharacterSet(t *testing.T) {
	for _, bad := range []string{"1>9-1", "1@9-1", "1/9-1", "1?9-1", "1.9-1>", "1.9-a*b", "1,9-1", "1.9-1%2"} {
		if e, err := ParseRPMEVR(bad); err == nil {
			t.Errorf("ParseRPMEVR(%q) = %+v, want an error", bad, e)
		}
	}
	for _, ok := range []string{"1.0_rc1+git~pre^post-1.el9_0", "2:4.18.0-513.5.1.el8_9"} {
		if _, err := ParseRPMEVR(ok); err != nil {
			t.Errorf("ParseRPMEVR(%q): %v", ok, err)
		}
	}
}
