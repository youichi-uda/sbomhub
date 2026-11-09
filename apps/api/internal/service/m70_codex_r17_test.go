package service

import "testing"

// Codex M70 R17 Medium-2: surrounding whitespace (any Unicode space) in the
// component's version or name is malformed data, not trimmed away.
func TestM70R17_NoTrimmingOfIdentity(t *testing.T) {
	for _, v := range []string{" 1.1.1k-1 ", " 1.1.1k-1", "1.1.1k-1\t"} {
		if _, reason := distroTargetFor("pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11", v, nil); reason == "" {
			t.Errorf("component version %q accepted", v)
		}
	}
	if _, reason := distroTargetFor("pkg:deb/debian/openssl@%201.1.1k-1?distro=debian-11", "", nil); reason == "" {
		t.Error("purl version with a leading space accepted")
	}
	if purlNameAgrees("pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11", " openssl") {
		t.Error("a name with surrounding whitespace agreed")
	}
}
