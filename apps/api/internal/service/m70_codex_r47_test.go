package service

import "testing"

// Codex M70 R47 Medium-1: component purl qualifiers are strict key=value.
func TestM70R47_StrictComponentQualifiers(t *testing.T) {
	for _, p := range []string{
		"pkg:deb/debian/openssl@1.1.1k-1?%64istro=debian-11",
		"pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11&arch",
		"pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11&arch=",
		"pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11&",
		"pkg:deb/debian/openssl@1.1.1k-1?=x",
	} {
		if _, ok := parsePurl(p); ok {
			t.Errorf("%s accepted", p)
		}
	}
	tgt, why := distroTargetFor("pkg:deb/debian/openssl@1.1.1k-1?arch=amd64&distro=debian-11", "1.1.1k-1", nil)
	if why != "" || tgt.release != "Debian:11" {
		t.Errorf("Syft purl: %q %+v", why, tgt)
	}
	if _, why := distroTargetFor("pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11&DISTRO=debian-12", "1.1.1k-1", nil); why == "" {
		t.Error("folded duplicate qualifier accepted")
	}
	p, ok := parsePurl("pkg:deb/debian/p@1.0?upstream=p%401.0%2Bdfsg")
	if !ok || p.qualifiers.Get("upstream") != "p@1.0+dfsg" {
		t.Errorf("percent-decoding: %+v %v", p, ok)
	}
}
