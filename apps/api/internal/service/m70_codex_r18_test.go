package service

import (
	"fmt"
	"testing"
)

// Codex M70 R18 High-1: payloads of earlier versions are misses.
func TestM70R18_PayloadVersionBumped(t *testing.T) {
	if distroCachePayloadVersion < 8 {
		t.Errorf("payload version %d: entries written before the R16 / R18 fixes would still be read", distroCachePayloadVersion)
	}
}

// Codex M70 R18 High-2: identity and version strings in an OSV answer are
// canonical (no surrounding/embedded whitespace in names and versions, no
// controls or non-ASCII anywhere): the query fails otherwise.
func TestM70R18_OSVIdentityStringsAreCanonical(t *testing.T) {
	for _, extra := range []string{
		`{"package":{"name":"p ","ecosystem":"Debian:11"}}`,
		`{"package":{"name":"p","ecosystem":" Debian:11"}}`,
		`{"package":{"name":"p","ecosystem":"Debian:11"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":" 3.0-1"}]}]}`,
		`{"package":{"name":"p","ecosystem":"Debian:11"},"versions":["1.0-1 "]}`,
		`{"package":{"name":"pé","ecosystem":"Debian:11"}}`,
	} {
		rec := fmt.Sprintf(`{"id":"DEBIAN-CVE-2026-0001","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:12"}},%s]}`, extra)
		if err := r15Query(t, `{"vulns":[`+r15OK+`,`+rec+`]}`); err == nil {
			t.Errorf("accepted %s", extra)
		}
	}
	// "Rocky Linux:9" keeps its inner space.
	ok := `{"vulns":[{"id":"RLSA-1","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}},{"package":{"name":"q","ecosystem":"Rocky Linux:9"}}]}]}`
	if err := r15Query(t, ok); err != nil {
		t.Errorf("an inner space in an ecosystem refused: %v", err)
	}
}

// Codex M70 R18 Medium-3: values reconstructed from qualifiers are checked
// too.
func TestM70R18_QualifierDerivedValuesAreCanonical(t *testing.T) {
	for _, purl := range []string{
		"pkg:deb/debian/linux-image@2.0-1?distro=debian-11&upstream=linux%40%202.0-1%20",
		"pkg:deb/debian/libc6@2.31-13?distro=debian-11&upstream=%20glibc",
		"pkg:rpm/almalinux/openssl@3.0.7-27.el9?distro=almalinux-9&epoch=%201",
		"pkg:deb/debian/openssl@1.1.1k-1?distro=debian-%2011",
		" pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11",
	} {
		if tgt, reason := distroTargetFor(purl, "", nil); reason == "" {
			t.Errorf("%q accepted as %+v", purl, tgt)
		}
	}
}
