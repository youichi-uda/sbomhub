package service

import "testing"

// Codex M70 R7 High-1: the NVD link may have been made on the version a CPE
// states; when that differs from the component's version, the distro verdict
// would be about another version than the link. No target.
func TestM70R7_CPEVersionMustAgree(t *testing.T) {
	for _, c := range []struct {
		cpes    []string
		version string
		agree   bool
	}{
		{[]string{"cpe:2.3:a:openssl:openssl:1.1.1k-1:*:*:*:*:*:*:*"}, "1.1.1k-1", true},
		{[]string{"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"}, "1.1.1k-1", true}, // ANY: the component version is used
		{[]string{"cpe:2.3:a:zlib:zlib:1\\:1.2.11.dfsg-2\\+deb11u2:*:*:*:*:*:*:*"}, "1:1.2.11.dfsg-2+deb11u2", true},
		{nil, "1.1.1k-1", true},
		{[]string{"cpe:2.3:a:openssl:openssl:1.0:*:*:*:*:*:*:*"}, "2.0-1", false},
		{[]string{"cpe:2.3:a:openssl:openssl:2.0-1:*:*:*:*:*:*:*", "cpe:2.3:a:openssl:libssl:1.0:*:*:*:*:*:*:*"}, "2.0-1", false},
		{[]string{"not a cpe"}, "2.0-1", true}, // never a candidate, never used by NVD
	} {
		if got := cpeVersionsAgree(c.cpes, c.version); got != c.agree {
			t.Errorf("%v / %q = %v, want %v", c.cpes, c.version, got, c.agree)
		}
	}
}

// Codex M70 R7 High-2: a Pro/ESM marker on the BINARY version counts even
// when an upstream qualifier states a standard source version.
func TestM70R7_ProMarkerOnBinaryVersion(t *testing.T) {
	purl := "pkg:deb/ubuntu/libssl1.1@1.1.1f-1ubuntu2.20+esm1?distro=ubuntu-20.04&upstream=openssl%401.1.1f-1ubuntu2.20"
	if _, reason := distroTargetFor(purl, "", nil); reason != "ubuntu_pro_stream" {
		t.Errorf("reason %q, want ubuntu_pro_stream", reason)
	}
}

// Codex M70 R7 Medium-3: OSV's versions list is exact string membership.
func TestM70R7_VersionsListIsExactStrings(t *testing.T) {
	dpkg := distroTarget{scheme: schemeDpkg}.comparator()
	if r := evalEntry("1.0", distroEntry{Versions: []string{"1.0-0"}}, dpkg); r.state != entryUndecidable {
		t.Errorf("1.0 vs listed 1.0-0 = %+v, want undecidable (not listed)", r)
	}
	if r := evalEntry("1.0-0", distroEntry{Versions: []string{"1.0-0"}}, dpkg); r.state != entryAffected {
		t.Errorf("exact listing = %+v, want affected", r)
	}
}

// Codex M70 R7 Medium-4: release numbers with leading zeros are not
// canonical.
func TestM70R7_ReleaseLeadingZeros(t *testing.T) {
	for _, purl := range []string{
		"pkg:deb/debian/openssl@1.1.1k-1?distro=debian-011",
		"pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11.07",
		"pkg:rpm/almalinux/openssl@3.0.7-27.el9?distro=almalinux-009",
	} {
		if _, reason := distroTargetFor(purl, "", nil); reason != "unknown_release" {
			t.Errorf("%s: %q, want unknown_release", purl, reason)
		}
	}
	if _, reason := distroTargetFor("pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11.0", "", nil); reason != "" {
		t.Errorf("debian-11.0: %q", reason)
	}
}
