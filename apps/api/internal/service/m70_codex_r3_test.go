package service

import (
	"context"
	"testing"
	"time"
)

// Codex M70 R3 High-1: the purl version and the component version must agree;
// the NVD link was made on the component version.
func TestM70R3_PurlAndComponentVersionMustAgree(t *testing.T) {
	for _, c := range []struct{ purl, version, reason string }{
		{"pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.20?distro=ubuntu-20.04", "1.1.1f-1ubuntu2.1", "version_mismatch"},
		{"pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11", "1.1.1k-1", ""},
		{"pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11", "0:1.1.1k-1", ""}, // the same version
		{"pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11", "", ""},
		{"pkg:rpm/almalinux/openssl@3.0.7-27.el9?epoch=1&distro=almalinux-9", "1:3.0.7-27.el9", ""},
		{"pkg:rpm/almalinux/openssl@3.0.7-27.el9?epoch=1&distro=almalinux-9", "3.0.7-27.el9", ""}, // Syft's component version has no epoch
		{"pkg:rpm/almalinux/openssl@3.0.7-27.el9?epoch=1&distro=almalinux-9", "3.0.7-28.el9", "version_mismatch"},
		// The component version is the binary's; with upstream=name@version
		// the SOURCE version is compared, but the binary still has to agree.
		{"pkg:deb/debian/linux-image-5.10.0-8-amd64@5.10.46-4?distro=debian-11&upstream=linux-signed-amd64%405.10.46%2B4", "5.10.46-5", "version_mismatch"},
	} {
		if _, reason := distroTargetFor(c.purl, c.version, nil); reason != c.reason {
			t.Errorf("%s / %q: reason %q, want %q", c.purl, c.version, reason, c.reason)
		}
	}
}

// Codex M70 R3 High-2: rpm distros take numeric releases only.
func TestM70R3_RPMReleaseIsNumeric(t *testing.T) {
	for _, rel := range []string{"stretch", "bullseye", "nine"} {
		if _, reason := distroTargetFor("pkg:rpm/almalinux/openssl@3.0.7-27.el9?distro=almalinux-"+rel, "", nil); reason != "unknown_release" {
			t.Errorf("almalinux-%s: %q", rel, reason)
		}
	}
}

// Codex M70 R3 High-3: a Debian ecosystem with an unknown suffix blocks the
// later_releases proof even when its major number is not later.
func TestM70R3_UnknownDebianSuffixBlocksLaterReleases(t *testing.T) {
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", version: "2.0-1", scheme: schemeDpkg}
	r := rec("DEBIAN-CVE-2021-0001", []string{"CVE-2021-0001"}, entry("Debian:12", "i", "0", "f", "1.0-1"), entry("Debian:11.sid", "i", "0"))
	if d := indexDistroRecords([]distroRecord{r}).decide(deb11, "CVE-2021-0001"); d.verdict != verdictNone {
		t.Errorf("= %+v, want no verdict", d)
	}
	for in, want := range map[string]int{"Debian:12": 12, "Debian:6.0": 6, "Debian:3.1": 3} {
		if n, ok := debianEcosystemMajor(in); !ok || n != want {
			t.Errorf("%s -> %d %v", in, n, ok)
		}
	}
	for _, bad := range []string{"Debian:11.sid", "Debian:12.", "Debian:sid", "Debian:1x", "Debian:12.0.1"} {
		if n, ok := debianEcosystemMajor(bad); ok {
			t.Errorf("%s parsed as %d", bad, n)
		}
	}
}

// Codex M70 R3 High-4: a multi-CVE erratum covering several binary packages
// does not say which CVE concerns which package.
func TestM70R3_MultiPackageErratumDoesNotSpeak(t *testing.T) {
	alma := distroTarget{family: "almalinux", query: "AlmaLinux:9", release: "AlmaLinux:9", pkg: "openssl-libs", version: "1:3.0.1-41.el9_0", scheme: schemeRPM}
	r := distroRecord{ID: "ALSA-1", CVEs: []string{"CVE-2021-0001", "CVE-2021-0002"}, Releases: 1, Packages: 4,
		Entries: []distroEntry{entry("AlmaLinux:9", "i", "0", "f", "1:3.0.1-43.el9_0")}}
	if d := indexDistroRecords([]distroRecord{r}).decide(alma, "CVE-2021-0002"); d.verdict != verdictNone {
		t.Errorf("= %+v, want no verdict", d)
	}
}

// Codex M70 R3 High-5: a multi-CVE, multi-release advisory gives no verdict
// for a release, whatever the CVE's records say about OTHER releases: their
// "introduced 0" does not prove the installed release had the vulnerable code
// (a 3.0-only CVE also reads "introduced 0" in Debian's data).
func TestM70R3_NonSpeakingAdvisoryNeverDecides(t *testing.T) {
	cve := []string{"CVE-2021-0001", "CVE-2021-0002"}
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", version: "1.0-1", scheme: schemeDpkg}
	multi := rec("DSA-1", cve, entry("Debian:10", "i", "0", "f", "0.9-1+deb10u1"), entry("Debian:11", "i", "0", "f", "1.0-1+deb11u1"))
	spec := rec("DEBIAN-CVE-2021-0001", []string{"CVE-2021-0001"}, entry("Debian:12", "i", "0", "f", "1.1-1"))
	if d := indexDistroRecords([]distroRecord{multi, spec}).decide(deb11, "CVE-2021-0001"); d.verdict != verdictNone {
		t.Errorf("= %+v, want no verdict", d)
	}
}

// Codex M70 R3 High-6: the process-wide slot is taken before the cache is
// read, so concurrent cache hits are bounded too.
func TestM70R3_CacheReadTakesASlot(t *testing.T) {
	// Fill every slot; a load must then wait (here: until its context ends)
	// even though no OSV request would be made.
	for i := 0; i < cap(distroQuerySlots); i++ {
		distroQuerySlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(distroQuerySlots); i++ {
			<-distroQuerySlots
		}
	}()
	s := &DistroService{gap: 0, now: time.Now}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, _, _, err := s.load(ctx, distroFetchKey{ecosystem: "Debian", pkg: "openssl"}, s.pacer())
	if err == nil {
		t.Error("load proceeded without a slot")
	}
}
