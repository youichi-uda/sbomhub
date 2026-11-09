package service

import (
	"testing"

	"github.com/sbomhub/sbomhub/internal/client"
)

// Codex M70 R1 High-1: a multi-CVE advisory spanning several releases does
// not say which of its CVEs applies to which release. Measured on the
// committed fixture: USN-5402-1 lists CVE-2022-1343 with Ubuntu 18.04 / 20.04
// fix entries, while UBUNTU-CVE-2022-1343 names only 22.04 — 20.04 is not
// affected by it.
func TestM70R1_MultiCVEAdvisoryDoesNotFanOut(t *testing.T) {
	ubu := m70OSVData(t, "ubuntu2204_openssl", "openssl")
	t2004, _ := distroTargetFor("pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.12?distro=ubuntu-20.04", "", nil)
	if d := ubu.decide(t2004, "CVE-2022-1343"); d.verdict != verdictNone {
		t.Errorf("Ubuntu 20.04 CVE-2022-1343 = %+v, want no verdict (UBUNTU-CVE names only 22.04)", d)
	}

	cve := []string{"CVE-2021-0001", "CVE-2021-0002"}
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", version: "1.0-1", scheme: schemeDpkg}
	// A two-release, two-CVE DSA alone: no verdict either way.
	multi := rec("DSA-1", cve, entry("Debian:10", "i", "0", "f", "0.9-1+deb10u1"), entry("Debian:11", "i", "0", "f", "1.0-1+deb11u1"))
	if d := indexDistroRecords([]distroRecord{multi}).decide(deb11, "CVE-2021-0001"); d.verdict != verdictNone {
		t.Errorf("uncorroborated multi-release advisory = %+v, want no verdict", d)
	}
	// ... corroborated by the CVE's own record (later releases affected at
	// the installed version): affected.
	spec := rec("DEBIAN-CVE-2021-0001", []string{"CVE-2021-0001"}, entry("Debian:12", "i", "0", "f", "1.1-1"))
	d := indexDistroRecords([]distroRecord{multi, spec}).decide(deb11, "CVE-2021-0001")
	if d.verdict != verdictAffected || d.evidence.Fixed != "1.0-1+deb11u1" {
		t.Errorf("corroborated = %+v, want affected at 1.0-1+deb11u1", d)
	}
	// The uncorroborated advisory never yields "fixed" either.
	deb11Fixed := deb11
	deb11Fixed.version = "1.0-1+deb11u2"
	if d := indexDistroRecords([]distroRecord{multi}).decide(deb11Fixed, "CVE-2021-0001"); d.verdict != verdictNone {
		t.Errorf("multi-release advisory fixed = %+v, want no verdict", d)
	}
	// A single-release (DLA-style) advisory speaks for that release.
	dla := rec("DLA-1", cve, entry("Debian:11", "i", "0", "f", "1.0-1+deb11u1"))
	if d := indexDistroRecords([]distroRecord{dla}).decide(deb11, "CVE-2021-0002"); d.verdict != verdictAffected {
		t.Errorf("single-release advisory = %+v, want affected", d)
	}
	// Ubuntu: a CVE-specific record makes the USNs irrelevant for that CVE.
	u := distroTarget{family: "ubuntu", query: "Ubuntu:20.04:LTS", release: "Ubuntu:20.04:LTS", pkg: "p", version: "1.0-1", scheme: schemeDpkg}
	usn := rec("USN-1", []string{"CVE-2021-0001"}, entry("Ubuntu:20.04:LTS", "i", "0", "f", "1.0-2"))
	ucve := rec("UBUNTU-CVE-2021-0001", []string{"CVE-2021-0001"}, entry("Ubuntu:22.04:LTS", "i", "0", "f", "2.0-1"))
	if d := indexDistroRecords([]distroRecord{usn, ucve}).decide(u, "CVE-2021-0001"); d.verdict != verdictNone {
		t.Errorf("Ubuntu USN beside a UBUNTU-CVE record = %+v, want no verdict", d)
	}
}

// Codex M70 R1 High-2: the later_releases rule is only for a Debian release
// the data has DROPPED (end of life). A supported release missing from one
// CVE's record is not-affected or untracked, never "fixed".
func TestM70R1_LaterReleasesOnlyForDroppedReleases(t *testing.T) {
	cve := []string{"CVE-2021-0001"}
	deb12 := distroTarget{family: "debian", query: "Debian", release: "Debian:12", releaseMajor: 12, pkg: "p", version: "2.0-1", scheme: schemeDpkg}
	later := rec("DEBIAN-CVE-2021-0001", cve, entry("Debian:13", "i", "0", "f", "1.0-1"), entry("Debian:14", "i", "0", "f", "1.0-1"))
	other := rec("DEBIAN-CVE-2021-0009", []string{"CVE-2021-0009"}, entry("Debian:12", "i", "0", "f", "1.5-1"))
	if d := indexDistroRecords([]distroRecord{later, other}).decide(deb12, "CVE-2021-0001"); d.verdict != verdictNone {
		t.Errorf("supported Debian 12 = %+v, want no verdict", d)
	}
	// Even if no record of the package names Debian 12, a release the
	// code does not know as end-of-life gets no later_releases verdict.
	if d := indexDistroRecords([]distroRecord{later}).decide(deb12, "CVE-2021-0001"); d.verdict != verdictNone {
		t.Errorf("Debian 12 (not end-of-life) = %+v, want no verdict", d)
	}
	// Debian 11, which the package's CVE records no longer name: allowed.
	deb11 := deb12
	deb11.release, deb11.releaseMajor = "Debian:11", 11
	if d := indexDistroRecords([]distroRecord{later}).decide(deb11, "CVE-2021-0001"); d.verdict != verdictFixed {
		t.Errorf("Debian 11 = %+v, want fixed (later_releases)", d)
	}
	// ... but not when some CVE record of the package still names Debian 11.
	still := rec("DEBIAN-CVE-2021-0008", []string{"CVE-2021-0008"}, entry("Debian:11", "i", "0", "f", "1.5-1"))
	if d := indexDistroRecords([]distroRecord{later, still}).decide(deb11, "CVE-2021-0001"); d.verdict != verdictNone {
		t.Errorf("Debian 11 still covered = %+v, want no verdict", d)
	}
}

// Codex M70 R1 High-3: a later Debian ecosystem the code cannot order
// ("Debian:sid") makes the later_releases proof undecidable.
func TestM70R1_UnparseableDebianEcosystemBlocksLaterReleases(t *testing.T) {
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", version: "2.0-1", scheme: schemeDpkg}
	r := rec("DEBIAN-CVE-2021-0001", []string{"CVE-2021-0001"}, entry("Debian:12", "i", "0", "f", "1.0-1"), entry("Debian:sid", "i", "0"))
	if d := indexDistroRecords([]distroRecord{r}).decide(deb11, "CVE-2021-0001"); d.verdict != verdictNone {
		t.Errorf("= %+v, want no verdict", d)
	}
}

// Codex M70 R1 High-4: OSV's affected set is the union of every range and
// the versions list; a member that cannot be evaluated forbids "fixed".
func TestM70R1_UnevaluableAffectedMemberForbidsFixed(t *testing.T) {
	dpkg := distroTarget{scheme: schemeDpkg}.comparator()
	fixedRange := client.OSVRange{Type: "ECOSYSTEM", Events: ev("i", "0", "f", "1.0-1")}
	for _, c := range []struct {
		name  string
		entry distroEntry
		want  entryState
	}{
		{"plus a GIT range", distroEntry{Ranges: []client.OSVRange{fixedRange, {Type: "GIT", Events: ev("i", "abc")}}}, entryUndecidable},
		{"plus a SEMVER range", distroEntry{Ranges: []client.OSVRange{fixedRange, {Type: "SEMVER", Events: ev("i", "0")}}}, entryUndecidable},
		{"plus an unparseable listed version", distroEntry{Ranges: []client.OSVRange{fixedRange}, Versions: []string{"not a version"}}, entryUndecidable},
		{"plus an evaluable, different listed version", distroEntry{Ranges: []client.OSVRange{fixedRange}, Versions: []string{"0.9-1"}}, entryFixed},
		{"a GIT range does not hide an affected ECOSYSTEM range", distroEntry{Ranges: []client.OSVRange{{Type: "ECOSYSTEM", Events: ev("i", "0", "f", "3.0-1")}, {Type: "GIT", Events: ev("i", "abc")}}}, entryAffected},
	} {
		if got := evalEntry("2.0-1", c.entry, dpkg); got.state != c.want {
			t.Errorf("%s: %+v, want state %d", c.name, got, c.want)
		}
	}
}

// Codex M70 R1 Medium: the whole release string is validated.
func TestM70R1_ReleaseSyntaxIsStrict(t *testing.T) {
	for _, purl := range []string{
		"pkg:deb/debian/openssl@1.1.1k-1?distro=debian-12.sid",
		"pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11.7.1",
		"pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11.",
		"pkg:rpm/almalinux/openssl@3.0.7-27.el9?distro=almalinux-9.garbage",
		"pkg:rpm/rocky/openssl@3.0.7-27.el9?distro=rocky-9x",
	} {
		if tgt, reason := distroTargetFor(purl, "", nil); reason != "unknown_release" {
			t.Errorf("%s: target %+v reason %q, want unknown_release", purl, tgt, reason)
		}
	}
	for _, purl := range []string{"pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11.7", "pkg:rpm/almalinux/openssl@3.0.7-27.el9?distro=almalinux-9.4"} {
		if _, reason := distroTargetFor(purl, "", nil); reason != "" {
			t.Errorf("%s: %q", purl, reason)
		}
	}
}
