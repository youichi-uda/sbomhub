package service

import "testing"

// Codex M70 R8 High-1: an entry whose ecosystem is a non-canonical spelling
// of a Debian / Ubuntu release (or empty) blocks every verdict for the CVE.
func TestM70R8_NoncanonicalEcosystemBlocks(t *testing.T) {
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", binary: "p", version: "2.0-1", scheme: schemeDpkg}
	for _, eco := range []string{"debian:11", "DEBIAN:11", "", "Debian: 11"} {
		r := rec("DEBIAN-CVE-2021-0001", []string{"CVE-2021-0001"}, entry(eco, "i", "0", "f", "3.0-1"), entry("Debian:12", "i", "0", "f", "1.0-1"))
		if d := indexDistroRecords([]distroRecord{r}).decide(deb11, "CVE-2021-0001"); d.verdict != verdictNone {
			t.Errorf("%q: %+v, want no verdict", eco, d)
		}
	}
}

// Codex M70 R8 High-2: a CPE that pins an update names another release.
func TestM70R8_CPEUpdateIsAConflict(t *testing.T) {
	if cpeVersionsAgree([]string{"cpe:2.3:a:x:y:1.0:beta:*:*:*:*:*:*"}, "1.0") {
		t.Error("1.0:beta agreed with 1.0")
	}
	if !cpeVersionsAgree([]string{"cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*", "cpe:2.3:a:x:y:1.0:-:*:*:*:*:*:*"}, "1.0") {
		t.Error("ANY / NA update disagreed")
	}
}

// Codex M70 R8 High-3: the component's name must be the purl's package name.
func TestM70R8_ComponentNameMustBeThePurlName(t *testing.T) {
	if purlNameAgrees("pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.10?distro=ubuntu-22.04", "libssl-doc") {
		t.Error("libssl-doc agreed with a libssl3 purl")
	}
	if !purlNameAgrees("pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11", "openssl") {
		t.Error("openssl disagreed")
	}
	if purlNameAgrees("pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11", "") {
		t.Error("an empty name agreed")
	}
}

// Codex M70 R8 High-4: evidence carries the data's own revision (the newest
// OSV `modified` of the package's records), in a fixed-width form that sorts
// as text, so a delayed scan with older data cannot overwrite newer evidence.
func TestM70R8_EvidenceCarriesDataRevision(t *testing.T) {
	a := distroRecord{ID: "DSA-1", CVEs: []string{"CVE-2021-0001"}, Releases: 1, Packages: 1, Modified: "2026-10-09T09:47:27.16Z",
		Entries: []distroEntry{entry("Debian:11", "i", "0", "f", "1.5-1")}}
	b := distroRecord{ID: "DSA-2", CVEs: []string{"CVE-2021-0002"}, Releases: 1, Packages: 1, Modified: "2026-10-09T09:47:27Z",
		Entries: []distroEntry{entry("Debian:11", "i", "0", "f", "1.5-1")}}
	d := indexDistroRecords([]distroRecord{a, b})
	if d.revision != "2026-10-09T09:47:27.160000000Z" {
		t.Errorf("revision %q", d.revision)
	}
	if normaliseModified("2026-10-09T09:47:27Z") >= normaliseModified("2026-10-09T09:47:27.1Z") {
		t.Error("revisions do not sort as text")
	}
	if normaliseModified("garbage") != "" {
		t.Error("an unparseable modified produced a revision")
	}
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", binary: "p", version: "2.0-1", scheme: schemeDpkg}
	if dec := d.decide(deb11, "CVE-2021-0001"); dec.evidence.DataModified != d.revision {
		t.Errorf("evidence data_modified %q", dec.evidence.DataModified)
	}
}

// Codex M70 R8 Medium-5: a "fixed" verdict's evidence version must itself be
// outside every deciding entry's affected set, or it is omitted.
func TestM70R8_FixedEvidenceVersionIsSafe(t *testing.T) {
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", binary: "p", version: "3.0-1", scheme: schemeDpkg}
	e1 := entry("Debian:11", "i", "0", "f", "2.0-1")
	e2 := entry("Debian:11", "i", "0", "f", "1.0-1")
	e2.Versions = []string{"2.0-1"}
	d := indexDistroRecords([]distroRecord{rec("DLA-1", []string{"CVE-2021-0001"}, e1), rec("DLA-2", []string{"CVE-2021-0001"}, e2)}).decide(deb11, "CVE-2021-0001")
	if d.verdict != verdictFixed || d.evidence.Fixed != "" {
		t.Errorf("= %+v, want fixed with no advertised version (2.0-1 is listed affected)", d)
	}
}
