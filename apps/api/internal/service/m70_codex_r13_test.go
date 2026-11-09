package service

import "testing"

// Codex M70 R13 High-2: a per-CVE record speaks for its own CVE only.
func TestM70R13_PerCVERecordIsExclusive(t *testing.T) {
	r := distroRecord{ID: "DEBIAN-CVE-2026-1111", CVEs: []string{"CVE-2026-1111", "CVE-2026-2222"}}
	if !r.speaksFor("CVE-2026-1111") || r.speaksFor("CVE-2026-2222") {
		t.Errorf("speaksFor: own=%v other=%v", r.speaksFor("CVE-2026-1111"), r.speaksFor("CVE-2026-2222"))
	}
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", binary: "p", version: "1.0-1", scheme: schemeDpkg}
	one := distroRecord{ID: "DEBIAN-CVE-2026-1111", CVEs: []string{"CVE-2026-1111", "CVE-2026-2222"}, Releases: 1, Packages: 1,
		Entries: []distroEntry{entry("Debian:11", "i", "0", "f", "0.5-1")}}
	if d := indexDistroRecords([]distroRecord{one}).decide(deb11, "CVE-2026-2222"); d.verdict != verdictNone {
		t.Errorf("other CVE via a single-pair per-CVE record = %+v", d)
	}
}

// Codex M70 R13 High-3: a misspelt ecosystem in the per-CVE record blocks
// later_releases.
func TestM70R13_MisspeltEcosystemBlocksLaterReleases(t *testing.T) {
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", binary: "p", version: "2.0-1", scheme: schemeDpkg}
	r := rec("DEBIAN-CVE-2021-0001", []string{"CVE-2021-0001"}, entry("Debain:11", "i", "0"), entry("Debian:12", "i", "0", "f", "1.0-1"))
	if d := indexDistroRecords([]distroRecord{r}).decide(deb11, "CVE-2021-0001"); d.verdict != verdictNone {
		t.Errorf("= %+v, want no verdict", d)
	}
}

// Codex M70 R13 Medium-5: the source identity distinguishes endpoints that
// differ only in credentials; the display URL never shows them.
func TestM70R13_SourceIdentity(t *testing.T) {
	a, b := "https://tenant-a:pw@mirror/v1", "https://tenant-b:pw@mirror/v1"
	if distroSourceID(a) == distroSourceID(b) {
		t.Error("credential-distinct endpoints share an identity")
	}
	if distroSource(a) != distroSource(b) || distroSource(a) != "https://mirror" {
		t.Errorf("display %q / %q", distroSource(a), distroSource(b))
	}
	if distroSourceID("") != distroSourceID("https://api.osv.dev/v1/") {
		t.Error("the default endpoint has two identities")
	}
}
