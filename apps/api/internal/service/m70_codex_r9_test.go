package service

import (
	"testing"

	"github.com/sbomhub/sbomhub/internal/client"
)

// Codex M70 R9 High-1: same-family ecosystem spellings that are not canonical
// block the CVE for Ubuntu and the rpm distros too; Ubuntu Pro streams are
// recognised (and ignored as other streams).
func TestM70R9_FamilyEcosystemsAreCanonical(t *testing.T) {
	ubu := distroTarget{family: "ubuntu", query: "Ubuntu:22.04:LTS", release: "Ubuntu:22.04:LTS", pkg: "p", binary: "p", version: "2.0-1", scheme: schemeDpkg}
	alma := distroTarget{family: "almalinux", query: "AlmaLinux:9", release: "AlmaLinux:9", pkg: "p", binary: "p", version: "1:2.0-1.el9", scheme: schemeRPM}
	for _, c := range []struct {
		t     distroTarget
		eco   string
		block bool
	}{
		{ubu, "Ubuntu:22.04", true},      // 22.04 is LTS: this spelling is not OSV's
		{ubu, "Ubuntu:23.10:LTS", true},  // not an LTS
		{ubu, "Ubuntu:22.4:LTS", true},   // malformed
		{ubu, "ubuntu:22.04:LTS", true},  // case variant
		{ubu, "Ubuntu:20.04:LTS", false}, // another release, canonical
		{ubu, "Ubuntu:23.10", false},
		{ubu, "Ubuntu:Pro:22.04:LTS", false},
		{ubu, "Ubuntu:Pro:FIPS-updates:22.04:LTS", false},
		{ubu, "Ubuntu:Pro:22.04", true},
		{alma, "AlmaLinux:09", true},
		{alma, "AlmaLinux:9.4", true},
		{alma, "almalinux:9", true},
		{alma, "AlmaLinux:8", false},
		{alma, "Debian:12", true}, // a foreign family in an AlmaLinux answer blocks (Codex R15 High-3)
	} {
		if got := noncanonicalFor(c.t, c.eco); got != c.block {
			t.Errorf("%s / %q: block=%v, want %v", c.t.family, c.eco, got, c.block)
		}
	}
}

// Codex M70 R9 High-2: the data revision counts every record the query
// returned, withdrawn ones included, so a withdrawal does not lower it.
func TestM70R9_RevisionCountsWithdrawnRecords(t *testing.T) {
	raw := []client.OSVPackageRecord{
		{ID: "DSA-1", Upstream: []string{"CVE-2021-0001"}, Modified: "2026-11-01T00:00:00Z",
			Affected: []client.OSVAffected{{Package: client.OSVPackage{Name: "p", Ecosystem: "Debian:11"}}}},
		{ID: "DSA-2", Upstream: []string{"CVE-2021-0002"}, Modified: "2026-11-05T00:00:00Z", Withdrawn: "2026-11-05T00:00:00Z",
			Affected: []client.OSVAffected{{Package: client.OSVPackage{Name: "p", Ecosystem: "Debian:11"}}}},
	}
	if got := rawRevision(raw); got != "2026-11-05T00:00:00.000000000Z" {
		t.Errorf("revision %q, want the withdrawn record's", got)
	}
}

// Codex M70 R9 High-3: CVE-specific authority needs a canonical CVE suffix,
// and applies only to that CVE.
func TestM70R9_CVERecordAuthorityIsPerCVE(t *testing.T) {
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", binary: "p", version: "1.0-1", scheme: schemeDpkg}
	rollup := distroRecord{ID: "DEBIAN-CVE-ROLLUP", CVEs: []string{"CVE-2021-0001", "CVE-2021-0002"}, Releases: 2, Packages: 1,
		Entries: []distroEntry{entry("Debian:10", "i", "0", "f", "0.9-1"), entry("Debian:11", "i", "0", "f", "1.5-1")}}
	if d := indexDistroRecords([]distroRecord{rollup}).decide(deb11, "CVE-2021-0001"); d.verdict != verdictNone {
		t.Errorf("DEBIAN-CVE-ROLLUP = %+v, want no verdict", d)
	}
	// DEBIAN-CVE-2021-0001 listing a second upstream CVE speaks only for its own.
	own := distroRecord{ID: "DEBIAN-CVE-2021-0001", CVEs: []string{"CVE-2021-0001", "CVE-2021-0002"}, Releases: 2, Packages: 1,
		Entries: []distroEntry{entry("Debian:10", "i", "0", "f", "0.9-1"), entry("Debian:11", "i", "0", "f", "1.5-1")}}
	data := indexDistroRecords([]distroRecord{own})
	if d := data.decide(deb11, "CVE-2021-0001"); d.verdict != verdictAffected {
		t.Errorf("own CVE = %+v, want affected", d)
	}
	if d := data.decide(deb11, "CVE-2021-0002"); d.verdict != verdictNone {
		t.Errorf("other CVE = %+v, want no verdict", d)
	}
}
