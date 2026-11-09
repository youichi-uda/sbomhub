package service

import (
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/client"
	"github.com/sbomhub/sbomhub/internal/model"
)

// ---------------------------------------------------------------------------
// Identifying the distro release (distroTargetFor)
// ---------------------------------------------------------------------------

func TestM70DistroTarget(t *testing.T) {
	deb11 := &distroOS{id: "debian", version: "11"}
	for _, c := range []struct {
		name, purl, version string
		os                  *distroOS
		want                distroTarget
		reason              string
	}{
		// Syft 1.46.0 output (testdata/m60/syft.cdx.json).
		{name: "syft openssl", purl: "pkg:deb/debian/openssl@1.1.1k-1?arch=amd64&distro=debian-11", version: "1.1.1k-1",
			want: distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "openssl", version: "1.1.1k-1", scheme: schemeDpkg}},
		{name: "syft libc6 -> source glibc, same version", purl: "pkg:deb/debian/libc6@2.31-13?arch=amd64&distro=debian-11&upstream=glibc",
			want: distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "glibc", version: "2.31-13", scheme: schemeDpkg}},
		{name: "syft kernel image -> source name@version", purl: "pkg:deb/debian/linux-image-5.10.0-8-amd64@5.10.46-4?arch=amd64&distro=debian-11&upstream=linux-signed-amd64%405.10.46%2B4",
			want: distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "linux-signed-amd64", version: "5.10.46+4", scheme: schemeDpkg}},
		{name: "epoch in the deb version", purl: "pkg:deb/debian/zlib1g@1:1.2.11.dfsg-2%2Bdeb11u2?distro=debian-11&upstream=zlib",
			want: distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "zlib", version: "1:1.2.11.dfsg-2+deb11u2", scheme: schemeDpkg}},
		{name: "point release", purl: "pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12.4",
			want: distroTarget{family: "debian", query: "Debian", release: "Debian:12", releaseMajor: 12, pkg: "openssl", version: "3.0.11-1~deb12u2", scheme: schemeDpkg}},
		{name: "codename", purl: "pkg:deb/debian/openssl@1.1.1k-1?distro=debian-bullseye",
			want: distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "openssl", version: "1.1.1k-1", scheme: schemeDpkg}},
		{name: "no qualifier, SBOM OS component", purl: "pkg:deb/debian/openssl@1.1.1k-1", os: deb11,
			want: distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "openssl", version: "1.1.1k-1", scheme: schemeDpkg}},
		{name: "ubuntu LTS", purl: "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?distro=ubuntu-22.04",
			want: distroTarget{family: "ubuntu", query: "Ubuntu:22.04:LTS", release: "Ubuntu:22.04:LTS", pkg: "openssl", version: "3.0.2-0ubuntu1.10", scheme: schemeDpkg}},
		{name: "ubuntu interim", purl: "pkg:deb/ubuntu/openssl@3.0.10-1ubuntu2?distro=ubuntu-23.10",
			want: distroTarget{family: "ubuntu", query: "Ubuntu:23.10", release: "Ubuntu:23.10", pkg: "openssl", version: "3.0.10-1ubuntu2", scheme: schemeDpkg}},
		{name: "almalinux epoch qualifier", purl: "pkg:rpm/almalinux/openssl-libs@3.0.7-27.el9?arch=x86_64&epoch=1&upstream=openssl-3.0.7-27.el9.src.rpm&distro=almalinux-9.4",
			want: distroTarget{family: "almalinux", query: "AlmaLinux:9", release: "AlmaLinux:9", pkg: "openssl-libs", version: "1:3.0.7-27.el9", scheme: schemeRPM}},
		{name: "rocky, no epoch", purl: "pkg:rpm/rocky/bash@5.1.8-9.el9?arch=x86_64&distro=rocky-9.3",
			want: distroTarget{family: "rocky", query: "Rocky Linux:9", release: "Rocky Linux:9", pkg: "bash", version: "5.1.8-9.el9", scheme: schemeRPM}},
		{name: "rpm epoch in version and qualifier agree", purl: "pkg:rpm/almalinux/openssl@1:3.0.7-27.el9?epoch=1&distro=almalinux-9",
			want: distroTarget{family: "almalinux", query: "AlmaLinux:9", release: "AlmaLinux:9", pkg: "openssl", version: "1:3.0.7-27.el9", scheme: schemeRPM}},

		// No guess.
		{name: "no release at all", purl: "pkg:deb/debian/openssl@1.1.1k-1", reason: "unknown_release"},
		{name: "OS component of another distro", purl: "pkg:deb/debian/openssl@1.1.1k-1", os: &distroOS{id: "ubuntu", version: "22.04"}, reason: "distro_mismatch"},
		{name: "qualifier names another distro", purl: "pkg:deb/ubuntu/openssl@1.1.1k-1?distro=debian-11", reason: "distro_mismatch"},
		{name: "sid / testing (no VERSION_ID)", purl: "pkg:deb/debian/openssl@3.6.5-1?distro=debian-", reason: "unknown_release"},
		{name: "unknown codename", purl: "pkg:deb/debian/openssl@3.6.5-1?distro=debian-sid", reason: "unknown_release"},
		{name: "distro qualifier twice", purl: "pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11&distro=debian-12", reason: "ambiguous_qualifier"},
		{name: "ubuntu release not YY.MM", purl: "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1?distro=ubuntu-jammy", reason: "unknown_release"},
		{name: "rhel: no OSV ecosystem without repository", purl: "pkg:rpm/redhat/openssl@3.0.7-27.el9?distro=rhel-9.4", reason: "unsupported_distro"},
		{name: "deb of another vendor", purl: "pkg:deb/raspbian/openssl@1.1.1k-1?distro=raspbian-11", reason: "unsupported_distro"},
		{name: "apk: no comparator", purl: "pkg:apk/alpine/openssl@3.1.4-r0?distro=alpine-3.18.4", reason: "no_comparator"},
		{name: "not a distro package", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", reason: "not_distro"},
		{name: "rpm epoch disagrees", purl: "pkg:rpm/almalinux/openssl@2:3.0.7-27.el9?epoch=1&distro=almalinux-9", reason: "bad_version"},
		{name: "rpm without release", purl: "pkg:rpm/almalinux/openssl@3.0.7?distro=almalinux-9", reason: "bad_version"},
		{name: "deb version dpkg refuses", purl: "pkg:deb/debian/openssl@abc?distro=debian-11", reason: "bad_version"},
		{name: "empty upstream qualifier name", purl: "pkg:deb/debian/libc6@2.31-13?distro=debian-11&upstream=%402.31", reason: "bad_upstream"},
		{name: "no version", purl: "pkg:deb/debian/openssl?distro=debian-11", reason: "no_version"},
		{name: "not a purl", purl: "openssl", reason: "no_purl"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, reason := distroTargetFor(c.purl, c.version, c.os)
			if reason != c.reason {
				t.Fatalf("reason = %q, want %q (target %+v)", reason, c.reason, got)
			}
			if c.reason == "" && got.binary == "" {
				t.Errorf("no binary name in %+v", got)
			}
			got.binary = "" // checked above; the table states the rest
			if c.reason == "" && got != c.want {
				t.Errorf("target = %+v\nwant     %+v", got, c.want)
			}
		})
	}
}

func TestM70UbuntuEcosystem(t *testing.T) {
	for in, want := range map[string]string{
		"14.04": "Ubuntu:14.04:LTS", "16.04": "Ubuntu:16.04:LTS", "18.04": "Ubuntu:18.04:LTS",
		"20.04": "Ubuntu:20.04:LTS", "22.04": "Ubuntu:22.04:LTS", "24.04": "Ubuntu:24.04:LTS",
		"23.04": "Ubuntu:23.04", "22.10": "Ubuntu:22.10", "24.10": "Ubuntu:24.10",
	} {
		if got, ok := ubuntuEcosystem(in); !ok || got != want {
			t.Errorf("ubuntuEcosystem(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "22", "22.4", "jammy", "2204", "22.04.3"} {
		if got, ok := ubuntuEcosystem(bad); ok {
			t.Errorf("ubuntuEcosystem(%q) = %q, want no release", bad, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Range evaluation (evalEntry / evalRange)
// ---------------------------------------------------------------------------

func ev(kv ...string) []client.OSVEvent {
	var out []client.OSVEvent
	for i := 0; i < len(kv); i += 2 {
		switch kv[i] {
		case "i":
			out = append(out, client.OSVEvent{Introduced: kv[i+1]})
		case "f":
			out = append(out, client.OSVEvent{Fixed: kv[i+1]})
		case "la":
			out = append(out, client.OSVEvent{LastAffected: kv[i+1]})
		case "l":
			out = append(out, client.OSVEvent{Limit: kv[i+1]})
		}
	}
	return out
}

func eco(events ...[]client.OSVEvent) []client.OSVRange {
	var out []client.OSVRange
	for _, e := range events {
		out = append(out, client.OSVRange{Type: "ECOSYSTEM", Events: e})
	}
	return out
}

func TestM70EvalEntry(t *testing.T) {
	dpkg := distroTarget{scheme: schemeDpkg}.comparator()
	rpm := distroTarget{scheme: schemeRPM}.comparator()
	for _, c := range []struct {
		name      string
		cmp       versionCmp
		installed string
		entry     distroEntry
		want      entryResult
	}{
		{"below the fix", dpkg, "1.1.1k-1", distroEntry{Ranges: eco(ev("i", "0", "f", "1.1.1k-1+deb11u1"))},
			entryResult{state: entryAffected, fix: "1.1.1k-1+deb11u1"}},
		{"at the fix", dpkg, "1.1.1k-1+deb11u1", distroEntry{Ranges: eco(ev("i", "0", "f", "1.1.1k-1+deb11u1"))},
			entryResult{state: entryFixed, fix: "1.1.1k-1+deb11u1"}},
		{"above the fix", dpkg, "1.1.1n-0+deb11u5", distroEntry{Ranges: eco(ev("i", "0", "f", "1.1.1k-1+deb11u1"))},
			entryResult{state: entryFixed, fix: "1.1.1k-1+deb11u1"}},
		{"tilde backport below the fix", dpkg, "3.0.11-1~deb12u1", distroEntry{Ranges: eco(ev("i", "0", "f", "3.0.11-1~deb12u2"))},
			entryResult{state: entryAffected, fix: "3.0.11-1~deb12u2"}},
		{"binNMU of the fixed source", dpkg, "2.31-13+deb11u5+b1", distroEntry{Ranges: eco(ev("i", "0", "f", "2.31-13+deb11u5"))},
			entryResult{state: entryFixed, fix: "2.31-13+deb11u5"}},
		{"events out of order are sorted", dpkg, "1.5-1", distroEntry{Ranges: eco(ev("f", "2.0-1", "i", "0"))},
			entryResult{state: entryAffected, fix: "2.0-1"}},
		{"introduced only: unfixed", dpkg, "1.1.1k-1", distroEntry{Ranges: eco(ev("i", "0"))},
			entryResult{state: entryAffected, noFix: true}},
		{"two intervals, in the second", dpkg, "2.5-1", distroEntry{Ranges: eco(ev("i", "0", "f", "1.0-2", "i", "2.0-1", "f", "3.0-1"))},
			entryResult{state: entryAffected, fix: "3.0-1"}},
		{"two intervals, between them", dpkg, "1.5-1", distroEntry{Ranges: eco(ev("i", "0", "f", "1.0-2", "i", "2.0-1", "f", "3.0-1"))},
			entryResult{state: entryFixed, fix: "1.0-2"}},
		{"two intervals, after both", dpkg, "3.1-1", distroEntry{Ranges: eco(ev("i", "0", "f", "1.0-2", "i", "2.0-1", "f", "3.0-1"))},
			entryResult{state: entryFixed, fix: "3.0-1"}},
		{"two ranges, one affected", dpkg, "1.5-1", distroEntry{Ranges: eco(ev("i", "0", "f", "1.0-1"), ev("i", "1.2-1", "f", "1.6-1"))},
			entryResult{state: entryAffected, fix: "1.6-1"}},
		{"two ranges, both fixed: the higher closing", dpkg, "2.0-1", distroEntry{Ranges: eco(ev("i", "0", "f", "1.0-1"), ev("i", "1.2-1", "f", "1.6-1"))},
			entryResult{state: entryFixed, fix: "1.6-1"}},
		{"listed in versions, ranges say fixed", dpkg, "1.0-1", distroEntry{Ranges: eco(ev("i", "0", "f", "0.9-1")), Versions: []string{"1.0-1"}},
			entryResult{state: entryAffected, fixUnknown: true}},
		{"listed in versions, no range", dpkg, "1.0-1", distroEntry{Versions: []string{"0.9-1", "1.0-1"}},
			entryResult{state: entryAffected, fixUnknown: true}},
		{"versions list without the installed one proves nothing", dpkg, "1.0-1", distroEntry{Versions: []string{"0.9-1"}},
			entryResult{state: entryUndecidable}},
		{"below the first introduced is not a fix", dpkg, "1.0-1", distroEntry{Ranges: eco(ev("i", "2.0-1", "f", "2.1-1"))},
			entryResult{state: entryUndecidable}},
		{"last_affected is not read", dpkg, "2.0-1", distroEntry{Ranges: eco(ev("i", "0", "la", "1.9-1"))},
			entryResult{state: entryUndecidable}},
		{"limit is not read", dpkg, "2.0-1", distroEntry{Ranges: eco(ev("i", "0", "l", "3.0-1"))},
			entryResult{state: entryUndecidable}},
		{"an event with two fields", dpkg, "2.0-1", distroEntry{Ranges: eco([]client.OSVEvent{{Introduced: "0", Fixed: "1.0-1"}})},
			entryResult{state: entryUndecidable}},
		{"an empty range", dpkg, "2.0-1", distroEntry{Ranges: eco([]client.OSVEvent{})},
			entryResult{state: entryUndecidable}},
		{"only a GIT range", dpkg, "2.0-1", distroEntry{Ranges: []client.OSVRange{{Type: "GIT", Events: ev("i", "abc", "f", "def")}}},
			entryResult{state: entryUndecidable}},
		{"a fixed version dpkg refuses", dpkg, "2.0-1", distroEntry{Ranges: eco(ev("i", "0", "f", "<unfixed>"))},
			entryResult{state: entryUndecidable}},
		{"installed epoch, fix states none", dpkg, "1:1.0-1", distroEntry{Ranges: eco(ev("i", "0", "f", "2.0-1"))},
			entryResult{state: entryUndecidable}},
		{"fix states an epoch, installed none", dpkg, "3.0-1", distroEntry{Ranges: eco(ev("i", "0", "f", "1:2.0-1"))},
			entryResult{state: entryUndecidable}},
		{"both state the epoch", dpkg, "1:3.0-1", distroEntry{Ranges: eco(ev("i", "0", "f", "1:2.0-1"))},
			entryResult{state: entryFixed, fix: "1:2.0-1"}},
		{"explicit zero epoch on one side is fine", dpkg, "0:3.0-1", distroEntry{Ranges: eco(ev("i", "0", "f", "2.0-1"))},
			entryResult{state: entryFixed, fix: "2.0-1"}},
		{"rpm: below the erratum", rpm, "1:3.0.1-41.el9_0", distroEntry{Ranges: eco(ev("i", "0", "f", "1:3.0.1-43.el9_0"))},
			entryResult{state: entryAffected, fix: "1:3.0.1-43.el9_0"}},
		{"rpm: at the erratum", rpm, "1:3.0.1-43.el9_0", distroEntry{Ranges: eco(ev("i", "0", "f", "1:3.0.1-43.el9_0"))},
			entryResult{state: entryFixed, fix: "1:3.0.1-43.el9_0"}},
		{"rpm: newer minor release", rpm, "1:3.0.7-27.el9", distroEntry{Ranges: eco(ev("i", "0", "f", "1:3.0.1-43.el9_0"))},
			entryResult{state: entryFixed, fix: "1:3.0.1-43.el9_0"}},
		{"rpm: dropped epoch is not compared", rpm, "3.0.7-27.el9", distroEntry{Ranges: eco(ev("i", "0", "f", "1:3.0.1-43.el9_0"))},
			entryResult{state: entryUndecidable}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := evalEntry(c.installed, c.entry, c.cmp); got != c.want {
				t.Errorf("evalEntry(%q) = %+v, want %+v", c.installed, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Decisions (distroData.decide)
// ---------------------------------------------------------------------------

// rec builds a record of ONE package; its release count is that of entries.
func rec(id string, cves []string, entries ...distroEntry) distroRecord {
	rel := map[string]bool{}
	for _, e := range entries {
		rel[e.Ecosystem] = true
	}
	return distroRecord{ID: id, CVEs: cves, Entries: entries, Releases: len(rel), Packages: 1}
}

func entry(eco string, events ...string) distroEntry {
	return distroEntry{Ecosystem: eco, Ranges: []client.OSVRange{{Type: "ECOSYSTEM", Events: ev(events...)}}}
}

func TestM70Decide(t *testing.T) {
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "openssl", version: "1.1.1k-1", scheme: schemeDpkg}
	ubu := distroTarget{family: "ubuntu", query: "Ubuntu:22.04:LTS", release: "Ubuntu:22.04:LTS", pkg: "openssl", binary: "openssl", version: "3.0.2-0ubuntu1.10", scheme: schemeDpkg}
	ubuEntry := func(eco string, events ...string) distroEntry {
		e := entry(eco, events...)
		e.Binaries, e.BinariesListed = []string{"libssl3", "openssl"}, true
		return e
	}
	cve := []string{"CVE-2021-3711"}
	for _, c := range []struct {
		name     string
		t        distroTarget
		recs     []distroRecord
		verdict  distroVerdict
		basis    string
		fixed    string
		records  string
		reason   string
		releases string
	}{
		{name: "release advisory, below its fix (DSA-4963-1)", t: deb11,
			recs:    []distroRecord{rec("DSA-4963-1", cve, entry("Debian:10", "i", "0", "f", "1.1.1d-0+deb10u7"), entry("Debian:11", "i", "0", "f", "1.1.1k-1+deb11u1"))},
			verdict: verdictAffected, basis: "release", fixed: "1.1.1k-1+deb11u1", records: "DSA-4963-1"},
		{name: "an OLDER release's backport never decides (1.1.1k-1 > buster's fix)", t: deb11,
			recs:   []distroRecord{rec("DSA-4963-1", cve, entry("Debian:10", "i", "0", "f", "1.1.1d-0+deb10u7"))},
			reason: "release_not_listed"},
		{name: "advisory and regression update: the later fix", t: distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "openssl", version: "1.1.1w-0+deb11u1", scheme: schemeDpkg},
			recs: []distroRecord{
				rec("DLA-3942-1", cve, entry("Debian:11", "i", "0", "f", "1.1.1n-0+deb11u6")),
				rec("DLA-3942-2", cve, entry("Debian:11", "i", "0", "f", "1.1.1w-0+deb11u2")),
			},
			verdict: verdictAffected, basis: "release", fixed: "1.1.1w-0+deb11u2", records: "DLA-3942-1 DLA-3942-2"},
		{name: "release fixed at or below the installed version", t: distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "openssl", version: "1.1.1n-0+deb11u5", scheme: schemeDpkg},
			recs:    []distroRecord{rec("DSA-4963-1", cve, entry("Debian:11", "i", "0", "f", "1.1.1k-1+deb11u1"))},
			verdict: verdictFixed, basis: "release", fixed: "1.1.1k-1+deb11u1", records: "DSA-4963-1"},
		{name: "release listed with no fix", t: deb11,
			recs:    []distroRecord{rec("DEBIAN-CVE-2021-3711", cve, entry("Debian:11", "i", "0"))},
			verdict: verdictUnfixed, basis: "release", records: "DEBIAN-CVE-2021-3711"},
		{name: "the CVE's own record, when it names the release, wins over an advisory", t: deb11,
			recs: []distroRecord{
				rec("DSA-1", cve, entry("Debian:11", "i", "0", "f", "1.1.1k-1+deb11u1")),
				rec("DEBIAN-CVE-2021-3711", cve, entry("Debian:11", "i", "0")),
			},
			verdict: verdictUnfixed, basis: "release", records: "DEBIAN-CVE-2021-3711"},
		{name: "unfixed beats a fixed entry for the same release", t: deb11,
			recs: []distroRecord{
				rec("DLA-1", cve, entry("Debian:11", "i", "0", "f", "1.1.1k-1+deb11u1")),
				rec("DLA-2", cve, entry("Debian:11", "i", "0")),
			},
			verdict: verdictUnfixed, basis: "release", records: "DLA-1 DLA-2"},
		{name: "affected beats an entry that cannot be evaluated", t: deb11,
			recs: []distroRecord{
				rec("DSA-1", cve, entry("Debian:11", "i", "0", "f", "1.1.1k-1+deb11u1")),
				rec("DSA-2", cve, entry("Debian:11", "i", "0", "la", "1.1.1j-1")),
			},
			// Affected for certain; with an entry not evaluable, no upgrade
			// target is advertised (Codex M70 R5 Medium-3).
			verdict: verdictAffected, basis: "release", fixed: "", records: "DSA-1 DSA-2"},
		{name: "fixed with an entry that cannot be evaluated: no verdict", t: distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "openssl", version: "1.1.1n-0+deb11u5", scheme: schemeDpkg},
			recs: []distroRecord{
				rec("DSA-1", cve, entry("Debian:11", "i", "0", "f", "1.1.1k-1+deb11u1")),
				rec("DSA-2", cve, entry("Debian:11", "i", "0", "la", "1.1.1j-1")),
			},
			reason: "undecidable"},
		{name: "EOL release: every later release fixed at or below (DEBIAN-CVE-2021-3449)", t: deb11,
			recs: []distroRecord{rec("DEBIAN-CVE-2021-3449", []string{"CVE-2021-3711"},
				entry("Debian:12", "i", "0", "f", "1.1.1k-1"), entry("Debian:13", "i", "0", "f", "1.1.1k-1"), entry("Debian:14", "i", "0", "f", "1.1.1k-1"))},
			verdict: verdictFixed, basis: "later_releases", fixed: "1.1.1k-1", records: "DEBIAN-CVE-2021-3449", releases: "Debian:12 Debian:13 Debian:14"},
		{name: "EOL release: a later release's fix ABOVE the installed version says nothing", t: deb11,
			recs: []distroRecord{rec("DEBIAN-CVE-2021-3711", cve,
				entry("Debian:12", "i", "0", "f", "1.1.1l-1"), entry("Debian:13", "i", "0", "f", "1.1.1l-1"))},
			reason: "later_release_not_fixed_at_installed"},
		{name: "EOL release: one later release still fixed above (bookworm backport)", t: deb11,
			recs: []distroRecord{rec("DEBIAN-CVE-X", cve,
				entry("Debian:12", "i", "0", "f", "3.0.11-1~deb12u2"), entry("Debian:13", "i", "0", "f", "1.1.1a-1"))},
			reason: "later_release_not_fixed_at_installed"},
		{name: "EOL release: a later release unfixed", t: deb11,
			recs:   []distroRecord{rec("DEBIAN-CVE-X", cve, entry("Debian:13", "i", "0", "f", "1.1.1a-1"), entry("Debian:14", "i", "0"))},
			reason: "later_release_not_fixed_at_installed"},
		{name: "EOL release: only older releases listed", t: deb11,
			recs:   []distroRecord{rec("DSA-OLD", cve, entry("Debian:9", "i", "0", "f", "1.1.0f-3+deb9u1"))},
			reason: "release_not_listed"},
		{name: "Ubuntu never borrows another release", t: ubu,
			recs:   []distroRecord{rec("UBUNTU-CVE-2021-3711", cve, entry("Ubuntu:24.04:LTS", "i", "0", "f", "1.0-1"))},
			reason: "release_not_listed"},
		{name: "Ubuntu release fixed", t: ubu,
			recs:    []distroRecord{rec("UBUNTU-CVE-2021-3711", cve, ubuEntry("Ubuntu:22.04:LTS", "i", "0", "f", "3.0.2-0ubuntu1.6"))},
			verdict: verdictFixed, basis: "release", fixed: "3.0.2-0ubuntu1.6", records: "UBUNTU-CVE-2021-3711"},
		{name: "no record for the CVE", t: deb11, recs: []distroRecord{rec("DSA-9", []string{"CVE-2099-0001"}, entry("Debian:11", "i", "0"))},
			reason: "no_record"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := indexDistroRecords(c.recs).decide(c.t, "cve-2021-3711")
			if d.verdict != c.verdict || d.reason != c.reason {
				t.Fatalf("verdict=%d reason=%q, want %d / %q (evidence %+v)", d.verdict, d.reason, c.verdict, c.reason, d.evidence)
			}
			if c.verdict == verdictNone {
				return
			}
			e := d.evidence
			if e.Basis != c.basis || e.Fixed != c.fixed || strings.Join(e.Records, " ") != c.records ||
				strings.Join(e.Ecosystems, " ") != c.releases || e.Release != c.t.release || e.Installed != c.t.version ||
				e.Package != c.t.pkg || e.Source != model.DistroSourceOSV {
				t.Errorf("evidence = %+v", e)
			}
			want := map[distroVerdict]string{verdictAffected: "affected", verdictUnfixed: "unfixed", verdictFixed: "fixed"}[c.verdict]
			if e.Status != want {
				t.Errorf("status = %q, want %q", e.Status, want)
			}
		})
	}
}

// reduceOSVRecords: CVE ids from the id, aliases and upstream; the queried
// package only; withdrawn records dropped.
func TestM70ReduceOSVRecords(t *testing.T) {
	in := []client.OSVPackageRecord{
		{ID: "DEBIAN-CVE-2021-3449", Affected: []client.OSVAffected{
			{Package: client.OSVPackage{Name: "openssl", Ecosystem: "Debian:12"}, Ranges: eco(ev("i", "0", "f", "1.1.1k-1"))},
			{Package: client.OSVPackage{Name: "openssl1.0", Ecosystem: "Debian:12"}, Ranges: eco(ev("i", "0"))},
		}},
		{ID: "DSA-5103-1", Upstream: []string{"CVE-2021-4160", "DEBIAN-CVE-2021-4160", "CVE-2022-0778"}, Affected: []client.OSVAffected{
			{Package: client.OSVPackage{Name: "openssl", Ecosystem: "Debian:11"}, Ranges: eco(ev("i", "0", "f", "1.1.1k-1+deb11u2"))},
		}},
		{ID: "ALSA-2022:6224", Aliases: []string{"cve-2022-1292"}, Affected: []client.OSVAffected{
			{Package: client.OSVPackage{Name: "openssl", Ecosystem: "AlmaLinux:9"}},
		}},
		{ID: "DSA-WITHDRAWN", Withdrawn: "2026-01-01T00:00:00Z", Upstream: []string{"CVE-2020-0001"}, Affected: []client.OSVAffected{
			{Package: client.OSVPackage{Name: "openssl", Ecosystem: "Debian:11"}},
		}},
		{ID: "DSA-OTHER", Upstream: []string{"CVE-2020-0002"}, Affected: []client.OSVAffected{
			{Package: client.OSVPackage{Name: "OpenSSL", Ecosystem: "Debian:11"}},
		}},
		{ID: "DSA-NOCVE", Upstream: []string{"DEBIAN-CVE-x", "GHSA-xxxx"}, Affected: []client.OSVAffected{
			{Package: client.OSVPackage{Name: "openssl", Ecosystem: "Debian:11"}},
		}},
	}
	got := reduceOSVRecords(in, "openssl")
	if len(got) != 3 {
		t.Fatalf("kept %d records, want 3: %+v", len(got), got)
	}
	want := []struct{ id, cves, ecos string }{
		{"DEBIAN-CVE-2021-3449", "CVE-2021-3449", "Debian:12"},
		{"DSA-5103-1", "CVE-2021-4160 CVE-2022-0778", "Debian:11"},
		{"ALSA-2022:6224", "CVE-2022-1292", "AlmaLinux:9"},
	}
	for i, w := range want {
		var ecos []string
		for _, e := range got[i].Entries {
			ecos = append(ecos, e.Ecosystem)
		}
		if got[i].ID != w.id || strings.Join(got[i].CVEs, " ") != w.cves || strings.Join(ecos, " ") != w.ecos {
			t.Errorf("record %d = %+v, want %+v", i, got[i], w)
		}
	}
}

func TestM70ParsePurl(t *testing.T) {
	p, ok := parsePurl("pkg:deb/debian/linux-image-5.10.0-8-amd64@5.10.46-4?arch=amd64&distro=debian-11&upstream=linux-signed-amd64%405.10.46%2B4#sub/path")
	if !ok || p.typ != "deb" || p.namespace != "debian" || p.name != "linux-image-5.10.0-8-amd64" || p.version != "5.10.46-4" ||
		p.qualifiers.Get("upstream") != "linux-signed-amd64@5.10.46+4" {
		t.Errorf("parsePurl = %+v, %v", p, ok)
	}
	p, ok = parsePurl("pkg:rpm/almalinux/openssl@1%3A3.0.7-27.el9")
	if !ok || p.version != "1:3.0.7-27.el9" {
		t.Errorf("percent-encoded epoch: %+v, %v", p, ok)
	}
	for _, bad := range []string{"", "pkg:", "pkg:deb", "deb/debian/openssl@1", "pkg:deb/debian/%zz@1", "pkg:deb/debian/openssl@1?a=%zz"} {
		if p, ok := parsePurl(bad); ok {
			t.Errorf("parsePurl(%q) = %+v, want failure", bad, p)
		}
	}
}
