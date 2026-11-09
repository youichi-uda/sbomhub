package service

import (
	"context"
	"testing"

	"github.com/sbomhub/sbomhub/internal/client"
)

// Codex M70 R4 High-1: only canonical Debian ecosystems are ordered:
// "Debian:N" (no leading zero) and OSV's historical "Debian:3.0" / "3.1" /
// "4.0" / "5.0" / "6.0". Anything else blocks later_releases.
func TestM70R4_DebianEcosystemIsCanonical(t *testing.T) {
	for in, want := range map[string]int{"Debian:7": 7, "Debian:12": 12, "Debian:14": 14, "Debian:3.0": 3, "Debian:3.1": 3, "Debian:6.0": 6} {
		if n, ok := debianEcosystemMajor(in); !ok || n != want {
			t.Errorf("%s -> %d %v, want %d", in, n, ok, want)
		}
	}
	for _, bad := range []string{"Debian:12.3", "Debian:012", "Debian:0", "Debian:7.0", "Debian:3.2", "Debian:12.0"} {
		if n, ok := debianEcosystemMajor(bad); ok {
			t.Errorf("%s parsed as %d", bad, n)
		}
	}
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", version: "2.0-1", scheme: schemeDpkg}
	r := rec("DEBIAN-CVE-2021-0001", []string{"CVE-2021-0001"}, entry("Debian:12.3", "i", "0", "f", "1.0-1"))
	if d := indexDistroRecords([]distroRecord{r}).decide(deb11, "CVE-2021-0001"); d.verdict != verdictNone {
		t.Errorf("Debian:12.3 proved %+v", d)
	}
}

// Codex M70 R4 High-3: an Ubuntu entry lists the BINARY packages it applies
// to; a binary of the same source that is not listed gets no verdict. On the
// committed fixture, UBUNTU-CVE-2021-3711 for 20.04 names libssl1.1 and
// openssl only.
func TestM70R4_UbuntuEntryBinariesAreHonoured(t *testing.T) {
	var resp struct {
		Vulns []client.OSVPackageRecord `json:"vulns"`
	}
	m70LoadJSON(t, "testdata/m70/osv/ubuntu2204_openssl.json.gz", &resp)
	data := indexDistroRecords(reduceOSVRecords(resp.Vulns, "openssl"))
	doc, _ := distroTargetFor("pkg:deb/ubuntu/libssl-doc@1.1.1f-1ubuntu2.7?distro=ubuntu-20.04&upstream=openssl", "", nil)
	if d := data.decide(doc, "CVE-2021-3711"); d.verdict != verdictNone {
		t.Errorf("libssl-doc = %+v, want no verdict (not a listed binary)", d)
	}
	lib, _ := distroTargetFor("pkg:deb/ubuntu/libssl1.1@1.1.1f-1ubuntu2.7?distro=ubuntu-20.04&upstream=openssl", "", nil)
	if d := data.decide(lib, "CVE-2021-3711"); d.verdict != verdictAffected {
		t.Errorf("libssl1.1 = %+v, want affected", d)
	}
	// An Ubuntu entry with no binaries list does not say which binaries.
	u := distroTarget{family: "ubuntu", query: "Ubuntu:22.04:LTS", release: "Ubuntu:22.04:LTS", pkg: "p", binary: "p", version: "1.0-1", scheme: schemeDpkg}
	r := rec("UBUNTU-CVE-2021-0001", []string{"CVE-2021-0001"}, entry("Ubuntu:22.04:LTS", "i", "0", "f", "1.0-2"))
	if d := indexDistroRecords([]distroRecord{r}).decide(u, "CVE-2021-0001"); d.verdict != verdictNone {
		t.Errorf("no binaries list = %+v, want no verdict", d)
	}
}

// Codex M70 R4 Medium-5: when the scan's context ends after the last fetch,
// the step still reports the interruption.
func TestM70R4_InterruptionAfterFetchIsReported(t *testing.T) {
	ctx, cancel := WithScanDeadline(context.Background(), 1)
	defer cancel()
	<-ctx.Done()
	rep := DistroScanReport{}
	rep.noteInterruption(ctx)
	if !rep.DeadlineExceeded || rep.incompleteErr() == nil {
		t.Errorf("report %+v", rep)
	}
}
