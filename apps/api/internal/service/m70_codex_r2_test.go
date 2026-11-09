package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/cache"
	"github.com/sbomhub/sbomhub/internal/client"
)

// Codex M70 R2 High-1: an advisory's CVE list is about ALL of its
// (package, release) entries; filtering it to one package must not turn it
// into a single-entry advisory. USN-5402-1 (committed fixture) lists four CVEs
// for openssl 18.04/20.04/22.04 and openssl1.0 18.04; UBUNTU-CVE-2022-1343
// names only openssl on 22.04.
func TestM70R2_AdvisoryCardinalityIsTheRecordsNotThePackages(t *testing.T) {
	var resp struct {
		Vulns []client.OSVPackageRecord `json:"vulns"`
	}
	m70LoadJSON(t, "testdata/m70/osv/ubuntu2204_openssl.json.gz", &resp)
	data := indexDistroRecords(reduceOSVRecords(resp.Vulns, "openssl1.0"))
	tgt, reason := distroTargetFor("pkg:deb/ubuntu/openssl1.0@1.0.2n-1ubuntu5.8?distro=ubuntu-18.04", "", nil)
	if reason != "" {
		t.Fatal(reason)
	}
	if d := data.decide(tgt, "CVE-2022-1343"); d.verdict != verdictNone {
		t.Errorf("openssl1.0 18.04 CVE-2022-1343 = %+v, want no verdict (multi-package, multi-CVE USN)", d)
	}
	// CVE-2022-1292 has its own UBUNTU-CVE record naming openssl1.0 on 18.04:
	// that record decides.
	if d := data.decide(tgt, "CVE-2022-1292"); d.verdict != verdictAffected || d.evidence.Records[0] != "UBUNTU-CVE-2022-1292" {
		t.Errorf("openssl1.0 18.04 CVE-2022-1292 = %+v, want affected from UBUNTU-CVE-2022-1292", d)
	}
	// A single-package, single-release, multi-CVE advisory still speaks.
	r := distroRecord{ID: "DLA-1", CVEs: []string{"CVE-2021-0001", "CVE-2021-0002"}, Releases: 1, Packages: 1,
		Entries: []distroEntry{entry("Debian:11", "i", "0", "f", "1.0-2")}}
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", version: "1.0-1", scheme: schemeDpkg}
	if d := indexDistroRecords([]distroRecord{r}).decide(deb11, "CVE-2021-0002"); d.verdict != verdictAffected {
		t.Errorf("single-pair DLA = %+v", d)
	}
	r.Packages = 2 // the same advisory also covered another source package
	if d := indexDistroRecords([]distroRecord{r}).decide(deb11, "CVE-2021-0002"); d.verdict != verdictNone {
		t.Errorf("two-pair DLA = %+v, want no verdict", d)
	}
}

// Codex M70 R2 High-2: OSV names the old Debian releases "Debian:3.0",
// "Debian:3.1", ..., "Debian:6.0"; collapsing them to a major number confuses
// 3.0 with 3.1. Releases before Debian 7 are not targets at all.
func TestM70R2_OldDebianReleasesAreNotTargets(t *testing.T) {
	for _, rel := range []string{"3.0", "3.1", "4.0", "5.0", "6.0", "6", "woody", "sarge", "squeeze"} {
		if tgt, reason := distroTargetFor("pkg:deb/debian/openssl@0.9.8-1?distro=debian-"+rel, "", nil); reason != "unknown_release" {
			t.Errorf("debian-%s: %+v %q, want unknown_release", rel, tgt, reason)
		}
	}
	if _, reason := distroTargetFor("pkg:deb/debian/openssl@1.0.1e-2?distro=debian-7", "", nil); reason != "" {
		t.Errorf("debian-7: %q", reason)
	}
}

// Codex M70 R2 High-3: a package query is bounded in TOTAL bytes, and pages
// are reduced as they arrive.
func TestM70R2_PackageQueryTotalBudget(t *testing.T) {
	big := `{"vulns":[{"id":"DSA-1","upstream":["CVE-2021-0001"],"affected":[{"package":{"name":"p","ecosystem":"Debian:11"}}],"pad":"` +
		strings.Repeat("x", 4096) + `"}],"next_page_token":"t"}`
	srv := newStaticOSV(t, big[:len(big)-len(`"t"}`)])
	c := client.NewOSVClient().WithBaseURL(srv)
	pages := 0
	_, err := c.QueryPackageEach(context.Background(), "Debian", "p", client.PackageQueryLimits{MaxPages: 50, MaxTotalBytes: 10000},
		nil, func([]client.OSVPackageRecord) error { pages++; return nil })
	if !errors.Is(err, client.ErrOSVQueryTruncated) {
		t.Errorf("err = %v, want ErrOSVQueryTruncated once the byte budget is spent", err)
	}
	if pages > 3 {
		t.Errorf("%d pages consumed, want the walk to stop at the byte budget", pages)
	}
}

// Codex M70 R2 Medium-6: the cache key includes the data source, so two
// deployments with different SBOMHUB_OSV_URL never read each other's data.
func TestM70R2_CacheKeyIncludesSource(t *testing.T) {
	a := cache.DistroCacheKey("https://api.osv.dev/v1", "Debian", "openssl")
	b := cache.DistroCacheKey("https://mirror.example/v1", "Debian", "openssl")
	if a == b {
		t.Error("same key for two OSV endpoints")
	}
	if a != cache.DistroCacheKey("https://api.osv.dev/v1/", "Debian", "openssl") {
		t.Error("a trailing slash changed the key")
	}
}

// Codex M70 R2 Medium-5: the down migration takes ACCESS EXCLUSIVE before it
// clears the distro labels, so no writer can relabel a row between the UPDATE
// and the narrowed CHECK.
func TestM70R2_DownMigrationLocksBeforeCleanup(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/070_component_vulnerabilities_distro_match.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	lock := strings.Index(s, "LOCK TABLE component_vulnerabilities IN ACCESS EXCLUSIVE MODE")
	upd := strings.Index(s, "UPDATE component_vulnerabilities")
	if lock < 0 || upd < 0 || lock > upd {
		t.Errorf("LOCK at %d, UPDATE at %d: the lock must come first", lock, upd)
	}
}

// newStaticOSV answers every query with prefix + a fresh page token.
func newStaticOSV(t *testing.T, prefix string) string {
	t.Helper()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n++
		_, _ = io.WriteString(w, prefix+`"t`+strconv.Itoa(n)+`"}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// An AlmaLinux erratum names the binary rpms of one source in one release:
// it speaks for every CVE it lists. Two releases: it does not.
func TestM70R2_RPMErratumSpeaksForItsRelease(t *testing.T) {
	cves := []string{"CVE-2021-0001", "CVE-2021-0002"}
	alma := distroTarget{family: "almalinux", query: "AlmaLinux:9", release: "AlmaLinux:9", pkg: "openssl-libs", version: "1:3.0.1-41.el9_0", scheme: schemeRPM}
	r := distroRecord{ID: "ALSA-1", CVEs: cves, Releases: 1, Packages: 4,
		Entries: []distroEntry{entry("AlmaLinux:9", "i", "0", "f", "1:3.0.1-43.el9_0")}}
	if d := indexDistroRecords([]distroRecord{r}).decide(alma, "CVE-2021-0002"); d.verdict != verdictAffected {
		t.Errorf("ALSA = %+v, want affected", d)
	}
	r.Releases = 2
	if d := indexDistroRecords([]distroRecord{r}).decide(alma, "CVE-2021-0002"); d.verdict != verdictNone {
		t.Errorf("two-release ALSA = %+v, want no verdict", d)
	}
}
