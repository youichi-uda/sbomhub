package service

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/client"
	"github.com/sbomhub/sbomhub/internal/pkgversion"
)

// M70 on the M60 fixture: Debian 11 openssl 1.1.1k-1 (Syft 1.46.0), whose
// 313 NVD links were ALL nvd_cpe_unverified under M60 (44 true per M60's
// ground truth, precision 14%).
//
// Inputs, all recorded live and committed:
//   - testdata/m60/nvd/v01_vms_openssl_p{0,1}: NVD's product-level answer
//     for openssl (2026-11-08), replayed through the real M60 lookup.
//   - testdata/m70/osv/debian_openssl.json.gz: OSV's answer for
//     {"package":{"name":"openssl","ecosystem":"Debian"}} (2026-11-09).
//   - testdata/m70/debian_tracker_openssl.json.gz: the openssl subset of the
//     Debian security tracker's JSON (2026-11-09), for the cross-check.

func m70LoadJSON(t *testing.T, path string, v any) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(zr).Decode(v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func m70OSVData(t *testing.T, name, pkg string) distroData {
	t.Helper()
	var resp struct {
		Vulns []client.OSVPackageRecord `json:"vulns"`
	}
	m70LoadJSON(t, filepath.Join("testdata", "m70", "osv", name+".json.gz"), &resp)
	return indexDistroRecords(reduceOSVRecords(resp.Vulns, pkg))
}

// m70OpenSSLLinks runs the M60 lookup for the fixture's openssl over the
// recorded NVD pages and returns the CVEs it keeps (the links M60 writes).
func m70OpenSSLLinks(t *testing.T) []string {
	t.Helper()
	r := &replayNVD{t: t, routes: map[string]string{
		"virtualMatchString=cpe:2.3:a:openssl:openssl@0":   "v01_vms_openssl_p0",
		"virtualMatchString=cpe:2.3:a:openssl:openssl@199": "v01_vms_openssl_p1",
	}}
	svc := NewNVDService(nil, nil, "", r.start().URL, false)
	l, err := svc.lookupComponent(context.Background(), m60Item(t, "openssl"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return m60IDs(l)
}

// m70UpstreamTruth is the ground truth M60 used, recomputed from the recorded
// NVD configurations: the CVEs whose vulnerable openssl:openssl criteria
// contain UPSTREAM 1.1.1k under OpenSSL's own ordering (numeric segments,
// then the letter suffix: 1.1.1j < 1.1.1k < 1.1.1l). Test-only oracle — the
// production matcher deliberately has no OpenSSL comparator (M60 option B).
func m70UpstreamTruth(t *testing.T) map[string]bool {
	t.Helper()
	re := regexp.MustCompile(`^(\d+(?:\.\d+)*)([a-z]*)$`)
	type key struct {
		n   [4]int
		sfx string
	}
	parse := func(v string) (key, bool) {
		m := re.FindStringSubmatch(v)
		if m == nil {
			return key{}, false
		}
		var k key
		for i, p := range strings.Split(m[1], ".") {
			if i >= 4 {
				return key{}, false
			}
			k.n[i], _ = strconv.Atoi(p)
		}
		k.sfx = m[2]
		return k, true
	}
	cmp := func(a, b key) int {
		for i := range a.n {
			if a.n[i] != b.n[i] {
				if a.n[i] < b.n[i] {
					return -1
				}
				return 1
			}
		}
		return strings.Compare(a.sfx, b.sfx)
	}
	inst, _ := parse("1.1.1k")
	truth := map[string]bool{}
	for _, page := range []string{"v01_vms_openssl_p0", "v01_vms_openssl_p1"} {
		var resp NVDResponse
		m70LoadJSON(t, filepath.Join("testdata", "m60", "nvd", page+".json.gz"), &resp)
		for _, e := range resp.entries() {
			for _, cfg := range e.CVE.Configurations {
				for _, n := range cfg.Nodes {
					if cfg.Negate || n.Negate {
						continue
					}
					for _, m := range n.CpeMatch {
						c, ok := parseCPE(m.Criteria)
						if !ok || c.Vendor != "openssl" || c.Product != "openssl" || !m.Vulnerable {
							continue
						}
						if cpeConcrete(c.Version) {
							v := c.Version
							if cpeConcrete(c.Update) {
								v += c.Update
							}
							if k, ok := parse(v); ok && cmp(k, inst) == 0 {
								truth[e.CVE.ID] = true
							}
							continue
						}
						in := true
						for _, b := range []struct {
							v  string
							ok func(int) bool
						}{
							{m.VersionStartIncluding, func(c int) bool { return c >= 0 }},
							{m.VersionStartExcluding, func(c int) bool { return c > 0 }},
							{m.VersionEndIncluding, func(c int) bool { return c <= 0 }},
							{m.VersionEndExcluding, func(c int) bool { return c < 0 }},
						} {
							if b.v == "" {
								continue
							}
							k, ok := parse(b.v)
							if !ok || !b.ok(cmp(inst, k)) {
								in = false
							}
						}
						if in {
							truth[e.CVE.ID] = true
						}
					}
				}
			}
		}
	}
	return truth
}

func TestM70Fixture_DebianOpenSSL(t *testing.T) {
	ids := m70OpenSSLLinks(t)
	if len(ids) != 313 {
		t.Fatalf("M60 lookup kept %d openssl CVEs, want 313", len(ids))
	}
	truth := m70UpstreamTruth(t)
	target, reason := distroTargetFor("pkg:deb/debian/openssl@1.1.1k-1?arch=amd64&distro=debian-11", "1.1.1k-1", nil)
	if reason != "" {
		t.Fatal(reason)
	}
	data := m70OSVData(t, "debian_openssl", "openssl")

	type row struct{ n, trueN int }
	byLabel := map[string]*row{}
	reasons := map[string]int{}
	var fixedIDs, affectedIDs []string
	for _, id := range ids {
		d := data.decide(target, id)
		label := "nvd_cpe_unverified (unchanged)"
		switch d.verdict {
		case verdictAffected:
			label = "distro_affected"
			affectedIDs = append(affectedIDs, id)
		case verdictUnfixed:
			label = "distro_unfixed"
		case verdictFixed:
			label = "distro_fixed/" + d.evidence.Basis
			fixedIDs = append(fixedIDs, id)
		default:
			reasons[d.reason]++
		}
		if byLabel[label] == nil {
			byLabel[label] = &row{}
		}
		byLabel[label].n++
		if truth[id] {
			byLabel[label].trueN++
		}
	}
	trueKept := 0
	for _, id := range ids {
		if truth[id] {
			trueKept++
		}
	}
	labels := make([]string, 0, len(byLabel))
	for l := range byLabel {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	for _, l := range labels {
		t.Logf("%-34s links=%3d true=%3d", l, byLabel[l].n, byLabel[l].trueN)
	}
	t.Logf("no-verdict reasons: %v; upstream truth among the 313 links: %d", reasons, trueKept)

	// Pinned on the recorded data (2026-11-09).
	want := map[string]row{
		"distro_affected":                {25, 25},
		"distro_fixed/later_releases":    {181, 0},
		"nvd_cpe_unverified (unchanged)": {107, 17},
	}
	for l, w := range want {
		if g := byLabel[l]; g == nil || *g != w {
			t.Errorf("%s = %+v, want %+v", l, g, w)
		}
	}
	if len(byLabel) != len(want) {
		t.Errorf("labels %v, want exactly %v", labels, want)
	}
	// The invariant on real data: no upstream-true CVE is labelled fixed.
	for _, id := range fixedIDs {
		if truth[id] {
			t.Errorf("%s is upstream-affected at 1.1.1k but labelled distro_fixed", id)
		}
	}
	// Every distro_affected CVE is a true finding.
	for _, id := range affectedIDs {
		if !truth[id] {
			t.Errorf("%s labelled distro_affected but not upstream-affected", id)
		}
	}
}

// Cross-check against the Debian security tracker (2026-11-09): for every CVE
// labelled distro_fixed on the later_releases basis, the tracker's UNSTABLE
// fixed version must be at or below 1.1.1k-1 by dpkg — that is the rule the
// tracker itself applies to a release without a release-specific note. And
// the CVEs the tracker marks not-affected (fixed_version "0") have no OSV
// record, so they must get no verdict (not "fixed").
func TestM70Fixture_DebianTrackerCrossCheck(t *testing.T) {
	var tracker map[string]map[string]struct {
		Releases map[string]struct {
			Status       string `json:"status"`
			FixedVersion string `json:"fixed_version"`
		} `json:"releases"`
	}
	m70LoadJSON(t, filepath.Join("testdata", "m70", "debian_tracker_openssl.json.gz"), &tracker)
	tr := tracker["openssl"]
	if len(tr) != 320 {
		t.Fatalf("tracker subset has %d openssl CVEs, want 320", len(tr))
	}
	for _, rel := range []string{"bullseye"} {
		for id, c := range tr {
			if _, ok := c.Releases[rel]; ok {
				t.Fatalf("tracker lists %s for %s; the EOL premise of later_releases no longer holds — re-measure", rel, id)
			}
		}
	}
	target, _ := distroTargetFor("pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11", "", nil)
	data := m70OSVData(t, "debian_openssl", "openssl")
	agree, notAffected := 0, 0
	for id, c := range tr {
		sid, ok := c.Releases["sid"]
		if !ok {
			continue
		}
		d := data.decide(target, id)
		if sid.FixedVersion == "0" {
			notAffected++
			if d.verdict != verdictNone {
				t.Errorf("%s: tracker not-affected (0), got verdict %d", id, d.verdict)
			}
			continue
		}
		if d.verdict != verdictFixed {
			continue
		}
		cmp, err := pkgversion.CompareDpkg(target.version, sid.FixedVersion)
		if err != nil || cmp < 0 {
			t.Errorf("%s labelled distro_fixed, but the tracker's unstable fix is %q (> 1.1.1k-1)", id, sid.FixedVersion)
			continue
		}
		agree++
	}
	t.Logf("distro_fixed CVEs agreeing with the tracker's unstable fix: %d; tracker not-affected CVEs: %d", agree, notAffected)
	if agree == 0 || notAffected != 29 {
		t.Errorf("agree=%d notAffected=%d", agree, notAffected)
	}
}

// The other recorded distros: the rules hold on real AlmaLinux 9 and
// Ubuntu 22.04 data too (exact release only).
func TestM70Fixture_OtherDistros(t *testing.T) {
	alma := m70OSVData(t, "almalinux9_openssl", "openssl")
	at, _ := distroTargetFor("pkg:rpm/almalinux/openssl@3.0.7-6.el9_2?epoch=1&distro=almalinux-9.2", "", nil)
	// ALSA-2023:2523 fixes CVE-2022-3358 at 1:3.0.7-6.el9_2: installed exactly that.
	if d := alma.decide(at, "CVE-2022-3358"); d.verdict != verdictFixed || d.evidence.Fixed != "1:3.0.7-6.el9_2" {
		t.Errorf("alma CVE-2022-3358 = %+v", d)
	}
	// ALSA-2023:0946 (1:3.0.1-47.el9_1) is below 3.0.7: fixed.
	if d := alma.decide(at, "CVE-2023-0286"); d.verdict != verdictFixed {
		t.Errorf("alma CVE-2023-0286 = %+v", d)
	}
	old, _ := distroTargetFor("pkg:rpm/almalinux/openssl@3.0.1-41.el9_0?epoch=1&distro=almalinux-9", "", nil)
	if d := alma.decide(old, "CVE-2022-3602"); d.verdict != verdictAffected || d.evidence.Fixed != "1:3.0.1-43.el9_0" {
		t.Errorf("alma CVE-2022-3602 on 3.0.1-41 = %+v", d)
	}
	// The SBOM dropped the epoch: no verdict.
	noEpoch, _ := distroTargetFor("pkg:rpm/almalinux/openssl@3.0.1-41.el9_0?distro=almalinux-9", "", nil)
	if d := alma.decide(noEpoch, "CVE-2022-3602"); d.verdict != verdictNone {
		t.Errorf("alma without epoch = %+v, want no verdict", d)
	}

	ubu := m70OSVData(t, "ubuntu2204_openssl", "openssl")
	ut, _ := distroTargetFor("pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?distro=ubuntu-22.04", "", nil)
	counts := map[distroVerdict]int{}
	for cve := range ubu.byCVE {
		counts[ubu.decide(ut, cve).verdict]++
	}
	t.Logf("ubuntu 22.04 openssl 3.0.2-0ubuntu1.10 over %d CVEs: none=%d affected=%d unfixed=%d fixed=%d",
		len(ubu.byCVE), counts[verdictNone], counts[verdictAffected], counts[verdictUnfixed], counts[verdictFixed])
	if counts[verdictAffected] == 0 || counts[verdictFixed] == 0 {
		t.Errorf("ubuntu verdicts %v: expected both affected and fixed", counts)
	}
}

// Debian 11 libc6 2.31-13 (Syft: upstream=glibc), on the recorded OSV glibc
// answer. M60 links nothing for it (Syft's CPE names no NVD product, and the
// keyword search answers 0), so this only shows that the source-package
// mapping reaches real data.
func TestM70Fixture_DebianGlibc(t *testing.T) {
	data := m70OSVData(t, "debian_glibc", "glibc")
	target, reason := distroTargetFor("pkg:deb/debian/libc6@2.31-13?arch=amd64&distro=debian-11&upstream=glibc", "2.31-13", nil)
	if reason != "" || target.pkg != "glibc" {
		t.Fatalf("target %+v reason %q", target, reason)
	}
	counts := map[distroVerdict]int{}
	for cve := range data.byCVE {
		counts[data.decide(target, cve).verdict]++
	}
	t.Logf("glibc 2.31-13 over %d CVEs: none=%d affected=%d unfixed=%d fixed=%d",
		len(data.byCVE), counts[verdictNone], counts[verdictAffected], counts[verdictUnfixed], counts[verdictFixed])
	if counts[verdictAffected] == 0 || counts[verdictFixed] == 0 {
		t.Errorf("verdicts %v", counts)
	}
}
