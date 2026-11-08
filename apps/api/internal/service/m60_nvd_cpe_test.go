package service

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// The NVD responses under testdata/m60/nvd were recorded from the LIVE NVD
// CVE API 2.0 on 2026-11-08 (no API key; request log in
// testdata/m60/nvd_calls.txt). Tests read them; none of them hits NVD.

func m60NVDFixture(t *testing.T, name string) *NVDResponse {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "m60", "nvd", name+".json.gz"))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	var r NVDResponse
	if err := json.NewDecoder(zr).Decode(&r); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return &r
}

func TestM60ParseCPE(t *testing.T) {
	cases := []struct {
		in   string
		want cpeName
		ok   bool
	}{
		{"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", cpeName{"a", "apache", "log4j", "2.14.1", "*"}, true},
		{"cpe:2.3:a:golang:x\\/net:0.7.0:*:*:*:*:go:*:*", cpeName{"a", "golang", "x/net", "0.7.0", "*"}, true},
		{"cpe:2.3:o:linux:linux_kernel:5.10.46:*:*:*:*:*:*:*", cpeName{"o", "linux", "linux_kernel", "5.10.46", "*"}, true},
		{"cpe:/a:openssl:openssl:1.1.1k", cpeName{"a", "openssl", "openssl", "1.1.1k", ""}, true},
		{"cpe:/a:foo%2fbar:baz", cpeName{"a", "foo/bar", "baz", "", ""}, true},
		{"cpe:2.3:a:Apache:Log4J:2.0:beta9:*:*:*:*:*:*", cpeName{"a", "apache", "log4j", "2.0", "beta9"}, true},
		{"cpe:2.3:x:apache:log4j:1:*:*:*:*:*:*:*", cpeName{}, false}, // bad part
		{"cpe:2.3:a:*:log4j:1:*:*:*:*:*:*:*", cpeName{}, false},      // vendor ANY
		{"cpe:2.3:a:apache:-:1:*:*:*:*:*:*:*", cpeName{}, false},     // product NA
		{"pkg:npm/lodash@4.17.20", cpeName{}, false},
	}
	for _, tc := range cases {
		got, ok := parseCPE(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("parseCPE(%q) = %+v,%v want %+v,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestM60CandidateQueryRoundTrips(t *testing.T) {
	c := cpeCandidate{part: "a", vendor: "golang", product: "x/net", version: "0.7.0+incompatible"}
	if got, want := c.query(), `cpe:2.3:a:golang:x\/net:0.7.0\+incompatible:*:*:*:*:*:*:*`; got != want {
		t.Errorf("query = %q want %q", got, want)
	}
	n, ok := parseCPE(c.query())
	if !ok || n.Vendor != "golang" || n.Product != "x/net" || n.Version != "0.7.0+incompatible" {
		t.Errorf("query does not parse back: %+v %v", n, ok)
	}
	if got, want := c.productQuery(), `cpe:2.3:a:golang:x\/net`; got != want {
		t.Errorf("productQuery = %q want %q", got, want)
	}
}

func TestM60NormaliseCPEVersion(t *testing.T) {
	cases := []struct {
		in     string
		distro bool
		want   string
	}{
		{"v0.7.0", false, "0.7.0"}, // measured: v0.7.0 -> 0 CVEs, 0.7.0 -> 2
		{"V1.2", false, "1.2"},
		{"version", false, "version"},
		{"1.1.1k-1", false, "1.1.1k-1"},      // not a distro package: untouched
		{"1.1.1k-1", true, "1.1.1k"},         // Debian revision
		{"1.1.1k-1+deb11u2", true, "1.1.1k"}, // Debian security update
		{"1:2.31-13", true, "2.31"},          // epoch + revision
		{"2.17-326.el7", true, "2.17"},       // RPM release
		{"1.1.1k-r0", true, "1.1.1k"},        // Alpine
		{"5.10.46", true, "5.10.46"},         // no revision
	}
	for _, tc := range cases {
		if got := normaliseCPEVersion(tc.in, tc.distro); got != tc.want {
			t.Errorf("normaliseCPEVersion(%q,%v) = %q want %q", tc.in, tc.distro, got, tc.want)
		}
	}
}

func TestM60CompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"1.1.1k", "1.1.1l", -1, true},
		{"1.1.1k", "1.1.1", 1, true}, // OpenSSL letter release is AFTER the base
		{"1.1.1k", "1.1.1ze", -1, true},
		{"1.1.1z", "1.1.1za", -1, true},
		{"1.0.2zd", "1.0.2", 1, true},
		{"9.0.30", "9.0.31", -1, true},
		{"9.0.30", "9.0.4", 1, true}, // numeric, not lexical
		{"2.14.1", "2.15.0", -1, true},
		{"2.0-beta9", "2.0", -1, true}, // pre-release before release
		{"2.0-rc1", "2.0-beta9", 1, true},
		{"9.0.0.M1", "9.0.0", -1, true},
		{"2.0-beta9", "2.0.1", -1, true},
		{"1.0", "1.0.0", 0, true},
		{"5.10.46", "5.10.46", 0, true},
		{"0.7.0", "0.17.0", -1, true},
		{"1.2.a", "1.2.3", 0, false}, // not orderable without the scheme
		{"", "1.0", 0, false},
	}
	for _, tc := range cases {
		got, ok := compareVersions(tc.a, tc.b)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("compareVersions(%q,%q) = %d,%v want %d,%v", tc.a, tc.b, got, ok, tc.want, tc.ok)
		}
	}
}

// Syft's candidate list for log4j-core is [log4j-core, log4j_core, log4j];
// all three survive, in order, and the version comes from the CPE.
func TestM60CPECandidatesFromSyft(t *testing.T) {
	comps, err := parseCycloneDX(m60Fixture(t, "syft.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	log4j := m60Find(t, comps, "log4j-core")
	var got []string
	for _, c := range cpeCandidates(log4j.CPEs, log4j.Version, log4j.Purl) {
		got = append(got, c.String())
	}
	want := []string{"a:apache:log4j-core@2.14.1", "a:apache:log4j_core@2.14.1", "a:apache:log4j@2.14.1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("log4j-core candidates = %q want %q", got, want)
	}

	// Debian openssl: upstream version, distro flag.
	ossl := m60Find(t, comps, "openssl")
	cs := cpeCandidates(ossl.CPEs, ossl.Version, ossl.Purl)
	if len(cs) != 1 || cs[0].String() != "a:openssl:openssl@1.1.1k" {
		t.Errorf("openssl candidates = %v", cs)
	}

	// The Debian kernel package has 18 Syft candidates; only the first 3 are
	// tried (each unknown one costs 2 requests).
	kern := m60Find(t, comps, "linux-image-5.10.0-8-amd64")
	if len(kern.CPEs) < 10 {
		t.Fatalf("fixture changed: kernel package has %d CPEs", len(kern.CPEs))
	}
	if n := len(cpeCandidates(kern.CPEs, kern.Version, kern.Purl)); n != nvdMaxCPECandidates {
		t.Errorf("kernel package yields %d candidates, want the cap %d", n, nvdMaxCPECandidates)
	}

	// No version anywhere -> no candidate (a version-less cpeName would match
	// every version of the product).
	if cs := cpeCandidates([]string{"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"}, "", ""); len(cs) != 0 {
		t.Errorf("version-less CPE produced candidates: %v", cs)
	}
}

// verifyCPEMatch against the live openssl 1.1.1k answer: NVD's cpeName
// returned 47 CVEs, 5 of which name openssl ONLY as a vulnerable=false
// platform. Those 5 are rejected; nothing is undecidable.
func TestM60VerifyCPEMatch_OpenSSLRejectsPlatformOnlyCVEs(t *testing.T) {
	r := m60NVDFixture(t, "p06_cpename_openssl")
	cand := cpeCandidate{part: "a", vendor: "openssl", product: "openssl", version: "1.1.1k"}
	var rejected []string
	matched, undecidable := 0, 0
	for _, e := range r.entries() {
		switch verifyCPEMatch(e.CVE, cand) {
		case cpeMatched:
			matched++
		case cpeUndecidable:
			undecidable++
		case cpeRejected:
			rejected = append(rejected, e.CVE.ID)
		}
	}
	sort.Strings(rejected)
	want := []string{"CVE-2009-1390", "CVE-2009-3765", "CVE-2009-3766", "CVE-2009-3767", "CVE-2019-0190"}
	if !reflect.DeepEqual(rejected, want) {
		t.Errorf("rejected = %q want %q", rejected, want)
	}
	if matched != 42 || undecidable != 0 {
		t.Errorf("matched=%d undecidable=%d, want 42 / 0", matched, undecidable)
	}
}

// Across every recorded cpeName answer, the local evaluation never disagrees
// with NVD's server-side VERSION evaluation: every rejection is a
// platform-only (vulnerable=false) appearance, never a version-range
// disagreement. This is the measured basis for letting the local verdict
// drop records.
func TestM60VerifyCPEMatch_NoVersionDisagreementOnRecordedAnswers(t *testing.T) {
	cases := []struct {
		fixture string
		cand    cpeCandidate
		want    int // CVEs kept (matched + undecidable)
	}{
		{"p01_cpename_log4j", cpeCandidate{"a", "apache", "log4j", "2.14.1", ""}, 10},
		{"p09_cpename_tomcat", cpeCandidate{"a", "apache", "tomcat", "9.0.30", ""}, 0},
		{"p11_cpename_lodash_node", cpeCandidate{"a", "lodash", "lodash", "4.17.20", ""}, 5},
		{"p14_cpename_xnet", cpeCandidate{"a", "golang", "networking", "0.7.0", ""}, 2},
		{"p15_cpename_gin", cpeCandidate{"a", "gin-gonic", "gin", "1.7.0", ""}, 2},
		{"p18_cpename_glibc", cpeCandidate{"a", "gnu", "glibc", "2.31", ""}, 0},
	}
	for _, tc := range cases {
		r := m60NVDFixture(t, tc.fixture)
		kept := 0
		for _, e := range r.entries() {
			v := verifyCPEMatch(e.CVE, tc.cand)
			if v != cpeRejected {
				kept++
				continue
			}
			// A rejection must be explained by the absence of ANY vulnerable
			// criterion for this product — not by our version comparator.
			for _, cfg := range e.CVE.Configurations {
				for _, n := range cfg.Nodes {
					for _, m := range n.CpeMatch {
						c, ok := parseCPE(m.Criteria)
						if ok && m.Vulnerable && c.Vendor == tc.cand.vendor && c.Product == tc.cand.product {
							t.Errorf("%s %s: rejected by the local VERSION check although NVD returned it (criterion %s %+v)",
								tc.fixture, e.CVE.ID, m.Criteria, m)
						}
					}
				}
			}
		}
		if tc.want > 0 && kept != tc.want {
			t.Errorf("%s: kept %d, want %d", tc.fixture, kept, tc.want)
		}
		if tc.want == 0 {
			t.Logf("%s: kept %d of %d", tc.fixture, kept, len(r.entries()))
		}
	}
}

// A version outside every range is rejected even if a server returned the
// CVE: the local check is not a rubber stamp.
func TestM60VerifyCPEMatch_RangeBoundaries(t *testing.T) {
	r := m60NVDFixture(t, "p01_cpename_log4j")
	var log4shell NVDCVE
	for _, e := range r.entries() {
		if e.CVE.ID == "CVE-2021-44228" {
			log4shell = e.CVE
		}
	}
	if log4shell.ID == "" {
		t.Fatal("fixture lacks CVE-2021-44228")
	}
	for v, want := range map[string]cpeVerdict{
		"2.14.1":    cpeMatched,
		"2.15.0":    cpeRejected, // fixed release
		"2.17.1":    cpeRejected,
		"2.12.1":    cpeMatched,
		"1.2.17":    cpeRejected, // log4j 1.x is not CVE-2021-44228
		"2.0-beta9": cpeMatched,  // NVD lists log4j:2.0:beta9 explicitly
		"2.0-rc2":   cpeMatched,
		"2.0":       cpeMatched,  // log4j:2.0:- (the final release)
		"2.0-beta1": cpeRejected, // not listed
		"2.0.1":     cpeMatched,  // >= 2.0.1, < 2.3.1
	} {
		got := verifyCPEMatch(log4shell, cpeCandidate{"a", "apache", "log4j", v, ""})
		if got != want {
			t.Errorf("CVE-2021-44228 @ %s = %v want %v", v, got, want)
		}
	}
	// A product the CVE never mentions is never MATCHED. Since Codex M60 R1
	// High-2 it is "undecidable" rather than rejected — rejection needs
	// positive evidence — which only matters for a mirror that answers a
	// cpeName query with records not about that product.
	if got := verifyCPEMatch(log4shell, cpeCandidate{"a", "apache", "log4j-core", "2.14.1", ""}); got == cpeMatched {
		t.Errorf("log4j-core product matched: %v", got)
	}
}
