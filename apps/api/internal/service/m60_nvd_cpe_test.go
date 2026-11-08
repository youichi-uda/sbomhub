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
	c := cpeCandidate{part: "a", vendor: "golang", product: "x/net", version: "0.7.0+incompatible", raw: "0.7.0+incompatible"}
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

// M60 decision 1 (option B): compareVersions decides ONLY plain dotted-numeric
// pairs. Everything else is undecidable — including every scheme-specific
// case Codex M60 R2-R13 raised against the earlier, smarter comparator, each
// of which is listed here so a future "improvement" cannot quietly start
// excluding on them again.
func TestM60CompareVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"9.0.30", "9.0.31", -1},
		{"9.0.30", "9.0.4", 1}, // numeric, not lexical
		{"2.14.1", "2.15.0", -1},
		{"1.0", "1.0.0", 0},
		{"5.10.46", "5.10.46", 0},
		{"0.7.0", "0.17.0", -1},
		{"v0.7.0", "0.7.0", 0}, // one leading v is allowed
		{"1.01", "1.1", 0},
		{"10", "9.99", 1},
	} {
		got, ok := compareVersions(tc.a, tc.b)
		if !ok || got != tc.want {
			t.Errorf("compareVersions(%q,%q) = %d,%v want %d", tc.a, tc.b, got, ok, tc.want)
		}
	}
	nonPlain := []string{
		"1.1.1k", "1.1.1za", "1.0.2zd", "2.0-beta9", "2.0-rc1", "9.0.0.M1", "9.0.0-M1",
		"1.0a1", "1.0b1", "1.0c", "1.0c1", "1.0a", "1.1.1a", "1.0-dev", "1.0-pre1", "1.0-preview",
		"1.0-SNAPSHOT", "1.0.0-1", "1.0.0+1", "v2.0.0+incompatible", "1.2.3+dfsg", "1.0.0-final",
		"4.1.100.Final", "1.0_final", "1.0final", "1.1.1-k", "1!2.0", "1.0~1", "1.0^20210101",
		"1..0", ".1", "1.0.", "1_2_3", "1.0.0-rc.1", "1.0 beta", "1.1.1k-1", "2.31-13", "1:2.31",
		"vv1.0", "", "V", "-1",
	}
	for _, v := range nonPlain {
		for _, other := range []string{"1.0", "2.0", v} {
			if c, ok := compareVersions(v, other); ok {
				t.Errorf("compareVersions(%q,%q) = %d decided; only plain dotted-numeric pairs may be", v, other, c)
			}
			if c, ok := compareVersions(other, v); ok {
				t.Errorf("compareVersions(%q,%q) = %d decided; only plain dotted-numeric pairs may be", other, v, c)
			}
		}
	}
}

// For a non-plain component version, or a criterion with a non-plain bound
// or a pinned update, NO criterion shape may reject: the verdict is matched
// (an unbounded "*" criterion — no comparison involved) or undecidable.
func TestM60NonPlainNeverRejectsByComparison(t *testing.T) {
	shapes := []NVDCPEMatch{
		{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:2.0:*:*:*:*:*:*:*"},
		{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:2.0:-:*:*:*:*:*:*"},
		{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:2.0:beta9:*:*:*:*:*:*"},
		{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:-:*:*:*:*:*:*:*"},
		{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionEndExcluding: "1.0"},
		{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionStartIncluding: "3.0", VersionEndExcluding: "3.1"},
		{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionStartExcluding: "0.1", VersionEndIncluding: "0.2"},
	}
	cands := []cpeCandidate{
		{part: "a", vendor: "v", product: "p", version: "2.0-beta9", raw: "2.0-beta9"},
		{part: "a", vendor: "v", product: "p", version: "1.1.1k", raw: "1.1.1k"},
		{part: "a", vendor: "v", product: "p", version: "1.1.1k", raw: "1.1.1k-1"},           // distro raw
		{part: "a", vendor: "v", product: "p", version: "2.0.0", raw: "v2.0.0+incompatible"}, // build metadata
		{part: "a", vendor: "v", product: "p", version: "2.0", update: "sp1", raw: "2.0"},    // pinned update
	}
	for _, c := range cands {
		for _, m := range shapes {
			crit, _ := parseCPE(m.Criteria)
			if got := criterionContains(crit, m, c); got == cpeRejected {
				t.Errorf("non-plain candidate %+v rejected by %s %+v", c, m.Criteria, m)
			}
		}
	}
	// A plain candidate against a non-plain bound or a pinned update: same.
	plainC := cpeCandidate{part: "a", vendor: "v", product: "p", version: "5.0", raw: "5.0"}
	for _, m := range []NVDCPEMatch{
		{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionStartIncluding: "2.0-beta9", VersionEndExcluding: "2.3"},
		{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:2.0:beta9:*:*:*:*:*:*"},
		{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionEndExcluding: "1.1.1b"},
	} {
		crit, _ := parseCPE(m.Criteria)
		if got := criterionContains(crit, m, plainC); got != cpeUndecidable {
			t.Errorf("plain 5.0 vs %s %+v = %v, want undecidable", m.Criteria, m, got)
		}
	}
	// And plain-vs-plain does decide, both ways.
	for _, tc := range []struct {
		m    NVDCPEMatch
		want cpeVerdict
	}{
		{NVDCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionStartIncluding: "4.0", VersionEndExcluding: "5.1"}, cpeMatched},
		{NVDCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionEndExcluding: "5.0"}, cpeRejected},
		{NVDCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:5.0.0:*:*:*:*:*:*:*"}, cpeMatched},
		{NVDCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:5.0:-:*:*:*:*:*:*"}, cpeMatched},
		{NVDCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:5.1:*:*:*:*:*:*:*"}, cpeRejected},
	} {
		crit, _ := parseCPE(tc.m.Criteria)
		if got := criterionContains(crit, tc.m, plainC); got != tc.want {
			t.Errorf("plain 5.0 vs %s %+v = %v, want %v", tc.m.Criteria, tc.m, got, tc.want)
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
// platform. Those 5 are rejected — on positive evidence that involves no
// version comparison. "1.1.1k" is not plain, so (option B) the other 42 are
// undecidable, not matched: kept, labelled nvd_cpe_unverified.
func TestM60VerifyCPEMatch_OpenSSLRejectsPlatformOnlyCVEs(t *testing.T) {
	r := m60NVDFixture(t, "p06_cpename_openssl")
	cand := cpeCandidate{part: "a", vendor: "openssl", product: "openssl", version: "1.1.1k", raw: "1.1.1k"}
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
	if matched != 0 || undecidable != 42 {
		t.Errorf("matched=%d undecidable=%d, want 0 / 42", matched, undecidable)
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
		{"p01_cpename_log4j", cpeCandidate{part: "a", vendor: "apache", product: "log4j", version: "2.14.1", raw: "2.14.1"}, 10},
		{"p09_cpename_tomcat", cpeCandidate{part: "a", vendor: "apache", product: "tomcat", version: "9.0.30", raw: "9.0.30"}, 0},
		{"p11_cpename_lodash_node", cpeCandidate{part: "a", vendor: "lodash", product: "lodash", version: "4.17.20", raw: "4.17.20"}, 5},
		{"p14_cpename_xnet", cpeCandidate{part: "a", vendor: "golang", product: "networking", version: "0.7.0", raw: "0.7.0"}, 2},
		{"p15_cpename_gin", cpeCandidate{part: "a", vendor: "gin-gonic", product: "gin", version: "1.7.0", raw: "1.7.0"}, 2},
		{"p18_cpename_glibc", cpeCandidate{part: "a", vendor: "gnu", product: "glibc", version: "2.31", raw: "2.31"}, 0},
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

// Log4Shell's configurations mix plain ranges with exact criteria that pin
// an update (log4j:2.0:beta9, 2.0:rc1, ...). Under option B a pinned update
// is not plain, so a version the plain ranges exclude is still UNDECIDABLE —
// kept as nvd_cpe_unverified — because one of its criteria cannot be decided.
// Versions inside a plain range, or equal to the NA criterion 2.0:-, match.
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
		"2.12.1":    cpeMatched,
		"2.0.1":     cpeMatched, // >= 2.0.1, < 2.3.1
		"2.0":       cpeMatched, // log4j:2.0:- (the final release)
		"2.15.0":    cpeUndecidable,
		"2.17.1":    cpeUndecidable,
		"1.2.17":    cpeUndecidable,
		"2.0-beta9": cpeUndecidable,
		"2.0-beta1": cpeUndecidable,
	} {
		got := verifyCPEMatch(log4shell, cpeCandidate{part: "a", vendor: "apache", product: "log4j", version: v, raw: v})
		if got != want {
			t.Errorf("CVE-2021-44228 @ %s = %v want %v", v, got, want)
		}
	}
	// A CVE whose configurations are plain throughout IS excluded by a plain
	// comparison (synthetic; see also TestM60NonPlainNeverRejectsByComparison).
	plainOnly := NVDCVE{Configurations: []NVDConfiguration{{Nodes: []NVDConfigNode{{CpeMatch: []NVDCPEMatch{
		{Vulnerable: true, Criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", VersionStartIncluding: "2.4", VersionEndExcluding: "2.15.0"},
	}}}}}}
	if got := verifyCPEMatch(plainOnly, cpeCandidate{part: "a", vendor: "apache", product: "log4j", version: "2.15.0", raw: "2.15.0"}); got != cpeRejected {
		t.Errorf("plain 2.15.0 outside plain [2.4,2.15.0) = %v, want rejected", got)
	}
	// A product the CVE never mentions is never MATCHED. Since Codex M60 R1
	// High-2 it is "undecidable" rather than rejected — rejection needs
	// positive evidence — which only matters for a mirror that answers a
	// cpeName query with records not about that product.
	if got := verifyCPEMatch(log4shell, cpeCandidate{part: "a", vendor: "apache", product: "log4j-core", version: "2.14.1", raw: "2.14.1"}); got == cpeMatched {
		t.Errorf("log4j-core product matched: %v", got)
	}
}

// The evidence behind "non-plain versions skip cpeName and walk the product":
// NVD's own cpeName answer for log4j 2.0-beta9 (recorded live 2026-11-08) has
// 4 CVEs and NOT Log4Shell, although CVE-2021-44228's configurations list
// log4j:2.0:beta9. NVD's server-side evaluation of a non-plain version is
// incomplete, so it may not stand in for an exclusion either.
func TestM60CPENameAnswerForQualifiedVersionIsIncomplete(t *testing.T) {
	r := m60NVDFixture(t, "w01_cpename_log4j_beta9_dash")
	for _, e := range r.entries() {
		if e.CVE.ID == "CVE-2021-44228" {
			t.Fatalf("fixture changed: the cpeName answer now contains Log4Shell")
		}
	}
	if n := len(r.entries()); n != 4 {
		t.Errorf("fixture holds %d CVEs, recorded 4", n)
	}
}
