package service

import "testing"

// Codex M60 R8 High: a letter token directly after '-' is a SemVer
// pre-release whatever it says, while Maven reads "-final" as the release and
// OpenSSL writes patch letters without a dash. Schemes agree only for a
// recognised pre-release word ("2.0-beta9", "2.0-rc1"); any other letters
// after '-' make the order undecidable. Release markers are dropped only
// after '.', where every scheme agrees ("4.1.100.Final").
func TestM60R8_LettersAfterDashAreDecidedOnlyForPreReleaseWords(t *testing.T) {
	for _, tc := range []struct{ a, b string }{
		{"1.0.0-final", "1.0.0"},
		{"1.1.1-k", "1.1.1"},
		{"1.0-ga", "1.0"},
		{"1.0-release", "1.0.1"},
	} {
		if c, ok := compareVersions(tc.a, tc.b); ok {
			t.Errorf("compareVersions(%q,%q) = %d decided; want undecidable", tc.a, tc.b, c)
		}
	}
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"2.0-beta9", "2.0", -1},
		{"2.0-rc1", "2.0", -1},
		{"9.0.0-M1", "9.0.0", -1},
		{"4.1.100.Final", "4.1.100", 0},
		{"1.1.1k", "1.1.1", 1},
	} {
		if c, ok := compareVersions(tc.a, tc.b); !ok || c != tc.want {
			t.Errorf("compareVersions(%q,%q) = %d,%v want %d", tc.a, tc.b, c, ok, tc.want)
		}
	}
	m := NVDCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", VersionEndExcluding: "1.0.0"}
	crit, _ := parseCPE(m.Criteria)
	if got := criterionContains(crit, m, cpeCandidate{part: "a", vendor: "v", product: "p", version: "1.0.0-final"}); got != cpeUndecidable {
		t.Errorf("1.0.0-final in (,1.0.0) = %v, want undecidable", got)
	}
}

// Codex M60 R8 Medium: a truncated CPE 2.3 string is not a CPE. Accepted, a
// mirror's "cpe:2.3:a:acme:widget" criterion read as "every version".
func TestM60R8_TruncatedCPEIsRejected(t *testing.T) {
	for _, s := range []string{
		"cpe:2.3:a:acme:widget",
		"cpe:2.3:a:acme:widget:1.0",
		"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*:extra",
		`cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:\`,
		"cpe:/a:acme:widget:1.0:u:e:l:extra",
	} {
		if _, ok := parseCPE(s); ok {
			t.Errorf("parseCPE(%q) accepted a malformed name", s)
		}
	}
	for _, s := range []string{"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", "cpe:/a:acme:widget", "cpe:/a:acme:widget:1.0:u:e:l"} {
		if _, ok := parseCPE(s); !ok {
			t.Errorf("parseCPE(%q) rejected a valid name", s)
		}
	}
	// A truncated criterion is no evidence: unverifiable, not a match.
	cve := NVDCVE{Configurations: []NVDConfiguration{{Nodes: []NVDConfigNode{{CpeMatch: []NVDCPEMatch{
		{Vulnerable: true, Criteria: "cpe:2.3:a:acme:widget"},
	}}}}}}
	if got := verifyCPEMatch(cve, cpeCandidate{part: "a", vendor: "acme", product: "widget", version: "1.0"}); got != cpeUndecidable {
		t.Errorf("truncated criterion = %v, want undecidable", got)
	}
}
