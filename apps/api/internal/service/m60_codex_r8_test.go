package service

import "testing"

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
	if got := verifyCPEMatch(cve, cpeCandidate{part: "a", vendor: "acme", product: "widget", version: "1.0", raw: "1.0"}); got != cpeUndecidable {
		t.Errorf("truncated criterion = %v, want undecidable", got)
	}
}
