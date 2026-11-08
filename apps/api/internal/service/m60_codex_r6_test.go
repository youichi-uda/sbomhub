package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Codex M60 R6 High-1: a criterion whose `update` is ANY accepts every
// update of its version, so candidate widget:2.0:beta1 is inside widget:2.0:*.
func TestM60R6_CriterionUpdateAnyAcceptsCandidateUpdate(t *testing.T) {
	c := cpeCandidate{part: "a", vendor: "v", product: "widget", version: "2.0", update: "beta1"}
	for _, tc := range []struct {
		criteria string
		want     cpeVerdict
	}{
		{"cpe:2.3:a:v:widget:2.0:*:*:*:*:*:*:*", cpeMatched},
		{"cpe:2.3:a:v:widget:2.0:beta1:*:*:*:*:*:*", cpeMatched},
		{"cpe:2.3:a:v:widget:2.0:beta2:*:*:*:*:*:*", cpeRejected},
		{"cpe:2.3:a:v:widget:2.0:-:*:*:*:*:*:*", cpeRejected}, // NA: the final release only
		{"cpe:2.3:a:v:widget:2.1:*:*:*:*:*:*:*", cpeRejected},
	} {
		cve := NVDCVE{Configurations: []NVDConfiguration{{Nodes: []NVDConfigNode{{CpeMatch: []NVDCPEMatch{
			{Vulnerable: true, Criteria: tc.criteria},
		}}}}}}
		if got := verifyCPEMatch(cve, c); got != tc.want {
			t.Errorf("%s vs 2.0:beta1 = %v, want %v", tc.criteria, got, tc.want)
		}
	}
}

// Codex M60 R6 High-2: a bare "a"/"b" is PEP 440 alpha/beta ("1.0a" < "1.0")
// or an OpenSSL patch letter ("1.1.1a" > "1.1.1") depending on the scheme; it
// is undecidable. Longer bare letters ("k", "za") stay OpenSSL patches.
func TestM60R6_BareAOrBIsSchemeDependent(t *testing.T) {
	for _, tc := range []struct{ a, b string }{{"1.0a", "1.0"}, {"1.0b", "1.0"}, {"1.1.1a", "1.1.1"}} {
		if _, ok := compareVersions(tc.a, tc.b); ok {
			t.Errorf("compareVersions(%q,%q) decided; want undecidable", tc.a, tc.b)
		}
	}
	if c, ok := compareVersions("1.1.1k", "1.1.1"); !ok || c != 1 {
		t.Errorf("1.1.1k vs 1.1.1 = %d,%v", c, ok)
	}
}

// Codex M60 R6 High-3: the product probe's answer must be ABOUT the product.
// A mirror that ignores virtualMatchString and answers with an unrelated
// record would otherwise make an unknown product "known", end the candidate
// walk with a verified "no CVE", and cache it.
func TestM60R6_ProbeAnswerMustNameTheProduct(t *testing.T) {
	unrelated := m60NVDFixture(t, "p03_vms_log4j") // one record about apache:log4j
	body, _ := json.Marshal(unrelated)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("virtualMatchString") != "" {
			_, _ = w.Write(body) // wrong answer for any product
			return
		}
		_, _ = w.Write([]byte(m60EmptyNVD))
	}))
	t.Cleanup(srv.Close)
	svc := NewNVDService(nil, nil, "", srv.URL, false)
	item := nvdWorkItem{
		key:        nvdComponentKey{Name: "widget", Version: "1.0"},
		candidates: cpeCandidates([]string{"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}, "1.0", ""),
	}
	l, err := svc.lookupComponent(context.Background(), item, nil)
	if err == nil {
		t.Errorf("probe answered with a record not about acme:widget, lookup accepted it (method %q, %d vulns)", l.method, len(l.vulns))
	} else if !strings.Contains(err.Error(), "acme") {
		t.Errorf("error does not name the product: %v", err)
	}
}

// Codex M60 R6 Medium: a CPE whose version is NA ("-") names a version-less
// thing; substituting the component version invents a CPE the SBOM did not
// assert. Such a candidate is skipped.
func TestM60R6_VersionNACandidateIsSkipped(t *testing.T) {
	if cs := cpeCandidates([]string{"cpe:2.3:a:acme:widget:-:*:*:*:*:*:*:*"}, "1.0", ""); len(cs) != 0 {
		t.Errorf("NA-version CPE produced candidates %v", cs)
	}
	if cs := cpeCandidates([]string{"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}, "1.0", ""); len(cs) != 1 || cs[0].version != "1.0" {
		t.Errorf("ANY-version CPE should take the component version: %v", cs)
	}
}
