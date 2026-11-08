package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
