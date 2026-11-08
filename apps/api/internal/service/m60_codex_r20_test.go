package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

// Codex M60 R20 High: CVEs an exact cpeName answer KEEPS (here unverifiable:
// its configurations were stripped) must not be thrown away when that
// answer carries no vulnerable evidence for the product and the walk falls
// through to the product query — which may then answer zero.
func TestM60R20_KeptCPENameRecordsSurviveTheFallThrough(t *testing.T) {
	stripped := `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2099-0100"}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cpeName") != "" {
			_, _ = w.Write([]byte(stripped))
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
	if err != nil {
		t.Fatal(err)
	}
	if len(l.vulns) != 1 || l.vulns[0].CVEID != "CVE-2099-0100" || l.methods[0] != model.MatchNVDCPEUnverified {
		t.Errorf("vulns=%v methods=%v method=%q, want CVE-2099-0100 kept as nvd_cpe_unverified", l.vulns, l.methods, l.method)
	}
}

// Same rule on the product walk: a record the walk keeps (it does not name
// the product, so it cannot be verified) survives even when the product
// itself appears only as a platform elsewhere in the answer.
func TestM60R20_KeptProductWalkRecordsSurviveUnknownProduct(t *testing.T) {
	answer := `{"resultsPerPage":2,"startIndex":0,"totalResults":2,"vulnerabilities":[
		{"cve":{"id":"CVE-2099-0200","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}]}]}]}},
		{"cve":{"id":"CVE-2099-0201"}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("virtualMatchString") != "" {
			_, _ = w.Write([]byte(answer))
			return
		}
		_, _ = w.Write([]byte(m60EmptyNVD))
	}))
	t.Cleanup(srv.Close)
	svc := NewNVDService(nil, nil, "", srv.URL, false)
	item := nvdWorkItem{
		key:        nvdComponentKey{Name: "widget", Version: "1.0-x"},
		candidates: cpeCandidates([]string{"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}, "1.0-x", ""),
	}
	l, err := svc.lookupComponent(context.Background(), item, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.vulns) != 1 || l.vulns[0].CVEID != "CVE-2099-0201" {
		t.Errorf("vulns=%v method=%q, want CVE-2099-0201 kept (unverified)", l.vulns, l.method)
	}
}
