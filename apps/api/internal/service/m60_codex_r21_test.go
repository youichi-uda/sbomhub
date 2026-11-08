package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Codex M60 R21 High: a product mentioned ONLY under negated nodes is not
// "absent" (which is undecidable, R14/R20): its configurations say the CVE is
// not the product's own. Such a record is rejected, so a wrong first
// candidate whose only records are like that does not end the walk.
func TestM60R21_NegatedOnlyMentionDoesNotEndTheWalk(t *testing.T) {
	negatedOnly := `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2099-0300",
		"configurations":[{"operator":"AND","nodes":[
			{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:other:app:*:*:*:*:*:*:*:*"}]},
			{"operator":"OR","negate":true,"cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:a:wrong:guess:*:*:*:*:*:*:*:*"}]}]}]}}]}`
	right := `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2099-0301",
		"configurations":[{"nodes":[{"operator":"OR","cpeMatch":[
			{"vulnerable":true,"criteria":"cpe:2.3:a:right:product:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		key := q.Get("cpeName") + q.Get("virtualMatchString")
		switch {
		case strings.Contains(key, "wrong:guess"):
			_, _ = w.Write([]byte(negatedOnly))
		case strings.Contains(key, "right:product"):
			_, _ = w.Write([]byte(right))
		default:
			_, _ = w.Write([]byte(m60EmptyNVD))
		}
	}))
	t.Cleanup(srv.Close)
	svc := NewNVDService(nil, nil, "", srv.URL, false)
	item := nvdWorkItem{
		key: nvdComponentKey{Name: "x", Version: "1.0"},
		candidates: cpeCandidates([]string{
			"cpe:2.3:a:wrong:guess:1.0:*:*:*:*:*:*:*",
			"cpe:2.3:a:right:product:1.0:*:*:*:*:*:*:*",
		}, "1.0", ""),
	}
	l, err := svc.lookupComponent(context.Background(), item, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.vulns) != 1 || l.vulns[0].CVEID != "CVE-2099-0301" {
		t.Errorf("vulns = %v, want CVE-2099-0301 from the second candidate", l.vulns)
	}
	// Directly: negated-only mention is rejected; no mention at all stays undecidable.
	c := cpeCandidate{part: "a", vendor: "wrong", product: "guess", version: "1.0", raw: "1.0"}
	var resp NVDResponse
	if err := decodeJSONForTest(negatedOnly, &resp); err != nil {
		t.Fatal(err)
	}
	if got := verifyCPEMatch(resp.entries()[0].CVE, c); got != cpeRejected {
		t.Errorf("negated-only mention = %v, want rejected", got)
	}
	if got := verifyCPEMatch(NVDCVE{ID: "CVE-2099-0302"}, c); got != cpeUndecidable {
		t.Errorf("no configurations = %v, want undecidable", got)
	}
}

func decodeJSONForTest(s string, v any) error { return json.Unmarshal([]byte(s), v) }
