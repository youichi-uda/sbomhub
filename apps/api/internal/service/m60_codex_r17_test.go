package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Codex M60 R17 High: a candidate that NVD names ONLY as a vulnerable=false
// platform is not a product with a verified "no CVE": its platform-only
// records are dropped as before, but the walk must go on to the next
// candidate (here the right one) instead of ending with a cached empty
// answer.
func TestM60R17_PlatformOnlyCandidateDoesNotEndTheSearch(t *testing.T) {
	platformOnly := `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2099-0001",
		"configurations":[{"operator":"AND","nodes":[
			{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:other:app:*:*:*:*:*:*:*:*"}]},
			{"operator":"OR","cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:a:wrong:guess:*:*:*:*:*:*:*:*"}]}]}]}}]}`
	right := `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2099-0002",
		"configurations":[{"nodes":[{"operator":"OR","cpeMatch":[
			{"vulnerable":true,"criteria":"cpe:2.3:a:right:product:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}}]}`
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		key := q.Get("cpeName") + q.Get("virtualMatchString")
		seen = append(seen, key)
		switch {
		case strings.Contains(key, "wrong:guess"):
			_, _ = w.Write([]byte(platformOnly))
		case strings.Contains(key, "right:product"):
			_, _ = w.Write([]byte(right))
		default:
			_, _ = w.Write([]byte(m60EmptyNVD))
		}
	}))
	t.Cleanup(srv.Close)
	var probe NVDResponse
	if err := json.Unmarshal([]byte(platformOnly), &probe); err != nil {
		t.Fatal(err)
	}
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
	if len(l.vulns) != 1 || l.vulns[0].CVEID != "CVE-2099-0002" {
		t.Errorf("vulns = %v (requests %q), want CVE-2099-0002 from the second candidate", l.vulns, seen)
	}
}

// Codex M60 R17 Medium: CPE quoting semantics. A quoted special character is
// literal and survives the round trip; an UNQUOTED wildcard inside a value,
// an illegal escape, unquoted punctuation, or a CPE 2.2 %01/%02 wildcard is
// not a single concrete product and is rejected.
func TestM60R17_CPEQuotingSemantics(t *testing.T) {
	for _, s := range []string{
		`cpe:2.3:a:acme:widget*:1.0:*:*:*:*:*:*:*`,
		`cpe:2.3:a:acme:wid?get:1.0:*:*:*:*:*:*:*`,
		`cpe:2.3:a:acme:widget:1.0\q:*:*:*:*:*:*:*`,
		`cpe:2.3:a:acme:wid@get:1.0:*:*:*:*:*:*:*`,
		`cpe:/a:acme:widget%01:1.0`,
		`cpe:/a:acme:widget:1.%02`,
	} {
		if n, ok := parseCPE(s); ok {
			t.Errorf("parseCPE(%q) accepted as %+v", s, n)
		}
	}
	n, ok := parseCPE(`cpe:2.3:a:acme:widget\*:1.0:*:*:*:*:*:*:*`)
	if !ok || n.Product != "widget*" {
		t.Fatalf("quoted * = %+v,%v, want literal product widget*", n, ok)
	}
	c := cpeCandidates([]string{`cpe:2.3:a:acme:widget\*:1.0:*:*:*:*:*:*:*`}, "", "")
	if len(c) != 1 || !strings.Contains(c[0].query(), `widget\*`) {
		t.Errorf("quoted literal lost in the query: %v", c)
	}
}
