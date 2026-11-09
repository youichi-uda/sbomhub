package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/client"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// Codex M70 R34 High-1: a record still in the answer (reduced away because
// it lost its CVE identity) is not "absent": the label is settled by the
// ordinary newer no-verdict, with no lookup.
func TestM70R34_ReducedAwayRecordIsNotAbsent(t *testing.T) {
	looked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			looked++
			http.NotFound(w, r)
			return
		}
		// R no longer has any CVE identity
		_, _ = io.WriteString(w, `{"vulns":[{"id":"DSA-7","modified":"2026-11-08T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}}]}]}`)
	}))
	defer srv.Close()
	s := NewDistroService(nil, srv.URL, nil, false)
	s.gap = 0
	tgt, _ := distroTargetFor("pkg:deb/debian/p@1.0-1?distro=debian-11", "1.0-1", nil)
	comp, vuln := uuid.New(), uuid.New()
	links := map[uuid.UUID][]repository.SbomLink{comp: {{ComponentID: comp, VulnerabilityID: vuln, CVEID: "CVE-2021-0001",
		Method: "distro_fixed", Records: []string{"DSA-7"}, WMSource: s.sourceID, WMRev: "2026-11-01T00:00:00.000000000Z",
		LabelSource: s.sourceID, LabelRev: "2026-11-01T00:00:00.000000000Z"}}}
	rep := DistroScanReport{NoVerdict: map[string]int{}}
	groups, err := s.fetchAndDecide(context.Background(), []distroWork{{comp: model.Component{ID: comp}, target: tgt}}, links, &rep)
	if err != nil {
		t.Fatal(err)
	}
	if looked != 0 || len(groups) != 1 || !groups[0][0].noVerdict || rep.LookupFailures != 0 {
		t.Errorf("looked=%d groups=%+v rep=%+v, want an ordinary settlement", looked, groups, rep)
	}
}

// Codex M70 R34 Medium-2: a base URL with a path prefix and a query keeps
// both.
func TestM70R34_BaseURLWithQuery(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	c := client.NewOSVClient().WithBaseURL(srv.URL + "/mirror/v1?api_key=secret")
	if _, err := c.QueryPackage(context.Background(), "Debian", "p", 5, nil); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/mirror/v1/query" || gotQuery != "api_key=secret" {
		t.Errorf("path=%q query=%q", gotPath, gotQuery)
	}
	_, _ = c.GetRecordState(context.Background(), "DSA-1")
	if gotPath != "/mirror/v1/vulns/DSA-1" || gotQuery != "api_key=secret" {
		t.Errorf("lookup path=%q query=%q", gotPath, gotQuery)
	}
}

// Codex M70 R34 Low-3.
func TestM70R34_ComponentPurlSubpath(t *testing.T) {
	for _, p := range []string{"pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11#", "pkg:deb/debian/openssl@1.1.1k-1#a//b", "pkg:deb/debian/openssl@1.1.1k-1#.."} {
		if _, ok := parsePurl(p); ok {
			t.Errorf("%s accepted", p)
		}
	}
	if _, ok := parsePurl("pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11#usr/lib"); !ok {
		t.Error("a valid subpath refused")
	}
}
