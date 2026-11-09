package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/client"
)

// Codex M70 R11 High-2: an active record without a valid `modified`, without
// an `affected` array, or naming no affected entry for the queried package is
// a structurally partial answer: the query fails.
func TestM70R11_PartialRecordsFailTheQuery(t *testing.T) {
	ok := `{"id":"DSA-1","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}}]}`
	for _, rec := range []string{
		`{"id":"DEBIAN-CVE-2026-0001","modified":"2026-11-01T00:00:00Z"}`,
		`{"id":"DEBIAN-CVE-2026-0001","modified":"2026-11-01T00:00:00Z","affected":null}`,
		`{"id":"DEBIAN-CVE-2026-0001","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}}]}`,
		`{"id":"DEBIAN-CVE-2026-0001","modified":"yesterday","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}}]}`,
		`{"id":"DEBIAN-CVE-2026-0001","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"other","ecosystem":"Debian:11"}}]}`,
		`{"id":"DEBIAN-CVE-2026-0001","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Ubuntu:22.04:LTS"}}]}`,
	} {
		body := `{"vulns":[` + ok + `,` + rec + `]}`
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
		_, err := client.NewOSVClient().WithBaseURL(srv.URL).QueryPackage(context.Background(), "Debian", "p", 2, nil)
		srv.Close()
		if err == nil {
			t.Errorf("accepted %s", rec)
		}
	}
	// A withdrawn record may carry no affected data.
	body := `{"vulns":[` + ok + `,{"id":"DSA-2","modified":"2026-11-02T00:00:00Z","withdrawn":"2026-11-02T00:00:00Z"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
	defer srv.Close()
	if _, err := client.NewOSVClient().WithBaseURL(srv.URL).QueryPackage(context.Background(), "Debian", "p", 2, nil); err != nil {
		t.Errorf("withdrawn record refused: %v", err)
	}
}

// Every committed fixture passes the structural check.
func TestM70R11_FixturesAreStructurallyComplete(t *testing.T) {
	for _, c := range []struct{ file, eco, pkg string }{
		{"debian_openssl", "Debian", "openssl"}, {"debian_glibc", "Debian", "glibc"},
		{"ubuntu2204_openssl", "Ubuntu:22.04:LTS", "openssl"}, {"almalinux9_openssl", "AlmaLinux:9", "openssl"},
	} {
		r := &replayOSV{t: t, routes: map[string]string{c.eco + "|" + c.pkg: c.file}}
		if _, err := client.NewOSVClient().WithBaseURL(r.start().URL).QueryPackage(context.Background(), c.eco, c.pkg, 2, nil); err != nil {
			t.Errorf("%s: %v", c.file, err)
		}
	}
}

// Codex M70 R11 High-1: evidence names the endpoint; the freshness rule only
// compares revisions of the same endpoint.
func TestM70R11_EvidenceNamesTheEndpoint(t *testing.T) {
	r := &replayOSV{t: t, routes: map[string]string{"Debian|openssl": "debian_openssl"}}
	url := r.start().URL
	s := NewDistroService(nil, url, nil, false)
	s.gap = 0
	tgt, _ := distroTargetFor("pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11", "1.1.1k-1", nil)
	var got string
	if _, _, err := s.loadSlotted(context.Background(), tgt.fetchKey(), s.pacer(), func(l distroLoad) error {
		d := l.data()
		d.source = s.source
		got = d.decide(tgt, "CVE-2023-0286").evidence.SourceURL
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got == "" || !strings.HasPrefix(got, "http://127.0.0.1") {
		t.Errorf("source_url %q", got)
	}
}
