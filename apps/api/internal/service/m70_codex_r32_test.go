package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sbomhub/sbomhub/internal/client"
	"github.com/sbomhub/sbomhub/internal/repository"
)

func r32Query(t *testing.T, eco, purl string) error {
	t.Helper()
	rec := `{"id":"ALSA-9","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"` + eco + `","purl":"` + purl + `"}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"vulns":[`+rec+`]}`) }))
	defer srv.Close()
	_, err := client.NewOSVClient().WithBaseURL(srv.URL).QueryPackage(context.Background(), eco, "p", 5, nil)
	return err
}

// Codex M70 R32 High-1 / Low-5.
func TestM70R32_RPMDistroAndSubpath(t *testing.T) {
	for _, c := range []struct {
		eco, purl string
		ok        bool
	}{
		{"Rocky Linux:9", "pkg:rpm/rocky-linux/p?distro=rocky-linux-9", true},
		{"Rocky Linux:9", "pkg:rpm/rocky-linux/p?distro=rocky-linux-9.3", true},
		{"Rocky Linux:9", "pkg:rpm/rocky-linux/p?distro=rocky-linux-8", false},
		{"Rocky Linux:9", "pkg:rpm/rocky-linux/p?distro=almalinux-9", false},
		{"AlmaLinux:9", "pkg:rpm/almalinux/p?distro=el9", true},
		{"AlmaLinux:9", "pkg:rpm/almalinux/p?distro=el8", false},
		{"AlmaLinux:9", "pkg:rpm/almalinux/p?distro=el", false},
		{"AlmaLinux:9", "pkg:rpm/almalinux/p#/foo/", false},
		{"AlmaLinux:9", "pkg:rpm/almalinux/p#foo//bar", false},
		{"AlmaLinux:9", "pkg:rpm/almalinux/p#foo/bar", true},
	} {
		if err := r32Query(t, c.eco, c.purl); (err == nil) != c.ok {
			t.Errorf("%s %s: err=%v, want ok=%v", c.eco, c.purl, err, c.ok)
		}
	}
}

// Codex M70 R32 Medium-2: a record edited to no longer name the package is
// "edited out" at its modified time; one still naming it while absent from
// the package query makes the lookup a failure.
func TestM70R32_EditedOutRecord(t *testing.T) {
	body := `{"id":"DSA-1","modified":"2026-11-03T00:00:00Z","affected":[{"package":{"name":"other","ecosystem":"Debian:11"}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
	defer srv.Close()
	s := NewDistroService(nil, srv.URL, nil, false)
	pace := func(context.Context) error { return nil }
	st := s.withdrawalResolver(context.Background(), pace)("Debian", "p")("DSA-1")
	if !st.editedOut || st.failed || st.rev != "2026-11-03T00:00:00.000000000Z" {
		t.Errorf("%+v, want edited out at its modified", st)
	}
	st = s.withdrawalResolver(context.Background(), pace)("Debian", "other")("DSA-1")
	if !st.failed {
		t.Errorf("%+v: a record still naming the package must fail the lookup", st)
	}
	// An edit-out OLDER than the label contradicts it: a failure.
	d := distroData{byCVE: map[string][]*distroRecord{}, ids: map[string]bool{}, sourceID: "S"}
	l := r32Link("2026-11-05T00:00:00.000000000Z")
	if _, failed := d.withdrawnClear(l, func(string) recordState { return recordState{editedOut: true, rev: "2026-11-03T00:00:00.000000000Z"} }); !failed {
		t.Error("an edit older than the label was accepted")
	}
	if p, failed := d.withdrawnClear(r32Link("2026-11-02T00:00:00.000000000Z"),
		func(string) recordState { return recordState{editedOut: true, rev: "2026-11-03T00:00:00.000000000Z"} }); p == nil || failed {
		t.Error("an edit-out after the label did not clear")
	}
}

func r32Link(labelRev string) repository.SbomLink {
	return repository.SbomLink{Method: "distro_fixed", Records: []string{"DSA-1"}, WMSource: "S", WMRev: labelRev, LabelSource: "S", LabelRev: labelRev}
}

// Codex M70 R33 High-2 / Medium-3 / Medium-4.
func TestM70R33_ArchPartialLookupBinaryName(t *testing.T) {
	if err := r32Query(t, "AlmaLinux:9", "pkg:rpm/almalinux/p?arch=aarch64"); err == nil {
		t.Error("an aarch64 rpm entry accepted")
	}
	for _, a := range []string{"src", "noarch"} { // R35 High-2: not wildcards
		if err := r32Query(t, "AlmaLinux:9", "pkg:rpm/almalinux/p?arch="+a); err == nil {
			t.Errorf("arch=%s accepted", a)
		}
	}
	for _, body := range []string{
		`{"id":"R","modified":"2026-11-01T00:00:00Z"}`,
		`{"id":"R","modified":"2026-11-01T00:00:00Z","affected":null}`,
		`{"id":"R","modified":"2026-11-01T00:00:00Z","affected":[{}]}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
		_, err := client.NewOSVClient().WithBaseURL(srv.URL).GetRecordState(context.Background(), "R")
		srv.Close()
		if err == nil {
			t.Errorf("partial record accepted: %s", body)
		}
	}
	withdrawn := `{"id":"R","modified":"2026-11-01T00:00:00Z","withdrawn":"2026-11-01T00:00:00Z"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, withdrawn) }))
	defer srv.Close()
	if _, err := client.NewOSVClient().WithBaseURL(srv.URL).GetRecordState(context.Background(), "R"); err != nil {
		t.Errorf("withdrawn record without affected refused: %v", err)
	}
	rec := `{"id":"USN-9-1","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Ubuntu:22.04:LTS"},"ecosystem_specific":{"binaries":[{"binary_name":" p"}]}}]}`
	if err := r27UbuntuQuery(t, `{"vulns":[`+rec+`]}`); err == nil {
		t.Error("a binary_name with whitespace accepted")
	}
}
