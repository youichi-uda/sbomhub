package service

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/sbomhub/sbomhub/internal/client"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// Every recorded live OSV answer passes the client's validation as it is
// (the strict checks must never refuse real data).
func TestM70R31_RecordedAnswersPassValidation(t *testing.T) {
	for _, c := range []struct{ file, eco, pkg string }{
		{"debian_openssl", "Debian", "openssl"}, {"debian_glibc", "Debian", "glibc"},
		{"ubuntu2204_openssl", "Ubuntu:22.04:LTS", "openssl"}, {"almalinux9_openssl", "AlmaLinux:9", "openssl"},
		{"debian_linux-signed-amd64", "Debian", "linux-signed-amd64"},
	} {
		f, err := os.Open("testdata/m70/osv/" + c.file + ".json.gz")
		if err != nil {
			t.Fatal(err)
		}
		zr, _ := gzip.NewReader(f)
		body, _ := io.ReadAll(zr)
		_ = f.Close()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.Copy(w, bytes.NewReader(body)) }))
		_, err = client.NewOSVClient().WithBaseURL(srv.URL).QueryPackage(context.Background(), c.eco, c.pkg, 5, nil)
		srv.Close()
		if err != nil {
			t.Errorf("%s: %v", c.file, err)
		}
	}
}

// Codex M70 R31 High-2: a purl's distro / arch qualifiers agree with the
// entry's ecosystem.
func TestM70R31_PurlQualifiersAgree(t *testing.T) {
	q := func(eco, purl string) error {
		rec := `{"id":"USN-9-1","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"` + eco + `","purl":"` + purl + `"}}]}`
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"vulns":[`+rec+`]}`) }))
		defer srv.Close()
		_, err := client.NewOSVClient().WithBaseURL(srv.URL).QueryPackage(context.Background(), eco, "p", 5, nil)
		return err
	}
	for _, c := range []struct {
		eco, purl string
		ok        bool
	}{
		{"Ubuntu:22.04:LTS", "pkg:deb/ubuntu/p@1?arch=source&distro=jammy", true},
		{"Ubuntu:22.04:LTS", "pkg:deb/ubuntu/p@1?arch=source&distro=bionic", false},
		{"Ubuntu:22.04:LTS", "pkg:deb/ubuntu/p@1?arch=amd64&distro=jammy", false},
		{"Ubuntu:Pro:16.04:LTS", "pkg:deb/ubuntu/p@1?arch=source&distro=esm-apps%2Fxenial", true},
		{"Ubuntu:Pro:16.04:LTS", "pkg:deb/ubuntu/p@1?arch=source&distro=esm-apps%2Fbionic", false},
		{"Ubuntu:27.04", "pkg:deb/ubuntu/p@1?distro=newname", true},
		{"Ubuntu:27.04", "pkg:deb/ubuntu/p@1?distro=jammy", false},
		{"Debian:12", "pkg:deb/debian/p?arch=source&distro=bookworm", true},
		{"Debian:12", "pkg:deb/debian/p?arch=source&distro=bullseye", false},
		{"Debian:12", "pkg:deb/debian/p?distro=debian-12", true},
	} {
		if err := q(c.eco, c.purl); (err == nil) != c.ok {
			t.Errorf("%s %s: err=%v, want ok=%v", c.eco, c.purl, err, c.ok)
		}
	}
}

// Codex M70 R31 High-1: a clear of a label whose records were withdrawn is a
// withdrawn clear (tombstones) even when the revision did not go down; a
// failed lookup writes nothing.
func TestM70R31_WithdrawnClearAtEqualRevision(t *testing.T) {
	d := distroData{byCVE: map[string][]*distroRecord{}, ids: map[string]bool{"B": true}, sourceID: "S", revision: "10"}
	l := repository.SbomLink{Method: "distro_fixed", Records: []string{"A"}, WMSource: "S", WMRev: "10", LabelSource: "S", LabelRev: "10"}
	var c DistroScanReport
	pl, ok := d.settleNoVerdict(l, []byte(`{}`), func(string) recordState { return recordState{withdrawn: true, rev: "10"} }, &c)
	if !ok || !pl.withdrawnClear {
		t.Errorf("%+v ok=%v, want a withdrawn clear", pl, ok)
	}
	if _, ok := d.settleNoVerdict(l, []byte(`{}`), func(string) recordState { return recordState{failed: true} }, &c); ok {
		t.Error("a failed lookup still wrote")
	}
	if pl, ok := d.settleNoVerdict(l, []byte(`{}`), func(string) recordState { return recordState{} }, &c); !ok || pl.withdrawnClear || !pl.noVerdict {
		t.Errorf("active record: %+v, want an ordinary settlement", pl)
	}
}

// Codex M70 R31 Medium-3: a record lookup without modified is a failure.
func TestM70R31_RecordLookupNeedsModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"id":"A"}`) }))
	defer srv.Close()
	if _, _, err := client.NewOSVClient().WithBaseURL(srv.URL).GetRecordState(context.Background(), "A"); err == nil {
		t.Error("record without modified accepted")
	}
}
