package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sbomhub/sbomhub/internal/client"
)

// Codex M70 R10 High-1: a `withdrawn` that is not an RFC 3339 time is not a
// withdrawal: the whole answer is refused.
func TestM70R10_MalformedWithdrawnFailsTheQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"vulns":[{"id":"DEBIAN-CVE-2026-1234","withdrawn":"unknown"}]}`)
	}))
	defer srv.Close()
	if _, err := client.NewOSVClient().WithBaseURL(srv.URL).QueryPackage(context.Background(), "Debian", "p", 2, nil); err == nil {
		t.Error("a malformed withdrawn was accepted")
	}
}

// Codex M70 R10 Medium-3: the later_releases evidence version is checked
// against every deciding entry's affected set.
func TestM70R10_LaterReleasesFixedVersionIsSafe(t *testing.T) {
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", binary: "p", version: "3.0-1", scheme: schemeDpkg}
	e12 := entry("Debian:12", "i", "0", "f", "1.0-1")
	e12.Versions = []string{"2.0-1"}
	e13 := entry("Debian:13", "i", "0", "f", "2.0-1")
	r := rec("DEBIAN-CVE-2021-0001", []string{"CVE-2021-0001"}, e12, e13)
	d := indexDistroRecords([]distroRecord{r}).decide(deb11, "CVE-2021-0001")
	if d.verdict != verdictFixed || d.evidence.Fixed != "" {
		t.Errorf("= %+v, want fixed with no advertised version", d)
	}
}
