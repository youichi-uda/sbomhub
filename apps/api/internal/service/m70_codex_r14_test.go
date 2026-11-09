package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sbomhub/sbomhub/internal/client"
)

// Codex M70 R14 High-1: a record dated in the future would poison the
// revision guard forever: the query fails.
func TestM70R14_FutureTimestampsFailTheQuery(t *testing.T) {
	for _, rec := range []string{
		`{"id":"DSA-9","modified":"9999-01-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}}]}`,
		`{"id":"DSA-9","modified":"2026-11-01T00:00:00Z","withdrawn":"9999-01-01T00:00:00Z"}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"vulns":[`+rec+`]}`)
		}))
		_, err := client.NewOSVClient().WithBaseURL(srv.URL).QueryPackage(context.Background(), "Debian", "p", 2, nil)
		srv.Close()
		if err == nil {
			t.Errorf("accepted %s", rec)
		}
	}
}

// Codex M70 R14 High-2 / High-3: versions must agree as TEXT (case
// included); only the rpm epoch reconstruction is an exception.
func TestM70R14_VersionAgreementIsTextual(t *testing.T) {
	if _, reason := distroTargetFor("pkg:deb/debian/openssl@1.0?distro=debian-11", "1.0-0", nil); reason != "version_mismatch" {
		t.Errorf("1.0 vs 1.0-0: %q", reason)
	}
	if _, reason := distroTargetFor("pkg:rpm/almalinux/openssl@3.0.7-27.el9?epoch=1&distro=almalinux-9", "3.0.7-27.el9", nil); reason != "" {
		t.Errorf("rpm epoch reconstruction: %q", reason)
	}
	if cpeVersionsAgree([]string{"cpe:2.3:a:x:y:1A-1:*:*:*:*:*:*:*"}, "1A-1") {
		t.Error("a CPE (lower-cased by parsing) agreed with an upper-case version")
	}
	if !cpeVersionsAgree([]string{"cpe:2.3:a:x:y:1a-1:*:*:*:*:*:*:*"}, "1a-1") {
		t.Error("identical lower-case versions disagreed")
	}
}

// Codex M70 R14 High-5: the API never shows source_id, and source_url is the
// origin only.
func TestM70R14_SourceDisplayIsOriginOnly(t *testing.T) {
	if got := distroSource("https://mirror.internal/v1/tok3n-secret"); got != "https://mirror.internal" {
		t.Errorf("display %q", got)
	}
}

// Codex M70 R14 Medium-6: malformed purls are refused, not normalised.
func TestM70R14_PurlStrictness(t *testing.T) {
	for _, bad := range []string{"pkg:/deb/debian/openssl@1.0-1?distro=debian-11", "pkg:deb/debian/openssl/@1.0-1",
		"pkg:deb/debian/openssl@?distro=debian-11", "pkg:deb//openssl@1.0-1"} {
		if p, ok := parsePurl(bad); ok {
			t.Errorf("parsePurl(%q) = %+v", bad, p)
		}
	}
}
