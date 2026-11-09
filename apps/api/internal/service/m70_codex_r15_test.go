package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sbomhub/sbomhub/internal/client"
)

const r15OK = `{"id":"DSA-1","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0-1"}]}]}]}`

func r15Query(t *testing.T, bodies ...string) error {
	t.Helper()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		b := bodies[len(bodies)-1]
		if n < len(bodies) {
			b = bodies[n]
		}
		n++
		_, _ = io.WriteString(w, b)
	}))
	defer srv.Close()
	_, err := client.NewOSVClient().WithBaseURL(srv.URL).QueryPackage(context.Background(), "Debian", "p", 5, nil)
	return err
}

// Codex M70 R15 High-1: every affected element is structurally complete.
func TestM70R15_EveryAffectedElementIsValidated(t *testing.T) {
	for _, extra := range []string{
		`{}`,
		`{"package":{"name":"p"}}`,
		`{"package":{"ecosystem":"Debian:11"}}`,
		`{"package":{"name":"p","ecosystem":"Debian:11"},"ranges":[{"events":[{"introduced":"0"}]}]}`,
		`{"package":{"name":"p","ecosystem":"Debian:11"},"ranges":[{"type":"ECOSYSTEM","events":[]}]}`,
		`{"package":{"name":"p","ecosystem":"Debian:11"},"ranges":[{"type":"ECOSYSTEM","events":[{}]}]}`,
		`{"package":{"name":"p","ecosystem":"Debian:11"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0","fixed":"1"}]}]}`,
		`{"package":{"name":"p","ecosystem":"Debian:11"},"versions":[""]}`,
	} {
		rec := fmt.Sprintf(`{"id":"DEBIAN-CVE-2026-0001","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:12"}},%s]}`, extra)
		if err := r15Query(t, `{"vulns":[`+r15OK+`,`+rec+`]}`); err == nil {
			t.Errorf("accepted affected element %s", extra)
		}
	}
	if err := r15Query(t, `{"vulns":[`+r15OK+`]}`); err != nil {
		t.Errorf("valid page refused: %v", err)
	}
}

// Codex M70 R15 High-2: `{}` ends a walk only as the FIRST page.
func TestM70R15_EmptyContinuationIsAnError(t *testing.T) {
	if err := r15Query(t, `{"vulns":[`+r15OK+`],"next_page_token":"t1"}`, `{}`); err == nil {
		t.Error("an empty continuation page ended the walk as complete")
	}
	if err := r15Query(t, `{}`); err != nil {
		t.Errorf("an empty first page refused: %v", err)
	}
}

// Codex M70 R15 High-3: for a Debian target, EVERY entry of the CVE's records
// must be a canonical Debian ecosystem ("Debain:11" blocks).
func TestM70R15_AnyNonCanonicalEntryBlocks(t *testing.T) {
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", binary: "p", version: "2.0-1", scheme: schemeDpkg}
	dsa := rec("DSA-1", []string{"CVE-2021-0001"}, entry("Debain:11", "i", "0", "f", "3.0-1"), entry("Debian:12", "i", "0", "f", "1.0-1"))
	spec := rec("DEBIAN-CVE-2021-0001", []string{"CVE-2021-0001"}, entry("Debian:12", "i", "0", "f", "1.0-1"))
	if d := indexDistroRecords([]distroRecord{dsa, spec}).decide(deb11, "CVE-2021-0001"); d.verdict != verdictNone {
		t.Errorf("= %+v, want no verdict", d)
	}
	alma := distroTarget{family: "almalinux", release: "AlmaLinux:9", scheme: schemeRPM}
	if !noncanonicalFor(alma, "Alma Linux:9") || !noncanonicalFor(alma, "Debian:12") {
		t.Error("a foreign or misspelt ecosystem in an AlmaLinux answer did not block")
	}
}

// Codex M70 R15 High-4: qualifier keys are case-insensitive, duplicates
// after folding are ambiguous, and an empty distro / upstream / epoch is an
// error, not an absence.
func TestM70R15_QualifierStrictness(t *testing.T) {
	os := &distroOS{id: "debian", version: "11"}
	for _, c := range []struct{ purl, reason string }{
		{"pkg:deb/debian/openssl@1.1.1k-1?Distro=debian-12", ""}, // folded: Debian 12, not the OS fallback
		{"pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11&DISTRO=debian-12", "ambiguous_qualifier"},
		{"pkg:deb/debian/openssl@1.1.1k-1?distro=", "no_purl"},                          // an empty value: refused by the strict parser (R47)
		{"pkg:deb/debian/libc6@2.31-13?distro=debian-11&upstream=", "no_purl"},          // an empty value: refused by the strict parser (R47)
		{"pkg:rpm/almalinux/openssl@3.0.7-27.el9?distro=almalinux-9&epoch=", "no_purl"}, // an empty value: refused by the strict parser (R47)
	} {
		tgt, reason := distroTargetFor(c.purl, "", os)
		if reason != c.reason {
			t.Errorf("%s: reason %q, want %q", c.purl, reason, c.reason)
		}
		if c.reason == "" && tgt.release != "Debian:12" {
			t.Errorf("%s: release %q, want Debian:12 (the qualifier, not the OS)", c.purl, tgt.release)
		}
	}
}
