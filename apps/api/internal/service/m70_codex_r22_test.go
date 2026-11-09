package service

import (
	"fmt"
	"strings"
	"testing"
)

// Codex M70 R22 High-2: an affected package's purl must name the same package
// and packaging type.
func TestM70R22_AffectedPurlAgrees(t *testing.T) {
	for _, purl := range []string{"pkg:rpm/almalinux/openssl-libs", "pkg:deb/debian/other?arch=source", "pkg:rpm/debian/p", "not-a-purl"} {
		rec := fmt.Sprintf(`{"id":"DSA-9","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11","purl":%q}}]}`, purl)
		if err := r15Query(t, `{"vulns":[`+rec+`]}`); err == nil {
			t.Errorf("purl %q accepted for Debian p", purl)
		}
	}
	ok := `{"id":"DSA-9","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11","purl":"pkg:deb/debian/p?arch=source"}}]}`
	if err := r15Query(t, `{"vulns":[`+ok+`]}`); err != nil {
		t.Errorf("agreeing purl refused: %v", err)
	}
}

// Codex M70 R22 High-3: identity / version strings are length-bounded.
func TestM70R22_FieldLengthBound(t *testing.T) {
	long := strings.Repeat("1", 300)
	rec := `{"id":"DSA-9","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"` + long + `"}]}]}]}`
	if err := r15Query(t, `{"vulns":[`+rec+`]}`); err == nil {
		t.Error("a 300-byte version accepted")
	}
	r := distroRecord{ID: "DSA-1", CVEs: []string{"CVE-2021-0001"}, Releases: 1, Packages: 1, Modified: normaliseModified("2026-11-01T00:00:00Z"),
		Entries: []distroEntry{entry("Debian:11", "i", "0", "f", long)}}
	if validDistroRecords([]distroRecord{r}) {
		t.Error("cached over-long version accepted")
	}
}
