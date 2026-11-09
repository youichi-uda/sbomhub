package service

import "testing"

// Codex M70 R21 High-2: a record id seen twice in one walk fails the query
// (within a page or across pages); a cached payload with duplicates is not
// one this build wrote.
func TestM70R21_DuplicateRecordIDsFail(t *testing.T) {
	if err := r15Query(t, `{"vulns":[`+r15OK+`,`+r15OK+`]}`); err == nil {
		t.Error("duplicate id within a page accepted")
	}
	if err := r15Query(t, `{"vulns":[`+r15OK+`],"next_page_token":"t1"}`, `{"vulns":[`+r15OK+`]}`); err == nil {
		t.Error("duplicate id across pages accepted")
	}
	r := distroRecord{ID: "DSA-1", CVEs: []string{"CVE-2021-0001"}, Releases: 1, Packages: 1, Modified: normaliseModified("2026-11-01T00:00:00Z"),
		Entries: []distroEntry{entry("Debian:11", "i", "0", "f", "1.0-1")}}
	if validDistroRecords([]distroRecord{r, r}) {
		t.Error("cached duplicates accepted")
	}
}

// Codex M70 R21 High-3: OSV ids (record, aliases, upstream) use OSV's
// character set [A-Za-z0-9:_.-].
func TestM70R21_OSVIDCharacterSet(t *testing.T) {
	for _, rec := range []string{
		`{"id":"DSA/1","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}}]}`,
		`{"id":"DSA-2","upstream":["CVE-2026-1111","CVE/2026/2222"],"modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}}]}`,
		`{"id":"DSA-3","aliases":["GHSA@x"],"modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}}]}`,
	} {
		if err := r15Query(t, `{"vulns":[`+rec+`]}`); err == nil {
			t.Errorf("accepted %s", rec)
		}
	}
}

// Codex M70 R21 High-1: payload version bumped for the new invariants.
func TestM70R21_PayloadVersion(t *testing.T) {
	if distroCachePayloadVersion < 10 {
		t.Errorf("payload version %d", distroCachePayloadVersion)
	}
}
