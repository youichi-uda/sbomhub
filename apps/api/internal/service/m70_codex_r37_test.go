package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// Codex M70 R37 High-1: a verdict on a link whose label rests on a record
// now withdrawn replaces it (whatever the rank); a failed lookup writes
// nothing.
func TestM70R37_VerdictReplacesWithdrawnLabel(t *testing.T) {
	d := indexDistroRecords([]distroRecord{rec("DSA-B", []string{"CVE-2021-0001"}, entry("Debian:11", "i", "0", "f", "0.9-1"))})
	d.sourceID = "S"
	tgt := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", binary: "p", version: "1.0-1", scheme: schemeDpkg}
	comp, vuln := uuid.New(), uuid.New()
	links := map[uuid.UUID][]repository.SbomLink{comp: {{ComponentID: comp, VulnerabilityID: vuln, CVEID: "CVE-2021-0001",
		Method: "distro_affected", Records: []string{"DSA-A", "DSA-B"}, WMSource: "S", WMRev: "x", LabelSource: "S", LabelRev: ""}}}
	work := []distroWork{{comp: model.Component{ID: comp}, target: tgt}}
	withdrawn := func(string, string) func(string) recordState {
		return func(string) recordState { return recordState{withdrawn: true, rev: "y"} }
	}
	groups, _, err := decideKey(context.Background(), d, time.Time{}, work, links, withdrawn)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0][0].method != model.MatchDistroFixed || groups[0][0].replace == nil {
		t.Fatalf("groups=%+v, want a fixed verdict replacing the withdrawn label", groups)
	}
	failing := func(string, string) func(string) recordState {
		return func(string) recordState { return recordState{failed: true} }
	}
	groups, counts, _ := decideKey(context.Background(), d, time.Time{}, work, links, failing)
	if len(groups) != 0 || counts.LookupFailures != 1 {
		t.Errorf("groups=%+v failures=%d, want nothing written and the failure reported", groups, counts.LookupFailures)
	}
}

// Codex M70 R37 Medium-2: OSV range requirements.
func TestM70R37_RangeSchema(t *testing.T) {
	for _, ranges := range []string{
		`[{"type":"ECOSYSTEM","events":[{"fixed":"2.0-1"}]}]`,
		`[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0-1"},{"last_affected":"1.5-1"}]}]`,
		`[{"type":"WHATEVER","events":[{"introduced":"0"}]}]`,
		`[{"type":"GIT","events":[{"introduced":"abc"}]}]`,
	} {
		rec := `{"id":"DSA-9","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"},"ranges":` + ranges + `,"versions":["1.0-1"]}]}`
		if err := r15Query(t, `{"vulns":[`+rec+`]}`); err == nil {
			t.Errorf("accepted: %s", ranges)
		}
	}
}

// Codex M70 R37 Medium-3: "rocky-linux" is the Rocky Linux family.
func TestM70R37_RockyLinuxNamespace(t *testing.T) {
	for _, p := range []string{
		"pkg:rpm/rocky-linux/openssl@3.0.7-27.el9?distro=rocky-linux-9",
		"pkg:rpm/rocky/openssl@3.0.7-27.el9?distro=rocky-9",
		"pkg:rpm/rocky-linux/openssl@3.0.7-27.el9?distro=rocky-9",
	} {
		tgt, why := distroTargetFor(p, "3.0.7-27.el9", nil)
		if why != "" || tgt.release != "Rocky Linux:9" {
			t.Errorf("%s: %q %+v", p, why, tgt)
		}
	}
}
