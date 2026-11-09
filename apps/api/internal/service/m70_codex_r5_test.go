package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/client"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// Codex M70 R5 High-1: Ubuntu Pro / FIPS / ESM builds are other streams with
// the same binary names; comparing them with the standard stream's fixes is
// wrong (openssl 1.1.1f-1ubuntu2.fips.7.1 > the standard fix 1.1.1f-1ubuntu2.8,
// while the FIPS stream is unfixed). They are no target.
func TestM70R5_UbuntuProStreamsAreNotTargets(t *testing.T) {
	for _, v := range []string{"1.1.1f-1ubuntu2.fips.7.1", "1.1.1-1ubuntu2.1~18.04.23+esm1", "2.31-0ubuntu9.9+esm2", "1.0-1~esm1"} {
		if tgt, reason := distroTargetFor("pkg:deb/ubuntu/openssl@"+v+"?distro=ubuntu-20.04", "", nil); reason != "ubuntu_pro_stream" {
			t.Errorf("%s: %+v %q, want ubuntu_pro_stream", v, tgt, reason)
		}
	}
	if _, reason := distroTargetFor("pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.20?distro=ubuntu-20.04", "", nil); reason != "" {
		t.Errorf("standard build: %q", reason)
	}
}

// Codex M70 R5 Medium-3: the advertised fixed version must itself be outside
// every affected range of the entries that decided.
func TestM70R5_AdvertisedFixIsNotAffected(t *testing.T) {
	dpkg := distroTarget{scheme: schemeDpkg}.comparator()
	two := distroEntry{Ranges: []client.OSVRange{
		{Type: "ECOSYSTEM", Events: ev("i", "0", "f", "2.0-1")},
		{Type: "ECOSYSTEM", Events: ev("i", "2.0-1", "f", "3.0-1")},
	}}
	if r := evalEntry("1.0-1", two, dpkg); r.state != entryAffected || r.fix != "" || !r.fixUnknown {
		t.Errorf("= %+v, want affected with the fix unknown (2.0-1 re-enters the second range)", r)
	}
	// A GIT range beside an affected ECOSYSTEM one: affected, fix unknown.
	git := distroEntry{Ranges: []client.OSVRange{
		{Type: "ECOSYSTEM", Events: ev("i", "0", "f", "2.0-1")},
		{Type: "GIT", Events: ev("i", "abc")},
	}}
	if r := evalEntry("1.0-1", git, dpkg); r.state != entryAffected || r.fix != "" || !r.fixUnknown {
		t.Errorf("GIT beside = %+v", r)
	}
	// Across entries of the release: one entry's fix inside another's range.
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", binary: "p", version: "1.0-1", scheme: schemeDpkg}
	a := rec("DLA-1", []string{"CVE-2021-0001"}, entry("Debian:11", "i", "0", "f", "2.0-1"))
	b := rec("DLA-2", []string{"CVE-2021-0001"}, distroEntry{Ecosystem: "Debian:11", Ranges: []client.OSVRange{
		{Type: "ECOSYSTEM", Events: ev("i", "0", "f", "1.5-1")},
		{Type: "ECOSYSTEM", Events: ev("i", "1.8-1", "f", "2.5-1")},
	}})
	d := indexDistroRecords([]distroRecord{a, b}).decide(deb11, "CVE-2021-0001")
	if d.verdict != verdictAffected || d.evidence.Fixed != "" {
		t.Errorf("= %+v, want affected with no advertised fix", d)
	}
}

// Codex M70 R5 High-2: package data is decided as soon as it is loaded and
// not retained: the step keeps only the pending relabels.
func TestM70R5_DecidesPerPackageWithoutRetainingData(t *testing.T) {
	r := &replayOSV{t: t, routes: map[string]string{"Debian|openssl": "debian_openssl"}}
	s := NewDistroService(nil, r.start().URL, nil, false)
	s.gap = 0
	comp := uuid.New()
	vuln := uuid.New()
	tgt, _ := distroTargetFor("pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11", "1.1.1k-1", nil)
	work := []distroWork{{comp: model.Component{ID: comp}, target: tgt}}
	links := map[uuid.UUID][]repository.SbomLink{comp: {{ComponentID: comp, VulnerabilityID: vuln, CVEID: "CVE-2023-0286"}}}
	rep := DistroScanReport{NoVerdict: map[string]int{}}
	groups, err := s.fetchAndDecide(context.Background(), work, links, &rep)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0]) != 1 || groups[0][0].method != model.MatchDistroAffected || rep.Affected != 1 {
		t.Errorf("groups=%+v rep=%+v", groups, rep)
	}
}
