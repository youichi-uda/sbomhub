package service

import (
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

// Codex M70 R45 High-1: an entry for a Debian release unknown here (its
// purl qualifiers cannot be checked) cannot vouch for a later-releases fix.
func TestM70R45_UnknownLaterReleaseNoVerdict(t *testing.T) {
	r := rec("DEBIAN-CVE-2021-0001", []string{"CVE-2021-0001"},
		entry("Debian:12", "i", "0", "f", "1.0-1"), entry("Debian:16", "i", "0", "f", "1.0-1"))
	tgt := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", binary: "p", version: "2.0-1", scheme: schemeDpkg}
	d := laterReleaseVerdict(tgt, []*distroRecord{&r}, model.DistroEvidence{}, tgt.comparator())
	if d.verdict != verdictNone || d.reason != "unverified_release" {
		t.Errorf("%+v, want no verdict (unverified_release)", d)
	}
	r2 := rec("DEBIAN-CVE-2021-0001", []string{"CVE-2021-0001"}, entry("Debian:12", "i", "0", "f", "1.0-1"))
	if d := laterReleaseVerdict(tgt, []*distroRecord{&r2}, model.DistroEvidence{}, tgt.comparator()); d.verdict != verdictFixed {
		t.Errorf("known later release: %+v, want fixed", d)
	}
}

// Codex M70 R45 Low-2: a second "#" is malformed.
func TestM70R45_SecondHash(t *testing.T) {
	if _, ok := parsePurl("pkg:deb/debian/p@2.0-1#usr#lib"); ok {
		t.Error("component purl with a second '#' accepted")
	}
	if err := r32Query(t, "AlmaLinux:9", "pkg:rpm/almalinux/p#usr#lib"); err == nil {
		t.Error("affected purl with a second '#' accepted")
	}
}
