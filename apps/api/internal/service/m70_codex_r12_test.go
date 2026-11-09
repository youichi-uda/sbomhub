package service

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// Codex M70 R12 High-4: the endpoint in evidence carries no credentials,
// query or fragment.
func TestM70R12_SourceURLIsSanitised(t *testing.T) {
	for in, want := range map[string]string{
		// origin only since Codex R14 High-5
		"https://svc:password@mirror.internal/v1?token=x#f": "https://mirror.internal",
		"https://api.osv.dev/v1/":                           "https://api.osv.dev",
		"":                                                  "https://api.osv.dev",
	} {
		if got := distroSource(in); got != want {
			t.Errorf("distroSource(%q) = %q, want %q", in, got, want)
		}
	}
	if got := distroSource("::not a url"); strings.Contains(got, "not a url") {
		t.Errorf("an unparseable URL leaked: %q", got)
	}
}

// Codex M70 R12 High-3: exactly one id form is per-CVE.
func TestM70R12_RecordCVEForms(t *testing.T) {
	for id, want := range map[string]string{
		"CVE-2026-1234": "CVE-2026-1234", "DEBIAN-CVE-2026-1234": "CVE-2026-1234", "UBUNTU-CVE-2026-1234": "CVE-2026-1234",
		"DEBIAN-UBUNTU-CVE-2026-1234": "", "UBUNTU-DEBIAN-CVE-2026-1234": "", "DSA-1": "", "DEBIAN-CVE-ROLLUP": "",
	} {
		if got := (&distroRecord{ID: id}).recordCVE(); got != want {
			t.Errorf("%s -> %q, want %q", id, got, want)
		}
	}
}

// Codex M70 R12 High-2: a cached record without a normalised modified is not
// one this build wrote.
func TestM70R12_CachedRecordsNeedModified(t *testing.T) {
	r := distroRecord{ID: "DSA-1", CVEs: []string{"CVE-2021-0001"}, Releases: 1, Packages: 1,
		Entries: []distroEntry{entry("Debian:11", "i", "0", "f", "1.0-1")}}
	if validDistroRecords([]distroRecord{r}) {
		t.Error("record without modified accepted")
	}
	r.Modified = "2026-11-01T00:00:00Z"
	if validDistroRecords([]distroRecord{r}) {
		t.Error("non-normalised modified accepted")
	}
	r.Modified = normaliseModified("2026-11-01T00:00:00Z")
	if !validDistroRecords([]distroRecord{r}) {
		t.Error("valid record refused")
	}
}

// Codex M70 R12 High-1: a link that holds a distro label but gets no verdict
// from a complete, successful fetch is queued to be CLEARED (back to the
// method it had before the distro step).
func TestM70R12_NoVerdictClearsAStaleDistroLabel(t *testing.T) {
	r := &replayOSV{t: t, routes: map[string]string{"Debian|openssl": "debian_openssl"}}
	s := NewDistroService(nil, r.start().URL, nil, false)
	s.gap = 0
	comp, vuln := uuid.New(), uuid.New()
	tgt, _ := distroTargetFor("pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11", "1.1.1k-1", nil)
	work := []distroWork{{comp: model.Component{ID: comp}, target: tgt}}
	links := map[uuid.UUID][]repository.SbomLink{comp: {
		// no OSV record for this CVE; the link was relabelled by an earlier scan
		{ComponentID: comp, VulnerabilityID: vuln, CVEID: "CVE-2009-0591", Method: "distro_fixed", LabelSource: s.sourceID},
	}}
	rep := DistroScanReport{NoVerdict: map[string]int{}}
	groups, err := s.fetchAndDecide(context.Background(), work, links, &rep)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0]) != 1 || !groups[0][0].noVerdict || !groups[0][0].wasDistro {
		t.Errorf("groups=%+v rep=%+v, want one clear", groups, rep)
	}
}
