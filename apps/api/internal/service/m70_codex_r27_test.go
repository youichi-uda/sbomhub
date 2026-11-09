package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sbomhub/sbomhub/internal/client"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// Codex M70 R27 High-1: the affected purl is parsed fully.
func TestM70R27_StrictAffectedPurl(t *testing.T) {
	for _, purl := range []string{
		"pkg:deb/debian/p@?arch=source", "pkg:deb/debian/p@", "pkg:deb/debian/p?arch=", "pkg:deb/debian/p?=x",
		"pkg:deb/debian/p?Arch=source", "pkg:deb/debian/p%zz", "pkg:deb//p", "pkg:deb/debian/p#",
		"pkg:deb/debian/p?arch=a&arch=b",
	} {
		rec := `{"id":"DSA-9","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11","purl":"` + purl + `"}}]}`
		if err := r15Query(t, `{"vulns":[`+rec+`]}`); err == nil {
			t.Errorf("%s accepted", purl)
		}
	}
	for _, purl := range []string{"pkg:deb/debian/p", "pkg:deb/debian/p?arch=source", "pkg:deb/Debian/p@1.0-1?arch=source&distro=bookworm"} {
		rec := `{"id":"DSA-9","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11","purl":"` + purl + `"}}]}`
		if err := r15Query(t, `{"vulns":[`+rec+`]}`); err != nil {
			t.Errorf("%s refused: %v", purl, err)
		}
	}
}

// Codex M70 R27 Medium-4: a present but malformed Ubuntu binaries list
// fails the query.
func TestM70R27_MalformedUbuntuBinaries(t *testing.T) {
	for _, es := range []string{`{"binaries":{}}`, `{"binaries":[{}]}`, `{"binaries":[{"binary_name":""}]}`, `{"binaries":["x"]}`} {
		rec := `{"id":"USN-9-1","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Ubuntu:22.04:LTS"},"ecosystem_specific":` + es + `}]}`
		if err := r27UbuntuQuery(t, `{"vulns":[`+rec+`]}`); err == nil {
			t.Errorf("%s accepted", es)
		}
	}
	ok := `{"id":"USN-9-1","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Ubuntu:22.04:LTS"},"ecosystem_specific":{"binaries":[{"binary_name":"p","binary_version":"1"}]}}]}`
	if err := r27UbuntuQuery(t, `{"vulns":[`+ok+`]}`); err != nil {
		t.Errorf("valid binaries refused: %v", err)
	}
}

// Codex M70 R27 High-2: an all-withdrawn label is cleared WITHOUT claiming
// the withdrawal time as a package revision: the clear carries the link's
// own watermark and the exact records it rests on.
func TestM70R27_WithdrawnClearKeepsWatermark(t *testing.T) {
	d := distroData{byCVE: map[string][]*distroRecord{}, ids: map[string]bool{"B": true}, sourceID: "S", revision: "05"}
	l := repository.SbomLink{ComponentID: uuid.New(), VulnerabilityID: uuid.New(), Method: "distro_fixed", Records: []string{"A"},
		WMSource: "S", WMRev: "10", LabelSource: "S", LabelRev: "10"}
	lookup := func(string) recordState { return recordState{withdrawn: true, rev: "20"} }
	var counts DistroScanReport
	pl := d.settleNoVerdict(l, []byte(`{"data_modified":"05"}`), lookup, &counts)
	if !pl.withdrawnClear || pl.noVerdict {
		t.Fatalf("%+v: want a withdrawn clear", pl)
	}
	var p struct {
		SourceID string   `json:"source_id"`
		Records  []string `json:"records"`
		WMRev    string   `json:"wm_rev"`
	}
	_ = json.Unmarshal(pl.evidence, &p)
	if p.WMRev != "10" || p.SourceID != "S" || len(p.Records) != 1 || p.Records[0] != "A" || counts.Cleared != 1 {
		t.Errorf("clear %s counts %+v", pl.evidence, counts)
	}
	// Evidence of another source, or a record withdrawn before the label's
	// revision: no withdrawn clear.
	l2 := l
	l2.LabelSource = "T"
	if pl := d.settleNoVerdict(l2, nil, lookup, &counts); pl.withdrawnClear {
		t.Error("cleared a label of another source")
	}
	if pl := d.settleNoVerdict(l, nil, func(string) recordState { return recordState{withdrawn: true, rev: "09"} }, &counts); pl.withdrawnClear {
		t.Error("cleared on a withdrawal older than the label")
	}
}

func r27UbuntuQuery(t *testing.T, body string) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
	defer srv.Close()
	_, err := client.NewOSVClient().WithBaseURL(srv.URL).QueryPackage(context.Background(), "Ubuntu:22.04:LTS", "p", 5, nil)
	return err
}
