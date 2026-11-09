package service

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// Codex M70 R26 High-1: an oversized-evidence settlement uses the same
// withdrawal handling as any other no verdict.
func TestM70R26_OversizedEvidenceResolvesWithdrawal(t *testing.T) {
	var recs []distroRecord
	for i := 0; i < 1500; i++ {
		r := rec(fmt.Sprintf("DLA-%04d-1", i), []string{"CVE-2021-0001"}, entry("Debian:11", "i", "0", "f", "9.0-1"))
		r.Modified = "2026-11-01T00:00:00Z"
		recs = append(recs, r)
	}
	d := indexDistroRecords(recs)
	d.sourceID = "S"
	if d.ids["DLA-0001-1"] != true || d.ids["A"] {
		t.Fatalf("ids index wrong")
	}
	tgt := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", binary: "p", version: "1.0-1", scheme: schemeDpkg}
	comp, vuln := uuid.New(), uuid.New()
	links := map[uuid.UUID][]repository.SbomLink{comp: {{ComponentID: comp, VulnerabilityID: vuln, CVEID: "CVE-2021-0001",
		Method: "distro_affected", Records: []string{"A"}, WMSource: "S", WMRev: "2026-11-05T00:00:00.000000000Z"}}}
	lookup := func(id string) recordState {
		if id == "A" {
			return recordState{withdrawn: true, rev: "2026-11-08T00:00:00.000000000Z"}
		}
		return recordState{failed: true}
	}
	groups, counts, err := decideKey(context.Background(), d, time.Time{}, []distroWork{{comp: model.Component{ID: comp}, target: tgt}}, links, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0]) != 1 || !groups[0][0].noVerdict || counts.NoVerdict["evidence_too_large"] != 1 {
		t.Fatalf("groups=%d counts=%+v", len(groups), counts)
	}
	var wm struct {
		DataModified string `json:"data_modified"`
	}
	_ = json.Unmarshal(groups[0][0].evidence, &wm)
	if wm.DataModified != "2026-11-08T00:00:00.000000000Z" {
		t.Errorf("watermark %s, want the withdrawal revision", groups[0][0].evidence)
	}
}

// Codex M70 R26 Medium-2: the link loop stops on a cancelled context.
func TestM70R26_LinkLoopHonoursCancellation(t *testing.T) {
	d := indexDistroRecords(nil)
	comp := uuid.New()
	var ls []repository.SbomLink
	for i := 0; i < 100; i++ {
		ls = append(ls, repository.SbomLink{ComponentID: comp, VulnerabilityID: uuid.New(), CVEID: fmt.Sprintf("CVE-2021-%04d", i)})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	groups, _, _ := decideKey(ctx, d, time.Time{}, []distroWork{{comp: model.Component{ID: comp}}}, map[uuid.UUID][]repository.SbomLink{comp: ls}, nil)
	if len(groups) != 0 {
		t.Errorf("cancelled scan still settled %d group(s)", len(groups))
	}
}
