package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// Codex M70 R23 High-2: next_page_token, when present, is a JSON string.
func TestM70R23_NullPageToken(t *testing.T) {
	if err := r15Query(t, `{"vulns":[`+r15OK+`],"next_page_token":null}`); err == nil {
		t.Error("null next_page_token accepted")
	}
	if err := r15Query(t, `{"vulns":[`+r15OK+`],"next_page_token":7}`); err == nil {
		t.Error("numeric next_page_token accepted")
	}
}

// Codex M70 R23 High-3: an affected purl's namespace is the distro of the
// ecosystem.
func TestM70R23_AffectedPurlNamespace(t *testing.T) {
	rec := fmt.Sprintf(`{"id":"DSA-9","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11","purl":%q}}]}`, "pkg:deb/ubuntu/p")
	if err := r15Query(t, `{"vulns":[`+rec+`]}`); err == nil {
		t.Error("an Ubuntu purl accepted for a Debian entry")
	}
}

// Codex M70 R23 Medium-4: a package-less entry holding only GIT ranges is
// valid OSV and is ignored, not a failure.
func TestM70R23_PackagelessGitEntry(t *testing.T) {
	rec := `{"id":"DSA-9","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}},{"ranges":[{"type":"GIT","repo":"https://x","events":[{"introduced":"abc"}]}]}]}`
	if err := r15Query(t, `{"vulns":[`+rec+`]}`); err != nil {
		t.Errorf("package-less GIT entry refused: %v", err)
	}
	bad := `{"id":"DSA-9","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}},{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`
	if err := r15Query(t, `{"vulns":[`+bad+`]}`); err == nil {
		t.Error("package-less ECOSYSTEM entry accepted")
	}
}

// Codex M70 R23 High-1: a verdict whose evidence is too large still settles
// the link (no-verdict with the watermark), never skips it.
func TestM70R23_OversizedEvidenceSettles(t *testing.T) {
	var ids []string
	var recs []distroRecord
	for i := 0; i < 1500; i++ {
		id := fmt.Sprintf("DLA-%04d-1", i)
		ids = append(ids, id)
		recs = append(recs, rec(id, []string{"CVE-2021-0001"}, entry("Debian:11", "i", "0", "f", "9.0-1")))
	}
	d := indexDistroRecords(recs)
	tgt := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", binary: "p", version: "1.0-1", scheme: schemeDpkg}
	comp, vuln := uuid.New(), uuid.New()
	groups, counts, err := decideKey(context.Background(), d, time.Time{}, []distroWork{{comp: model.Component{ID: comp}, target: tgt}},
		map[uuid.UUID][]repository.SbomLink{comp: {{ComponentID: comp, VulnerabilityID: vuln, CVEID: "CVE-2021-0001", Method: "distro_fixed"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0]) != 1 || !groups[0][0].noVerdict || counts.NoVerdict["evidence_too_large"] != 1 || !groups[0][0].wasDistro {
		t.Errorf("groups=%+v counts=%+v, want one no-verdict settlement", groups, counts)
	}
	_ = ids
}
