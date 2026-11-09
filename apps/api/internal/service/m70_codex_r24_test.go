package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// Codex M70 R24 High-1: when the record a distro label rests on is WITHDRAWN,
// OSV's query omits it and the package revision goes down; the record is
// then looked up by id and its withdrawal is the newer revision the clear
// rests on.
func TestM70R24_WithdrawnRecordClearsDespiteLowerRevision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/query":
			_, _ = io.WriteString(w, `{}`) // the withdrawn record is gone
		case r.URL.Path == "/vulns/DLA-7":
			_, _ = io.WriteString(w, `{"id":"DLA-7","modified":"2026-11-08T00:00:00Z","withdrawn":"2026-11-08T00:00:00Z"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	s := NewDistroService(nil, srv.URL, nil, false)
	s.gap = 0
	tgt, _ := distroTargetFor("pkg:deb/debian/p@1.0-1?distro=debian-11", "1.0-1", nil)
	comp, vuln := uuid.New(), uuid.New()
	links := map[uuid.UUID][]repository.SbomLink{comp: {{ComponentID: comp, VulnerabilityID: vuln, CVEID: "CVE-2021-0001",
		Method: "distro_fixed", Records: []string{"DLA-7"}, WMSource: s.sourceID, WMRev: "2026-11-01T00:00:00.000000000Z",
		LabelSource: s.sourceID, LabelRev: "2026-11-01T00:00:00.000000000Z"}}}
	rep := DistroScanReport{NoVerdict: map[string]int{}}
	groups, err := s.fetchAndDecide(context.Background(), []distroWork{{comp: model.Component{ID: comp}, target: tgt}}, links, &rep)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0]) != 1 || !groups[0][0].withdrawnClear {
		t.Fatalf("groups %+v", groups)
	}
	var p struct {
		WMRev string `json:"wm_rev"`
	}
	_ = json.Unmarshal(groups[0][0].evidence, &p)
	if p.WMRev != "2026-11-01T00:00:00.000000000Z" { // R27 High-2: watermark kept
		t.Errorf("clear %s, want the link's own watermark", groups[0][0].evidence)
	}
}

// Codex M70 R24 Medium-2 / Medium-3.
func TestM70R24_GitVersionsAndNestedPrefixes(t *testing.T) {
	git := `{"id":"DSA-9","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}},{"ranges":[{"type":"GIT","repo":"https://x","events":[{"introduced":"abc"}]}],"versions":["v1.2"]}]}`
	if err := r15Query(t, `{"vulns":[`+git+`]}`); err != nil {
		t.Errorf("package-less GIT entry with versions refused: %v", err)
	}
	for _, id := range []string{"DEBIAN-UBUNTU-CVE-2026-1234", "UBUNTU-DEBIAN-CVE-2026-1234", "X-CVE-2026-1234"} {
		rec := strings.Replace(r15OK, `"DSA-1"`, `"`+id+`"`, 1)
		if err := r15Query(t, `{"vulns":[`+rec+`]}`); err == nil {
			t.Errorf("%s accepted", id)
		}
	}
}
