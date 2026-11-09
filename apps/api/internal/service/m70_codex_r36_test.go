package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sbomhub/sbomhub/internal/client"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// Codex M70 R36 High-1: a present but undecided record does not keep a
// withdrawn record's label: only the absent records are resolved.
func TestM70R36_PresentUndecidedRecordDoesNotBlock(t *testing.T) {
	d := distroData{byCVE: map[string][]*distroRecord{}, ids: map[string]bool{"B": true}, sourceID: "S", revision: "01"}
	l := repository.SbomLink{Method: "distro_affected", Records: []string{"A", "B"}, WMSource: "S", WMRev: "02", LabelSource: "S", LabelRev: "02"}
	asked := map[string]bool{}
	p, failed := d.withdrawnClear(l, func(id string) recordState {
		asked[id] = true
		return recordState{withdrawn: true, rev: "03"}
	})
	if p == nil || failed || !asked["A"] || asked["B"] {
		t.Errorf("p=%s failed=%v asked=%v, want A resolved and cleared", p, failed, asked)
	}
}

// Codex M70 R36 Medium-2: an encoded "/" in the base path stays encoded.
func TestM70R36_EscapedBasePath(t *testing.T) {
	var uri string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uri = r.RequestURI
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	c := client.NewOSVClient().WithBaseURL(srv.URL + "/feeds/team%2Fprod?key=x")
	if _, err := c.QueryPackage(context.Background(), "Debian", "p", 5, nil); err != nil {
		t.Fatal(err)
	}
	if uri != "/feeds/team%2Fprod/query?key=x" {
		t.Errorf("request URI %q", uri)
	}
}
