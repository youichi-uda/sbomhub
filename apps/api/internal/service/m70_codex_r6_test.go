package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sbomhub/sbomhub/internal/client"
)

// Codex M70 R6 High-2: OSV writes an open-ended range ("introduced 0", no
// fixed) both for "vulnerable, no fix" and for undecided statuses (Debian
// "undetermined", Ubuntu "needs-triage"). It is no verdict.
func TestM70R6_OpenEndedRangeIsNoVerdict(t *testing.T) {
	dpkg := distroTarget{scheme: schemeDpkg}.comparator()
	if r := evalEntry("1.0-1", distroEntry{Ranges: eco(ev("i", "0"))}, dpkg); r.state != entryUndecidable {
		t.Errorf("open-ended range = %+v, want undecidable", r)
	}
	deb11 := distroTarget{family: "debian", query: "Debian", release: "Debian:11", releaseMajor: 11, pkg: "p", binary: "p", version: "1.0-1", scheme: schemeDpkg}
	r := rec("DEBIAN-CVE-2026-36499", []string{"CVE-2026-36499"}, entry("Debian:11", "i", "0"))
	if d := indexDistroRecords([]distroRecord{r}).decide(deb11, "CVE-2026-36499"); d.verdict != verdictNone {
		t.Errorf("= %+v, want no verdict", d)
	}
}

// Codex M70 R6 Medium-3: a 200 JSON object that is neither `{}` nor carries
// a vulns array or a page token is not an answer.
func TestM70R6_UnrecognisedEnvelopeIsAnError(t *testing.T) {
	for _, body := range []string{`{"error":"backend unavailable"}`, `{"vulns":null}`, `{"vulns":{}}`, `{"next_page_token":""}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
		_, err := client.NewOSVClient().WithBaseURL(srv.URL).QueryPackage(context.Background(), "Debian", "p", 2, nil)
		srv.Close()
		if err == nil {
			t.Errorf("%s accepted", body)
		}
	}
	for _, body := range []string{`{}`, `{"vulns":[]}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
		_, err := client.NewOSVClient().WithBaseURL(srv.URL).QueryPackage(context.Background(), "Debian", "p", 2, nil)
		srv.Close()
		if err != nil {
			t.Errorf("%s rejected: %v", body, err)
		}
	}
}

// Codex M70 R6 High-1: the slot is held until the package's data has been
// used, not only while it is loaded.
func TestM70R6_SlotCoversTheUse(t *testing.T) {
	r := &replayOSV{t: t, routes: map[string]string{"Debian|openssl": "debian_openssl"}}
	s := NewDistroService(nil, r.start().URL, nil, false)
	s.gap = 0
	inUse := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, _, err := s.loadSlotted(context.Background(), distroFetchKey{ecosystem: "Debian", pkg: "openssl"}, s.pacer(),
			func(distroLoad) error { close(inUse); <-release; return nil })
		done <- err
	}()
	<-inUse
	if got := len(distroQuerySlots); got != 1 {
		t.Errorf("slots held while the data is in use = %d, want 1", got)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := len(distroQuerySlots); got != 0 {
		t.Errorf("slots held after use = %d, want 0", got)
	}
}
