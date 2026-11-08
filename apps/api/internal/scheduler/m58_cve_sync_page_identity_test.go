package scheduler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// m58Total is the window size every page in this file reports.
const m58Total = 3706

// m58Page renders one NVD /cves/2.0 page of n records starting at id offset
// first, echoing startIndex as `echo`.
func m58Page(echo, first, n int) string {
	const total = m58Total
	items := make([]string, 0, n)
	for i := 0; i < n; i++ {
		items = append(items, fmt.Sprintf(`{"cve": {"id": "CVE-2026-%07d", "published": "2026-01-01T00:00:00.000",
			"lastModified": "2026-07-01T00:00:00.000", "descriptions": [{"lang": "en", "value": "x"}],
			"metrics": {}, "configurations": []}}`, first+i))
	}
	return fmt.Sprintf(`{"resultsPerPage": %d, "startIndex": %d, "totalResults": %d, "vulnerabilities": [%s]}`,
		n, echo, total, strings.Join(items, ","))
}

// TestM58CVESync_AFollowUpPageMustBeThePageThatWasAskedFor (M57 residual #3,
// Codex M57 R2 Medium).
//
// The fetch loop decided it was done when startIndex + len(page) reached
// totalResults, and never looked at the startIndex the page said it was. A
// mirror (SBOMHUB_NVD_URL) that answers every request with page zero —
// ignoring startIndex, as a cache keyed on the path alone does — therefore
// produced 2000 + 2000 >= 3706: the loop stopped, the duplicates were
// processed twice, 1,706 records were never seen, and the watermark moved
// past them. With the M57 replay overlap and the M58 full re-read, multi-page
// reads are the normal case rather than the exception.
func TestM58CVESync_AFollowUpPageMustBeThePageThatWasAskedFor(t *testing.T) {
	const total = m58Total
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		w.Header().Set("Content-Type", "application/json")
		if start == 0 {
			_, _ = w.Write([]byte(m58Page(0, 0, 2000)))
			return
		}
		// The faulty mirror: page zero again, saying so.
		_, _ = w.Write([]byte(m58Page(0, 0, 2000)))
	}))
	defer srv.Close()

	j := NewCVESyncJob(nil, nil, "k", 24*time.Hour, nil, srv.URL, false)
	j.pageDelay = 0
	cves, err := j.fetchModifiedCVEs(context.Background(), time.Now().Add(-24*time.Hour))
	if err == nil {
		t.Fatalf("fetchModifiedCVEs accepted a follow-up page that echoed startIndex 0 and returned %d records "+
			"for a window of %d: the missing records are silently dropped and the watermark moves past them",
			len(cves), total)
	}
}

// TestM58CVESync_AShortFollowUpPageIsNotTheEnd: a page that holds fewer
// records than remain, without being the last page, must not be read as the
// end of the window either.
func TestM58CVESync_AnEmptyPageBeforeTheEndIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		w.Header().Set("Content-Type", "application/json")
		if start == 0 {
			_, _ = w.Write([]byte(m58Page(0, 0, 2000)))
			return
		}
		_, _ = w.Write([]byte(m58Page(start, start, 0)))
	}))
	defer srv.Close()

	j := NewCVESyncJob(nil, nil, "k", 24*time.Hour, nil, srv.URL, false)
	j.pageDelay = 0
	if _, err := j.fetchModifiedCVEs(context.Background(), time.Now().Add(-24*time.Hour)); err == nil {
		t.Fatal("an empty page at startIndex 2000 of 3706 was accepted as the end of the window")
	}
}

// TestM58CVESync_ACorrectlyPagedWindowIsReadWhole is the control: the
// validation must not refuse a well-formed multi-page window.
func TestM58CVESync_ACorrectlyPagedWindowIsReadWhole(t *testing.T) {
	const total = m58Total
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		n := total - start
		if n > 2000 {
			n = 2000
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(m58Page(start, start, n)))
	}))
	defer srv.Close()

	j := NewCVESyncJob(nil, nil, "k", 24*time.Hour, nil, srv.URL, false)
	j.pageDelay = 0
	cves, err := j.fetchModifiedCVEs(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("fetchModifiedCVEs: %v", err)
	}
	if len(cves) != total {
		t.Fatalf("read %d records, want %d", len(cves), total)
	}
}
