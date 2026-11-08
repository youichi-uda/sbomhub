package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// M62: overall scan deadline, partial-failure escalation, and the
// fetch/write split. These are the unit (no database) halves; the
// transaction, lock and cache halves are in m62_*_integration_test.go.

// m62Collect is an onLookup that records which items answered.
type m62Collect struct {
	mu    sync.Mutex
	names []string
	look  map[string]nvdLookup
}

func (c *m62Collect) on(item *nvdWorkItem, l nvdLookup) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.look == nil {
		c.look = map[string]nvdLookup{}
	}
	c.names = append(c.names, item.key.Name)
	c.look[item.key.Name] = l
}

// m62KeywordItems builds keyword-only work items.
func m62KeywordItems(names ...string) map[nvdComponentKey]*nvdWorkItem {
	out := map[nvdComponentKey]*nvdWorkItem{}
	for _, n := range names {
		k := nvdComponentKey{Name: n, Version: "1.0.0"}
		out[k] = &nvdWorkItem{key: k}
	}
	return out
}

// m62BlockingNVD answers "fast" keyword queries at once with an empty
// result and holds every other request until the request's context ends.
func m62BlockingNVD(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Query().Get("keywordSearch"), "fast") {
			_, _ = w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"format":"NVD_CVE","version":"2.0","timestamp":"2026-11-08T00:00:00.000","vulnerabilities":[]}`))
			return
		}
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The deadline stops the sweep, the items it interrupted are NOT counted as
// fetch failures, and the report says the deadline fired.
func TestM62NVDFetch_DeadlineStopsTheSweepAndIsReported(t *testing.T) {
	// An API key gives 5 workers, so the fast item is answered whatever
	// order the work map hands the items out in.
	svc := NewNVDService(nil, nil, "k", m62BlockingNVD(t).URL, false)
	svc.paceInterval = time.Millisecond

	ctx, cancel := WithScanDeadline(context.Background(), 300*time.Millisecond)
	defer cancel()
	c := &m62Collect{}
	start := time.Now()
	rep := svc.fetchComponents(ctx, m62KeywordItems("fast-a", "slow-b", "slow-c"), c.on)
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("the sweep ran %s past a 300ms deadline", el)
	}
	if rep.Processed != 1 || rep.FetchFailures != 0 || rep.Unscanned != 2 || !rep.DeadlineExceeded || rep.Cancelled {
		t.Fatalf("processed=%d fetch_failures=%d unscanned=%d deadline=%v cancelled=%v, want 1/0/2/true/false",
			rep.Processed, rep.FetchFailures, rep.Unscanned, rep.DeadlineExceeded, rep.Cancelled)
	}
	err := rep.incompleteErr()
	if !errors.Is(err, ErrScanDeadlineExceeded) {
		t.Fatalf("incompleteErr = %v, want it to wrap ErrScanDeadlineExceeded", err)
	}
	if got := ScanReasons(err); !slices.Equal(got, []string{ScanReasonDeadlineExceeded}) {
		t.Errorf("reasons = %v, want [deadline_exceeded]", got)
	}
	if !slices.Equal(c.names, []string{"fast-a"}) {
		t.Errorf("answered items = %v, want only fast-a", c.names)
	}
}

// A cancellation that is not the deadline (shutdown) is reported as such.
func TestM62NVDFetch_PlainCancellationIsNotReportedAsDeadline(t *testing.T) {
	svc := NewNVDService(nil, nil, "", m62BlockingNVD(t).URL, false)
	svc.paceInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	rep := svc.fetchComponents(ctx, m62KeywordItems("slow-a"), (&m62Collect{}).on)
	if rep.DeadlineExceeded || !rep.Cancelled || rep.Unscanned != 1 {
		t.Fatalf("deadline=%v cancelled=%v unscanned=%d, want false/true/1", rep.DeadlineExceeded, rep.Cancelled, rep.Unscanned)
	}
	if got := ScanReasons(rep.incompleteErr()); !slices.Equal(got, []string{ScanReasonCancelled}) {
		t.Errorf("reasons = %v, want [cancelled]", got)
	}
}

// When the deadline fires INSIDE a CPE page walk, the pages verified before
// it are kept and the answer is reported truncated (M60's rule for a page
// failing partway) and is never cacheable. Any other cancellation still
// discards the walk (TestM60CPEWalk_FirstPageFailureAndCancellationStayErrors).
func TestM62CPEWalk_DeadlineMidWalkKeepsVerifiedPagesAsTruncated(t *testing.T) {
	pager := &cannedNVDPager{total: 7059}
	svc := NewNVDService(nil, nil, "", pager.start(t).URL, false)
	// Cancelling with the deadline as the cause is the deterministic
	// stand-in for a 30-minute timer expiring between page 2 and page 3.
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	pages := 0
	pace := func(pctx context.Context) error {
		pages++
		if pages == 3 {
			cancel(ErrScanDeadlineExceeded)
		}
		return pctx.Err()
	}
	l, err := svc.lookupComponent(ctx, m60PlainItem(t), pace)
	if err != nil {
		t.Fatalf("a deadline inside the walk discarded its verified pages: %v", err)
	}
	if !l.truncated || !l.partialFailure || !l.uncacheable || len(l.vulns) != 598 {
		t.Errorf("truncated=%v partial=%v uncacheable=%v vulns=%d, want true/true/true/598",
			l.truncated, l.partialFailure, l.uncacheable, len(l.vulns))
	}
}

// A keyword lookup that fails while another component answers is escalated
// (fetch_failed); before M62 the sweep reported success.
func TestM62NVDFetch_PartialKeywordFailureIsEscalated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Query().Get("keywordSearch"), "fast") {
			_, _ = w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"format":"NVD_CVE","version":"2.0","timestamp":"2026-11-08T00:00:00.000","vulnerabilities":[]}`))
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	svc := NewNVDService(nil, nil, "k", srv.URL, false)
	svc.paceInterval = time.Millisecond
	rep := svc.fetchComponents(context.Background(), m62KeywordItems("fast-a", "broken-b"), (&m62Collect{}).on)
	if rep.Processed != 1 || rep.FetchFailures != 1 || rep.Unscanned != 0 {
		t.Fatalf("processed=%d fetch_failures=%d unscanned=%d, want 1/1/0", rep.Processed, rep.FetchFailures, rep.Unscanned)
	}
	if got := ScanReasons(rep.incompleteErr()); !slices.Equal(got, []string{ScanReasonFetchFailed}) {
		t.Errorf("reasons = %v, want [fetch_failed]", got)
	}
}

// A PARTIAL fetch failure is now escalated (it was reported as success
// before M62: only a total failure was).
func TestM62NVDReport_PartialFetchFailureIsEscalated(t *testing.T) {
	err := NVDScanReport{UniqueComponents: 10, Processed: 7, FetchFailures: 3}.incompleteErr()
	if !errors.Is(err, ErrScanFetchFailed) {
		t.Fatalf("incompleteErr = %v, want ErrScanFetchFailed", err)
	}
	if !strings.Contains(err.Error(), "3 of 10") {
		t.Errorf("message %q does not say how many failed", err)
	}
}

// Every applicable reason is reported, not only the first.
func TestM62NVDReport_AllReasonsAreReported(t *testing.T) {
	err := NVDScanReport{UniqueComponents: 10, Processed: 5, FetchFailures: 1, Unscanned: 4,
		DeadlineExceeded: true, TruncatedComponents: 1, RefusedWrites: 2}.incompleteErr()
	want := []string{ScanReasonDeadlineExceeded, ScanReasonFetchFailed, ScanReasonTruncated, ScanReasonWriteRefused}
	if got := ScanReasons(err); !slices.Equal(got, want) {
		t.Errorf("reasons = %v, want %v", got, want)
	}
}

// JVN: a partial lookup failure is escalated too.
func TestM62JVNReport_PartialFetchFailureIsEscalated(t *testing.T) {
	err := JVNScanReport{Components: 5, Scanned: 4, Failed: 1}.Err()
	if !errors.Is(err, ErrScanFetchFailed) {
		t.Fatalf("JVN Err = %v, want ErrScanFetchFailed", err)
	}
}

func TestM62JVNReport_DeadlineIsReported(t *testing.T) {
	err := JVNScanReport{Components: 5, Scanned: 2, Unscanned: 3, Cancelled: true, DeadlineExceeded: true}.Err()
	if got := ScanReasons(err); !slices.Equal(got, []string{ScanReasonDeadlineExceeded}) {
		t.Errorf("reasons = %v, want [deadline_exceeded]", got)
	}
}

// The guard that makes "no network I/O inside a transaction" structural.
func TestM62ScanScope_RefusesMissingScope(t *testing.T) {
	if _, err := scanScopeFrom(context.Background()); !errors.Is(err, ErrScanNoScope) {
		t.Errorf("no scope: err = %v, want ErrScanNoScope", err)
	}
	svc := NewNVDService(nil, nil, "", "http://127.0.0.1:1", false)
	if _, err := svc.ScanComponentsWithReport(context.Background(), [16]byte{1}); !errors.Is(err, ErrScanNoScope) {
		t.Errorf("NVD scan without scope: err = %v, want ErrScanNoScope", err)
	}
	jvn := NewJVNService(nil, nil, "http://127.0.0.1:1", false)
	if _, err := jvn.ScanComponentsReport(context.Background(), [16]byte{1}); !errors.Is(err, ErrScanNoScope) {
		t.Errorf("JVN scan without scope: err = %v, want ErrScanNoScope", err)
	}
}

func TestM62WithScanDeadline_DefaultsAndCause(t *testing.T) {
	ctx, cancel := WithScanDeadline(context.Background(), 0)
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok || time.Until(dl) < DefaultScanDeadline-time.Minute {
		t.Errorf("zero deadline did not default to %s", DefaultScanDeadline)
	}
	short, c2 := WithScanDeadline(context.Background(), time.Millisecond)
	defer c2()
	<-short.Done()
	if !scanDeadlineFired(short) {
		t.Errorf("an expired scan deadline is not recognised as one")
	}
}
