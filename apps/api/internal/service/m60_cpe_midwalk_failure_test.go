package service

import (
	"context"
	"testing"
	"time"
)

// Found by the M60 decision-2 end-to-end run (2026-11-08, live NVD): with the
// kernel-sized CPE budget, NVD answered deep kernel pages in 15-36 s and one
// page (startIndex=1592) took 35.8 s at NVD, past the 30 s client timeout.
// The whole lookup then failed: the kernel kept 0 findings and the scan
// counted a PARTIAL fetch failure, which is not escalated — a false clean.
//
// On the CPE path a page failure after at least one good page now keeps the
// verified pages and reports the answer TRUNCATED (escalated, never cached).
func TestM60CPEWalk_MidWalkFailureIsTruncationNotLoss(t *testing.T) {
	pager := &cannedNVDPager{total: 7059}
	pager.rewrite = func(page int, resp *NVDResponse) {
		if page == 3 {
			resp.ResultsPerPage = nil // a page that fails validation
		}
	}
	svc := NewNVDService(nil, nil, "", pager.start(t).URL, false)
	l, err := svc.lookupComponent(context.Background(), m60PlainItem(t), nil)
	if err != nil {
		t.Fatalf("mid-walk failure discarded the lookup: %v", err)
	}
	// pages 0-2 good: 200 + 199 + 199 records.
	if !l.truncated || len(l.vulns) != 598 || l.requests != 4 || !l.uncacheable {
		t.Errorf("truncated=%v vulns=%d requests=%d uncacheable=%v, want true / 598 / 4 / true",
			l.truncated, len(l.vulns), l.requests, l.uncacheable)
	}
	if l.total-l.fetched <= 0 {
		t.Errorf("dropped matches not reported: total=%d fetched=%d", l.total, l.fetched)
	}
}

// A failure on the FIRST page is still a fetch failure (nothing verified), as
// is a cancelled context at any page.
func TestM60CPEWalk_FirstPageFailureAndCancellationStayErrors(t *testing.T) {
	pager := &cannedNVDPager{total: 7059}
	pager.rewrite = func(page int, resp *NVDResponse) {
		if page == 0 {
			resp.ResultsPerPage = nil
		}
	}
	svc := NewNVDService(nil, nil, "", pager.start(t).URL, false)
	if _, err := svc.lookupComponent(context.Background(), m60PlainItem(t), nil); err == nil {
		t.Errorf("first-page failure was not an error")
	}

	ok := &cannedNVDPager{total: 7059}
	svc2 := NewNVDService(nil, nil, "", ok.start(t).URL, false)
	ctx, cancel := context.WithCancel(context.Background())
	pages := 0
	pace := func(ctx context.Context) error {
		pages++
		if pages == 3 {
			cancel()
		}
		return ctx.Err()
	}
	if _, err := svc2.lookupComponent(ctx, m60PlainItem(t), pace); err == nil {
		t.Errorf("a cancelled walk was not an error")
	}
}

// The NVD client timeout is sized from the measured worst deep page (35.8 s).
func TestM60NVDClientTimeoutCoversMeasuredDeepPages(t *testing.T) {
	svc := NewNVDService(nil, nil, "", "http://127.0.0.1:1", false)
	if svc.httpClient.Timeout < 36*time.Second {
		t.Errorf("NVD client timeout %s is below the measured 35.8 s kernel page", svc.httpClient.Timeout)
	}
}
