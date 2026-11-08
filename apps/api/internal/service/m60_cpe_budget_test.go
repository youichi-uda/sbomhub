package service

import (
	"context"
	"testing"
)

// M60 decision 2: the CPE path gets its own page budget, sized for a full
// Linux kernel; the keyword path keeps nvdMaxPagesPerComponent (996 records).
//
// Measured 2026-11-08 (live NVD): cpeName for linux_kernel 5.10.46 has
// totalResults=7059, i.e. 1 + ceil((7059-200)/199) = 36 pages.

func m60PlainItem(t *testing.T) nvdWorkItem {
	t.Helper()
	return nvdWorkItem{
		key:        nvdComponentKey{Name: "linux-kernel", Version: "5.10.46"},
		candidates: cpeCandidates([]string{"cpe:2.3:o:linux:linux_kernel:5.10.46:*:*:*:*:*:*:*"}, "5.10.46", ""),
	}
}

func TestM60CPEBudget_KernelSizedAnswerIsComplete(t *testing.T) {
	pager := &cannedNVDPager{total: 7059}
	svc := NewNVDService(nil, nil, "", pager.start(t).URL, false)
	p := &countingPacer{}
	l, err := svc.lookupComponent(context.Background(), m60PlainItem(t), p.pace)
	if err != nil {
		t.Fatal(err)
	}
	if l.truncated || len(l.vulns) != 7059 || l.requests != 36 {
		t.Errorf("truncated=%v vulns=%d requests=%d, want false / 7059 / 36", l.truncated, len(l.vulns), l.requests)
	}
	// Every request after the item's first takes a tick of the sweep's shared
	// limiter: the rate limit holds however many pages the walk spends.
	if p.n != l.requests-1 {
		t.Errorf("pacer ticks = %d for %d requests, want one per request after the first", p.n, l.requests)
	}
}

func TestM60CPEBudget_OverBudgetAnswerIsStillTruncated(t *testing.T) {
	over := nvdPageSize + (nvdCPEMaxPagesPerComponent-1)*(nvdPageSize-1) + 1
	pager := &cannedNVDPager{total: over}
	svc := NewNVDService(nil, nil, "", pager.start(t).URL, false)
	l, err := svc.lookupComponent(context.Background(), m60PlainItem(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !l.truncated || l.requests != nvdCPEMaxPagesPerComponent || l.total-l.fetched != 1 {
		t.Errorf("truncated=%v requests=%d dropped=%d, want true / %d / 1",
			l.truncated, l.requests, l.total-l.fetched, nvdCPEMaxPagesPerComponent)
	}
	if l.uncacheable != true {
		t.Errorf("a truncated CPE answer was cacheable")
	}
}

func TestM60CPEBudget_KeywordPathKeepsItsBudget(t *testing.T) {
	pager := &cannedNVDPager{total: 7059}
	svc := NewNVDService(nil, nil, "", pager.start(t).URL, false)
	res, err := svc.searchByKeyword(context.Background(), "linux", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.truncated || res.pages != nvdMaxPagesPerComponent || res.fetched != 996 {
		t.Errorf("keyword walk: truncated=%v pages=%d fetched=%d, want true / %d / 996",
			res.truncated, res.pages, res.fetched, nvdMaxPagesPerComponent)
	}
}
