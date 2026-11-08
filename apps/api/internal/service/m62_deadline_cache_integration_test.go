//go:build integration

// M62 — a scan cut off by its deadline must not cache a partial answer as
// complete, against a real Redis cache.
//
//	cd apps/api && REDIS_URL=redis://localhost:6379 go test -tags=integration -count=1 -run M62 ./internal/service
package service

import (
	"context"
	"testing"
	"time"

	"github.com/sbomhub/sbomhub/internal/cache"
)

// A CPE walk the deadline cuts off between pages keeps its verified pages as a
// TRUNCATED answer, and neither the answer nor an "unknown product" marker is
// cached: the next scan re-walks instead of being served a partial answer.
func TestM62NVDCache_DeadlineMidWalkCachesNothing(t *testing.T) {
	rdb := m55RedisOrSkip(t)
	nvdCache := cache.NewNVDCache(rdb)
	item := m60PlainItem(t)
	var names []string
	for _, c := range item.candidates {
		names = append(names, nvdCPECacheName(c), nvdNoCPECacheName(c))
	}
	names = append(names, nvdCacheName(item.key.Name, item.key.Version))
	m60CacheCleanup(t, nvdCache, names...)

	pager := &cannedNVDPager{total: 7059}
	svc := NewNVDServiceWithCache(nil, nil, "", nvdCache, pager.start(t).URL, false)
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
	l, err := svc.lookupComponent(ctx, item, pace)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !l.truncated {
		t.Fatalf("a walk cut off by the deadline was not reported truncated")
	}
	for _, n := range names {
		if e, err := nvdCache.Get(context.Background(), n, ""); err == nil && e != nil {
			t.Errorf("cache entry %q was written for a walk the deadline cut off", n)
		}
	}
}

// A whole sweep cut off by the deadline: the item it interrupted mid-request
// leaves no cache entry either (keyword path).
func TestM62NVDCache_DeadlineMidRequestCachesNothing(t *testing.T) {
	rdb := m55RedisOrSkip(t)
	nvdCache := cache.NewNVDCache(rdb)
	names := []string{nvdCacheName("slow-a", "1.0.0")}
	m60CacheCleanup(t, nvdCache, names...)

	svc := NewNVDServiceWithCache(nil, nil, "k", nvdCache, m62BlockingNVD(t).URL, false)
	svc.paceInterval = time.Millisecond
	ctx, cancel := WithScanDeadline(context.Background(), 300*time.Millisecond)
	defer cancel()
	rep := svc.fetchComponents(ctx, m62KeywordItems("slow-a"), (&m62Collect{}).on)
	if !rep.DeadlineExceeded {
		t.Fatalf("deadline not reported: %+v", rep)
	}
	if e, err := nvdCache.Get(context.Background(), names[0], ""); err == nil && e != nil {
		t.Errorf("cache entry written for a lookup the deadline interrupted")
	}
}
