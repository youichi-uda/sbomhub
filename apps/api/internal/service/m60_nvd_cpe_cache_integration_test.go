//go:build integration

// M60 — the CPE path against a real Redis cache.
//
//	cd apps/api && REDIS_URL=redis://localhost:6379 go test -tags=integration -count=1 -run M60 ./internal/service
package service

import (
	"context"
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/cache"
	"github.com/sbomhub/sbomhub/internal/model"
)

func m60CacheCleanup(t *testing.T, nvdCache *cache.NVDCache, names ...string) {
	t.Helper()
	for _, n := range names {
		_ = nvdCache.Delete(context.Background(), n, "")
	}
	t.Cleanup(func() {
		for _, n := range names {
			_ = nvdCache.Delete(context.Background(), n, "")
		}
	})
}

// The verified answer and the "unknown product" marker are both served from
// the cache on the next scan: no request for a known-good candidate, and the
// unknown candidates of log4j-core cost nothing the second time.
func TestM60NVDCache_SecondLookupIsServedFromCache(t *testing.T) {
	rdb := m55RedisOrSkip(t)
	nvdCache := cache.NewNVDCache(rdb)
	item := m60Item(t, "log4j-core")
	var names []string
	for _, c := range item.candidates {
		names = append(names, nvdCPECacheName(c), nvdNoCPECacheName(c))
	}
	m60CacheCleanup(t, nvdCache, names...)

	r := &replayNVD{t: t, routes: map[string]string{
		"cpeName=cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*": "p01_cpename_log4j",
	}}
	svc := NewNVDServiceWithCache(nil, nil, "", nvdCache, r.start().URL, false)

	first, err := svc.lookupComponent(context.Background(), item, nil)
	if err != nil || first.requests != 5 || first.fromCache {
		t.Fatalf("first lookup: requests=%d fromCache=%v err=%v", first.requests, first.fromCache, err)
	}
	second, err := svc.lookupComponent(context.Background(), item, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.requests != 0 || !second.fromCache || len(second.vulns) != len(first.vulns) || second.method != model.MatchNVDCPE {
		t.Errorf("second lookup: requests=%d fromCache=%v vulns=%d/%d method=%q",
			second.requests, second.fromCache, len(second.vulns), len(first.vulns), second.method)
	}
	// M67: the CVSS version the network answer chose survives the cache, so
	// a row created from a CPE-path cache hit carries it like any other.
	versions := map[string]string{}
	for _, v := range first.vulns {
		if v.CVSSVersion != nil {
			versions[v.CVEID] = *v.CVSSVersion
		}
	}
	if len(versions) == 0 {
		t.Fatal("fixture yields no CVSS version on the network path")
	}
	for _, v := range second.vulns {
		want, ok := versions[v.CVEID]
		if !ok {
			continue
		}
		if v.CVSSVersion == nil || *v.CVSSVersion != want {
			t.Errorf("%s from cache: cvss_version=%v, want %q", v.CVEID, v.CVSSVersion, want)
		}
	}
}

// Codex M60 R4 Low: a lookup that SPENT requests (an unknown candidate probed
// over the network) and then got its answer from the cache is not a cache
// hit — NVDScanReport.CacheHits promises "no HTTP request".
func TestM60NVDCache_MixedNetworkAndCacheIsNotACacheHit(t *testing.T) {
	rdb := m55RedisOrSkip(t)
	nvdCache := cache.NewNVDCache(rdb)
	item := nvdWorkItem{
		key: nvdComponentKey{Name: "log4j-core", Version: "2.14.1"},
		candidates: cpeCandidates([]string{
			"cpe:2.3:a:apache:log4j-core:2.14.1:*:*:*:*:*:*:*", // unknown -> 2 requests
			"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",      // pre-cached below
		}, "2.14.1", ""),
	}
	var names []string
	for _, c := range item.candidates {
		names = append(names, nvdCPECacheName(c), nvdNoCPECacheName(c))
	}
	m60CacheCleanup(t, nvdCache, names...)
	if err := nvdCache.Set(context.Background(), nvdCPECacheName(item.candidates[1]), "",
		[]cache.CachedVuln{{CVEID: "CVE-2021-44228", Severity: "CRITICAL"}}); err != nil {
		t.Fatal(err)
	}

	r := &replayNVD{t: t}
	svc := NewNVDServiceWithCache(nil, nil, "", nvdCache, r.start().URL, false)
	l, err := svc.lookupComponent(context.Background(), item, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.requests(), "|"); l.requests != 2 || !strings.Contains(got, "log4j-core") {
		t.Fatalf("requests=%d (%s), want the 2 probes of the unknown candidate", l.requests, got)
	}
	if l.fromCache {
		t.Errorf("lookup that issued %d request(s) reported as a cache hit", l.requests)
	}
}
