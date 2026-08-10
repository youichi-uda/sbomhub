//go:build integration

// Package service — M55: the Redis result cache must not launder a truncated
// NVD lookup into a complete-looking one.
//
// Run with:
//
//	cd apps/api && REDIS_URL=redis://localhost:6379 \
//	    go test -tags=integration -count=1 -run M55NVDCache ./internal/service
//
// # The hole this closes
//
// cache.VulnCacheEntry has no field for "this is a PREFIX of the match set",
// and getVulnerabilitiesWithCache returns a cache hit before searchByKeyword is
// ever reached. So if a truncated lookup were cached, the truncation signal
// would survive exactly ONE scan: the scan that fetched it would report the
// component as truncated, and every scan for the next cache.NVDCacheTTL (24h)
// would serve the same short list, see no truncation, and report the whole
// sweep as complete.
//
// That is worse than not detecting truncation at all, because it is
// intermittent: the same SBOM would fail one scan and pass the next with
// identical data.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/sbomhub/sbomhub/internal/cache"
)

func m55RedisOrSkip(t *testing.T) *redis.Client {
	t.Helper()
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("M55 NVD cache integration test requires REDIS_URL " +
			"(e.g. redis://localhost:6379). Run redis, then re-run with -tags=integration.")
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("parse REDIS_URL %q: %v", url, err)
	}
	c := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		_ = c.Close()
		t.Skipf("redis unreachable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// m55CachePager is the same measured-shape canned NVD endpoint as
// cannedNVDPager, kept separate so the unit-test file stays free of the redis
// import.
func m55CachePager(t *testing.T, total int) (*httptest.Server, func() int) {
	t.Helper()
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		rpp, _ := strconv.Atoi(r.URL.Query().Get("resultsPerPage"))
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		n := rpp
		if start+n > total {
			n = total - start
		}
		if n < 0 {
			n = 0
		}
		entries := make([]NVDVulnEntry, 0, n)
		for i := 0; i < n; i++ {
			entries = append(entries, NVDVulnEntry{CVE: NVDCVE{
				ID:           fmt.Sprintf("CVE-2093-%07d", start+i),
				Published:    "2093-01-01T00:00:00.000",
				Descriptions: []NVDDesc{{Lang: "en", Value: "m55 cache probe"}},
			}})
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(NVDResponse{
			ResultsPerPage:  nvdIntPtr(len(entries)),
			StartIndex:      nvdIntPtr(start),
			TotalResults:    nvdIntPtr(total),
			Vulnerabilities: nvdEntriesPtr(entries),
		}); err != nil {
			t.Errorf("encode canned NVD page: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() int { return requests }
}

func TestM55NVDCache_TruncatedLookupsAreNotCached(t *testing.T) {
	rdb := m55RedisOrSkip(t)

	cases := []struct {
		name        string
		total       int
		wantTrunc   bool
		wantCached  bool
		secondCalls int // HTTP requests the SECOND lookup must issue
	}{
		{
			// Fits inside one page: complete, cacheable, and the second
			// lookup must not touch the network at all.
			name: "complete result is cached", total: 44,
			wantTrunc: false, wantCached: true, secondCalls: 0,
		},
		{
			// Beyond the budget: incomplete, and must be re-walked every
			// time so the truncation is re-reported every time.
			name: "truncated result is not cached", total: 21670,
			wantTrunc: true, wantCached: false, secondCalls: nvdMaxPagesPerComponent,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			name := fmt.Sprintf("m55-cache-%d-%d", tc.total, time.Now().UnixNano())
			version := "1.0"

			nvdCache := cache.NewNVDCache(rdb)
			t.Cleanup(func() {
				if err := nvdCache.Delete(ctx, nvdCacheName(name, version), ""); err != nil {
					t.Errorf("cleanup: delete cache entry: %v", err)
				}
			})

			srv, calls := m55CachePager(t, tc.total)
			svc := NewNVDServiceWithCache(nil, nil, "", nvdCache, srv.URL, false)

			first, err := svc.getVulnerabilitiesWithCache(ctx, name, version, nil)
			if err != nil {
				t.Fatalf("first lookup: %v", err)
			}
			if first.fromCache {
				t.Fatal("the first lookup was served from cache; the key was not unique")
			}
			if first.truncated != tc.wantTrunc {
				t.Fatalf("truncated = %v, want %v (total=%d)", first.truncated, tc.wantTrunc, tc.total)
			}
			before := calls()

			// Is it in Redis? Read through the same namespaced name the
			// scanner writes under (nvdCacheSchema).
			entry, err := nvdCache.Get(ctx, nvdCacheName(name, version), "")
			if err != nil {
				t.Fatalf("cache get: %v", err)
			}
			if tc.wantCached && entry == nil {
				t.Error("a COMPLETE result was not cached; every scan would re-walk it for nothing")
			}
			if !tc.wantCached && entry != nil {
				t.Fatalf("a TRUNCATED result was cached (%d entries). The cache has no field for "+
					"'this is a prefix', so the next %s of scans would serve it as a complete "+
					"answer and report no truncation at all — the signal would survive exactly "+
					"one scan.", len(entry.Vulnerabilities), cache.NVDCacheTTL)
			}

			// What does a SECOND lookup do?
			second, err := svc.getVulnerabilitiesWithCache(ctx, name, version, nil)
			if err != nil {
				t.Fatalf("second lookup: %v", err)
			}
			if got := calls() - before; got != tc.secondCalls {
				t.Errorf("second lookup issued %d requests, want %d", got, tc.secondCalls)
			}
			if second.fromCache != tc.wantCached {
				t.Errorf("second lookup fromCache = %v, want %v", second.fromCache, tc.wantCached)
			}
			if second.truncated != tc.wantTrunc {
				t.Errorf("second lookup truncated = %v, want %v — a repeated scan of the same "+
					"SBOM must reach the same conclusion about completeness",
					second.truncated, tc.wantTrunc)
			}
		})
	}
}

// TestM55NVDCache_PreM55EntriesAreNotServed is the Codex M55 R1 (High)
// regression: the upgrade path.
//
// Not caching a truncated result does nothing about the truncated results that
// are ALREADY in Redis. A pre-M55 build cached the first 20 matches of every
// component under `nvd:vuln:<name>:<version>`, and cache.VulnCacheEntry carries
// no completeness metadata — so after an upgrade (and throughout any rolling
// deployment where an older instance still writes to the same Redis) those
// 20-record prefixes would be served as complete cache hits for up to
// cache.NVDCacheTTL: no HTTP request, no page walk, no truncation, nothing
// downstream able to tell.
//
// The fix is a namespaced key (nvdCacheSchema), so this test writes an entry in
// the OLD key format and asserts the scanner does not read it.
func TestM55NVDCache_PreM55EntriesAreNotServed(t *testing.T) {
	rdb := m55RedisOrSkip(t)
	ctx := context.Background()

	name := fmt.Sprintf("m55-legacy-%d", time.Now().UnixNano())
	version := "1.0"

	// Exactly what a pre-M55 build wrote: the first 20 of 563 matches, at the
	// un-namespaced key.
	legacy := make([]cache.CachedVuln, 0, 20)
	for i := 0; i < 20; i++ {
		legacy = append(legacy, cache.CachedVuln{
			CVEID:       fmt.Sprintf("CVE-2093-%07d", i),
			Description: "pre-M55 cached prefix",
			Severity:    "HIGH",
		})
	}
	legacyCache := cache.NewNVDCache(rdb)
	if err := legacyCache.Set(ctx, name, version, legacy); err != nil {
		t.Fatalf("seed legacy cache entry: %v", err)
	}
	t.Cleanup(func() {
		if err := legacyCache.Delete(ctx, name, version); err != nil {
			t.Errorf("cleanup: delete legacy entry: %v", err)
		}
		if err := legacyCache.Delete(ctx, nvdCacheName(name, version), ""); err != nil {
			t.Errorf("cleanup: delete namespaced entry: %v", err)
		}
	})

	// Sanity: the legacy entry really is there, under the legacy key.
	if entry, err := legacyCache.Get(ctx, name, version); err != nil || entry == nil {
		t.Fatalf("precondition: legacy entry not readable (entry=%v err=%v)", entry, err)
	}

	srv, calls := m55CachePager(t, 563) // measured: keywordSearch=openssl
	svc := NewNVDServiceWithCache(nil, nil, "", cache.NewNVDCache(rdb), srv.URL, false)

	got, err := svc.getVulnerabilitiesWithCache(ctx, name, version, nil)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.fromCache {
		t.Fatal("a pre-M55 cache entry was served as a complete answer. It holds the first 20 " +
			"of 563 matches and has no field that says so, so every scan for the next 24h " +
			"would report that component as checked and clean.")
	}
	if calls() != 3 {
		t.Errorf("issued %d requests, want 3 — the lookup must fall through to a full page "+
			"walk", calls())
	}
	if len(got.vulns) != 563 {
		t.Errorf("got %d matches, want 563", len(got.vulns))
	}
}
