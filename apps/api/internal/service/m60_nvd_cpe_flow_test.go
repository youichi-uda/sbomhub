package service

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

// replayNVD serves the recorded live NVD responses (testdata/m60/nvd) keyed by
// the ONE search parameter of each request, and records every request.
type replayNVD struct {
	t      *testing.T
	routes map[string]string // "cpeName=<v>" / "virtualMatchString=<v>" / "keywordSearch=<v>" -> fixture
	fail   map[string]int    // same keys -> HTTP status to fail with
	mu     sync.Mutex
	seen   []string
}

const m60EmptyNVD = `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"format":"NVD_CVE","version":"2.0","timestamp":"2026-11-08T07:11:41.000","vulnerabilities":[]}`

func (r *replayNVD) start() *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		var key string
		for _, p := range []string{"cpeName", "virtualMatchString", "keywordSearch"} {
			if v := q.Get(p); v != "" {
				key = p + "=" + v
			}
		}
		r.mu.Lock()
		r.seen = append(r.seen, key)
		r.mu.Unlock()
		if code, ok := r.fail[key]; ok {
			http.Error(w, "boom", code)
			return
		}
		name, ok := r.routes[key]
		if !ok {
			// Unknown query: NVD's real answer for a product/keyword it has
			// nothing for (measured shape, 146 bytes).
			_, _ = io.WriteString(w, m60EmptyNVD)
			return
		}
		f, err := os.Open(filepath.Join("testdata", "m60", "nvd", name+".json.gz"))
		if err != nil {
			r.t.Errorf("fixture %s: %v", name, err)
			http.Error(w, err.Error(), 500)
			return
		}
		defer f.Close()
		zr, err := gzip.NewReader(f)
		if err != nil {
			r.t.Errorf("gunzip %s: %v", name, err)
			return
		}
		_, _ = io.Copy(w, zr)
	}))
	r.t.Cleanup(srv.Close)
	return srv
}

func (r *replayNVD) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func m60Item(t *testing.T, name string) nvdWorkItem {
	t.Helper()
	comps, err := parseCycloneDX(m60Fixture(t, "syft.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := m60Find(t, comps, name)
	return nvdWorkItem{
		key:        nvdComponentKey{Name: c.Name, Version: c.Version, CPEKey: nvdCPEKey(c.CPEs), Distro: isDistroComponent(c.Purl)},
		candidates: cpeCandidates(c.CPEs, c.Version, c.Purl),
		distro:     isDistroComponent(c.Purl),
	}
}

func m60IDs(l nvdLookup) []string {
	var ids []string
	for _, v := range l.vulns {
		ids = append(ids, v.CVEID)
	}
	sort.Strings(ids)
	return ids
}

type countingPacer struct{ n int }

func (p *countingPacer) pace(ctx context.Context) error { p.n++; return ctx.Err() }

// log4j-core 2.14.1 from Syft: the first two candidates name products NVD
// does not know (measured: cpeName and the product probe both answer 0), the
// third is NVD's product. Before M60 the keyword search for "log4j-core
// 2.14.1" answered 0 records — Log4Shell was never linked.
func TestM60Lookup_Log4jCoreReachesNVDProductThroughThirdCandidate(t *testing.T) {
	r := &replayNVD{t: t, routes: map[string]string{
		"cpeName=cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*": "p01_cpename_log4j",
	}}
	srv := r.start()
	svc := NewNVDService(nil, nil, "", srv.URL, false)
	p := &countingPacer{}

	l, err := svc.lookupComponent(context.Background(), m60Item(t, "log4j-core"), p.pace)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if l.method != model.MatchNVDCPE {
		t.Errorf("method = %q, want nvd_cpe", l.method)
	}
	ids := m60IDs(l)
	for _, want := range []string{"CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832"} {
		if i := sort.SearchStrings(ids, want); i >= len(ids) || ids[i] != want {
			t.Errorf("missing %s in %v", want, ids)
		}
	}
	if len(ids) != 10 {
		t.Errorf("got %d CVEs, want the 10 NVD returned (all verified)", len(ids))
	}
	wantReqs := []string{
		"cpeName=cpe:2.3:a:apache:log4j-core:2.14.1:*:*:*:*:*:*:*",
		"virtualMatchString=cpe:2.3:a:apache:log4j-core",
		"cpeName=cpe:2.3:a:apache:log4j_core:2.14.1:*:*:*:*:*:*:*",
		"virtualMatchString=cpe:2.3:a:apache:log4j_core",
		"cpeName=cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
	}
	if got := r.requests(); strings.Join(got, "\n") != strings.Join(wantReqs, "\n") {
		t.Errorf("requests =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(wantReqs, "\n"))
	}
	if l.requests != 5 {
		t.Errorf("requests accounted = %d, want 5", l.requests)
	}
	// The worker paid for the first request; the other four each take a tick.
	if p.n != 4 {
		t.Errorf("pacer ticks = %d, want 4 (one per request after the item's first)", p.n)
	}
}

// Debian openssl 1.1.1k-1: matched on the upstream version, labelled
// nvd_cpe_distro, and the 5 platform-only CVEs NVD returned are dropped.
func TestM60Lookup_DebianOpenSSLIsDistroLabelledAndVerified(t *testing.T) {
	r := &replayNVD{t: t, routes: map[string]string{
		"cpeName=cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*": "p06_cpename_openssl",
	}}
	svc := NewNVDService(nil, nil, "", r.start().URL, false)
	l, err := svc.lookupComponent(context.Background(), m60Item(t, "openssl"), nil)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if l.method != model.MatchNVDCPEDistro {
		t.Errorf("method = %q, want nvd_cpe_distro", l.method)
	}
	if len(l.vulns) != 42 || l.cpeRejected != 5 || l.cpeUndecidable != 0 {
		t.Errorf("kept=%d rejected=%d undecidable=%d, want 42/5/0", len(l.vulns), l.cpeRejected, l.cpeUndecidable)
	}
	for _, v := range l.vulns {
		if v.CVEID == "CVE-2009-1390" || v.CVEID == "CVE-2019-0190" {
			t.Errorf("platform-only CVE %s was kept", v.CVEID)
		}
	}
}

// libc6 (Debian): Syft's only CPE names a product NVD has never heard of
// (measured: virtualMatchString=cpe:2.3:a:libc6:libc6 -> 0). The lookup must
// fall back to the keyword search — never report the component clean on the
// strength of a wrong CPE.
func TestM60Lookup_UnknownProductFallsBackToKeyword(t *testing.T) {
	r := &replayNVD{t: t, routes: map[string]string{
		"keywordSearch=libc6 2.31-13": "k07_libc6",
	}}
	svc := NewNVDService(nil, nil, "", r.start().URL, false)
	p := &countingPacer{}
	l, err := svc.lookupComponent(context.Background(), m60Item(t, "libc6"), p.pace)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if l.method != model.MatchNVDKeyword || !l.keywordFallback {
		t.Errorf("method=%q fallback=%v, want nvd_keyword fallback", l.method, l.keywordFallback)
	}
	got := r.requests()
	if len(got) != 3 || got[2] != "keywordSearch=libc6 2.31-13" {
		t.Errorf("requests = %q", got)
	}
	if p.n != 2 || l.requests != 3 {
		t.Errorf("ticks=%d requests=%d, want 2 / 3", p.n, l.requests)
	}
}

// A known product whose version is unaffected: cpeName answers 0, the probe
// says the product exists, and that is a FINAL verified "none" — no keyword
// request, links labelled nvd_cpe.
func TestM60Lookup_KnownProductUnaffectedVersionIsFinal(t *testing.T) {
	r := &replayNVD{t: t, routes: map[string]string{
		"virtualMatchString=cpe:2.3:a:apache:log4j": "p03_vms_log4j",
	}}
	svc := NewNVDService(nil, nil, "", r.start().URL, false)
	item := nvdWorkItem{
		key:        nvdComponentKey{Name: "log4j-core", Version: "2.25.3"},
		candidates: cpeCandidates([]string{"cpe:2.3:a:apache:log4j:2.25.3:*:*:*:*:*:*:*"}, "2.25.3", ""),
	}
	l, err := svc.lookupComponent(context.Background(), item, nil)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if l.method != model.MatchNVDCPE || len(l.vulns) != 0 {
		t.Errorf("method=%q vulns=%d, want nvd_cpe / 0", l.method, len(l.vulns))
	}
	for _, q := range r.requests() {
		if strings.HasPrefix(q, "keywordSearch=") {
			t.Errorf("keyword fallback issued for a known product: %q", q)
		}
	}
}

// A failure on ANY CPE request is a failed lookup. In particular a failed
// product probe must not be read as "unknown product" (which would route to
// the keyword path and report a CPE-matchable component as keyword-only, or
// clean).
func TestM60Lookup_ProbeFailureIsAFetchFailureNotAFallback(t *testing.T) {
	for _, failing := range []string{
		"cpeName=cpe:2.3:a:apache:log4j:2.25.3:*:*:*:*:*:*:*",
		"virtualMatchString=cpe:2.3:a:apache:log4j",
	} {
		r := &replayNVD{t: t, fail: map[string]int{failing: http.StatusServiceUnavailable}}
		svc := NewNVDService(nil, nil, "", r.start().URL, false)
		item := nvdWorkItem{
			key:        nvdComponentKey{Name: "log4j-core", Version: "2.25.3"},
			candidates: cpeCandidates([]string{"cpe:2.3:a:apache:log4j:2.25.3:*:*:*:*:*:*:*"}, "2.25.3", ""),
		}
		l, err := svc.lookupComponent(context.Background(), item, nil)
		if err == nil {
			t.Errorf("%s failing: lookup returned nil error (method %q, %d vulns)", failing, l.method, len(l.vulns))
		}
		for _, q := range r.requests() {
			if strings.HasPrefix(q, "keywordSearch=") {
				t.Errorf("%s failing: fell back to keyword", failing)
			}
		}
		if l.requests != len(r.requests()) {
			t.Errorf("%s failing: accounted %d requests, issued %d", failing, l.requests, len(r.requests()))
		}
	}
}

// Components without any CPE keep the pre-M60 behaviour exactly: one keyword
// walk, no CPE request, labelled nvd_keyword (not a fallback).
func TestM60Lookup_NoCPEIsKeywordOnly(t *testing.T) {
	r := &replayNVD{t: t, routes: map[string]string{"keywordSearch=glibc 2.31": "k10_glibc"}}
	svc := NewNVDService(nil, nil, "", r.start().URL, false)
	l, err := svc.lookupComponent(context.Background(), nvdWorkItem{key: nvdComponentKey{Name: "glibc", Version: "2.31"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if l.method != model.MatchNVDKeyword || l.keywordFallback || len(l.vulns) != 3 {
		t.Errorf("method=%q fallback=%v vulns=%d, want nvd_keyword/false/3", l.method, l.keywordFallback, len(l.vulns))
	}
	if got := r.requests(); len(got) != 1 {
		t.Errorf("requests = %q, want exactly the keyword walk", got)
	}
}
