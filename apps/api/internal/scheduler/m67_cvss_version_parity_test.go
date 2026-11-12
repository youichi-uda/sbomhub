package scheduler

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sbomhub/sbomhub/internal/service"
)

// m67Fixture reads one of the LIVE NVD responses recorded for M60
// (service/testdata/m60/nvd, recorded 2026-11-08). These are the only recorded
// fixtures that carry cvssMetricV40, always beside a cvssMetricV31.
func m67Fixture(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "service", "testdata", "m60", "nvd", name+".json.gz"))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gunzip %s: %v", name, err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

// TestM67_SyncAndScannerStoreTheSameCVSS (M67). The daily CVE sync (which the
// monthly reconcile shares) and the NVD scanner / search parse the same NVD
// record through different code. Before M67 they disagreed on which CVSS
// version wins: the sync took v4.0 first and the scanner v3.x, so on the
// recorded fixture CVE-2026-34479 (v3.1 Primary 7.5 HIGH, v4.0 Secondary 6.9
// MEDIUM) the stored severity flipped between HIGH and MEDIUM depending on
// which path wrote the row last.
//
// Both paths are driven through their real decoders: the sync through
// fetchModifiedCVEs against the recorded page, the scanner's converter through
// NVDService.SearchByCVEID against a one-record answer cut from the same page.
func TestM67_SyncAndScannerStoreTheSameCVSS(t *testing.T) {
	type rec struct {
		CVE struct {
			ID      string `json:"id"`
			Metrics struct {
				V31 json.RawMessage `json:"cvssMetricV31"`
				V40 json.RawMessage `json:"cvssMetricV40"`
			} `json:"metrics"`
		} `json:"cve"`
	}
	checkedBoth := 0
	for _, name := range []string{"p01_cpename_log4j", "v02_vms_log4j", "p11_cpename_lodash_node"} {
		t.Run(name, func(t *testing.T) {
			body := m67Fixture(t, name)
			var page struct {
				Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
			}
			if err := json.Unmarshal(body, &page); err != nil {
				t.Fatal(err)
			}
			byID := map[string]json.RawMessage{}
			hasBoth := map[string]bool{}
			for _, raw := range page.Vulnerabilities {
				var r rec
				if err := json.Unmarshal(raw, &r); err != nil {
					t.Fatal(err)
				}
				byID[r.CVE.ID] = raw
				hasBoth[r.CVE.ID] = len(r.CVE.Metrics.V31) > 0 && len(r.CVE.Metrics.V40) > 0
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if id := req.URL.Query().Get("cveId"); id != "" {
					raw, ok := byID[id]
					if !ok {
						_, _ = io.WriteString(w, `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"format":"NVD_CVE","version":"2.0","timestamp":"2026-11-08T07:11:41.000","vulnerabilities":[]}`)
						return
					}
					_, _ = io.WriteString(w, `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"format":"NVD_CVE","version":"2.0","timestamp":"2026-11-08T07:11:41.000","vulnerabilities":[`+string(raw)+`]}`)
					return
				}
				_, _ = w.Write(body)
			}))
			defer srv.Close()

			j := NewCVESyncJob(nil, nil, "", 24*time.Hour, nil, srv.URL, false)
			synced, err := j.fetchModifiedCVEs(context.Background(), time.Now().Add(-24*time.Hour))
			if err != nil {
				t.Fatalf("fetchModifiedCVEs: %v", err)
			}
			if len(synced) != len(byID) {
				t.Fatalf("sync read %d records, the fixture holds %d", len(synced), len(byID))
			}
			nvd := service.NewNVDService(nil, nil, "", srv.URL, false)
			for _, s := range synced {
				v, err := nvd.SearchByCVEID(context.Background(), s.ID)
				if err != nil || v == nil {
					t.Fatalf("SearchByCVEID(%s) = %v, %v", s.ID, v, err)
				}
				if s.Severity != v.Severity || !sameFloat(s.CVSSScore, v.CVSSScore) || !sameStr(s.CVSSVersion, v.CVSSVersion) {
					t.Errorf("%s: sync stores %s/%v/v%s, scanner stores %s/%v/v%s",
						s.ID, s.Severity, deref(s.CVSSScore), derefS(s.CVSSVersion),
						v.Severity, deref(v.CVSSScore), derefS(v.CVSSVersion))
				}
				if hasBoth[s.ID] {
					checkedBoth++
					if derefS(s.CVSSVersion) != "3.1" {
						t.Errorf("%s carries v3.1 and v4.0; the sync stored v%s, want v3.1", s.ID, derefS(s.CVSSVersion))
					}
				}
				if s.ID == "CVE-2026-34479" && (s.Severity != "HIGH" || deref(s.CVSSScore) != 7.5) {
					t.Errorf("CVE-2026-34479: sync stores %s/%v, want NVD's v3.1 Primary HIGH/7.5", s.Severity, deref(s.CVSSScore))
				}
			}
		})
	}
	if checkedBoth == 0 {
		t.Fatal("no fixture record carried both v3.1 and v4.0; the parity check proved nothing")
	}
}

func sameFloat(a, b *float64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func sameStr(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func deref(p *float64) any {
	if p == nil {
		return "nil"
	}
	return *p
}

func derefS(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// TestM67CVESync_MissingBaseScoreIsNotZero (Codex M67 R3, High): the sync
// decodes NVD metrics through service.NVDMetrics too, so an empty v3.1 entry
// must not outrank a valid v4.0 9.8 CRITICAL here either.
func TestM67CVESync_MissingBaseScoreIsNotZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"totalResults": 1, "startIndex": 0, "resultsPerPage": 2000,
			"vulnerabilities": [{"cve": {"id": "CVE-2026-0002",
				"published": "2026-01-01T00:00:00.000", "lastModified": "2026-07-01T00:00:00.000",
				"descriptions": [{"lang": "en", "value": "x"}],
				"metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": null}}, {"type": "Secondary"}],
				            "cvssMetricV40": [{"type": "Secondary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
				"configurations": []}}]}`)
	}))
	defer srv.Close()
	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, nil, srv.URL, false)
	cves, err := j.fetchModifiedCVEs(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil || len(cves) != 1 {
		t.Fatalf("fetchModifiedCVEs = %v, %v", cves, err)
	}
	if c := cves[0]; c.Severity != "CRITICAL" || deref(c.CVSSScore) != 9.8 || derefS(c.CVSSVersion) != "4.0" {
		t.Errorf("sync extracted %s/%v/v%s, want CRITICAL/9.8/v4.0", c.Severity, deref(c.CVSSScore), derefS(c.CVSSVersion))
	}
}

// TestM67CVESync_V2MetricLevelSeverity (Codex M67 R4, Medium): the sync's
// decode path reads NVD's metric-level v2 baseSeverity too.
func TestM67CVESync_V2MetricLevelSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"totalResults": 1, "startIndex": 0, "resultsPerPage": 2000,
			"vulnerabilities": [{"cve": {"id": "CVE-2026-0003",
				"published": "2026-01-01T00:00:00.000", "lastModified": "2026-07-01T00:00:00.000",
				"descriptions": [{"lang": "en", "value": "x"}],
				"metrics": {"cvssMetricV2": [{"type": "Primary", "cvssData": {"version": "2.0", "baseScore": null}, "baseSeverity": "HIGH"}]},
				"configurations": []}}]}`)
	}))
	defer srv.Close()
	j := NewCVESyncJob(nil, nil, "", 24*time.Hour, nil, srv.URL, false)
	cves, err := j.fetchModifiedCVEs(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil || len(cves) != 1 {
		t.Fatalf("fetchModifiedCVEs = %v, %v", cves, err)
	}
	if c := cves[0]; c.Severity != "HIGH" || c.CVSSScore != nil || derefS(c.CVSSVersion) != "2.0" {
		t.Errorf("sync extracted %s/%v/v%s, want HIGH/nil/v2.0", c.Severity, deref(c.CVSSScore), derefS(c.CVSSVersion))
	}
}

// m67Page1 is one NVD page holding a single scored record.
const m67Page1 = `{"totalResults": 1, "startIndex": 0, "resultsPerPage": 2000,
	"vulnerabilities": [{"cve": {"id": "CVE-2026-0004",
		"published": "2026-01-01T00:00:00.000", "lastModified": "2026-07-01T00:00:00.000",
		"descriptions": [{"lang": "en", "value": "x"}],
		"metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
		"configurations": []}}]}`

// TestM67CVESync_CanonicalProvenanceIsPerResponse (Codex M67 R8, High). The
// equal-timestamp re-derivation may only use a record that really came from
// NVD. The configured URL alone does not establish that: the client honours
// HTTPS_PROXY (a caching proxy can serve a stale body) and follows redirects.
// Each page is therefore marked canonical only when the request was not
// routed through a proxy and the final URL is still the canonical endpoint.
func TestM67CVESync_CanonicalProvenanceIsPerResponse(t *testing.T) {
	serve := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, m67Page1)
	}
	canonicalOf := func(t *testing.T, j *CVESyncJob) bool {
		t.Helper()
		cves, err := j.fetchModifiedCVEs(context.Background(), time.Now().Add(-24*time.Hour))
		if err != nil || len(cves) != 1 {
			t.Fatalf("fetchModifiedCVEs = %v, %v", cves, err)
		}
		return cves[0].Canonical
	}

	nvd := httptest.NewServer(http.HandlerFunc(serve))
	defer nvd.Close()

	t.Run("direct to the canonical endpoint", func(t *testing.T) {
		j := NewCVESyncJob(nil, nil, "", time.Hour, nil, nvd.URL, false)
		j.canonicalEndpoint, _ = url.Parse(nvd.URL) // stands in for services.nvd.nist.gov
		if !canonicalOf(t, j) {
			t.Error("a direct answer from the canonical endpoint was not marked canonical")
		}
	})
	t.Run("a mirror URL", func(t *testing.T) {
		j := NewCVESyncJob(nil, nil, "", time.Hour, nil, nvd.URL, false)
		if canonicalOf(t, j) {
			t.Error("a mirror's answer was marked canonical")
		}
	})
	t.Run("through a proxy", func(t *testing.T) {
		proxy := httptest.NewServer(http.HandlerFunc(serve)) // a caching proxy answering itself
		defer proxy.Close()
		proxyURL, _ := url.Parse(proxy.URL)
		j := NewCVESyncJob(nil, nil, "", time.Hour, nil, nvd.URL, false)
		j.canonicalEndpoint, _ = url.Parse(nvd.URL)
		j.httpClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
		if canonicalOf(t, j) {
			t.Error("an answer routed through a proxy was marked canonical")
		}
	})
	t.Run("redirected away", func(t *testing.T) {
		other := httptest.NewServer(http.HandlerFunc(serve))
		defer other.Close()
		redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"?"+r.URL.RawQuery, http.StatusFound)
		}))
		defer redirect.Close()
		j := NewCVESyncJob(nil, nil, "", time.Hour, nil, redirect.URL, false)
		j.canonicalEndpoint, _ = url.Parse(redirect.URL)
		if canonicalOf(t, j) {
			t.Error("an answer that was redirected to another host was marked canonical")
		}
	})
	t.Run("an unknown transport", func(t *testing.T) {
		j := NewCVESyncJob(nil, nil, "", time.Hour, nil, nvd.URL, false)
		j.canonicalEndpoint, _ = url.Parse(nvd.URL)
		j.httpClient = &http.Client{Transport: roundTripFunc(http.DefaultTransport.RoundTrip)}
		if canonicalOf(t, j) {
			t.Error("an answer through a transport whose proxy use cannot be inspected was marked canonical")
		}
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
