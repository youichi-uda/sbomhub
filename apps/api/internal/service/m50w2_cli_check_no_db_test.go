package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestM50W2CheckVulnerabilitiesTouchesNoRepository pins the one claim that lets
// POST /api/v1/cli/check stay reachable by a project-scoped API key.
//
// middleware/project_scope.go classifies that route scopeNoProjectResource with
// the reason "stateless OSV lookup over components supplied in the request body;
// CLIService.CheckVulnerabilities issues no SQL and persists nothing". Codex
// round 6 correctly objected that the original evidence for this — no repository
// identifier appears in the function body — is not a proof: a helper called from
// it could reach a repository without naming one at the call site.
//
// This is the proof. The service is constructed with all three repositories nil,
// so ANY repository access on this path dereferences a nil *sql.DB inside
// ProjectRepository.q / SbomRepository.q / ComponentRepository.q and panics. The
// call completing normally is therefore an observation that no repository was
// touched, transitively, not an argument that none was named.
//
// Offline mode is deliberately NOT used: it short-circuits before the OSV query
// and would make the test pass without exercising the real path. A local
// httptest OSV stand-in keeps the whole body live.
func TestM50W2CheckVulnerabilitiesTouchesNoRepository(t *testing.T) {
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// One result set per query, with one vulnerability, so the response
		// walk, severity mapping and result assembly all run.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{{
				"vulns": []map[string]any{{
					"id":      "GHSA-m50w2-test",
					"summary": "seeded by TestM50W2CheckVulnerabilitiesTouchesNoRepository",
					"database_specific": map[string]any{
						"severity": "HIGH",
					},
				}},
			}},
		})
	}))
	defer osv.Close()

	// All three repositories nil: any query panics rather than silently working.
	svc := NewCLIService(nil, nil, nil).WithOSVBaseURL(osv.URL).WithOffline(false)

	res, err := svc.CheckVulnerabilities(context.Background(), []CLIComponentInput{{
		Name:      "libm50w2",
		Version:   "1.0.0",
		Ecosystem: "Go",
	}})
	if err != nil {
		t.Fatalf("CheckVulnerabilities with nil repositories returned an error: %v.\n"+
			"If this is a nil-pointer panic surfaced as an error, the route's "+
			"scopeNoProjectResource classification in middleware/project_scope.go is "+
			"wrong and a project-scoped key is being let through to tenant data.", err)
	}
	if res == nil {
		t.Fatal("CheckVulnerabilities returned a nil result")
	}
	if res.TotalComponents != 1 {
		t.Errorf("TotalComponents = %d, want 1 (the OSV path must actually have run, "+
			"otherwise this test proves nothing)", res.TotalComponents)
	}
	if res.TotalVulns != 1 {
		t.Errorf("TotalVulns = %d, want 1 (the stub returned one vulnerability; a zero "+
			"here means the response walk was skipped)", res.TotalVulns)
	}
}

// TestM50W2CheckVulnerabilitiesPairsResultsWithComponentsByIndex pins the
// behaviour of the OSV result loop across the M50 W2 rewrite of its bounds.
//
// The loop used to be `for i, r := range osvResp.Results { if i >= len(components)
// { break }; comp := components[i] }` and is now
// `for i := 0; i < len(osvResp.Results) && i < len(components); i++`. The rewrite
// is meant to be behaviour-preserving — it moves both bounds into the loop
// condition so gosec's G602 analysis can see that the index is within both
// slices — but "meant to be" is not a property, so this test states the two
// behaviours that could have changed:
//
//  1. PAIRING: OSV answers one result per query in submission order, so result i
//     describes component i. A vulnerability reported for result 1 must be
//     attributed to component 1, not component 0.
//  2. TRUNCATION: iteration stops at whichever slice runs out first, in both
//     directions, without panicking.
func TestM50W2CheckVulnerabilitiesPairsResultsWithComponentsByIndex(t *testing.T) {
	// Serve one distinctly-identifiable vulnerability per result slot.
	newOSV := func(resultCount int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			results := make([]map[string]any, 0, resultCount)
			for i := 0; i < resultCount; i++ {
				results = append(results, map[string]any{
					"vulns": []map[string]any{{
						"id":                "OSV-SLOT-" + string(rune('A'+i)),
						"database_specific": map[string]any{"severity": "HIGH"},
					}},
				})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
		}))
	}

	comps := func(n int) []CLIComponentInput {
		out := make([]CLIComponentInput, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, CLIComponentInput{
				Name:      "comp-" + string(rune('a'+i)),
				Version:   "1.0.0",
				Ecosystem: "Go",
			})
		}
		return out
	}

	for _, tc := range []struct {
		name          string
		components    int
		osvResults    int
		wantVulns     int
		wantPairs     map[string]string // vuln id -> component name
		wantAbsentIDs []string
	}{
		{
			name: "equal lengths pair index-for-index", components: 3, osvResults: 3, wantVulns: 3,
			wantPairs: map[string]string{
				"OSV-SLOT-A": "comp-a", "OSV-SLOT-B": "comp-b", "OSV-SLOT-C": "comp-c",
			},
		},
		{
			name: "more OSV results than components truncates at components", components: 2, osvResults: 4, wantVulns: 2,
			wantPairs: map[string]string{
				"OSV-SLOT-A": "comp-a", "OSV-SLOT-B": "comp-b",
			},
			wantAbsentIDs: []string{"OSV-SLOT-C", "OSV-SLOT-D"},
		},
		{
			name: "fewer OSV results than components truncates at results", components: 4, osvResults: 2, wantVulns: 2,
			wantPairs: map[string]string{
				"OSV-SLOT-A": "comp-a", "OSV-SLOT-B": "comp-b",
			},
			wantAbsentIDs: []string{"OSV-SLOT-C", "OSV-SLOT-D"},
		},
		{
			name: "no OSV results at all", components: 3, osvResults: 0, wantVulns: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			osv := newOSV(tc.osvResults)
			defer osv.Close()
			svc := NewCLIService(nil, nil, nil).WithOSVBaseURL(osv.URL).WithOffline(false)

			res, err := svc.CheckVulnerabilities(context.Background(), comps(tc.components))
			if err != nil {
				t.Fatalf("CheckVulnerabilities: %v", err)
			}
			if res.TotalVulns != tc.wantVulns {
				t.Errorf("TotalVulns = %d, want %d", res.TotalVulns, tc.wantVulns)
			}
			got := map[string]string{}
			for _, v := range res.Vulnerabilities {
				got[v.ID] = v.Package
			}
			for id, wantComp := range tc.wantPairs {
				if got[id] != wantComp {
					t.Errorf("vulnerability %s attributed to package %q, want %q — the "+
						"result/component pairing is off by index", id, got[id], wantComp)
				}
			}
			for _, id := range tc.wantAbsentIDs {
				if _, present := got[id]; present {
					t.Errorf("vulnerability %s was reported, but its result slot is beyond "+
						"the shorter of the two slices — the loop over-ran", id)
				}
			}
		})
	}
}
