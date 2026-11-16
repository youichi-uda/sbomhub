package cra

// M75 — the CRA runner fills CRATemplateData.CVSSScore / CVSSVersion from
// the stored vulnerability (vulnerabilities.cvss_score / cvss_version,
// scoped to the run's tenant and project), so the "(CVSS v3.1)" label the
// templates gained in M74 actually appears in generated drafts. Only a
// canonical stored version is printed; no score, no score line.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// cvssVulnLookup answers both the CVE re-resolve and the CVSS lookup, like
// *repository.VulnerabilityRepository does in production.
type cvssVulnLookup struct {
	*fakeVulnCVE
	score   *float64
	version *string
	err     error
	calls   int
}

func (l *cvssVulnLookup) GetCVSSByIDInProject(_ context.Context, _, _, _ uuid.UUID) (*float64, *string, error) {
	l.calls++
	return l.score, l.version, l.err
}

func f64(v float64) *float64 { return &v }
func str(v string) *string   { return &v }

func runCVSS(t *testing.T, lookup *cvssVulnLookup, disabled bool, lang Lang) (*RunResult, string, error) {
	t.Helper()
	h := newTestHarness(t)
	lookup.fakeVulnCVE = okVulnCVE(h.cveID)
	var provider llm.Provider = h.provider
	if disabled {
		provider = &llm.DisabledProvider{Reason: "test"}
	}
	r := NewRunner(RunnerConfig{
		VEXDrafts:           h.drafts,
		AdvisoryExcerpts:    h.advisories,
		ReachabilityResults: h.reach,
		CRAReports:          h.craReports,
		LLMCalls:            h.llmCalls,
		VulnerabilityCVE:    lookup,
		Audit:               h.audit,
		Provider:            provider,
		Clock:               fixedClock(h.clockTime),
		GeneratedBy:         "SBOMHub/test",
	})
	in := h.baseInput()
	in.ReportType = ReportTypeEarlyWarning
	in.Lang = lang
	res, err := r.Run(context.Background(), in)
	if err != nil {
		return res, "", err
	}
	if len(h.craReports.inserted) != 1 {
		t.Fatalf("cra_reports = %d, want 1", len(h.craReports.inserted))
	}
	return res, h.craReports.inserted[0].DraftText, nil
}

func TestRunner_Run_FillsCVSSScoreAndVersion(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		for _, lang := range []Lang{LangEN, LangJA} {
			lookup := &cvssVulnLookup{score: f64(9.8), version: str("3.1")}
			_, draft, err := runCVSS(t, lookup, disabled, lang)
			if err != nil {
				t.Fatalf("disabled=%v %s: %v", disabled, lang, err)
			}
			want := "**CVSS score**: 9.8 (CVSS v3.1)\n"
			if lang == LangJA {
				want = "**CVSS スコア**: 9.8 (CVSS v3.1)\n"
			}
			if !strings.Contains(draft, want) {
				t.Errorf("disabled=%v %s: want %q in draft:\n%s", disabled, lang, want, draft)
			}
			if lookup.calls == 0 {
				t.Errorf("disabled=%v %s: CVSS lookup not called", disabled, lang)
			}
		}
	}
}

func TestRunner_Run_CVSSVersionOnlyWhenCanonical(t *testing.T) {
	cases := []struct {
		name    string
		score   *float64
		version *string
		want    string // line expected in the EN draft, "" = no score line
	}{
		{"v4", f64(10), str("4.0"), "**CVSS score**: 10.0 (CVSS v4.0)\n"},
		{"v2", f64(5), str("2.0"), "**CVSS score**: 5.0 (CVSS v2.0)\n"},
		{"unknown version", f64(7.5), nil, "**CVSS score**: 7.5\n"},
		{"non-canonical version", f64(7.5), str("4"), "**CVSS score**: 7.5\n"},
		{"padded version", f64(7.5), str(" 3.1"), "**CVSS score**: 7.5\n"},
		{"no score", nil, str("3.1"), ""},
		{"nothing", nil, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, draft, err := runCVSS(t, &cvssVulnLookup{score: c.score, version: c.version}, false, LangEN)
			if err != nil {
				t.Fatal(err)
			}
			if c.want == "" {
				if strings.Contains(draft, "CVSS score") || strings.Contains(draft, "CVSS v") {
					t.Errorf("score line printed without a score:\n%s", draft)
				}
				return
			}
			if !strings.Contains(draft, c.want) {
				t.Errorf("want %q in draft:\n%s", c.want, draft)
			}
			if strings.Count(draft, "CVSS v") > strings.Count(c.want, "CVSS v") {
				t.Errorf("unexpected version label in draft:\n%s", draft)
			}
		})
	}
}

func TestRunner_Run_CVSSLookupErrorFailsTheRun(t *testing.T) {
	boom := errors.New("db down")
	lookup := &cvssVulnLookup{err: boom}
	res, _, err := runCVSS(t, lookup, false, LangEN)
	if !errors.Is(err, boom) || res != nil {
		t.Fatalf("Run = (%v, %v), want the lookup error", res, err)
	}
}

// A lookup that only resolves the CVE (no CVSS method) keeps the old
// output: no score line, no error.
func TestRunner_Run_NoCVSSLookupPrintsNoScore(t *testing.T) {
	h := newTestHarness(t)
	in := h.baseInput()
	in.ReportType = ReportTypeEarlyWarning
	in.Lang = LangEN
	if _, err := h.runner.Run(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if d := h.craReports.inserted[0].DraftText; strings.Contains(d, "CVSS score") {
		t.Errorf("score line without a CVSS lookup:\n%s", d)
	}
}
