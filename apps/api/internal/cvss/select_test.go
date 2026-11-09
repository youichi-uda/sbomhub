package cvss

import (
	"math"
	"testing"
)

func f(v float64) *float64 { return &v }

// TestSelect_Rule is the product rule as a table (M67): v3.1 > v3.0 > v4.0 >
// v2, NVD's Primary over a Secondary within one version, and inside the same
// (version, primacy) the more severe assessment, so the result never depends
// on the order the feed listed them in.
func TestSelect_Rule(t *testing.T) {
	cases := []struct {
		name    string
		in      []Assessment
		version Version
		score   *float64
		sev     string
	}{
		{"nothing", nil, "", nil, "UNKNOWN"},
		{
			"v3.1 outranks v4.0 even when v4.0 is listed first and scores higher",
			[]Assessment{
				{Version: V40, Primary: true, Score: f(9.3), Severity: "CRITICAL"},
				{Version: V31, Primary: true, Score: f(7.5), Severity: "HIGH"},
			},
			V31, f(7.5), "HIGH",
		},
		{
			"v3.1 outranks v4.0 even when v4.0 scores lower (the M67 fixture shape)",
			[]Assessment{
				{Version: V40, Primary: false, Score: f(6.9), Severity: "MEDIUM"},
				{Version: V31, Primary: true, Score: f(7.5), Severity: "HIGH"},
			},
			V31, f(7.5), "HIGH",
		},
		{
			"v3.1 outranks v3.0",
			[]Assessment{
				{Version: V30, Primary: true, Score: f(9.8), Severity: "CRITICAL"},
				{Version: V31, Primary: false, Score: f(5.0), Severity: "MEDIUM"},
			},
			V31, f(5.0), "MEDIUM",
		},
		{
			"v3.0 outranks v4.0",
			[]Assessment{
				{Version: V40, Primary: true, Score: f(9.0), Severity: "CRITICAL"},
				{Version: V30, Primary: false, Score: f(4.0), Severity: "MEDIUM"},
			},
			V30, f(4.0), "MEDIUM",
		},
		{
			"v4.0 outranks v2",
			[]Assessment{
				{Version: V2, Primary: true, Score: f(10.0)},
				{Version: V40, Primary: false, Score: f(2.0), Severity: "LOW"},
			},
			V40, f(2.0), "LOW",
		},
		{
			"v4-only CVE is scored, not UNKNOWN",
			[]Assessment{{Version: V40, Primary: false, Score: f(6.3), Severity: "MEDIUM"}},
			V40, f(6.3), "MEDIUM",
		},
		{
			"v2 severity is banded from the score on the three-band scale",
			[]Assessment{{Version: V2, Primary: true, Score: f(9.3)}},
			V2, f(9.3), "HIGH",
		},
		{
			"Primary beats a Secondary listed first within a version",
			[]Assessment{
				{Version: V31, Primary: false, Score: f(6.3), Severity: "MEDIUM"},
				{Version: V31, Primary: true, Score: f(9.8), Severity: "CRITICAL"},
			},
			V31, f(9.8), "CRITICAL",
		},
		{
			"Primary beats a MORE severe Secondary within a version",
			[]Assessment{
				{Version: V31, Primary: false, Score: f(8.2), Severity: "HIGH"},
				{Version: V31, Primary: true, Score: f(5.3), Severity: "MEDIUM"},
			},
			V31, f(5.3), "MEDIUM",
		},
		{
			"no Primary: the more severe Secondary wins, whatever the order",
			[]Assessment{
				{Version: V31, Primary: false, Score: f(4.3), Severity: "MEDIUM"},
				{Version: V31, Primary: false, Score: f(8.8), Severity: "HIGH"},
			},
			V31, f(8.8), "HIGH",
		},
		{
			"equal rating: the higher score breaks the tie",
			[]Assessment{
				{Version: V31, Score: f(7.1), Severity: "HIGH"},
				{Version: V31, Score: f(8.1), Severity: "HIGH"},
			},
			V31, f(8.1), "HIGH",
		},
		{
			"stated severity milder than the score's band: the band wins",
			[]Assessment{{Version: V31, Primary: true, Score: f(9.8), Severity: "LOW"}},
			V31, f(9.8), "CRITICAL",
		},
		{
			"an out-of-range score is dropped but its stated severity kept",
			[]Assessment{{Version: V31, Primary: true, Score: f(42), Severity: "HIGH"}},
			V31, nil, "HIGH",
		},
		{
			"NaN is dropped",
			[]Assessment{{Version: V31, Primary: true, Score: f(math.NaN()), Severity: "MEDIUM"}},
			V31, nil, "MEDIUM",
		},
		{
			"an assessment with nothing usable is not a candidate",
			[]Assessment{
				{Version: V31, Primary: true, Score: nil, Severity: ""},
				{Version: V2, Primary: true, Score: f(10.0)},
			},
			V2, f(10.0), "HIGH",
		},
		{
			"an unrecognised version ranks below every known one",
			[]Assessment{
				{Version: "", Score: f(0.1), Severity: "LOW"},
				{Version: V2, Score: f(10.0), Severity: "HIGH"},
			},
			V2, f(10.0), "HIGH",
		},
		{
			"an unrecognised version alone is still stored, banded harshly, with no version",
			[]Assessment{{Version: "", Score: f(9.8), Severity: "Low"}},
			"", f(9.8), "CRITICAL",
		},
		{
			"v2 0.0 is LOW: the v2 scale has no None band",
			[]Assessment{{Version: V2, Primary: true, Score: f(0.0)}},
			V2, f(0.0), "LOW",
		},
		{
			"0.0 is a real score (None), not absent",
			[]Assessment{{Version: V31, Primary: true, Score: f(0.0), Severity: "NONE"}},
			V31, f(0.0), "NONE",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Select(tc.in)
			if got.Version != tc.version || got.Severity != tc.sev || !sameScore(got.Score, tc.score) {
				t.Errorf("Select = {%q %v %q}, want {%q %v %q}",
					got.Version, fmtScore(got.Score), got.Severity, tc.version, fmtScore(tc.score), tc.sev)
			}
			// Order independence: the reversed input must give the same answer.
			rev := make([]Assessment, len(tc.in))
			for i := range tc.in {
				rev[len(tc.in)-1-i] = tc.in[i]
			}
			if r := Select(rev); r.Version != got.Version || r.Severity != got.Severity || !sameScore(r.Score, got.Score) {
				t.Errorf("Select depends on input order: reversed gives {%q %v %q}", r.Version, fmtScore(r.Score), r.Severity)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]Version{
		"3.1": V31, " 3.0 ": V30, "4.0": V40, "2.0": V2, "2": V2, "4": V40,
		"3": "", "9.9": "", "": "", "3.10": "",
	} {
		if got := ParseVersion(in); got != want {
			t.Errorf("ParseVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOutranks(t *testing.T) {
	a := Selection{Version: V30, Score: f(5.0), Severity: "MEDIUM"}
	b := Selection{Version: V2, Score: f(10.0), Severity: "HIGH"}
	if !Outranks(a, b) || Outranks(b, a) {
		t.Error("the version rule must decide before severity between two selections")
	}
	// Without versions the rating decides, then the score; equality keeps the incumbent.
	c := Selection{Score: f(9.8), Severity: "CRITICAL"}
	d := Selection{Score: f(10.0), Severity: "HIGH"}
	if !Outranks(c, d) || Outranks(d, c) || Outranks(c, c) {
		t.Error("rating, then score, then incumbent")
	}
}

func sameScore(a, b *float64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func fmtScore(p *float64) any {
	if p == nil {
		return "nil"
	}
	return *p
}
