package service

import (
	"encoding/json"
	"testing"

	"github.com/sbomhub/sbomhub/internal/cache"
	"github.com/sbomhub/sbomhub/internal/cvss"
	"github.com/sbomhub/sbomhub/internal/model"
)

// TestM67JVN_VersionRuleAppliesToJVN (M67). JVN advisories are catalogue
// writers too, so they follow the same rule as NVD records: v3.x before v2.
// Before M67 the JVN scanner kept the MOST SEVERE entry across versions, so
// an advisory with v3.0 MEDIUM beside v2 HIGH was stored HIGH while the NVD
// record for the same CVE stored the v3 rating.
func TestM67JVN_VersionRuleAppliesToJVN(t *testing.T) {
	svc := NewJVNService(nil, nil, "", false)

	got := svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2026-000001",
		CVSS: []JVNCVSS{
			jvnTestCVSS("2.0", "High", "7.5"),
			jvnTestCVSS("3.0", "Medium", "5.3"),
		},
	})
	if got == nil {
		t.Fatal("item was dropped")
	}
	if got.Severity != "MEDIUM" || got.CVSSScore == nil || *got.CVSSScore != 5.3 {
		t.Errorf("stored %s/%v, want the v3.0 MEDIUM/5.3 (v3.x outranks v2)", got.Severity, got.CVSSScore)
	}
	if got.CVSSVersion == nil || *got.CVSSVersion != "3.0" {
		t.Errorf("stored version %v, want 3.0", got.CVSSVersion)
	}

	// A v2-only JVN advisory keeps working: scored, banded on the v2 scale,
	// version recorded.
	got = svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2026-000002",
		CVSS:       []JVNCVSS{jvnTestCVSS("2.0", "Low", "9.3")},
	})
	if got == nil || got.Severity != "HIGH" || got.CVSSScore == nil || *got.CVSSScore != 9.3 ||
		got.CVSSVersion == nil || *got.CVSSVersion != "2.0" {
		t.Errorf("v2-only advisory stored %+v, want HIGH/9.3/v2.0", got)
	}

	// An unrecognised version is stored with no version, never as a fake one.
	got = svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2026-000003",
		CVSS:       []JVNCVSS{jvnTestCVSS("9.9", "High", "7.0")},
	})
	if got == nil || got.Severity != "HIGH" || got.CVSSVersion != nil {
		t.Errorf("unknown-version advisory stored %+v, want HIGH with no version", got)
	}
}

// TestM67JVN_DuplicateCVEUsesTheVersionRule: two advisories citing one CVE are
// arbitrated by the same rule — version first, then rating.
func TestM67JVN_DuplicateCVEUsesTheVersionRule(t *testing.T) {
	v := func(s string) *string { return &s }
	v3 := 5.3
	v2 := 10.0
	a := model.Vulnerability{CVEID: "CVE-2026-0001", CVSSScore: &v3, Severity: "MEDIUM", CVSSVersion: v("3.0")}
	b := model.Vulnerability{CVEID: "CVE-2026-0001", CVSSScore: &v2, Severity: "HIGH", CVSSVersion: v("2.0")}
	if !jvnOutranks(a, b) {
		t.Error("a v3.0 advisory did not displace a v2 one")
	}
	if jvnOutranks(b, a) {
		t.Error("a v2 advisory displaced a v3.0 one")
	}
	// The M55 R4 case with real versions: v3.1 CRITICAL 9.8 vs v2 HIGH 10.0.
	v31crit, v2high := 9.8, 10.0
	c := model.Vulnerability{CVEID: "CVE-2026-0001", CVSSScore: &v31crit, Severity: "CRITICAL", CVSSVersion: v("3.1")}
	d := model.Vulnerability{CVEID: "CVE-2026-0001", CVSSScore: &v2high, Severity: "HIGH", CVSSVersion: v("2.0")}
	if !jvnOutranks(c, d) || jvnOutranks(d, c) {
		t.Error("a v2 HIGH/10.0 displaced, or was not displaced by, a v3.1 CRITICAL/9.8")
	}
}

// TestM67NVDCache_PreM67EntryIsRefetched (Codex M67 R1, High). A Redis entry
// written by a pre-M67 build carries scores chosen by the old scanner rule.
// Serving it would let the scanner create a catalogue row that never went
// through cvss.Select — and Create's ON CONFLICT DO NOTHING means no later
// scan repairs it. Entries are stamped with the CVSS rule revision by
// NVDCache.Set; an unstamped (pre-M67) entry is unusable, so the lookup goes
// to NVD exactly as on a miss.
//
// The stamp is per ENTRY, not inferred from a missing per-CVE version: a
// CachedVuln with no version is legitimate (no assessment was chosen), and
// rejecting such entries once disabled the CPE path's cache outright
// (TestM60NVDCache_SecondLookupIsServedFromCache went red on the first cut).
func TestM67NVDCache_PreM67EntryIsRefetched(t *testing.T) {
	score := 4.0
	v31 := "3.1"
	legacy := &cache.VulnCacheEntry{Vulnerabilities: []cache.CachedVuln{
		{CVEID: "CVE-2026-0001", Severity: "MEDIUM", CVSSScore: &score, CVSSVersion: &v31},
	}}
	if _, usable := cachedNVDVulns(legacy, "x", "1"); usable {
		t.Error("a pre-M67 cache entry (no CVSS rule stamp) was served")
	}
	cpeShape := &cache.VulnCacheEntry{CVSSRule: cache.CVSSRuleCurrent, Vulnerabilities: []cache.CachedVuln{
		{CVEID: "CVE-2026-0001", Severity: "MEDIUM", CVSSScore: &score},
	}}
	if _, usable := cachedNVDVulns(cpeShape, "x", "1"); !usable {
		t.Error("a current entry without per-CVE versions (the CPE path's shape) was refused")
	}
	current := &cache.VulnCacheEntry{CVSSRule: cache.CVSSRuleCurrent, Vulnerabilities: []cache.CachedVuln{
		{CVEID: "CVE-2026-0001", Severity: "MEDIUM", CVSSScore: &score, CVSSVersion: &v31},
		{CVEID: "CVE-2026-0002", Severity: "UNKNOWN"},
	}}
	got, usable := cachedNVDVulns(current, "x", "1")
	if !usable || len(got) != 2 || got[0].CVSSVersion == nil || *got[0].CVSSVersion != "3.1" {
		t.Errorf("a current entry was not served intact: usable=%v %+v", usable, got)
	}
}

// TestM67NVD_MissingBaseScoreIsNotZero (Codex M67 R3, High). baseScore absent
// or null on the wire used to decode as a real 0.0. Under version precedence
// an empty v3.1 entry then beat a valid v4.0 9.8 CRITICAL and was stored
// 0.0 / NONE — a critical gate passes on it. An absent score is absent.
func TestM67NVD_MissingBaseScoreIsNotZero(t *testing.T) {
	cases := []struct {
		name, metrics string
		version       cvss.Version
		score         *float64
		sev           string
	}{
		{"absent v3.1 beside a valid v4.0",
			`{"cvssMetricV31":[{"type":"Primary","cvssData":{"version":"3.1"}}],
			  "cvssMetricV40":[{"type":"Secondary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]}`,
			cvss.V40, ptrF(9.8), "CRITICAL"},
		{"null v3.1 beside a valid v4.0",
			`{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":null}}],
			  "cvssMetricV40":[{"type":"Secondary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]}`,
			cvss.V40, ptrF(9.8), "CRITICAL"},
		{"lone absent score", `{"cvssMetricV31":[{"type":"Primary","cvssData":{}}]}`, "", nil, "UNKNOWN"},
		// Codex M67 R5, High: cvssData ITSELF absent / null, not just baseScore.
		{"absent cvssData beside a valid v4.0",
			`{"cvssMetricV31":[{"type":"Primary"}],
			  "cvssMetricV40":[{"type":"Secondary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]}`,
			cvss.V40, ptrF(9.8), "CRITICAL"},
		{"null cvssData beside a valid v4.0",
			`{"cvssMetricV31":[{"type":"Primary","cvssData":null}],
			  "cvssMetricV40":[{"type":"Secondary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]}`,
			cvss.V40, ptrF(9.8), "CRITICAL"},
		{"absent cvssData, v2 rating on the metric", `{"cvssMetricV2":[{"type":"Primary","baseSeverity":"HIGH"}]}`,
			cvss.V2, nil, "HIGH"},
		{"absent score with a stated rating keeps the rating",
			`{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseSeverity":"HIGH"}}]}`, cvss.V31, nil, "HIGH"},
		{"a real 0.0 stays 0.0", `{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":0.0,"baseSeverity":"NONE"}}]}`,
			cvss.V31, ptrF(0), "NONE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var m NVDMetrics
			if err := json.Unmarshal([]byte(tc.metrics), &m); err != nil {
				t.Fatal(err)
			}
			got := SelectNVDCVSS(m)
			if got.Version != tc.version || got.Severity != tc.sev || !eqF(got.Score, tc.score) {
				t.Errorf("SelectNVDCVSS = {%q %v %q}, want {%q %v %q}", got.Version, got.Score, got.Severity, tc.version, tc.score, tc.sev)
			}
		})
	}
	var m NVDMetrics
	if err := json.Unmarshal([]byte(`{"cvssMetricV31":[{"cvssData":{"baseScore":"9.8"}}]}`), &m); err == nil {
		t.Error("a non-numeric baseScore decoded; it must fail as it did before")
	}
}

func ptrF(v float64) *float64 { return &v }

func eqF(a, b *float64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// TestM67NVD_V2MetricLevelSeverity (Codex M67 R4, Medium). NVD's v2 metric
// carries baseSeverity on the METRIC object, not in cvssData (recorded live,
// CVE-2021-44228: {"type":"Primary","cvssData":{"version":"2.0","baseScore":
// 9.3},"baseSeverity":"HIGH",...}). It was not modelled, so a v2 rating with
// no usable score was stored UNKNOWN, and a rating harsher than the score's
// band was lost. The rule is the same as everywhere: the harsher wins.
func TestM67NVD_V2MetricLevelSeverity(t *testing.T) {
	cases := []struct {
		name, metrics string
		score         *float64
		sev           string
	}{
		{"recorded shape", `{"cvssMetricV2":[{"type":"Primary","cvssData":{"version":"2.0","baseScore":9.3},"baseSeverity":"HIGH"}]}`,
			ptrF(9.3), "HIGH"},
		{"rating only (score null)", `{"cvssMetricV2":[{"type":"Primary","cvssData":{"baseScore":null},"baseSeverity":"HIGH"}]}`,
			nil, "HIGH"},
		{"rating harsher than the score's band", `{"cvssMetricV2":[{"type":"Primary","cvssData":{"baseScore":2.0},"baseSeverity":"HIGH"}]}`,
			ptrF(2.0), "HIGH"},
		{"band harsher than the rating", `{"cvssMetricV2":[{"type":"Primary","cvssData":{"baseScore":9.3},"baseSeverity":"LOW"}]}`,
			ptrF(9.3), "HIGH"},
		{"out-of-range score keeps the rating", `{"cvssMetricV2":[{"type":"Primary","cvssData":{"baseScore":42},"baseSeverity":"MEDIUM"}]}`,
			nil, "MEDIUM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var m NVDMetrics
			if err := json.Unmarshal([]byte(tc.metrics), &m); err != nil {
				t.Fatal(err)
			}
			got := SelectNVDCVSS(m)
			if got.Version != cvss.V2 || got.Severity != tc.sev || !eqF(got.Score, tc.score) {
				t.Errorf("SelectNVDCVSS = {%q %v %q}, want {2.0 %v %q}", got.Version, got.Score, got.Severity, tc.score, tc.sev)
			}
		})
	}
}
