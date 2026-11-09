package service

import (
	"testing"

	"github.com/sbomhub/sbomhub/internal/cache"
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
	if !jvnMoreSevere(a, b) {
		t.Error("a v3.0 advisory did not displace a v2 one")
	}
	if jvnMoreSevere(b, a) {
		t.Error("a v2 advisory displaced a v3.0 one")
	}
}

// TestM67NVDCache_PreM67ScoredEntryIsRefetched (Codex M67 R1, High). A Redis
// entry written by a pre-M67 build carries a score chosen by the old scanner
// rule and no cvss_version. Serving it would let the scanner create a
// catalogue row that never went through cvss.Select — and Create's ON
// CONFLICT DO NOTHING means no later scan repairs it. Such an entry is
// treated as unusable, so the lookup goes to NVD exactly as on a miss.
func TestM67NVDCache_PreM67ScoredEntryIsRefetched(t *testing.T) {
	score := 4.0
	v31 := "3.1"
	legacy := &cache.VulnCacheEntry{Vulnerabilities: []cache.CachedVuln{
		{CVEID: "CVE-2026-0001", Severity: "MEDIUM", CVSSScore: &score},
	}}
	if _, usable := cachedNVDVulns(legacy, "x", "1"); usable {
		t.Error("a scored pre-M67 cache entry (no cvss_version) was served")
	}
	current := &cache.VulnCacheEntry{Vulnerabilities: []cache.CachedVuln{
		{CVEID: "CVE-2026-0001", Severity: "MEDIUM", CVSSScore: &score, CVSSVersion: &v31},
		{CVEID: "CVE-2026-0002", Severity: "UNKNOWN"}, // unscored: no version by design
	}}
	got, usable := cachedNVDVulns(current, "x", "1")
	if !usable || len(got) != 2 || got[0].CVSSVersion == nil || *got[0].CVSSVersion != "3.1" {
		t.Errorf("a current entry was not served intact: usable=%v %+v", usable, got)
	}
}
