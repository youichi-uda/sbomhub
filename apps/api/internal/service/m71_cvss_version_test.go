package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
)

func m71Str(s string) *string { return &s }

// M71: the CVE detail (blast radius) carries the stored version beside the
// score, and omits it when unknown.
func TestM71BuildCVEImpact_CarriesCVSSVersion(t *testing.T) {
	meta := &model.CVEImpactMeta{VulnerabilityID: uuid.New(), Severity: "HIGH", CVSSScore: f64p(7.5), CVSSVersion: m71Str("3.1")}
	got := buildCVEImpact("CVE-2026-34478", meta, nil, 1)
	if got.CVSSVersion == nil || *got.CVSSVersion != "3.1" {
		t.Fatalf("CVSSVersion = %v, want 3.1", got.CVSSVersion)
	}
	b, _ := json.Marshal(got)
	if !strings.Contains(string(b), `"cvss_score":7.5,"cvss_version":"3.1"`) {
		t.Fatalf("JSON: %s", b)
	}
	meta.CVSSVersion = nil
	b, _ = json.Marshal(buildCVEImpact("CVE-2026-34478", meta, nil, 1))
	if strings.Contains(string(b), "cvss_version") {
		t.Fatalf("unknown version must be omitted: %s", b)
	}
}

// The CVE search answered from NVD (CVE not stored locally) carries the
// version the NVD conversion chose, like the stored path.
func TestM71SearchByCVE_NVDFallbackCarriesCVSSVersion(t *testing.T) {
	svc := NewSearchServiceWithNVD(&fakeSearchRepo{}, &fakeNVD{vuln: &model.Vulnerability{
		CVEID: "CVE-2026-34478", Severity: "HIGH", CVSSScore: f64p(7.5), CVSSVersion: m71Str("3.1"),
	}})
	got, err := svc.SearchByCVE(context.Background(), "CVE-2026-34478")
	if err != nil {
		t.Fatal(err)
	}
	if got.CVSSVersion == nil || *got.CVSSVersion != "3.1" {
		t.Fatalf("CVSSVersion = %v, want 3.1", got.CVSSVersion)
	}
}
