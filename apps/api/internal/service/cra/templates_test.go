package cra

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixedGoldenInput returns the CRATemplateData used by every golden-file
// test in this package. Keeping the fixture in one function means
// regenerating goldens (via gen_golden_test.go under -tags genGolden) and
// comparing against goldens (the tests below) start from the exact same
// input — so any divergence is necessarily a template diff and never a
// fixture drift.
//
// The values are intentionally human-readable rather than realistic so
// reviewers can scan a golden file and immediately see whether a given
// field rendered into the expected section.
func fixedGoldenInput() CRATemplateData {
	return CRATemplateData{
		ProductName:    "SmartGateway-X1",
		ProductVersion: "1.4.2",
		VendorName:     "Example Manufacturing Co., Ltd.",

		CVEID:                "CVE-2026-12345",
		CVSSScore:            "9.8",
		CVSSVector:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Severity:             "Critical",
		VulnerabilitySummary: "Remote code execution via unauthenticated MQTT broker handler.",
		VulnerabilityDetail:  "An attacker can craft a malformed CONNECT packet that triggers a buffer overflow in the MQTT broker module, leading to remote code execution as root on the gateway device.",
		RootCause:            "Missing length validation on the client identifier field in libmosquitto 2.0.14 (CVE-2026-12345).",

		ExploitationStatus:   "Actively exploited in the wild",
		KEVListed:            true,
		EPSSScore:            "0.94",
		ExploitationEvidence: "Vendor SOC observed scanning campaigns targeting affected MQTT port from 2026-06-20 onward; PoC published on a public exploit site on 2026-06-22.",

		PreliminaryImpactScope: "All SmartGateway-X1 units shipped between 2024-Q1 and 2026-Q2 with firmware 1.0.0 through 1.4.2 inclusive.",
		AffectedComponents: []AffectedComponent{
			{Name: "libmosquitto", Version: "2.0.14", FixedVersion: "2.0.15", PURL: "pkg:generic/libmosquitto@2.0.14"},
			{Name: "smartgw-mqtt-bridge", Version: "1.4.2", FixedVersion: "1.4.3", PURL: "pkg:generic/smartgw-mqtt-bridge@1.4.2"},
		},
		AffectedProductVersions: []string{"1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.4.1", "1.4.2"},

		ImmediateMitigations: "Disable inbound MQTT (port 1883) at the device firewall until firmware 1.4.3 is installed.",
		MitigationSteps: []string{
			"Block inbound TCP port 1883 at the perimeter firewall.",
			"Disable the MQTT broker on the device via the admin console (Settings > Services > MQTT > Disable).",
			"Rotate any device credentials that may have been exposed.",
		},
		RemediationPlan: "Firmware 1.4.3 patches libmosquitto to 2.0.15 and adds input length validation in the MQTT bridge. Staged rollout begins 2026-06-26.",
		FixedVersions: []FixedVersion{
			{Version: "1.4.3", ReleaseDate: "2026-06-26", Channel: "OTA + manufacturer download portal"},
			{Version: "1.5.0", ReleaseDate: "2026-07-15", Channel: "OTA"},
		},

		PermanentRemediation:    "Firmware 1.4.3 has been released and shipped to 100% of fleet via OTA as of 2026-07-02. libmosquitto upgraded to 2.0.15; defensive length validation added to smartgw-mqtt-bridge 1.4.3.",
		PreventionMeasures: []string{
			"Add libmosquitto to the SBOM watchlist with a 24h SLA on new CVEs.",
			"Enforce a fuzzing gate on the MQTT bridge in CI.",
			"Adopt the secure-by-default firewall profile so MQTT is closed unless explicitly enabled.",
		},
		UserNotificationSummary: "End-user advisory PSIRT-2026-007 was published in Japanese and English on 2026-06-23. Direct email notification was sent to all registered fleet operators on the same day.",
		Timeline: []TimelineEntry{
			{Timestamp: "2026-06-22T08:30:00Z", Event: "Awareness: PoC observed on public exploit site."},
			{Timestamp: "2026-06-23T07:00:00Z", Event: "Early warning submitted to CSIRT."},
			{Timestamp: "2026-06-25T07:00:00Z", Event: "Detailed notification submitted."},
			{Timestamp: "2026-06-26T00:00:00Z", Event: "Firmware 1.4.3 released."},
			{Timestamp: "2026-07-02T12:00:00Z", Event: "100% fleet OTA coverage reached."},
			{Timestamp: "2026-07-05T09:00:00Z", Event: "Final report submitted."},
		},

		ReporterName: "Taro Yamada",
		ReporterRole: "PSIRT Lead",
		ContactEmail: "psirt@example.co.jp",
		ContactPhone: "+81-3-1234-5678",

		SubmittedAt:    "2026-06-23T07:00:00Z",
		AwarenessTime:  "2026-06-22T08:30:00Z",
		ResolutionTime: "2026-07-02T12:00:00Z",
		ReportID:       "SBH-CRA-2026-0001",

		EarlyWarningReportID:         "SBH-CRA-2026-0001",
		DetailedNotificationReportID: "SBH-CRA-2026-0002",

		GeneratedBy: "SBOMHub v0.9.0 (test fixture)",
		GeneratedAt: "2026-06-23T07:00:00Z",
	}
}

// TestRender_GoldenFiles compares every (reportType, lang) combination
// against the committed fixture under testdata/golden/. Run with
// `UPDATE_GOLDENS=1 go test ./internal/service/cra/...` to refresh.
//
// Six combinations total: 3 report types x 2 langs (M2 issue #33 AC).
func TestRender_GoldenFiles(t *testing.T) {
	data := fixedGoldenInput()
	for _, rt := range SupportedReportTypes() {
		for _, lang := range SupportedLangs() {
			rt, lang := rt, lang
			t.Run(string(rt)+"_"+string(lang), func(t *testing.T) {
				got, err := Render(rt, lang, data)
				if err != nil {
					t.Fatalf("Render(%s, %s): %v", rt, lang, err)
				}
				path := filepath.Join("testdata", "golden", string(rt)+"_"+string(lang)+".md")
				if os.Getenv("UPDATE_GOLDENS") == "1" {
					if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
						t.Fatalf("UPDATE_GOLDENS write %s: %v", path, err)
					}
					return
				}
				wantBytes, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read golden %s: %v (run with UPDATE_GOLDENS=1 to create)", path, err)
				}
				want := string(wantBytes)
				if got != want {
					t.Errorf("golden mismatch for %s/%s\n--- got ---\n%s\n--- want ---\n%s", rt, lang, got, want)
				}
				// Cross-check: every rendered draft must contain the legal-notice block
				// (PRODUCT_REBOOT_PLAN.md §8.5 — AI is drafts-only). This guards against
				// a future edit accidentally deleting the disclaimer.
				if !containsLegalNotice(got, lang) {
					t.Errorf("golden %s/%s missing legal-notice disclaimer", rt, lang)
				}
			})
		}
	}
}

// containsLegalNotice asserts the rendered draft contains the legal-notice
// block in the appropriate language. Matching is intentionally lenient
// (substring match on the central phrase) so wording can evolve without
// breaking this guard — the precise wording is enforced by the golden
// files themselves.
func containsLegalNotice(rendered string, lang Lang) bool {
	switch lang {
	case LangJA:
		return strings.Contains(rendered, "本文書は SBOMHub による下書きであり")
	case LangEN:
		return strings.Contains(rendered, "This document is a draft generated by SBOMHub")
	default:
		return false
	}
}

func TestRender_UnknownTemplate(t *testing.T) {
	cases := []struct {
		name       string
		reportType ReportType
		lang       Lang
	}{
		{name: "unknown report type", reportType: "interim_report", lang: LangJA},
		{name: "unknown lang", reportType: ReportTypeEarlyWarning, lang: "fr"},
		{name: "empty report type", reportType: "", lang: LangJA},
		{name: "empty lang", reportType: ReportTypeEarlyWarning, lang: ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := Render(tc.reportType, tc.lang, CRATemplateData{ProductName: "x", CVEID: "CVE-x"})
			if err == nil {
				t.Fatalf("expected error for reportType=%q lang=%q, got nil", tc.reportType, tc.lang)
			}
			// Only the unknown-template cases (non-empty inputs that don't match)
			// should match ErrUnknownTemplate; the empty-input cases return a
			// plain validation error.
			if tc.reportType != "" && tc.lang != "" && !errors.Is(err, ErrUnknownTemplate) {
				t.Errorf("expected errors.Is(err, ErrUnknownTemplate) for %s; got %v", tc.name, err)
			}
		})
	}
}

func TestSupportedReportTypes_Stable(t *testing.T) {
	got := SupportedReportTypes()
	want := []ReportType{
		ReportTypeEarlyWarning,
		ReportTypeDetailedNotification,
		ReportTypeFinalReport,
	}
	if len(got) != len(want) {
		t.Fatalf("len(SupportedReportTypes()) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("SupportedReportTypes()[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestSupportedLangs_Stable(t *testing.T) {
	got := SupportedLangs()
	want := []Lang{LangJA, LangEN}
	if len(got) != len(want) {
		t.Fatalf("len(SupportedLangs()) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("SupportedLangs()[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}
