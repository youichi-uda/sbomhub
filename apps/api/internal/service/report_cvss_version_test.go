package service

// M74 — the PDF / Excel reports name the CVSS version of every Top Risk
// score they print (model.TopRisk.CVSSVersion, already read by
// GetTopRisksByTenant since M71). The PDF line's label becomes "CVSS v3.1";
// the Excel Top Risks sheet gets a NEW trailing column (F) so existing
// column positions A-E are unchanged. Unknown versions print the bare label
// and an empty cell — never a guessed version.

import (
	"bytes"
	"testing"

	"github.com/xuri/excelize/v2"

	"github.com/sbomhub/sbomhub/internal/model"
)

func TestReportCVSSLabel(t *testing.T) {
	if got := reportCVSSLabel(strPtr("3.1")); got != "CVSS v3.1" {
		t.Errorf("reportCVSSLabel(3.1) = %q", got)
	}
	if got := reportCVSSLabel(nil); got != "CVSS" {
		t.Errorf("reportCVSSLabel(nil) = %q", got)
	}
	if got := reportCVSSLabel(strPtr("v9")); got != "CVSS" {
		t.Errorf("reportCVSSLabel(unrecognised) = %q, want bare CVSS", got)
	}
}

func TestReportTopRiskLines_NameCVSSVersion(t *testing.T) {
	ja := GetTranslations("ja")
	en := GetTranslations("en")
	scored := model.TopRisk{CVEID: "CVE-1", CVSSScore: f64p(9.1), CVSSVersion: strPtr("3.1"),
		EPSSScore: f64p(0.5), ProjectName: "app-a"}
	if got, want := executiveTopRiskText(scored, en), "app-a - CVSS v3.1: 9.1"; got != want {
		t.Errorf("executive line = %q, want %q", got, want)
	}
	if got, want := technicalTopRiskText(scored, ja), "CVSS v3.1: 9.1, EPSS: 50.00%"; got != want {
		t.Errorf("technical line = %q, want %q", got, want)
	}
	unknown := model.TopRisk{CVEID: "CVE-2", CVSSScore: f64p(5), ProjectName: "app-b"}
	if got, want := executiveTopRiskText(unknown, ja), "app-b - CVSS: 5.0"; got != want {
		t.Errorf("executive line (unknown version) = %q, want %q", got, want)
	}
	unscored := model.TopRisk{CVEID: "CVE-3", CVSSVersion: strPtr("4.0"), ProjectName: "app-c"}
	if got, want := executiveTopRiskText(unscored, ja), "app-c - CVSS v4.0: 未採点"; got != want {
		t.Errorf("executive line (versioned, unscored) = %q, want %q", got, want)
	}
}

func TestGenerateExcel_TopRisksCVSSVersionColumn(t *testing.T) {
	for _, lang := range []string{"ja", "en"} {
		svc := NewReportService(nil, nil, nil, nil, nil, nil, t.TempDir())
		tr := GetTranslations(lang)

		data := buildFullReportData()
		data.TopRisks[0].CVSSVersion = strPtr("3.1")
		data.TopRisks = append(data.TopRisks,
			model.TopRisk{CVEID: "CVE-2026-0002", CVSSScore: f64p(5), Severity: "MEDIUM",
				ProjectName: "app-b", ComponentName: "libq"}, // version unknown
		)

		b, err := svc.generateExcel(data, model.ReportTypeExecutive, lang)
		if err != nil {
			t.Fatalf("%s: generateExcel: %v", lang, err)
		}
		f, err := excelize.OpenReader(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("%s: open workbook: %v", lang, err)
		}
		get := func(cell string) string {
			v, err := f.GetCellValue(tr.SheetTopRisks, cell)
			if err != nil {
				t.Fatalf("%s: %s: %v", lang, cell, err)
			}
			return v
		}
		// Existing columns keep their positions.
		if get("D1") != tr.CVSS || get("E1") != tr.EPSS {
			t.Errorf("%s: D1/E1 = %q/%q, want %q/%q (columns must not shift)", lang, get("D1"), get("E1"), tr.CVSS, tr.EPSS)
		}
		if tr.CVSSVersion == "" {
			t.Fatalf("%s: CVSSVersion translation is empty", lang)
		}
		if get("F1") != tr.CVSSVersion {
			t.Errorf("%s: F1 = %q, want %q", lang, get("F1"), tr.CVSSVersion)
		}
		if get("D2") != "9.1" || get("F2") != "3.1" {
			t.Errorf("%s: row 2 D/F = %q/%q, want 9.1/3.1", lang, get("D2"), get("F2"))
		}
		if get("F3") != "" {
			t.Errorf("%s: unknown version F3 = %q, want empty (no guessed version)", lang, get("F3"))
		}
		_ = f.Close()
	}
}
