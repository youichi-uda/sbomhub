package cra

// M74 — a CRA draft that prints a CVSS score names its CVSS version
// (CRATemplateData.CVSSVersion, the vulnerabilities.cvss_version value) in
// both languages and all three report types. Only a canonical version is
// printed; an unknown / unrecognised version prints nothing, never a guess.

import (
	"strings"
	"testing"
)

func TestRender_CVSSVersionNamedWithScore(t *testing.T) {
	for _, rt := range SupportedReportTypes() {
		for _, lang := range SupportedLangs() {
			data := fixedGoldenInput()
			data.CVSSScore = "7.5"
			data.CVSSVector = ""
			data.CVSSVersion = "3.1"
			out, err := Render(rt, lang, data)
			if err != nil {
				t.Fatalf("%s/%s: %v", rt, lang, err)
			}
			label := "**CVSS score**: 7.5 (CVSS v3.1)"
			if lang == LangJA {
				label = "**CVSS スコア**: 7.5 (CVSS v3.1)"
			}
			if !strings.Contains(out, label) {
				t.Errorf("%s/%s: draft does not name the CVSS version; want %q in:\n%s", rt, lang, label, out)
			}

			// Unrecognised or absent version: the score line is unchanged
			// and no version is invented.
			for _, v := range []string{"", "9.9", "*x*", "4", "2", " 3.1"} {
				data.CVSSVersion = v
				out, err := Render(rt, lang, data)
				if err != nil {
					t.Fatalf("%s/%s: %v", rt, lang, err)
				}
				if strings.Contains(out, "CVSS v") || strings.Contains(out, "*x*") {
					t.Errorf("%s/%s: version %q rendered a version:\n%s", rt, lang, v, out)
				}
				if !strings.Contains(out, ": 7.5\n") {
					t.Errorf("%s/%s: version %q changed the score line:\n%s", rt, lang, v, out)
				}
			}

			// A version without a score prints no score line at all.
			data.CVSSScore = ""
			data.CVSSVersion = "3.1"
			out, err = Render(rt, lang, data)
			if err != nil {
				t.Fatalf("%s/%s: %v", rt, lang, err)
			}
			if strings.Contains(out, "CVSS v3.1") {
				t.Errorf("%s/%s: version printed without a score:\n%s", rt, lang, out)
			}
		}
	}
}

// With both a version and a vector the version comes first, then the
// vector (the golden fixtures carry both since M75).
func TestRender_CVSSVersionAndVector(t *testing.T) {
	data := fixedGoldenInput()
	data.CVSSVersion = "3.1"
	out, err := Render(ReportTypeEarlyWarning, LangEN, data)
	if err != nil {
		t.Fatal(err)
	}
	want := "**CVSS score**: " + data.CVSSScore + " (CVSS v3.1) (" + data.CVSSVector + ")"
	if !strings.Contains(out, want) {
		t.Errorf("want %q in:\n%s", want, out)
	}
}
