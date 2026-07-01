// Package cra implements EU Cyber Resilience Act (CRA) Article 14
// vulnerability reporting support for SBOMHub (M2; PRODUCT_REBOOT_PLAN.md §7.2,
// GitHub issue #33).
//
// This file (Wave M2-1) provides the template engine and data types used by
// the CRA report drafter. The runner (Wave M2-3, issue #31) wires the LLM,
// the repository (Wave M2-2, issue #32) persists drafts, and the HTTP
// handlers (Wave M2-4, issue #36) expose them. All three other agents are
// out of scope for this file; the engine here is intentionally pure and
// has no DB / HTTP / LLM dependency.
//
// The package layers as follows:
//
//   - templates/*.tmpl    — Markdown templates per report type and language.
//   - templates.go        — engine: CRATemplateData struct, Render dispatcher,
//     embedded template registry.
//   - templates_test.go   — golden-file tests (testdata/golden/*.md).
//
// Discipline (PRODUCT_REBOOT_PLAN.md §8.5 "AI は下書きまで"):
// every template terminates with a legal-notice block stating that the
// document is a SBOMHub draft and that final review / approval is the
// manufacturer's responsibility. The engine never tries to "finalise"
// a report.
package cra

import (
	"bytes"
	"embed"
	"fmt"
	"strings"
	"text/template"
)

// templatesFS embeds the six Markdown templates that ship with the binary
// (3 report types x 2 languages). The runner does not need to find these
// on disk at runtime — this is intentional so that container deploys
// cannot accidentally drift between binary version and template version.
//
//go:embed templates/*.tmpl
var templatesFS embed.FS

// ReportType enumerates the three CRA Article 14 report types.
//
// Strings match the PRODUCT_REBOOT_PLAN.md §7.2 spec and are used directly
// as the {{ReportType}} portion of template filenames.
type ReportType string

const (
	// ReportTypeEarlyWarning is the 24-hour early warning required by
	// CRA Article 14(2)(a) once a manufacturer becomes aware of an
	// actively exploited vulnerability.
	ReportTypeEarlyWarning ReportType = "early_warning"

	// ReportTypeDetailedNotification is the 72-hour detailed notification
	// required by CRA Article 14(2)(b).
	ReportTypeDetailedNotification ReportType = "detailed_notification"

	// ReportTypeFinalReport is the post-remediation final report required
	// by CRA Article 14(2)(c).
	ReportTypeFinalReport ReportType = "final_report"
)

// Lang enumerates the supported draft languages.
//
// SBOMHub primary ICP is Japanese SMB manufacturers shipping to EU,
// so ja and en are both first-class outputs.
type Lang string

const (
	LangJA Lang = "ja"
	LangEN Lang = "en"
)

// CRATemplateData is the input struct passed to every template.
//
// All fields are optional from the engine's perspective — templates use
// {{if}} guards to render placeholders for missing data — but several
// fields (ProductName, CVEID, ExploitationStatus, SubmittedAt) are
// effectively required for a meaningful report. The runner is expected
// to populate as many fields as it can from advisory_excerpts /
// reachability_results / triage drafts and fall back to placeholders for
// the rest (which the human reviewer fills in).
//
// Field naming follows the PRODUCT_REBOOT_PLAN.md §7.2 field list
// (製品名 / CVE / 悪用状況 / 影響コンポーネント / 対象バージョン /
// 緩和策 / 是正予定 / 恒久対応 / 再発防止 / 修正バージョン) plus the
// common metadata required by every CRA submission (報告者 / 連絡先 /
// 提出日時).
type CRATemplateData struct {
	// --- Product identity ---
	ProductName    string // 製品名 (required)
	ProductVersion string // 製品バージョン (optional)
	VendorName     string // 製造業者名 (optional, defaults to tenant org name)

	// --- Vulnerability identity ---
	CVEID                string // CVE ID (required, e.g. "CVE-2025-12345")
	CVSSScore            string // free-form (e.g. "9.8") so unknown can be empty without zero-ambiguity
	CVSSVector           string // optional (e.g. "CVSS:3.1/AV:N/...")
	Severity             string // optional (e.g. "Critical")
	VulnerabilitySummary string // short summary (used by early warning + as fallback in detailed/final)
	VulnerabilityDetail  string // longer technical description (detailed + final)
	RootCause            string // root-cause analysis (detailed + final)

	// --- Exploitation status (24h trigger) ---
	ExploitationStatus   string // required (e.g. "actively exploited", "PoC available", "no known exploitation")
	KEVListed            bool   // CISA KEV listed
	EPSSScore            string // free-form percentile/score
	ExploitationEvidence string // free-form citation / quote

	// --- Impact scope ---
	PreliminaryImpactScope  string              // early warning narrative
	AffectedComponents      []AffectedComponent // affected components table
	AffectedProductVersions []string            // affected product version list

	// --- Mitigation / remediation ---
	ImmediateMitigations string         // 24h-window quick mitigations
	MitigationSteps      []string       // 72h numbered mitigation list
	RemediationPlan      string         // 72h remediation plan narrative
	FixedVersions        []FixedVersion // released or planned fix versions (72h + final)

	// --- Final report fields ---
	PermanentRemediation    string          // final: permanent remediation narrative
	PreventionMeasures      []string        // final: recurrence-prevention measures
	UserNotificationSummary string          // final: how end users were notified
	Timeline                []TimelineEntry // final: incident timeline

	// --- Reporter / contact ---
	ReporterName string
	ReporterRole string
	ContactEmail string
	ContactPhone string

	// --- Submission metadata ---
	SubmittedAt    string // ISO-8601 UTC (string, so the engine does not depend on a time package format choice)
	AwarenessTime  string // ISO-8601 UTC, start of the 24h / 72h clock
	ResolutionTime string // ISO-8601 UTC, when remediation completed (final)
	ReportID       string // internal tracking ID

	// --- Cross-report linking ---
	EarlyWarningReportID         string // detailed + final: link back to the 24h report
	DetailedNotificationReportID string // final: link back to the 72h report

	// --- Provenance ---
	GeneratedBy string // e.g. "SBOMHub v1.2.3" or "SBOMHub (LLM: anthropic/claude-opus-4-7)"
	GeneratedAt string // ISO-8601 UTC, when the draft was rendered
}

// AffectedComponent is one row in the "影響コンポーネント" / "Affected
// components" table.
type AffectedComponent struct {
	Name         string
	Version      string
	FixedVersion string
	PURL         string
}

// FixedVersion is one row in the "修正バージョン" / "Released fixed
// versions" table.
type FixedVersion struct {
	Version     string
	ReleaseDate string // free-form (allow "2026-Q3", "TBD", etc.)
	Channel     string // free-form (e.g. "official tarball", "apt repo")
}

// TimelineEntry is one row in the incident timeline (final report).
type TimelineEntry struct {
	Timestamp string // free-form (ISO-8601 or descriptive)
	Event     string
}

// templateFuncs are the helper functions exposed to every template.
//
// add1 exists so that {{range $i, $v := ...}} ... {{add1 $i}}. ... {{end}}
// can produce 1-based numbered lists without writing arithmetic in every
// template. Kept tiny on purpose — anything more involved should be done
// in Go before calling Render.
var templateFuncs = template.FuncMap{
	"add1": func(i int) int { return i + 1 },
}

// templateCache holds the parsed templates keyed by "<reportType>_<lang>".
//
// Parsed once at package init so Render is allocation-light. Parse
// failures at init are fatal (the embedded FS is shipped with the
// binary; a parse failure means the build is broken and we want a loud
// failure, not a quiet runtime error on the first Render call).
var templateCache = func() map[string]*template.Template {
	cache := make(map[string]*template.Template, 6)
	keys := []string{
		"early_warning_ja",
		"early_warning_en",
		"detailed_notification_ja",
		"detailed_notification_en",
		"final_report_ja",
		"final_report_en",
	}
	for _, key := range keys {
		path := "templates/" + key + ".tmpl"
		raw, err := templatesFS.ReadFile(path)
		if err != nil {
			panic(fmt.Sprintf("cra: embedded template %s missing: %v", path, err))
		}
		tmpl, err := template.New(key).Funcs(templateFuncs).Parse(string(raw))
		if err != nil {
			panic(fmt.Sprintf("cra: embedded template %s failed to parse: %v", path, err))
		}
		cache[key] = tmpl
	}
	return cache
}()

// Render produces the Markdown draft for a given report type and language.
//
// reportType must be one of ReportType{EarlyWarning,DetailedNotification,
// FinalReport}; lang must be one of Lang{JA,EN}. Any other combination
// returns ErrUnknownTemplate. Template execution errors (e.g. a
// CRATemplateData field referenced by a template was renamed) propagate
// as wrapped errors so the runner can surface them in the audit log.
//
// Output is Markdown. The engine intentionally uses text/template (not
// html/template): the draft is reviewed and edited by humans before
// submission and is not rendered into a web page, so HTML escaping
// would be wrong (e.g. `&` in product names would become `&amp;`).
// Callers that go on to render the draft into HTML for preview should
// run it through a Markdown -> HTML pipeline that performs escaping at
// that boundary.
func Render(reportType ReportType, lang Lang, data CRATemplateData) (string, error) {
	if reportType == "" {
		return "", fmt.Errorf("cra: Render: reportType is required")
	}
	if lang == "" {
		return "", fmt.Errorf("cra: Render: lang is required")
	}
	key := string(reportType) + "_" + string(lang)
	tmpl, ok := templateCache[key]
	if !ok {
		return "", fmt.Errorf("cra: Render: %w: reportType=%q lang=%q", ErrUnknownTemplate, reportType, lang)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("cra: Render: template %q execution failed: %w", key, err)
	}
	// Collapse trailing whitespace runs so golden files are stable when
	// optional blocks at the end of a template are skipped. We deliberately
	// preserve a single trailing newline (POSIX text-file convention).
	out := strings.TrimRight(buf.String(), "\n") + "\n"
	return out, nil
}

// ErrUnknownTemplate is returned by Render when the (reportType, lang)
// combination does not correspond to an embedded template.
//
// Sentinel error so the runner can errors.Is-match it (e.g. to fall back
// to a sane default language rather than failing the request).
var ErrUnknownTemplate = fmt.Errorf("unknown template")

// SupportedReportTypes returns the list of report types the engine can
// render. Stable order (early -> detailed -> final) suitable for UI
// dropdowns.
func SupportedReportTypes() []ReportType {
	return []ReportType{
		ReportTypeEarlyWarning,
		ReportTypeDetailedNotification,
		ReportTypeFinalReport,
	}
}

// SupportedLangs returns the list of languages the engine can render.
// Stable order (ja -> en) matching the Japanese-primary ICP.
func SupportedLangs() []Lang {
	return []Lang{LangJA, LangEN}
}
