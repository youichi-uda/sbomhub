// Package diff_export renders the supply-chain churn diff envelope as
// CSV or PDF for M11-4 (issue #79). Pure formatting layer over
// internal/service/diff — no LLM, no domain persistence.
//
// Audit policy: the diff CSV / PDF download is a deterministic
// representation of data the GET /diff endpoint already exposes, so it
// emits no audit_logs row of its own. The ambient request-level audit
// middleware (path + method + tenant + user) is the only audit trail
// these endpoints need; this matches the rest of the read-back surface
// (GET /sbom, GET /vex/export, etc.).
package diff_export

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/row"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/core/entity"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/sbomhub/sbomhub/internal/assets"
	"github.com/sbomhub/sbomhub/internal/service/diff"
)

// Service renders the diff envelope produced by diff.Service.Compute
// into CSV or PDF bytes.
type Service struct {
	diffSvc *diff.Service
}

// NewService wires the export service over the supply-chain diff
// service. Both renderers share the same Compute() call so the export
// output is byte-for-byte derivable from the diff endpoint's JSON.
func NewService(d *diff.Service) *Service {
	if d == nil {
		panic("diff_export.NewService: diff service is required")
	}
	return &Service{diffSvc: d}
}

// Request bundles the inputs to RenderCSV / RenderPDF. Mirrors
// diff.Request so the export endpoints share the same query string
// contract as GET /diff.
type Request struct {
	TenantID   uuid.UUID
	ProjectID  uuid.UUID
	FromSbomID uuid.UUID
	ToSbomID   uuid.UUID
	// Lang affects PDF heading copy ("ja" | "en", default "en"). The CSV
	// renderer ignores Lang — its column names are stable English ids so
	// downstream tooling (spreadsheets, CI pipelines) does not have to
	// branch on locale.
	Lang string
}

// RenderCSV returns the diff as CSV bytes + a suggested filename.
//
// Schema (1 row per item):
//
//	type, kind, name, version, from_version, to_version, purl,
//	license, cve_id, severity, from_severity, to_severity,
//	component_name, component_version, policy_name
//
// type ∈ {component, vulnerability, license_policy_violation}
// kind ∈ {added, removed, version_changed, resolved, severity_changed}
//
// Unused columns are left empty per-row so the CSV is regular and a
// downstream consumer can `awk -F,` reliably.
func (s *Service) RenderCSV(ctx context.Context, req Request) ([]byte, string, error) {
	d, err := s.diffSvc.Compute(ctx, diff.Request{
		TenantID:   req.TenantID,
		ProjectID:  req.ProjectID,
		FromSbomID: req.FromSbomID,
		ToSbomID:   req.ToSbomID,
	})
	if err != nil {
		return nil, "", err
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{
		"type", "kind", "name", "version", "from_version", "to_version",
		"purl", "license", "cve_id", "severity", "from_severity",
		"to_severity", "component_name", "component_version", "policy_name",
	})

	for _, c := range d.Components.Added {
		_ = w.Write([]string{
			"component", "added", c.Name, c.Version, "", "",
			c.Purl, c.License, "", "", "", "", "", "", "",
		})
	}
	for _, c := range d.Components.Removed {
		_ = w.Write([]string{
			"component", "removed", c.Name, c.Version, "", "",
			c.Purl, c.License, "", "", "", "", "", "", "",
		})
	}
	for _, c := range d.Components.VersionChanged {
		_ = w.Write([]string{
			"component", "version_changed", c.Name, "", c.FromVersion, c.ToVersion,
			c.Purl, "", "", "", "", "", "", "", "",
		})
	}
	for _, v := range d.Vulnerabilities.Added {
		_ = w.Write([]string{
			"vulnerability", "added", "", "", "", "",
			"", "", v.CVEID, v.Severity, "", "",
			v.ComponentName, v.ComponentVersion, "",
		})
	}
	for _, v := range d.Vulnerabilities.Resolved {
		_ = w.Write([]string{
			"vulnerability", "resolved", "", "", "", "",
			"", "", v.CVEID, v.Severity, "", "",
			"", "", "",
		})
	}
	for _, v := range d.Vulnerabilities.SeverityChanged {
		_ = w.Write([]string{
			"vulnerability", "severity_changed", "", "", "", "",
			"", "", v.CVEID, "", v.FromSeverity, v.ToSeverity,
			"", "", "",
		})
	}
	for _, v := range d.Licenses.AddedPolicyViolations {
		_ = w.Write([]string{
			"license_policy_violation", "added", "", "", "", "",
			"", v.License, "", "", "", "",
			v.ComponentName, "", v.PolicyName,
		})
	}
	for _, v := range d.Licenses.RemovedPolicyViolations {
		_ = w.Write([]string{
			"license_policy_violation", "removed", "", "", "", "",
			"", v.License, "", "", "", "",
			v.ComponentName, "", v.PolicyName,
		})
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, "", fmt.Errorf("csv flush: %w", err)
	}

	filename := buildFilename(d, "csv")
	return buf.Bytes(), filename, nil
}

// RenderPDF returns the diff as a single-page PDF + a suggested filename.
//
// Layout: title + from/to header block, then a section per bucket
// (components added/removed/version_changed, vulnerabilities added/
// resolved/severity_changed, license violations added/removed). Each
// section is capped at 50 rows for printability — the CSV is the
// canonical full export.
func (s *Service) RenderPDF(ctx context.Context, req Request) ([]byte, string, error) {
	d, err := s.diffSvc.Compute(ctx, diff.Request{
		TenantID:   req.TenantID,
		ProjectID:  req.ProjectID,
		FromSbomID: req.FromSbomID,
		ToSbomID:   req.ToSbomID,
	})
	if err != nil {
		return nil, "", err
	}

	tr := pickTranslations(req.Lang)

	fontBytes, err := assets.Fonts.ReadFile("fonts/IPAGothic.ttf")
	if err != nil {
		return nil, "", fmt.Errorf("load embedded font: %w", err)
	}
	cfg := config.NewBuilder().
		WithPageNumber().
		WithLeftMargin(15).
		WithTopMargin(15).
		WithRightMargin(15).
		WithCustomFonts([]*entity.CustomFont{
			{Family: "IPAGothic", Style: fontstyle.Normal, Bytes: fontBytes},
			{Family: "IPAGothic", Style: fontstyle.Bold, Bytes: fontBytes},
		}).
		WithDefaultFont(&props.Font{Family: "IPAGothic"}).
		Build()

	m := maroto.New(cfg)

	m.AddRows(pdfTitle(tr.Title))
	m.AddRows(pdfSubtitle(fmt.Sprintf("%s: %s",
		tr.Project, d.ProjectID.String(),
	)))
	m.AddRows(pdfSubtitle(fmt.Sprintf("%s: %s   →   %s: %s",
		tr.From, sbomRefLabel(d.From, tr.Baseline),
		tr.To, sbomRefLabel(d.To, "-"),
	)))
	m.AddRows(pdfSubtitle(fmt.Sprintf("%s: %s",
		tr.GeneratedAt, time.Now().UTC().Format("2006-01-02 15:04 UTC"),
	)))

	// Summary block
	m.AddRows(pdfSectionHeader(tr.Summary))
	m.AddRows(pdfKV(tr.ComponentsAdded, fmt.Sprintf("%d", len(d.Components.Added))))
	m.AddRows(pdfKV(tr.ComponentsRemoved, fmt.Sprintf("%d", len(d.Components.Removed))))
	m.AddRows(pdfKV(tr.ComponentsChanged, fmt.Sprintf("%d", len(d.Components.VersionChanged))))
	m.AddRows(pdfKV(tr.VulnsAdded, fmt.Sprintf("%d", len(d.Vulnerabilities.Added))))
	m.AddRows(pdfKV(tr.VulnsResolved, fmt.Sprintf("%d", len(d.Vulnerabilities.Resolved))))
	m.AddRows(pdfKV(tr.VulnsSeverityChanged, fmt.Sprintf("%d", len(d.Vulnerabilities.SeverityChanged))))
	m.AddRows(pdfKV(tr.LicensesAdded, fmt.Sprintf("%d", len(d.Licenses.AddedPolicyViolations))))
	m.AddRows(pdfKV(tr.LicensesRemoved, fmt.Sprintf("%d", len(d.Licenses.RemovedPolicyViolations))))

	// Components added
	if len(d.Components.Added) > 0 {
		m.AddRows(pdfSectionHeader(tr.ComponentsAdded))
		for i, c := range d.Components.Added {
			if i >= 50 {
				m.AddRows(pdfRowSingle(fmt.Sprintf("… +%d %s", len(d.Components.Added)-50, tr.MoreItems)))
				break
			}
			m.AddRows(pdfKV(c.Name, c.Version))
		}
	}
	if len(d.Components.Removed) > 0 {
		m.AddRows(pdfSectionHeader(tr.ComponentsRemoved))
		for i, c := range d.Components.Removed {
			if i >= 50 {
				m.AddRows(pdfRowSingle(fmt.Sprintf("… +%d %s", len(d.Components.Removed)-50, tr.MoreItems)))
				break
			}
			m.AddRows(pdfKV(c.Name, c.Version))
		}
	}
	if len(d.Components.VersionChanged) > 0 {
		m.AddRows(pdfSectionHeader(tr.ComponentsChanged))
		for i, c := range d.Components.VersionChanged {
			if i >= 50 {
				m.AddRows(pdfRowSingle(fmt.Sprintf("… +%d %s", len(d.Components.VersionChanged)-50, tr.MoreItems)))
				break
			}
			m.AddRows(pdfKV(c.Name, fmt.Sprintf("%s → %s", c.FromVersion, c.ToVersion)))
		}
	}

	// Vulnerabilities
	if len(d.Vulnerabilities.Added) > 0 {
		m.AddRows(pdfSectionHeader(tr.VulnsAdded))
		for i, v := range d.Vulnerabilities.Added {
			if i >= 50 {
				m.AddRows(pdfRowSingle(fmt.Sprintf("… +%d %s", len(d.Vulnerabilities.Added)-50, tr.MoreItems)))
				break
			}
			m.AddRows(pdfKV(v.CVEID, fmt.Sprintf("%s — %s@%s", v.Severity, v.ComponentName, v.ComponentVersion)))
		}
	}
	if len(d.Vulnerabilities.Resolved) > 0 {
		m.AddRows(pdfSectionHeader(tr.VulnsResolved))
		for i, v := range d.Vulnerabilities.Resolved {
			if i >= 50 {
				m.AddRows(pdfRowSingle(fmt.Sprintf("… +%d %s", len(d.Vulnerabilities.Resolved)-50, tr.MoreItems)))
				break
			}
			m.AddRows(pdfKV(v.CVEID, v.Severity))
		}
	}
	if len(d.Vulnerabilities.SeverityChanged) > 0 {
		m.AddRows(pdfSectionHeader(tr.VulnsSeverityChanged))
		for i, v := range d.Vulnerabilities.SeverityChanged {
			if i >= 50 {
				m.AddRows(pdfRowSingle(fmt.Sprintf("… +%d %s", len(d.Vulnerabilities.SeverityChanged)-50, tr.MoreItems)))
				break
			}
			m.AddRows(pdfKV(v.CVEID, fmt.Sprintf("%s → %s", v.FromSeverity, v.ToSeverity)))
		}
	}

	// Licence violations
	if len(d.Licenses.AddedPolicyViolations) > 0 {
		m.AddRows(pdfSectionHeader(tr.LicensesAdded))
		for i, v := range d.Licenses.AddedPolicyViolations {
			if i >= 50 {
				m.AddRows(pdfRowSingle(fmt.Sprintf("… +%d %s", len(d.Licenses.AddedPolicyViolations)-50, tr.MoreItems)))
				break
			}
			m.AddRows(pdfKV(v.ComponentName, fmt.Sprintf("%s — %s", v.License, v.PolicyName)))
		}
	}
	if len(d.Licenses.RemovedPolicyViolations) > 0 {
		m.AddRows(pdfSectionHeader(tr.LicensesRemoved))
		for i, v := range d.Licenses.RemovedPolicyViolations {
			if i >= 50 {
				m.AddRows(pdfRowSingle(fmt.Sprintf("… +%d %s", len(d.Licenses.RemovedPolicyViolations)-50, tr.MoreItems)))
				break
			}
			m.AddRows(pdfKV(v.ComponentName, fmt.Sprintf("%s — %s", v.License, v.PolicyName)))
		}
	}

	doc, gerr := m.Generate()
	if gerr != nil {
		return nil, "", fmt.Errorf("pdf generate: %w", gerr)
	}
	return doc.GetBytes(), buildFilename(d, "pdf"), nil
}

// ---------- translations ----------

type translations struct {
	Title                string
	Project              string
	From                 string
	To                   string
	Baseline             string
	GeneratedAt          string
	Summary              string
	ComponentsAdded      string
	ComponentsRemoved    string
	ComponentsChanged    string
	VulnsAdded           string
	VulnsResolved        string
	VulnsSeverityChanged string
	LicensesAdded        string
	LicensesRemoved      string
	MoreItems            string
}

func pickTranslations(lang string) translations {
	lang = strings.ToLower(strings.TrimSpace(lang))
	if lang == "ja" {
		return translations{
			Title:                "SBOM 差分レポート",
			Project:              "プロジェクト ID",
			From:                 "比較元",
			To:                   "比較先",
			Baseline:             "初回ベースライン",
			GeneratedAt:          "生成日時",
			Summary:              "サマリ",
			ComponentsAdded:      "コンポーネント追加",
			ComponentsRemoved:    "コンポーネント削除",
			ComponentsChanged:    "コンポーネント バージョン変更",
			VulnsAdded:           "脆弱性 新規検出",
			VulnsResolved:        "脆弱性 解消",
			VulnsSeverityChanged: "脆弱性 重大度変更",
			LicensesAdded:        "ライセンス違反 新規",
			LicensesRemoved:      "ライセンス違反 解消",
			MoreItems:            "件 (省略)",
		}
	}
	return translations{
		Title:                "SBOM Diff Report",
		Project:              "Project ID",
		From:                 "From",
		To:                   "To",
		Baseline:             "Initial baseline",
		GeneratedAt:          "Generated at",
		Summary:              "Summary",
		ComponentsAdded:      "Components added",
		ComponentsRemoved:    "Components removed",
		ComponentsChanged:    "Components version-changed",
		VulnsAdded:           "Vulnerabilities added",
		VulnsResolved:        "Vulnerabilities resolved",
		VulnsSeverityChanged: "Vulnerabilities severity changed",
		LicensesAdded:        "License violations added",
		LicensesRemoved:      "License violations resolved",
		MoreItems:            "more (truncated)",
	}
}

// ---------- pdf helpers ----------

func pdfTitle(s string) core.Row {
	return row.New(16).Add(
		col.New(12).Add(text.New(s, props.Text{
			Size: 18, Style: fontstyle.Bold, Align: align.Center, Family: "IPAGothic",
		})),
	)
}

func pdfSubtitle(s string) core.Row {
	return row.New(7).Add(
		col.New(12).Add(text.New(s, props.Text{
			Size: 9, Align: align.Center, Color: &props.Color{Red: 100, Green: 100, Blue: 100}, Family: "IPAGothic",
		})),
	)
}

func pdfSectionHeader(s string) core.Row {
	return row.New(12).Add(
		col.New(12).Add(text.New(s, props.Text{
			Size: 12, Style: fontstyle.Bold, Top: 4, Family: "IPAGothic",
		})),
	)
}

func pdfKV(k, v string) core.Row {
	return row.New(6).Add(
		col.New(6).Add(text.New(k, props.Text{Size: 9, Family: "IPAGothic"})),
		col.New(6).Add(text.New(v, props.Text{Size: 9, Align: align.Right, Family: "IPAGothic"})),
	)
}

func pdfRowSingle(s string) core.Row {
	return row.New(6).Add(
		col.New(12).Add(text.New(s, props.Text{
			Size: 8, Align: align.Right, Color: &props.Color{Red: 120, Green: 120, Blue: 120}, Family: "IPAGothic",
		})),
	)
}

// ---------- filename ----------

func sbomRefLabel(ref *diff.SbomRef, fallback string) string {
	if ref == nil {
		return fallback
	}
	short := ref.SbomID.String()
	if len(short) >= 8 {
		short = short[:8]
	}
	return short
}

func buildFilename(d *diff.Response, ext string) string {
	from := "baseline"
	if d.From != nil {
		from = shortID(d.From.SbomID)
	}
	to := "latest"
	if d.To != nil {
		to = shortID(d.To.SbomID)
	}
	return fmt.Sprintf("sbomhub-diff-%s-%s.%s", from, to, ext)
}

func shortID(id uuid.UUID) string {
	s := id.String()
	if len(s) >= 8 {
		return s[:8]
	}
	return s
}
