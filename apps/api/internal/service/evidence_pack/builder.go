// Package evidence_pack bundles approved AI compliance artefacts
// (approved VEX drafts + approved CRA reports + METI self-assessment
// placeholder) into a single downloadable Markdown file. Issue #34 /
// Wave M2-6.
//
// Design notes:
//
//   - PRODUCT_REBOOT_PLAN.md §6 defines the Evidence Pack as the
//     primary export surface a Japanese SMB manufacturer hands to an
//     EU CRA auditor: "approved VEX statements + approved CRA reports
//     + METI self-assessment, with audit trail". M2-6 ships the
//     Markdown bundle; PDF + Zip + background-job + public-link
//     handoff are deferred to M3 (issue #34 Acceptance Criteria).
//
//   - PRODUCT_REBOOT_PLAN.md §8.5 ("AI は下書きまで, 人間が承認する").
//     The bundle therefore consults ONLY rows whose `decision = 'approved'`.
//     Pending / rejected / edited drafts are never included — surfacing
//     unapproved AI text to an auditor would invert the entire spec.
//
//   - All reads run inside the request-scoped TenantTx so RLS bounds the
//     SELECT to the caller's tenant. The builder still passes tenantID
//     to the repositories (belt + braces) to mirror the rest of the
//     codebase.
//
//   - The builder does NOT take a *sql.DB. It composes narrow
//     interfaces (VEXDraftReader, CRAReportReader, ProjectReader) so
//     it can be tested without Postgres and so future callers (M3 job
//     queue, public-link generator) can swap stores without
//     re-implementing the bundle layout.
package evidence_pack

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// FormatMarkdown is the only format M2-6 supports. PDF + Zip ship in
// M3 (issue #34 Acceptance Criteria). The constant exists so callers
// (handler, tests) reference a single source of truth.
const FormatMarkdown = "markdown"

// VEXDraftReader is the persistence contract for approved VEX drafts.
// Satisfied by *repository.VEXDraftsRepository.ListByProject — kept
// as an interface so the builder unit test can pass an in-memory fake
// (no Postgres). Same pattern as triage.VexDraftStore.
type VEXDraftReader interface {
	ListByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter repository.VEXDraftListFilter) ([]repository.VEXDraft, error)
}

// CRAReportReader is the persistence contract for approved CRA reports.
// Satisfied by *repository.CRAReportsRepository.ListByProject.
type CRAReportReader interface {
	ListByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter repository.CRAReportListFilter) ([]repository.CRAReport, error)
}

// ProjectReader resolves project metadata for the bundle header.
// Satisfied by *repository.ProjectRepository.GetByTenant.
//
// We deliberately use GetByTenant rather than Get so the lookup is
// scoped against the caller's tenant — defence-in-depth alongside RLS.
// A missing / cross-tenant project surfaces as (nil, sql.ErrNoRows)
// which the handler maps to 404.
type ProjectReader interface {
	GetByTenant(ctx context.Context, tenantID, projectID uuid.UUID) (*model.Project, error)
}

// BuildInput is the request payload for Builder.Build.
//
// All three Include* booleans default to true semantics at the
// handler layer (POST body with empty include_* booleans should
// still produce a complete bundle). The handler is responsible for
// supplying the defaults so the builder stays a pure transform.
// ※要確認: handler defaulting is intentional — once the UI grows
// per-section toggles the handler can stop forcing true.
type BuildInput struct {
	TenantID  uuid.UUID
	ProjectID uuid.UUID

	// Section toggles. Default behaviour at the handler layer is "true,
	// true, true" — produce a complete bundle. False omits the
	// corresponding section entirely (header / TOC / footer adapt).
	IncludeVEXApproved     bool
	IncludeCRAApproved     bool
	IncludeMETIPlaceholder bool

	// Format must be FormatMarkdown for M2-6. The handler rejects
	// other values with 400 before the builder runs.
	Format string

	// Now is overridable for tests; defaults to time.Now().UTC() at
	// build time. Captured here (not at Build start) so the audit
	// payload, filename, and bundle header all share one timestamp.
	Now time.Time
}

// BuildResult is what Builder.Build returns.
//
// ContentBytes is the rendered Markdown body. The handler writes it
// directly to the HTTP response with Content-Type: text/markdown and
// Content-Disposition: attachment; filename="<Filename>".
type BuildResult struct {
	Format       string
	Filename     string
	ContentBytes []byte
	BuiltAt      time.Time

	// Counts of artefacts included, surfaced so the handler can mirror
	// them into the audit_log row without re-parsing the Markdown.
	VEXApprovedCount int
	CRAApprovedCount int
	METIIncluded     bool
}

// Builder composes the three readers into a single Build entrypoint.
type Builder struct {
	vex      VEXDraftReader
	cra      CRAReportReader
	projects ProjectReader
}

// NewBuilder constructs a Builder. nil arguments panic at construction
// so misconfiguration surfaces immediately (matches triage.NewRunner).
func NewBuilder(vex VEXDraftReader, cra CRAReportReader, projects ProjectReader) *Builder {
	if vex == nil {
		panic("evidence_pack.NewBuilder: vex reader is required")
	}
	if cra == nil {
		panic("evidence_pack.NewBuilder: cra reader is required")
	}
	if projects == nil {
		panic("evidence_pack.NewBuilder: projects reader is required")
	}
	return &Builder{vex: vex, cra: cra, projects: projects}
}

// Build renders the Markdown bundle.
//
// Error contract:
//   - missing TenantID / ProjectID / unsupported Format → input error
//     (caller maps to 400)
//   - project not found in tenant scope → ProjectReader returns
//     sql.ErrNoRows, which the caller maps to 404 (handler does this
//     via errors.Is on the wrapped err)
//   - repository failure → wrapped (caller maps to 500)
func (b *Builder) Build(ctx context.Context, in BuildInput) (*BuildResult, error) {
	if in.TenantID == uuid.Nil {
		return nil, fmt.Errorf("evidence_pack.Build: tenant_id is required")
	}
	if in.ProjectID == uuid.Nil {
		return nil, fmt.Errorf("evidence_pack.Build: project_id is required")
	}
	if in.Format == "" {
		in.Format = FormatMarkdown
	}
	if in.Format != FormatMarkdown {
		return nil, fmt.Errorf("evidence_pack.Build: unsupported format %q (M2-6 supports %q only; PDF/Zip ship in M3)", in.Format, FormatMarkdown)
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// Step 1: resolve project metadata so the bundle header carries the
	// human-readable name + description. GetByTenant enforces tenant
	// scope as defence-in-depth; RLS does the same at the SQL layer.
	project, err := b.projects.GetByTenant(ctx, in.TenantID, in.ProjectID)
	if err != nil {
		// sql.ErrNoRows is propagated verbatim so the handler can do
		// errors.Is(err, sql.ErrNoRows) → 404. Anything else is wrapped.
		return nil, fmt.Errorf("evidence_pack.Build: resolve project: %w", err)
	}
	if project == nil {
		// GetByTenant returns sql.ErrNoRows on miss in current impl; this
		// nil-check guards against future impls that swallow ErrNoRows.
		return nil, fmt.Errorf("evidence_pack.Build: project not found in tenant scope")
	}

	// Step 2: fetch approved VEX drafts (decision='approved' only).
	// Reading the entire approved set inline is intentional for MVP —
	// the orchestrator note in issue #34 says "large project でも数十
	// sec 想定". Background-job + paged streaming is M3.
	// ※要確認: MaxListLimit (500) from repository is the per-call cap.
	// A project with >500 approved VEX rows would silently truncate
	// here; M3 should either paginate within the builder or raise the
	// cap. Tracked in TODO below.
	var (
		vexRows         []repository.VEXDraft
		vexFetchAll     bool
		vexFetchedCount int
	)
	if in.IncludeVEXApproved {
		// Pull up to the repository max in one call. The handler-side
		// pagination cap (handler.MaxListLimit = 500) does NOT apply
		// here because this is an internal caller — but we are still
		// bounded by the repository-side clamp. Documented in
		// repository/vex_drafts.go const vexDraftsListMaxLimit.
		vexRows, err = b.vex.ListByProject(ctx, in.TenantID, in.ProjectID, repository.VEXDraftListFilter{
			Decision: "approved",
			Limit:    500, // ※要確認: matches vexDraftsListMaxLimit; M3 should paginate
		})
		if err != nil {
			return nil, fmt.Errorf("evidence_pack.Build: list approved vex drafts: %w", err)
		}
		vexFetchedCount = len(vexRows)
		// "fetched all" is true when the repository returned fewer rows
		// than the cap; if it returned exactly the cap there MAY be more.
		vexFetchAll = vexFetchedCount < 500
		// Stable ordering: created_at DESC, id ASC matches the
		// repository's ORDER BY so subsequent re-builds produce the
		// same byte output (audit-friendly).
		sort.SliceStable(vexRows, func(i, j int) bool {
			if !vexRows[i].CreatedAt.Equal(vexRows[j].CreatedAt) {
				return vexRows[i].CreatedAt.After(vexRows[j].CreatedAt)
			}
			return vexRows[i].ID.String() < vexRows[j].ID.String()
		})
	}

	// Step 3: fetch approved CRA reports.
	var (
		craRows         []repository.CRAReport
		craFetchAll     bool
		craFetchedCount int
	)
	if in.IncludeCRAApproved {
		craRows, err = b.cra.ListByProject(ctx, in.TenantID, in.ProjectID, repository.CRAReportListFilter{
			Decision: "approved",
			Limit:    500, // ※要確認: matches craReportsListMaxLimit
		})
		if err != nil {
			return nil, fmt.Errorf("evidence_pack.Build: list approved cra reports: %w", err)
		}
		craFetchedCount = len(craRows)
		craFetchAll = craFetchedCount < 500
		sort.SliceStable(craRows, func(i, j int) bool {
			if !craRows[i].CreatedAt.Equal(craRows[j].CreatedAt) {
				return craRows[i].CreatedAt.After(craRows[j].CreatedAt)
			}
			return craRows[i].ID.String() < craRows[j].ID.String()
		})
	}

	// Step 4: render the bundle.
	body := renderMarkdown(renderInput{
		Project:                project,
		Now:                    now,
		IncludeVEXApproved:     in.IncludeVEXApproved,
		IncludeCRAApproved:     in.IncludeCRAApproved,
		IncludeMETIPlaceholder: in.IncludeMETIPlaceholder,
		VEXRows:                vexRows,
		CRARows:                craRows,
		VEXTruncated:           !vexFetchAll,
		CRATruncated:           !craFetchAll,
	})

	return &BuildResult{
		Format:           FormatMarkdown,
		Filename:         buildFilename(in.ProjectID, now),
		ContentBytes:     body,
		BuiltAt:          now,
		VEXApprovedCount: vexFetchedCount,
		CRAApprovedCount: craFetchedCount,
		METIIncluded:     in.IncludeMETIPlaceholder,
	}, nil
}

// buildFilename produces the download filename per orchestrator spec:
// "evidence-pack-<project_id-short>-<YYYYMMDD-HHMMSS>.md".
//
// project_id-short = first 8 chars of the UUID (matches the convention
// used in the public-link UI for human-friendly identifiers).
func buildFilename(projectID uuid.UUID, now time.Time) string {
	short := projectID.String()
	if len(short) > 8 {
		short = short[:8]
	}
	return fmt.Sprintf("evidence-pack-%s-%s.md", short, now.UTC().Format("20060102-150405"))
}

// ----------------------------------------------------------------------------
// Markdown rendering
// ----------------------------------------------------------------------------

type renderInput struct {
	Project *model.Project
	Now     time.Time

	IncludeVEXApproved     bool
	IncludeCRAApproved     bool
	IncludeMETIPlaceholder bool

	VEXRows []repository.VEXDraft
	CRARows []repository.CRAReport

	// True when the per-section fetch returned exactly the cap and
	// might have been truncated. Surfaces a warning banner in the
	// bundle so an auditor knows the file may be incomplete.
	VEXTruncated bool
	CRATruncated bool
}

// renderMarkdown returns the byte body of the bundle. The layout is
// deliberately deterministic: header → legal disclaimer → TOC →
// sections in fixed order → footer. Section ordering is fixed
// (VEX → CRA → METI) so an auditor reading multiple bundles never has
// to hunt for the section they want.
func renderMarkdown(r renderInput) []byte {
	var buf bytes.Buffer

	writeHeader(&buf, r)
	writeDisclaimer(&buf)
	writeTOC(&buf, r)

	if r.IncludeVEXApproved {
		writeVEXSection(&buf, r)
	}
	if r.IncludeCRAApproved {
		writeCRASection(&buf, r)
	}
	if r.IncludeMETIPlaceholder {
		writeMETIPlaceholderSection(&buf)
	}

	writeFooter(&buf, r)
	return buf.Bytes()
}

// writeHeader writes the H1 + metadata block.
func writeHeader(buf *bytes.Buffer, r renderInput) {
	projName := "(unnamed project)"
	projDesc := ""
	if r.Project != nil {
		if r.Project.Name != "" {
			projName = r.Project.Name
		}
		projDesc = r.Project.Description
	}

	fmt.Fprintf(buf, "# SBOMHub AI Compliance Evidence Pack\n\n")
	fmt.Fprintf(buf, "**Project**: %s\n\n", projName)
	if projDesc != "" {
		fmt.Fprintf(buf, "**Description**: %s\n\n", projDesc)
	}
	if r.Project != nil {
		fmt.Fprintf(buf, "**Project ID**: `%s`\n\n", r.Project.ID.String())
	}
	fmt.Fprintf(buf, "**Generated at**: %s (UTC)\n\n", r.Now.UTC().Format(time.RFC3339))
	fmt.Fprintf(buf, "**Bundle format**: Markdown (M2-6; PDF/Zip ship in M3)\n\n")
	fmt.Fprintf(buf, "**Source**: SBOMHub https://github.com/youichi-uda/sbomhub\n\n")
	buf.WriteString("---\n\n")
}

// writeDisclaimer writes the legal "AI is draft only" banner required
// by PRODUCT_REBOOT_PLAN.md §8.5. This is load-bearing for the
// product positioning ("AI drafts only. Humans approve.") and MUST
// remain at the top of every bundle so an auditor reading the file
// sees it before any AI-generated text.
func writeDisclaimer(buf *bytes.Buffer) {
	buf.WriteString("## 法的免責 / Legal Disclaimer\n\n")
	buf.WriteString("本バンドルに含まれる VEX ステートメントおよび CRA 報告書ドラフトは、 ")
	buf.WriteString("SBOMHub の AI トリアージ機能 (LLM) が生成した **下書き** を、 ")
	buf.WriteString("人間のレビュアーが **承認** したものです。 ")
	buf.WriteString("`decision = 'approved'` の行のみがバンドル対象であり、 ")
	buf.WriteString("AI が生成したまま未承認のドラフト (pending / rejected / edited) は含まれません。 ")
	buf.WriteString("詳細は `PRODUCT_REBOOT_PLAN.md §8.5` (\"AI は下書きまで, 人間が承認する\") を参照。\n\n")
	buf.WriteString("> The VEX statements and CRA report drafts in this bundle were initially generated by SBOMHub's AI triage (LLM) ")
	buf.WriteString("and subsequently **approved by a human reviewer**. Only rows with `decision = 'approved'` are included. ")
	buf.WriteString("Pending / rejected / edited AI output is intentionally excluded. ")
	buf.WriteString("See PRODUCT_REBOOT_PLAN.md §8.5 (\"AI drafts only. Humans approve.\").\n\n")
	buf.WriteString("---\n\n")
}

// writeTOC writes a TOC listing every section that will follow.
func writeTOC(buf *bytes.Buffer, r renderInput) {
	buf.WriteString("## Table of Contents\n\n")
	idx := 1
	if r.IncludeVEXApproved {
		fmt.Fprintf(buf, "%d. [Approved VEX Statements](#%d-approved-vex-statements) — %d entries\n", idx, idx, len(r.VEXRows))
		idx++
	}
	if r.IncludeCRAApproved {
		fmt.Fprintf(buf, "%d. [Approved CRA Reports](#%d-approved-cra-reports) — %d entries\n", idx, idx, len(r.CRARows))
		idx++
	}
	if r.IncludeMETIPlaceholder {
		fmt.Fprintf(buf, "%d. [METI 自己評価 / METI Self-Assessment](#%d-meti-self-assessment-placeholder) — placeholder (M3)\n", idx, idx)
		idx++
	}
	buf.WriteString("\n---\n\n")
}

// writeVEXSection writes Section 1.
func writeVEXSection(buf *bytes.Buffer, r renderInput) {
	buf.WriteString("## 1. Approved VEX Statements\n\n")
	buf.WriteString("VEX (Vulnerability Exploitability eXchange) statements describe whether a vulnerability is exploitable in this project. ")
	buf.WriteString("Each entry below was AI-drafted and human-approved (`decision = 'approved'`).\n\n")

	if r.VEXTruncated {
		buf.WriteString("> ⚠️ **Warning**: more than the repository fetch cap (500) approved VEX drafts exist for this project. ")
		buf.WriteString("This bundle includes only the most recently created 500. ")
		buf.WriteString("Full export will land in M3 (paged background job).\n\n")
	}

	if len(r.VEXRows) == 0 {
		buf.WriteString("_No approved VEX drafts found for this project._\n\n")
		buf.WriteString("---\n\n")
		return
	}

	for i := range r.VEXRows {
		writeVEXEntry(buf, i+1, &r.VEXRows[i])
	}
	buf.WriteString("---\n\n")
}

// writeVEXEntry renders one approved VEX row.
func writeVEXEntry(buf *bytes.Buffer, n int, d *repository.VEXDraft) {
	fmt.Fprintf(buf, "### 1.%d %s — %s\n\n", n, escapeMD(d.CVEID), escapeMD(d.State))
	fmt.Fprintf(buf, "- **Draft ID**: `%s`\n", d.ID.String())
	fmt.Fprintf(buf, "- **Component ID**: `%s`\n", d.ComponentID.String())
	fmt.Fprintf(buf, "- **Vulnerability ID**: `%s`\n", d.VulnerabilityID.String())
	fmt.Fprintf(buf, "- **State**: `%s`\n", escapeMD(d.State))
	if d.Justification != "" {
		fmt.Fprintf(buf, "- **Justification**: `%s`\n", escapeMD(d.Justification))
	}
	if d.Confidence != nil {
		fmt.Fprintf(buf, "- **AI confidence**: %.2f\n", *d.Confidence)
	}
	if d.Provider != "" || d.Model != "" {
		fmt.Fprintf(buf, "- **LLM provenance**: provider=`%s` model=`%s`\n", escapeMD(d.Provider), escapeMD(d.Model))
	}
	if d.PromptHash != "" {
		fmt.Fprintf(buf, "- **Prompt hash**: `%s`\n", escapeMD(d.PromptHash))
	}
	if d.ResponseHash != "" {
		fmt.Fprintf(buf, "- **Response hash**: `%s`\n", escapeMD(d.ResponseHash))
	}
	fmt.Fprintf(buf, "- **Approved at**: %s\n", formatTimePtr(d.DecisionAt))
	if d.DecisionBy != nil {
		fmt.Fprintf(buf, "- **Approved by (user id)**: `%s`\n", d.DecisionBy.String())
	}
	if d.DecisionNote != "" {
		fmt.Fprintf(buf, "- **Approval note**: %s\n", escapeMD(d.DecisionNote))
	}
	fmt.Fprintf(buf, "- **Created at**: %s\n", d.CreatedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(buf, "- **Updated at**: %s\n\n", d.UpdatedAt.UTC().Format(time.RFC3339))

	if d.Detail != "" {
		buf.WriteString("**Detail**:\n\n")
		writeFencedBlock(buf, d.Detail)
	}

	if len(d.Evidence) > 0 {
		buf.WriteString("**Evidence** (JSON):\n\n")
		writeFencedJSON(buf, d.Evidence)
	}

	buf.WriteString("\n")
}

// writeCRASection writes Section 2.
func writeCRASection(buf *bytes.Buffer, r renderInput) {
	buf.WriteString("## 2. Approved CRA Reports\n\n")
	buf.WriteString("EU Cyber Resilience Act (CRA) vulnerability report drafts: 24h early warning, 72h detailed notification, and final report. ")
	buf.WriteString("Each entry below was AI-drafted and human-approved (`decision = 'approved'`). ")
	buf.WriteString("**No CRA report is auto-submitted** — submission to ENISA / national CSIRT remains a human decision.\n\n")

	if r.CRATruncated {
		buf.WriteString("> ⚠️ **Warning**: more than the repository fetch cap (500) approved CRA reports exist for this project. ")
		buf.WriteString("This bundle includes only the most recently created 500. ")
		buf.WriteString("Full export will land in M3 (paged background job).\n\n")
	}

	if len(r.CRARows) == 0 {
		buf.WriteString("_No approved CRA reports found for this project._\n\n")
		buf.WriteString("---\n\n")
		return
	}

	for i := range r.CRARows {
		writeCRAEntry(buf, i+1, &r.CRARows[i])
	}
	buf.WriteString("---\n\n")
}

// writeCRAEntry renders one approved CRA report row.
func writeCRAEntry(buf *bytes.Buffer, n int, c *repository.CRAReport) {
	fmt.Fprintf(buf, "### 2.%d %s — %s (%s)\n\n", n, escapeMD(c.CVEID), escapeMD(c.ReportType), escapeMD(c.Lang))
	fmt.Fprintf(buf, "- **Report ID**: `%s`\n", c.ID.String())
	fmt.Fprintf(buf, "- **Vulnerability ID**: `%s`\n", c.VulnerabilityID.String())
	fmt.Fprintf(buf, "- **Report type**: `%s` (one of early_warning [24h] | detailed_notification [72h] | final_report)\n", escapeMD(c.ReportType))
	fmt.Fprintf(buf, "- **Language**: `%s`\n", escapeMD(c.Lang))
	fmt.Fprintf(buf, "- **Publication state**: `%s`\n", escapeMD(c.State))
	if c.Provider != "" || c.Model != "" {
		fmt.Fprintf(buf, "- **LLM provenance**: provider=`%s` model=`%s`\n", escapeMD(c.Provider), escapeMD(c.Model))
	}
	if c.PromptHash != "" {
		fmt.Fprintf(buf, "- **Prompt hash**: `%s`\n", escapeMD(c.PromptHash))
	}
	if c.ResponseHash != "" {
		fmt.Fprintf(buf, "- **Response hash**: `%s`\n", escapeMD(c.ResponseHash))
	}
	fmt.Fprintf(buf, "- **Approved at**: %s\n", formatTimePtr(c.DecisionAt))
	if c.DecisionBy != nil {
		fmt.Fprintf(buf, "- **Approved by (user id)**: `%s`\n", c.DecisionBy.String())
	}
	if c.DecisionNote != "" {
		fmt.Fprintf(buf, "- **Approval note**: %s\n", escapeMD(c.DecisionNote))
	}
	if c.SourceVEXDraftID != nil {
		fmt.Fprintf(buf, "- **Source VEX draft**: `%s`\n", c.SourceVEXDraftID.String())
	}
	fmt.Fprintf(buf, "- **Created at**: %s\n", c.CreatedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(buf, "- **Updated at**: %s\n\n", c.UpdatedAt.UTC().Format(time.RFC3339))

	buf.WriteString("**Draft text**:\n\n")
	writeFencedBlock(buf, c.DraftText)

	if len(c.Evidence) > 0 {
		buf.WriteString("**Evidence** (JSON):\n\n")
		writeFencedJSON(buf, c.Evidence)
	}

	buf.WriteString("\n")
}

// writeMETIPlaceholderSection writes the M3 placeholder per the
// orchestrator spec ("METI 自己評価は M3 placeholder (空セクション +
// 「(M3 で実装予定)」表記)").
func writeMETIPlaceholderSection(buf *bytes.Buffer) {
	buf.WriteString("## 3. METI 自己評価 / METI Self-Assessment (placeholder)\n\n")
	buf.WriteString("経済産業省 (METI) ソフトウェア管理に向けたガイダンスの自己評価項目を、 ")
	buf.WriteString("SBOM スキャン履歴・CI 設定・脆弱性マッチング履歴から自動充填するセクション。\n\n")
	buf.WriteString("> 🚧 **(M3 で実装予定)** — `PRODUCT_REBOOT_PLAN.md §13 M3` (METI 自己評価 prefill)。 ")
	buf.WriteString("本ウェーブ (M2-6) では VEX + CRA のみをバンドルし、 METI 項目は次マイルストンで追加します。\n\n")
	buf.WriteString("> 🚧 **(Planned for M3)** — see `PRODUCT_REBOOT_PLAN.md §13 M3` (METI self-assessment prefill). ")
	buf.WriteString("M2-6 bundles VEX + CRA only; METI items land in the next milestone.\n\n")
	buf.WriteString("---\n\n")
}

// writeFooter writes the bundle footer with counts + bundle id.
func writeFooter(buf *bytes.Buffer, r renderInput) {
	buf.WriteString("## Bundle Summary\n\n")
	fmt.Fprintf(buf, "- VEX approved entries: %d\n", len(r.VEXRows))
	fmt.Fprintf(buf, "- CRA approved entries: %d\n", len(r.CRARows))
	fmt.Fprintf(buf, "- METI self-assessment: %s\n", metiStatus(r.IncludeMETIPlaceholder))
	fmt.Fprintf(buf, "- Generated at: %s (UTC)\n", r.Now.UTC().Format(time.RFC3339))
	buf.WriteString("\n")
	buf.WriteString("_End of Evidence Pack._\n")
}

func metiStatus(included bool) string {
	if included {
		return "placeholder (M3 で実装予定 / planned for M3)"
	}
	return "omitted from this bundle"
}

// ----------------------------------------------------------------------------
// Markdown helpers
// ----------------------------------------------------------------------------

// escapeMD escapes the Markdown special characters that could break
// rendering when interpolated as inline text. We keep the set
// intentionally small: only chars that materially change the rendered
// output (backtick → code escape, pipe → table break, asterisk +
// underscore → emphasis). Backslash leads so the rest do not
// double-escape.
//
// This is NOT an XSS sanitiser — bundles are rendered by external
// auditors using their own Markdown viewers, not by our web UI.
// ※要確認: if M3 ships an in-app bundle viewer, revisit this with a
// real Markdown serializer (e.g. blackfriday writer).
func escapeMD(s string) string {
	if s == "" {
		return s
	}
	r := strings.NewReplacer(
		"\\", `\\`,
		"`", "\\`",
		"|", `\|`,
		"*", `\*`,
		"_", `\_`,
	)
	return r.Replace(s)
}

// writeFencedBlock writes a fenced text block with the given body.
// We pick four backticks as the fence so the block can safely contain
// triple-backtick code fences (common in LLM-drafted detail strings).
func writeFencedBlock(buf *bytes.Buffer, body string) {
	buf.WriteString("````\n")
	buf.WriteString(body)
	if !strings.HasSuffix(body, "\n") {
		buf.WriteString("\n")
	}
	buf.WriteString("````\n\n")
}

// writeFencedJSON writes the raw JSON bytes inside a json fenced
// block. Same four-backtick fence as writeFencedBlock so the same
// caller pattern works.
func writeFencedJSON(buf *bytes.Buffer, body []byte) {
	buf.WriteString("````json\n")
	buf.Write(body)
	if len(body) == 0 || body[len(body)-1] != '\n' {
		buf.WriteString("\n")
	}
	buf.WriteString("````\n\n")
}

// formatTimePtr renders a nullable timestamp. Empty string when nil.
func formatTimePtr(t *time.Time) string {
	if t == nil {
		return "(not recorded)"
	}
	return t.UTC().Format(time.RFC3339)
}
