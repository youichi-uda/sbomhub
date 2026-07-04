// Package evidence_pack bundles approved AI compliance artefacts
// (approved VEX drafts + approved CRA reports + METI self-assessment)
// into a single downloadable Markdown file. Issue #34 / Wave M2-6
// (initial bundle) + issue #42 / Wave M3-6 (METI section turned from
// placeholder into the live evaluator-driven self-assessment).
//
// Design notes:
//
//   - PRODUCT_REBOOT_PLAN.md §6 defines the Evidence Pack as the
//     primary export surface a Japanese SMB manufacturer hands to an
//     EU CRA auditor: "approved VEX statements + approved CRA reports
//
//   - METI self-assessment, with audit trail". M2-6 shipped the
//     Markdown bundle with VEX + CRA + a METI placeholder; M3-6
//     replaces the placeholder with the live meti_assessments rows
//     produced by the M3-2 evaluator and indexed by the M3-3 catalog.
//
//   - PRODUCT_REBOOT_PLAN.md §8.5 ("AI は下書きまで, 人間が承認する").
//     The bundle therefore consults ONLY rows whose `decision = 'approved'`
//     for VEX / CRA. The METI section is different: it reports the
//     evaluator's verdict (with operator overrides taking precedence
//     when present) — METI self-assessment is not an "approve / reject"
//     drafting workflow, it is a directly-attestable status the
//     operator endorses by including it in the bundle.
//
//   - All reads run inside the request-scoped TenantTx so RLS bounds the
//     SELECT to the caller's tenant. The builder still passes tenantID
//     to the repositories (belt + braces) to mirror the rest of the
//     codebase.
//
//   - The builder does NOT take a *sql.DB. It composes narrow
//     interfaces (VEXDraftReader, CRAReportReader, ProjectReader,
//     METIAssessmentReader, METICatalog) so it can be tested without
//     Postgres and so future callers (M3 job queue, public-link
//     generator) can swap stores without re-implementing the bundle
//     layout.
package evidence_pack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/meti"
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

// METIAssessmentReader is the persistence contract for the
// meti_assessments rows feeding the M3-6 METI section.
// Satisfied by *repository.MetiAssessmentsRepository.ListByProject.
//
// The filter zero-value ("all phases, all statuses, no override
// filter") is what the bundle uses — every criterion present in the
// project's evaluator history is rendered so the auditor sees the
// complete self-assessment.
type METIAssessmentReader interface {
	ListByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter repository.MetiAssessmentListFilter) ([]repository.MetiAssessment, error)
}

// METICatalog resolves human-readable titles / descriptions for
// criteria referenced by meti_assessments rows. Satisfied by the
// meti package's package-level lookups (LoadCatalog / GetCriterion /
// ListByPhase / Phases) via the catalogAdapter constructed in
// cmd/server/main.go.
//
// The interface stays narrow — only the two methods the bundle needs
// (per-phase iteration order + per-id title/description lookup) — so
// future catalog implementations (e.g. tenant-customised criteria)
// can substitute without re-implementing unused helpers.
type METICatalog interface {
	// GetCriterion returns the catalog entry for the given id. The
	// second return is false when the id is not in the catalog (e.g. a
	// row left over from an older catalog revision); the renderer
	// falls back to showing the criterion_id only in that case so a
	// stale row does not break the bundle.
	GetCriterion(id string) (*meti.Criterion, bool)
	// Phases returns the ordered list of valid phases. The bundle
	// renders one sub-section per phase in this order so the auditor
	// always sees env_setup → sbom_creation → sbom_operation
	// (chronological progression of the METI ver 2.0 guidance).
	Phases() []meti.Phase
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
	IncludeVEXApproved    bool
	IncludeCRAApproved    bool
	IncludeMETIAssessment bool

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
	VEXApprovedCount  int
	CRAApprovedCount  int
	METIIncluded      bool
	METIRowCount      int
	METIAchievedCount int
}

// Builder composes the readers into a single Build entrypoint.
type Builder struct {
	vex      VEXDraftReader
	cra      CRAReportReader
	projects ProjectReader
	meti     METIAssessmentReader
	catalog  METICatalog

	// vexExporter renders the CycloneDX VEX document for the zip's
	// vex.cdx.json entry. It is OPTIONAL: the Markdown path never
	// consults it, so existing 5-arg NewBuilder callers keep working.
	// It is injected via WithVEXExporter (see zip.go) and is required
	// only when FormatZip is requested with the VEX section enabled.
	vexExporter VEXExporter
}

// NewBuilder constructs a Builder. nil arguments panic at construction
// so misconfiguration surfaces immediately (matches triage.NewRunner).
//
// metiReader / catalog may be nil ONLY when the operator has disabled
// the METI section globally (M3-6: no current call site does this,
// but allowing nil keeps the constructor backwards-compatible with
// the M2-6 callers in tests that pre-date this wave). When either is
// nil, IncludeMETIAssessment=true will return an error at Build time
// so the misconfiguration cannot silently produce an empty section.
func NewBuilder(
	vex VEXDraftReader,
	cra CRAReportReader,
	projects ProjectReader,
	meti METIAssessmentReader,
	catalog METICatalog,
) *Builder {
	if vex == nil {
		panic("evidence_pack.NewBuilder: vex reader is required")
	}
	if cra == nil {
		panic("evidence_pack.NewBuilder: cra reader is required")
	}
	if projects == nil {
		panic("evidence_pack.NewBuilder: projects reader is required")
	}
	// meti + catalog are deliberately allowed nil at construction so
	// existing test wiring keeps compiling; the Build path checks them
	// at the point of use.
	return &Builder{vex: vex, cra: cra, projects: projects, meti: meti, catalog: catalog}
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
	// FormatZip (F405 / M31) is a NEW render target that reuses the
	// Markdown builder output for its report.md entry (see zip.go);
	// FormatMarkdown remains the pre-existing default behaviour.
	switch in.Format {
	case FormatMarkdown, FormatZip:
		// supported
	default:
		return nil, fmt.Errorf("evidence_pack.Build: unsupported format %q (supported: %q, %q)", in.Format, FormatMarkdown, FormatZip)
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

	// Step 4: fetch METI self-assessment rows. The evaluator stores at
	// most one row per (project, criterion) — for a 32-criterion
	// catalog the fetch is well under the 500-row clamp, so we issue a
	// single ListByProject with the zero filter (all phases, all
	// statuses, all override states).
	var (
		metiRows        []repository.MetiAssessment
		metiFetchAll    bool
		metiAchievedCnt int
	)
	if in.IncludeMETIAssessment {
		if b.meti == nil || b.catalog == nil {
			return nil, fmt.Errorf("evidence_pack.Build: METI assessment requested but reader/catalog not wired (server configuration error)")
		}
		metiRows, err = b.meti.ListByProject(ctx, in.TenantID, in.ProjectID, repository.MetiAssessmentListFilter{
			Limit: 500, // ※要確認: matches metiAssessmentsListMaxLimit; catalog has <30 items today
		})
		if err != nil {
			return nil, fmt.Errorf("evidence_pack.Build: list meti assessments: %w", err)
		}
		metiFetchAll = len(metiRows) < 500
		for i := range metiRows {
			if effectiveStatus(&metiRows[i]) == "achieved" {
				metiAchievedCnt++
			}
		}
	}

	// Step 5: render the Markdown bundle. This byte body is the
	// FormatMarkdown output verbatim AND the zip's report.md entry, so
	// the two formats never drift.
	body := renderMarkdown(renderInput{
		Project:               project,
		Now:                   now,
		IncludeVEXApproved:    in.IncludeVEXApproved,
		IncludeCRAApproved:    in.IncludeCRAApproved,
		IncludeMETIAssessment: in.IncludeMETIAssessment,
		VEXRows:               vexRows,
		CRARows:               craRows,
		METIRows:              metiRows,
		Catalog:               b.catalog,
		VEXTruncated:          !vexFetchAll,
		CRATruncated:          !craFetchAll,
		METITruncated:         in.IncludeMETIAssessment && !metiFetchAll,
	})

	// Step 6: FormatZip assembles the Markdown report plus the
	// machine-readable, integrity-verifiable artefacts into a single
	// zip. FormatMarkdown falls through to the unchanged return below.
	if in.Format == FormatZip {
		return b.assembleZip(ctx, assembleZipInput{
			in:                in,
			now:               now,
			reportMD:          body,
			craRows:           craRows,
			metiRows:          metiRows,
			metiAchievedCount: metiAchievedCnt,
			vexCount:          vexFetchedCount,
			craCount:          craFetchedCount,
		})
	}

	return &BuildResult{
		Format:            FormatMarkdown,
		Filename:          buildFilename(in.ProjectID, now),
		ContentBytes:      body,
		BuiltAt:           now,
		VEXApprovedCount:  vexFetchedCount,
		CRAApprovedCount:  craFetchedCount,
		METIIncluded:      in.IncludeMETIAssessment,
		METIRowCount:      len(metiRows),
		METIAchievedCount: metiAchievedCnt,
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

	IncludeVEXApproved    bool
	IncludeCRAApproved    bool
	IncludeMETIAssessment bool

	VEXRows  []repository.VEXDraft
	CRARows  []repository.CRAReport
	METIRows []repository.MetiAssessment

	// Catalog is consulted for titles / descriptions when rendering
	// METI rows. May be nil when IncludeMETIAssessment is false.
	Catalog METICatalog

	// True when the per-section fetch returned exactly the cap and
	// might have been truncated. Surfaces a warning banner in the
	// bundle so an auditor knows the file may be incomplete.
	VEXTruncated  bool
	CRATruncated  bool
	METITruncated bool
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
	if r.IncludeMETIAssessment {
		writeMETISection(&buf, r)
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
	buf.WriteString("METI 自己評価セクションは評価器 (M3-2) の判定結果を、 ")
	buf.WriteString("運用者の上書き (override) が存在する場合はそれを優先して表示します。 ")
	buf.WriteString("詳細は `PRODUCT_REBOOT_PLAN.md §8.5` (\"AI は下書きまで, 人間が承認する\") を参照。\n\n")
	buf.WriteString("> The VEX statements and CRA report drafts in this bundle were initially generated by SBOMHub's AI triage (LLM) ")
	buf.WriteString("and subsequently **approved by a human reviewer**. Only rows with `decision = 'approved'` are included. ")
	buf.WriteString("Pending / rejected / edited AI output is intentionally excluded. ")
	buf.WriteString("The METI self-assessment section reports the evaluator (M3-2) verdict; an operator override, when present, takes precedence over the evaluator value. ")
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
	if r.IncludeMETIAssessment {
		fmt.Fprintf(buf, "%d. [METI 自己評価 / METI Self-Assessment](#%d-meti-self-assessment) — %d entries\n", idx, idx, len(r.METIRows))
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

// writeMETISection writes Section 3 — the live METI self-assessment.
// M3-6 (issue #42) replaces the M2-6 placeholder with one Markdown
// table per phase, plus an "Improvement Actions" subsection that
// surfaces every criterion whose effective status is not 'achieved'
// so an auditor can scan remediation commitments without paging
// through the full table.
//
// Layout invariants (the regression test pins these):
//   - phases render in catalog order (env_setup → sbom_creation →
//     sbom_operation), even when the input rows are out of order;
//   - within a phase, rows render in criterion_id ASC order (the same
//     order the repository uses for ListByProject so re-builds produce
//     byte-identical output);
//   - status column shows the effective status (override wins over
//     evaluator) with the evaluator-original noted in parens when an
//     override is in effect, so the auditor sees both values;
//   - a row whose criterion_id is not in the catalog falls back to
//     "(unknown criterion)" — the row is still rendered so a stale
//     catalog cannot silently drop attested evidence;
//   - the Improvement Actions subsection lists every non-achieved row
//     in (phase, criterion_id) order so the auditor sees the gaps
//     grouped the same way as the main tables.
func writeMETISection(buf *bytes.Buffer, r renderInput) {
	buf.WriteString("## 3. METI 自己評価 / METI Self-Assessment\n\n")
	buf.WriteString("経済産業省 (METI) 「ソフトウェア管理に向けた SBOM (Software Bill of Materials) ")
	buf.WriteString("の導入に関する手引 ver 2.0」 に基づく自己評価結果です。 ")
	buf.WriteString("SBOMHub の評価器 (M3-2) が SBOM スキャン履歴・脆弱性マッチング履歴・CI 設定から ")
	buf.WriteString("自動評価し、 運用者の override が存在する場合はそれを優先します。\n\n")
	buf.WriteString("> METI ver 2.0 self-assessment results. Auto-evaluated from SBOM scan history, vulnerability matching history, and CI settings by the SBOMHub evaluator (M3-2); operator overrides, when present, take precedence over the evaluator verdict.\n\n")

	if r.METITruncated {
		buf.WriteString("> ⚠️ **Warning**: more than the repository fetch cap (500) METI assessment rows exist for this project. ")
		buf.WriteString("This bundle includes only the first 500 (ordered by phase, criterion_id). ")
		buf.WriteString("The catalog currently ships ~32 criteria so truncation should not occur in practice — investigate any project that triggers this banner.\n\n")
	}

	if len(r.METIRows) == 0 {
		buf.WriteString("_No METI self-assessment rows found for this project. ")
		buf.WriteString("Run `POST /api/v1/projects/:id/meti/assessment/refresh` to populate._\n\n")
		buf.WriteString("---\n\n")
		return
	}

	// Group rows by phase. The repository already orders rows by
	// (criterion_phase ASC, criterion_id ASC) but we re-group locally
	// because (a) we cannot trust the caller to have done so for fake
	// readers in tests, and (b) we want phase iteration to match the
	// catalog's chronological Phases() order even if a stray phase
	// string slipped in.
	byPhase := make(map[meti.Phase][]repository.MetiAssessment, 3)
	for i := range r.METIRows {
		p := meti.Phase(r.METIRows[i].CriterionPhase)
		byPhase[p] = append(byPhase[p], r.METIRows[i])
	}
	for p := range byPhase {
		phaseRows := byPhase[p]
		sort.SliceStable(phaseRows, func(i, j int) bool {
			return phaseRows[i].CriterionID < phaseRows[j].CriterionID
		})
		byPhase[p] = phaseRows
	}

	// Phase iteration: catalog-provided order first (so the bundle
	// matches the UI tab order), then any unknown phases the rows
	// carry, alphabetically, so they still render.
	phaseOrder := []meti.Phase{}
	seen := map[meti.Phase]struct{}{}
	if r.Catalog != nil {
		for _, p := range r.Catalog.Phases() {
			if _, ok := byPhase[p]; ok {
				phaseOrder = append(phaseOrder, p)
				seen[p] = struct{}{}
			}
		}
	}
	extras := []meti.Phase{}
	for p := range byPhase {
		if _, ok := seen[p]; !ok {
			extras = append(extras, p)
		}
	}
	sort.Slice(extras, func(i, j int) bool { return string(extras[i]) < string(extras[j]) })
	phaseOrder = append(phaseOrder, extras...)

	for idx, p := range phaseOrder {
		writeMETIPhaseTable(buf, idx+1, p, byPhase[p], r.Catalog)
	}

	writeMETIImprovementActions(buf, r.METIRows, r.Catalog)
	buf.WriteString("---\n\n")
}

// writeMETIPhaseTable renders one Markdown table for the rows in a
// single phase. The table columns are pinned by the regression test:
//
//	| Criterion | Title (JA / EN) | Status | Evidence | Improvement Action |
//
// "Evidence" is rendered as a compact summary ("N items: kind1, kind2, ...")
// so the row stays one line; the full JSON evidence column would
// explode the table layout (full evidence is intentionally NOT
// rendered inline — auditors who need it consult the
// /meti/assessment API).
func writeMETIPhaseTable(buf *bytes.Buffer, n int, phase meti.Phase, rows []repository.MetiAssessment, catalog METICatalog) {
	// The phase identifier carries underscores that Markdown would
	// otherwise render as emphasis; escape so the heading reads
	// literally. The chapter-pointer suffix is appended raw so the
	// Japanese chapter title stays human-readable.
	fmt.Fprintf(buf, "### 3.%d Phase: %s %s\n\n", n, escapeMD(string(phase)), phaseChapterSuffix(phase))
	if len(rows) == 0 {
		buf.WriteString("_No assessment rows for this phase._\n\n")
		return
	}
	buf.WriteString("| Criterion | Title (JA / EN) | Status | Evidence | Improvement Action |\n")
	buf.WriteString("|-----------|-----------------|--------|----------|--------------------|\n")
	for i := range rows {
		row := &rows[i]
		titleJA, titleEN := metiCriterionTitles(row.CriterionID, catalog)
		fmt.Fprintf(buf, "| `%s` | %s / %s | %s | %s | %s |\n",
			escapeMD(row.CriterionID),
			escapeMD(titleJA),
			escapeMD(titleEN),
			metiStatusCell(row),
			metiEvidenceSummary(row.Evidence),
			metiImprovementCell(row.ImprovementAction),
		)
	}
	buf.WriteString("\n")
}

// writeMETIImprovementActions writes the "Improvement Actions"
// subsection — every row whose effective status is not 'achieved'.
// 'not_applicable' rows are excluded because they represent
// criteria that do not apply to the project, not gaps to remediate.
func writeMETIImprovementActions(buf *bytes.Buffer, rows []repository.MetiAssessment, catalog METICatalog) {
	gaps := make([]repository.MetiAssessment, 0, len(rows))
	for i := range rows {
		s := effectiveStatus(&rows[i])
		if s == "achieved" || s == "not_applicable" {
			continue
		}
		gaps = append(gaps, rows[i])
	}
	sort.SliceStable(gaps, func(i, j int) bool {
		if gaps[i].CriterionPhase != gaps[j].CriterionPhase {
			return gaps[i].CriterionPhase < gaps[j].CriterionPhase
		}
		return gaps[i].CriterionID < gaps[j].CriterionID
	})

	buf.WriteString("### 3.Z Improvement Actions\n\n")
	buf.WriteString("The following criteria have an outstanding remediation gap (effective status != `achieved`, excluding `not_applicable`). ")
	buf.WriteString("`Improvement Action` text is operator-authored when present; an empty cell means the operator has not yet recorded a plan.\n\n")
	if len(gaps) == 0 {
		buf.WriteString("_No outstanding improvement actions — all applicable criteria are `achieved`._\n\n")
		return
	}
	for i := range gaps {
		row := &gaps[i]
		titleJA, _ := metiCriterionTitles(row.CriterionID, catalog)
		fmt.Fprintf(buf, "- **`%s`** (%s) — %s — status: `%s`",
			escapeMD(row.CriterionID),
			escapeMD(row.CriterionPhase),
			escapeMD(titleJA),
			escapeMD(effectiveStatus(row)),
		)
		if strings.TrimSpace(row.ImprovementAction) != "" {
			fmt.Fprintf(buf, "\n  - Improvement action: %s", escapeMDMultiline(row.ImprovementAction))
		} else {
			buf.WriteString("\n  - Improvement action: _(not recorded)_")
		}
		buf.WriteString("\n")
	}
	buf.WriteString("\n")
}

// effectiveStatus returns the operator override when present, else
// the evaluator status. Captures the same "override wins" semantics
// the M3-4 handler uses when rendering the project dashboard so the
// bundle and the dashboard agree on every row.
func effectiveStatus(a *repository.MetiAssessment) string {
	if a.OverrideStatus != "" {
		return a.OverrideStatus
	}
	return a.Status
}

// metiStatusCell renders the Status column of the phase table. When
// an override is in effect we surface both values so the auditor sees
// the evaluator-original alongside the operator decision.
func metiStatusCell(a *repository.MetiAssessment) string {
	if a.OverrideStatus != "" && a.OverrideStatus != a.Status {
		return fmt.Sprintf("`%s` (override; evaluator: `%s`)", escapeMD(a.OverrideStatus), escapeMD(a.Status))
	}
	return fmt.Sprintf("`%s`", escapeMD(effectiveStatus(a)))
}

// metiCriterionTitles looks up the catalog title strings for one
// criterion. Returns ("(unknown criterion)", "(unknown criterion)")
// when the id is not in the catalog so the table cell still renders.
func metiCriterionTitles(criterionID string, catalog METICatalog) (string, string) {
	if catalog == nil {
		return "(catalog unavailable)", "(catalog unavailable)"
	}
	c, ok := catalog.GetCriterion(criterionID)
	if !ok {
		return "(unknown criterion)", "(unknown criterion)"
	}
	return c.TitleJA, c.TitleEN
}

// metiEvidenceSummary renders a one-line summary of the evidence
// JSON array for the Status table. The full JSON is intentionally
// NOT rendered inline (table-width blowup); auditors who need the
// raw evidence consult the /meti/assessment API.
//
// Empty / nil / non-array evidence renders as "—" so the column
// width stays predictable.
func metiEvidenceSummary(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "—"
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return "_(unparseable)_"
	}
	if len(items) == 0 {
		return "—"
	}
	kinds := make([]string, 0, len(items))
	seenKind := map[string]struct{}{}
	for _, it := range items {
		var kv struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(it, &kv); err != nil || kv.Kind == "" {
			continue
		}
		if _, dup := seenKind[kv.Kind]; dup {
			continue
		}
		seenKind[kv.Kind] = struct{}{}
		kinds = append(kinds, kv.Kind)
	}
	sort.Strings(kinds)
	if len(kinds) == 0 {
		return fmt.Sprintf("%d items", len(items))
	}
	return fmt.Sprintf("%d items: %s", len(items), escapeMD(strings.Join(kinds, ", ")))
}

// metiImprovementCell renders the Improvement Action table cell.
// A multi-line improvement action is collapsed to single-line text
// (newlines → " / ") so the row stays one Markdown table row; the
// full text is reproduced in the Improvement Actions subsection.
func metiImprovementCell(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "—"
	}
	collapsed := strings.ReplaceAll(s, "\r\n", "\n")
	collapsed = strings.ReplaceAll(collapsed, "\n", " / ")
	return escapeMD(collapsed)
}

// escapeMDMultiline is escapeMD applied to a body that may contain
// newlines; used in the Improvement Actions subsection where the
// full text is preserved (vs the table cell which collapses to one
// line). Newlines themselves are preserved but indented so the
// rendered bullet keeps its hanging-indent shape.
func escapeMDMultiline(s string) string {
	if s == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = escapeMD(lines[i])
	}
	return strings.Join(lines, "\n    ")
}

// phaseChapterSuffix returns the human-readable chapter pointer for
// one phase. The phase identifier itself is emitted separately so the
// caller can escape it for Markdown without double-escaping the
// Japanese chapter title.
func phaseChapterSuffix(p meti.Phase) string {
	switch p {
	case meti.PhaseEnvSetup:
		return "(環境構築・体制整備 / METI ver 2.0 ch.4)"
	case meti.PhaseSBOMCreation:
		return "(SBOM 作成・共有 / METI ver 2.0 ch.5)"
	case meti.PhaseSBOMOperation:
		return "(SBOM 運用・管理 / METI ver 2.0 ch.6+7)"
	default:
		return ""
	}
}

// writeFooter writes the bundle footer with counts + bundle id.
func writeFooter(buf *bytes.Buffer, r renderInput) {
	buf.WriteString("## Bundle Summary\n\n")
	fmt.Fprintf(buf, "- VEX approved entries: %d\n", len(r.VEXRows))
	fmt.Fprintf(buf, "- CRA approved entries: %d\n", len(r.CRARows))
	fmt.Fprintf(buf, "- METI self-assessment: %s\n", metiSummaryLine(r))
	fmt.Fprintf(buf, "- Generated at: %s (UTC)\n", r.Now.UTC().Format(time.RFC3339))
	buf.WriteString("\n")
	buf.WriteString("_End of Evidence Pack._\n")
}

// metiSummaryLine reports the included / count / achieved tuple for
// the footer. Kept as a helper so the test can pin the exact string.
func metiSummaryLine(r renderInput) string {
	if !r.IncludeMETIAssessment {
		return "omitted from this bundle"
	}
	achieved := 0
	for i := range r.METIRows {
		if effectiveStatus(&r.METIRows[i]) == "achieved" {
			achieved++
		}
	}
	return fmt.Sprintf("included (%d criteria; %d achieved)", len(r.METIRows), achieved)
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
