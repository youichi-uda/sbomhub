package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
)

// CRAReport is the in-process representation of one cra_reports row
// (migration 038, PRODUCT_REBOOT_PLAN.md §13 M2, issue #35). Defined
// here rather than under internal/model/ to keep migration #35's
// surface area small; once internal/service/cra/ stabilises the
// public shape (M2-3 / M2-4), this type may be lifted into
// internal/model alongside the other CRA model types.
//
// json tags are present on every field because this struct is the
// wire shape the /cra/reports handler (#36 / M2-4) serialises
// directly -- omitting tags here would mean the handler either has
// to define a parallel DTO (drift risk) or expose Go-style PascalCase
// keys to the Web UI. The M1 F28 review showed wire-shape drift
// between repository and handler causes silent UI breakage; we lock
// the JSON shape at the struct definition to prevent that.
// ※要確認: relocate to internal/model when service/cra/ stabilises
// the public shape.
type CRAReport struct {
	ID       uuid.UUID `json:"id"`
	TenantID uuid.UUID `json:"tenant_id"`

	// Soft references -- see migration 038 header. project_id /
	// vulnerability_id are required.
	ProjectID       uuid.UUID `json:"project_id"`
	VulnerabilityID uuid.UUID `json:"vulnerability_id"`

	CVEID string `json:"cve_id"`

	// CRA reporting milestone: 'early_warning' (24h) | 'detailed_notification' (72h) | 'final_report'.
	ReportType string `json:"report_type"`

	// Language: 'ja' | 'en'.
	Lang string `json:"lang"`

	// Publication lifecycle (independent of `Decision`): 'draft' | 'approved' | 'submitted' | 'archived'.
	State string `json:"state"`

	// Rendered report body. Required by the DB (NOT NULL).
	DraftText string `json:"draft_text"`

	// LLM provenance. Empty strings land as SQL NULL via
	// nullableString so the column reflects "no model attributable"
	// rather than the empty literal.
	Provider     string `json:"provider,omitempty"`
	Model        string `json:"model,omitempty"`
	PromptHash   string `json:"prompt_hash,omitempty"`
	ResponseHash string `json:"response_hash,omitempty"`

	// Evidence: JSONB array of {kind, ref} citations. NOT NULL +
	// CHECK length > 0 at the DB layer enforces the "no AI output
	// without evidence" rule -- the application MUST pass a non-
	// empty array. Local Insert validation catches the empty case
	// before the DB does so the error path is identifiable without
	// parsing pq error codes.
	Evidence json.RawMessage `json:"evidence"`

	// Primary evidence pointers.
	SourceVEXDraftID *uuid.UUID `json:"source_vex_draft_id,omitempty"`
	LLMCallID        *uuid.UUID `json:"llm_call_id,omitempty"`

	// Human decision lifecycle (independent of `State`). Decision
	// defaults to 'pending' at the DB layer; Insert sets it locally
	// too so the in-memory struct reflects the persisted state.
	Decision     string     `json:"decision"`
	DecisionBy   *uuid.UUID `json:"decision_by,omitempty"`
	DecisionAt   *time.Time `json:"decision_at,omitempty"`
	DecisionNote string     `json:"decision_note,omitempty"`

	CreatedBy *uuid.UUID `json:"created_by,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CRAReportListFilter narrows ListByProject. Zero values mean "do not
// filter on this field"; Limit defaults to craReportsListDefaultLimit
// (100) and is clamped to craReportsListMaxLimit (500) as defense-
// in-depth against handler misuse (mirrors M1 F24 pattern).
// ※要確認: M2-4 handler (#36) may add more filters (e.g. state,
// report_type). Keeping the surface minimal until the handler scope
// concretises which combinations matter.
type CRAReportListFilter struct {
	CVEID      string
	ReportType string
	Lang       string
	State      string
	Decision   string
	Limit      int
	Offset     int
}

// Bounds applied by ListByProject. Mirrors VEXDraft constants. Aligned
// with the handler constants by convention; the package boundary stops
// us from importing the handler symbols directly, so any drift will
// surface in the handler-side F24-equivalent regression test once
// M2-4 (#36) lands.
const (
	craReportsListDefaultLimit = 100
	craReportsListMaxLimit     = 500
)

// CRAReportDecisionUpdate is the input shape for UpdateDecision. It
// is a separate type from CRAReport to make it impossible to acci-
// dentally over-write the AI fields (report_type / lang / draft_text
// / model hashes / evidence / source pointers) when applying a human
// decision. The /cra/reports handler should only ever be able to
// flip the decision lifecycle fields and (for the 'edited' case) the
// draft_text itself.
//
// EditedDraftText is the one AI field the operator IS allowed to
// rewrite during an 'edited' decision -- the whole point of editing a
// CRA report is to refine the prose before submission. report_type /
// lang / evidence / model hashes stay frozen because those identify
// the artefact's provenance.
//
// Pointer fields use the same "nil pointer == do not change, set
// pointer == overwrite (incl. empty)" contract as
// VEXDraftDecisionUpdate.
type CRAReportDecisionUpdate struct {
	Decision     string    // required: 'approved' | 'edited' | 'rejected'
	DecisionBy   uuid.UUID // required: the user making the decision
	DecisionAt   time.Time // optional: defaults to NOW() if zero
	DecisionNote string    // optional human note

	// EditedDraftText applies only when Decision == 'edited'. It
	// overwrites the AI draft_text column. For 'approved' / 'rejected'
	// decisions it is ignored. Pointer so the caller can distinguish
	// "do not change" from "set to empty".
	// ※要確認: should an 'approved' decision also be able to overwrite
	// draft_text? Current design keeps approved == "AI text is fine,
	// ship it"; an operator who wants to tweak text must use 'edited'.
	// Same contract as VEXDraftDecisionUpdate. Sticking with it until
	// UI feedback says otherwise.
	EditedDraftText *string
}

// CRAReportsRepository persists rows in the cra_reports table. Every
// read and write is tenant-scoped both by the RLS policy installed in
// migration 038 (USING + WITH CHECK on tenant_id) AND by an explicit
// `tenant_id = $N` clause in this file -- same belt + braces
// rationale as AdvisoryExcerptsRepository / ReachabilityResultsRepository /
// LLMCallsRepository / VEXDraftsRepository.
type CRAReportsRepository struct {
	db *sql.DB
}

func NewCRAReportsRepository(db *sql.DB) *CRAReportsRepository {
	return &CRAReportsRepository{db: db}
}

// q routes the statement through the request-scoped transaction when
// one is attached to ctx; falls back to r.db otherwise. Joining the
// request tx is what makes `SET LOCAL app.current_tenant_id` visible
// to the INSERT/UPDATE below, which is what makes the RLS WITH CHECK
// pass for legitimate writes.
func (r *CRAReportsRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// Insert writes one cra_reports row. The CRA report runner (M2-3) is
// the primary caller; a /cra/reports seed-from-UI handler is a
// possible secondary caller that omits provider / model / hashes
// (those land as NULL).
//
// Validation:
//   - TenantID / ProjectID / VulnerabilityID must be non-zero.
//   - CVEID, ReportType, Lang, DraftText must be non-empty. The CHECK
//     constraints at the DB layer also enforce ReportType / Lang
//     allow-lists; we validate locally so the error path is
//     identifiable without parsing pq error codes.
//   - Evidence MUST be a non-empty JSON array. This mirrors the
//     CHECK constraint at the DB layer -- catching it locally turns
//     a pq constraint error into a clearer Go error and short-
//     circuits a round-trip.
//
// If c.ID is the zero UUID, a fresh one is assigned and written
// back. If c.State is empty, it defaults to 'draft' to match the
// column default. If c.Decision is empty, it defaults to 'pending'.
func (r *CRAReportsRepository) Insert(ctx context.Context, c *CRAReport) error {
	if c == nil {
		return fmt.Errorf("CRAReportsRepository.Insert: nil CRAReport")
	}
	if c.TenantID == uuid.Nil {
		return fmt.Errorf("CRAReportsRepository.Insert: tenant_id is required (RLS + NOT NULL)")
	}
	if c.ProjectID == uuid.Nil {
		return fmt.Errorf("CRAReportsRepository.Insert: project_id is required")
	}
	if c.VulnerabilityID == uuid.Nil {
		return fmt.Errorf("CRAReportsRepository.Insert: vulnerability_id is required")
	}
	if c.CVEID == "" {
		return fmt.Errorf("CRAReportsRepository.Insert: cve_id is required")
	}
	if c.ReportType == "" {
		return fmt.Errorf("CRAReportsRepository.Insert: report_type is required (one of early_warning|detailed_notification|final_report)")
	}
	if c.Lang == "" {
		return fmt.Errorf("CRAReportsRepository.Insert: lang is required (one of ja|en)")
	}
	if c.DraftText == "" {
		return fmt.Errorf("CRAReportsRepository.Insert: draft_text is required (NOT NULL)")
	}
	// Evidence-required gate. The DB CHECK enforces this too, but we
	// trip early so the error is "missing evidence" rather than
	// "check_violation on cra_reports_evidence_check".
	if !hasNonEmptyJSONArray(c.Evidence) {
		return fmt.Errorf("CRAReportsRepository.Insert: evidence is required (non-empty JSON array); PRODUCT_REBOOT_PLAN.md §8.5 \"no AI output without evidence\"")
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if c.State == "" {
		c.State = "draft"
	}
	if c.Decision == "" {
		c.Decision = "pending"
	}

	const query = `
		INSERT INTO cra_reports (
			id, tenant_id,
			project_id, vulnerability_id,
			cve_id,
			report_type, lang, state,
			draft_text,
			provider, model, prompt_hash, response_hash,
			evidence,
			source_vex_draft_id, llm_call_id,
			decision, decision_by, decision_at, decision_note,
			created_by,
			created_at, updated_at
		) VALUES (
			$1, $2,
			$3, $4,
			$5,
			$6, $7, $8,
			$9,
			$10, $11, $12, $13,
			$14,
			$15, $16,
			$17, $18, $19, $20,
			$21,
			NOW(), NOW()
		)
		RETURNING id, created_at, updated_at
	`

	err := r.q(ctx).QueryRowContext(ctx, query,
		c.ID, c.TenantID,
		c.ProjectID, c.VulnerabilityID,
		c.CVEID,
		c.ReportType, c.Lang, c.State,
		c.DraftText,
		nullableString(c.Provider), nullableString(c.Model),
		nullableString(c.PromptHash), nullableString(c.ResponseHash),
		[]byte(c.Evidence),
		nullableUUID(c.SourceVEXDraftID), nullableUUID(c.LLMCallID),
		c.Decision, nullableUUID(c.DecisionBy), nullableTime(c.DecisionAt), nullableString(c.DecisionNote),
		nullableUUID(c.CreatedBy),
	).Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert cra_reports: %w", err)
	}
	return nil
}

// Get returns the single cra_reports row for (tenant, id) or
// (nil, nil) if no row exists. tenantID MUST come from the
// authenticated session, never from a user-supplied body --
// otherwise this becomes a cross-tenant disclosure primitive.
func (r *CRAReportsRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (*CRAReport, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("CRAReportsRepository.Get: tenant_id is required")
	}
	if id == uuid.Nil {
		return nil, fmt.Errorf("CRAReportsRepository.Get: id is required")
	}

	const query = `
		SELECT id, tenant_id,
			project_id, vulnerability_id,
			cve_id,
			report_type, lang, state,
			draft_text,
			provider, model, prompt_hash, response_hash,
			evidence,
			source_vex_draft_id, llm_call_id,
			decision, decision_by, decision_at, decision_note,
			created_by,
			created_at, updated_at
		FROM cra_reports
		WHERE tenant_id = $1 AND id = $2
	`
	row := r.q(ctx).QueryRowContext(ctx, query, tenantID, id)
	c, err := scanCRAReportRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query cra_reports: %w", err)
	}
	return &c, nil
}

// ListByProject returns cra_reports rows for one project, ordered by
// most-recently-created first for the /cra/reports queue UI. Optional
// filters: CVEID, ReportType, Lang, State, Decision. tenantID MUST
// come from the authenticated session.
func (r *CRAReportsRepository) ListByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter CRAReportListFilter) ([]CRAReport, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("CRAReportsRepository.ListByProject: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return nil, fmt.Errorf("CRAReportsRepository.ListByProject: project_id is required")
	}

	// Defense-in-depth pagination bounds, same rationale as
	// VEXDraftsRepository.ListByProject (M1 #F24). The handler layer
	// already rejects ?limit=<huge> with 400 BEFORE this method runs,
	// but the repo is a reachable surface for any internal caller that
	// builds a CRAReportListFilter directly (e.g. M2-6 evidence pack
	// bundler in issue #34). Without this clamp, a caller that trusts
	// user input upstream and forgets to bound it could still trigger
	// the DoS pattern.
	limit := filter.Limit
	if limit <= 0 {
		limit = craReportsListDefaultLimit
	}
	if limit > craReportsListMaxLimit {
		limit = craReportsListMaxLimit
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	// Build query incrementally so optional filters do not introduce
	// SQL injection vectors via string interpolation. Pattern matches
	// VEXDraftsRepository.ListByProject.
	args := []interface{}{tenantID, projectID}
	argIdx := 3
	where := "WHERE tenant_id = $1 AND project_id = $2"
	if filter.CVEID != "" {
		where += fmt.Sprintf(" AND cve_id = $%d", argIdx)
		args = append(args, filter.CVEID)
		argIdx++
	}
	if filter.ReportType != "" {
		where += fmt.Sprintf(" AND report_type = $%d", argIdx)
		args = append(args, filter.ReportType)
		argIdx++
	}
	if filter.Lang != "" {
		where += fmt.Sprintf(" AND lang = $%d", argIdx)
		args = append(args, filter.Lang)
		argIdx++
	}
	if filter.State != "" {
		where += fmt.Sprintf(" AND state = $%d", argIdx)
		args = append(args, filter.State)
		argIdx++
	}
	if filter.Decision != "" {
		where += fmt.Sprintf(" AND decision = $%d", argIdx)
		args = append(args, filter.Decision)
		argIdx++
	}

	query := fmt.Sprintf(`
		SELECT id, tenant_id,
			project_id, vulnerability_id,
			cve_id,
			report_type, lang, state,
			draft_text,
			provider, model, prompt_hash, response_hash,
			evidence,
			source_vex_draft_id, llm_call_id,
			decision, decision_by, decision_at, decision_note,
			created_by,
			created_at, updated_at
		FROM cra_reports
		%s
		ORDER BY created_at DESC, id ASC
		LIMIT $%d OFFSET $%d
	`, where, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := r.q(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query cra_reports by project: %w", err)
	}
	defer rows.Close()

	out := make([]CRAReport, 0)
	for rows.Next() {
		c, err := scanCRAReportRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan cra_reports row: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cra_reports rows: %w", err)
	}
	return out, nil
}

// CountByProject returns the total cra_reports row count matching the
// project + filter combination, ignoring pagination. M1 F28 pattern:
// the /cra/reports handler (M2-4, #36) emits this as the X-Total-Count
// header so the Web UI (M2-5, #32) can render "N / total 件" and trip
// a "more than one page" warning banner when total > limit.
//
// The filter shape must match ListByProject so the two queries return
// adjudicated cardinalities on the same units (avoiding the M1 #F29
// regression class where COUNT and SELECT used different join shapes).
func (r *CRAReportsRepository) CountByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter CRAReportListFilter) (int, error) {
	if tenantID == uuid.Nil {
		return 0, fmt.Errorf("CRAReportsRepository.CountByProject: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return 0, fmt.Errorf("CRAReportsRepository.CountByProject: project_id is required")
	}

	args := []interface{}{tenantID, projectID}
	argIdx := 3
	where := "WHERE tenant_id = $1 AND project_id = $2"
	if filter.CVEID != "" {
		where += fmt.Sprintf(" AND cve_id = $%d", argIdx)
		args = append(args, filter.CVEID)
		argIdx++
	}
	if filter.ReportType != "" {
		where += fmt.Sprintf(" AND report_type = $%d", argIdx)
		args = append(args, filter.ReportType)
		argIdx++
	}
	if filter.Lang != "" {
		where += fmt.Sprintf(" AND lang = $%d", argIdx)
		args = append(args, filter.Lang)
		argIdx++
	}
	if filter.State != "" {
		where += fmt.Sprintf(" AND state = $%d", argIdx)
		args = append(args, filter.State)
		argIdx++
	}
	if filter.Decision != "" {
		where += fmt.Sprintf(" AND decision = $%d", argIdx)
		args = append(args, filter.Decision)
		argIdx++
	}

	query := fmt.Sprintf(`SELECT COUNT(*) FROM cra_reports %s`, where)
	var n int
	if err := r.q(ctx).QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("count cra_reports by project: %w", err)
	}
	return n, nil
}

// UpdateDecision applies a human decision to one cra_reports row. The
// AI evidence trail (report_type / lang / model hashes / evidence /
// FK pointers) is preserved UNCONDITIONALLY -- only the decision
// lifecycle fields and, for the 'edited' case, the draft_text itself
// may be overwritten.
//
// State-machine guard (M2 Codex review #F31): the UPDATE only matches
// rows whose current decision is 'pending'. Previously an already
// approved / rejected / edited report could be re-decided, and an
// approved report's draft_text could be silently overwritten via a
// follow-up decision='edited' call (COALESCE($7, draft_text) treats a
// non-nil EditedDraftText as an overwrite). With the guard in place
// any re-decision attempt returns sql.ErrNoRows so the handler can
// surface a 409 ("already decided") instead of silently rewriting
// compliance evidence. The state column (draft / approved / submitted
// / archived) is intentionally NOT guarded here — it's the
// publication lifecycle, not the decision lifecycle, and a separate
// submit endpoint will own those transitions.
//
// Validation:
//   - tenantID / id / upd.Decision / upd.DecisionBy must all be set.
//   - Decision must be one of 'approved' | 'edited' | 'rejected'.
//     'pending' is rejected because Insert already defaults to it
//     and there is no UI affordance for "un-decide" a draft.
//
// Returns sql.ErrNoRows wrapped as a typed error when the UPDATE
// matches zero rows. After the F31 guard, that happens in either of
// two cases:
//  1. (tenant, id) does not match any existing row (wrong id /
//     foreign tenant).
//  2. The row exists but its current decision is not 'pending'
//     (already decided — re-decision rejected).
//
// Handlers that load the report first (loadReportScoped) can
// disambiguate by inspecting the report's prior decision; bare
// callers should treat ErrNoRows as "could not apply decision" and
// surface a 409 to the operator.
func (r *CRAReportsRepository) UpdateDecision(ctx context.Context, tenantID, id uuid.UUID, upd CRAReportDecisionUpdate) error {
	if tenantID == uuid.Nil {
		return fmt.Errorf("CRAReportsRepository.UpdateDecision: tenant_id is required")
	}
	if id == uuid.Nil {
		return fmt.Errorf("CRAReportsRepository.UpdateDecision: id is required")
	}
	if upd.DecisionBy == uuid.Nil {
		return fmt.Errorf("CRAReportsRepository.UpdateDecision: decision_by is required (audit trail)")
	}
	switch upd.Decision {
	case "approved", "edited", "rejected":
		// ok
	case "", "pending":
		return fmt.Errorf("CRAReportsRepository.UpdateDecision: decision must be one of approved|edited|rejected, got %q", upd.Decision)
	default:
		return fmt.Errorf("CRAReportsRepository.UpdateDecision: unknown decision %q", upd.Decision)
	}

	decisionAt := upd.DecisionAt
	if decisionAt.IsZero() {
		decisionAt = time.Now().UTC()
	}

	// COALESCE($N, draft_text) lets the caller supply NULL for "do
	// not change" -- only meaningful for the edited case but harmless
	// for approved/rejected (we pass nil from the Go side either
	// way). The decision lifecycle columns are unconditionally set
	// so an approved decision after a previous rejected one would
	// overwrite decision_at / decision_note correctly -- HOWEVER, the
	// `decision = 'pending'` guard below means an already-decided
	// report cannot reach this code path at all (returns ErrNoRows
	// instead, which the handler surfaces as 409). The 'pending'
	// literal is intentionally inline (not a bind parameter) so the
	// argument count stays at 7 and the mock-based unit tests do not
	// have to add a placeholder. M2 Codex review #F31 state-machine
	// guard.
	const query = `
		UPDATE cra_reports SET
			decision      = $3,
			decision_by   = $4,
			decision_at   = $5,
			decision_note = $6,
			draft_text    = COALESCE($7, draft_text),
			updated_at    = NOW()
		WHERE tenant_id = $1 AND id = $2 AND decision = 'pending'
	`

	res, err := r.q(ctx).ExecContext(ctx, query,
		tenantID, id,
		upd.Decision, upd.DecisionBy, decisionAt, nullableString(upd.DecisionNote),
		nullableStringPtr(upd.EditedDraftText),
	)
	if err != nil {
		return fmt.Errorf("update cra_reports decision: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update cra_reports decision (RowsAffected): %w", err)
	}
	if n == 0 {
		// Same shape as sql.ErrNoRows so handlers can errors.Is-check.
		return fmt.Errorf("update cra_reports decision: %w", sql.ErrNoRows)
	}
	return nil
}

// MarkSubmitted flips one cra_reports row from its current publication
// state to 'submitted'. This is the state transition migration 038
// (:86-96) deliberately deferred to the application layer: it is the
// publication lifecycle, NOT the decision lifecycle, and is written by
// the (manual) submission-record action -- the Record path in the Wave B
// (F419) handler, inside the SAME TenantTx that INSERTs the
// cra_submissions row and emits the cra_submission_recorded audit row.
// Reaching this method is what first makes cra_reports.state='submitted'
// attainable in prod (the dead 'submitted' UI is otherwise unreachable).
//
// The `AND decision = 'approved'` guard is belt-and-braces with the
// handler's approved-only 409 gate: only an approved report is
// submittable ("humans approve before submit"). A rejected / pending /
// edited report is never flipped, even if a caller bypasses the handler.
//
// Idempotent by construction: the guard matches on decision, not state,
// so re-submitting an already-'submitted' approved report matches the
// same row and keeps state='submitted' (an incident produces many
// submissions over its Art.14 timeline). n == 0 is therefore NOT an
// error here -- unlike UpdateDecision, whose zero-rows case signals
// "already decided" and is surfaced as a 409. Here zero rows can only
// mean wrong id / foreign tenant / non-approved report, all of which the
// handler has already gated; a stray zero-row UPDATE is a tolerated
// no-op, not a failure. We still read RowsAffected so a driver-side
// RowsAffected error is surfaced.
func (r *CRAReportsRepository) MarkSubmitted(ctx context.Context, tenantID, reportID uuid.UUID) error {
	if tenantID == uuid.Nil {
		return fmt.Errorf("CRAReportsRepository.MarkSubmitted: tenant_id is required")
	}
	if reportID == uuid.Nil {
		return fmt.Errorf("CRAReportsRepository.MarkSubmitted: id is required")
	}

	const query = `
		UPDATE cra_reports SET
			state      = 'submitted',
			updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND decision = 'approved'
	`

	res, err := r.q(ctx).ExecContext(ctx, query, tenantID, reportID)
	if err != nil {
		return fmt.Errorf("update cra_reports state (mark submitted): %w", err)
	}
	if _, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("update cra_reports state (mark submitted, RowsAffected): %w", err)
	}
	// n == 0 is a tolerated idempotent no-op (see doc comment); the
	// handler's approved-only guard is the authoritative check.
	return nil
}

// scanCRAReportRow scans one cra_reports row from either *sql.Row or
// *sql.Rows. Uses the shared rowScanner interface from
// advisory_excerpts.go.
func scanCRAReportRow(rs rowScanner) (CRAReport, error) {
	var (
		c              CRAReport
		provider       sql.NullString
		model          sql.NullString
		promptHash     sql.NullString
		responseHash   sql.NullString
		evidence       []byte
		sourceVEXDraft sql.NullString
		llmCallID      sql.NullString
		decisionBy     sql.NullString
		decisionAt     sql.NullTime
		decisionNote   sql.NullString
		createdBy      sql.NullString
	)
	if err := rs.Scan(
		&c.ID, &c.TenantID,
		&c.ProjectID, &c.VulnerabilityID,
		&c.CVEID,
		&c.ReportType, &c.Lang, &c.State,
		&c.DraftText,
		&provider, &model, &promptHash, &responseHash,
		&evidence,
		&sourceVEXDraft, &llmCallID,
		&c.Decision, &decisionBy, &decisionAt, &decisionNote,
		&createdBy,
		&c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return c, err
	}
	if provider.Valid {
		c.Provider = provider.String
	}
	if model.Valid {
		c.Model = model.String
	}
	if promptHash.Valid {
		c.PromptHash = promptHash.String
	}
	if responseHash.Valid {
		c.ResponseHash = responseHash.String
	}
	c.Evidence = bytesToJSON(evidence)
	if sourceVEXDraft.Valid {
		if u, err := uuid.Parse(sourceVEXDraft.String); err == nil {
			c.SourceVEXDraftID = &u
		}
	}
	if llmCallID.Valid {
		if u, err := uuid.Parse(llmCallID.String); err == nil {
			c.LLMCallID = &u
		}
	}
	if decisionBy.Valid {
		if u, err := uuid.Parse(decisionBy.String); err == nil {
			c.DecisionBy = &u
		}
	}
	if decisionAt.Valid {
		t := decisionAt.Time
		c.DecisionAt = &t
	}
	if decisionNote.Valid {
		c.DecisionNote = decisionNote.String
	}
	if createdBy.Valid {
		if u, err := uuid.Parse(createdBy.String); err == nil {
			c.CreatedBy = &u
		}
	}
	return c, nil
}
