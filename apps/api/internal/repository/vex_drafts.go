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

// VEXDraft is the in-process representation of one vex_drafts row
// (migration 035, PRODUCT_REBOOT_PLAN.md §8.5, issue #27). Defined
// here rather than under internal/model/ to keep migration #27's
// surface area small; once internal/service/triage/ lands (agent B /
// agent C), this type may be lifted into internal/model alongside
// the other VEX model types.
// ※要確認: relocate to internal/model when service/triage/ stabilises
// the public shape.
type VEXDraft struct {
	ID       uuid.UUID
	TenantID uuid.UUID

	// Soft references -- see migration 035 header. project_id /
	// component_id / vulnerability_id are required; sbom_id is
	// optional.
	ProjectID       uuid.UUID
	SBOMID          *uuid.UUID
	ComponentID     uuid.UUID
	VulnerabilityID uuid.UUID

	CVEID string

	// AI / human VEX content.
	State         string // 'not_affected' | 'affected' | 'under_investigation' | 'resolved'
	Justification string
	Detail        string

	// Calibrated confidence in [0.00, 1.00]. Pointer because hand-
	// authored drafts skip confidence scoring entirely.
	Confidence *float64

	// LLM provenance. Empty strings land as SQL NULL via
	// nullableString so the column reflects "no model attributable"
	// rather than the empty literal.
	Provider     string
	Model        string
	PromptHash   string
	ResponseHash string

	// Evidence: JSONB array of {kind, ref} citations. NOT NULL +
	// CHECK length > 0 at the DB layer enforces the "no AI output
	// without evidence" rule -- the application MUST pass a non-empty
	// array. Local Insert validation catches the empty case before
	// the DB does so the error path is identifiable without parsing
	// pq error codes.
	Evidence json.RawMessage

	// Primary evidence pointers.
	AdvisoryExcerptID    *uuid.UUID
	ReachabilityResultID *uuid.UUID
	LLMCallID            *uuid.UUID

	// Human decision lifecycle. Decision defaults to 'pending' at the
	// DB layer; Insert sets it locally too so the in-memory struct
	// reflects the persisted state.
	Decision     string // 'pending' | 'approved' | 'edited' | 'rejected'
	DecisionBy   *uuid.UUID
	DecisionAt   *time.Time
	DecisionNote string

	CreatedBy *uuid.UUID

	CreatedAt time.Time
	UpdatedAt time.Time
}

// VEXDraftListFilter narrows ListByProject. Zero values mean "do not
// filter on this field"; Limit defaults to listDefaultLimit
// (vexDraftsListDefaultLimit, 100) and is clamped to
// vexDraftsListMaxLimit (500) as defense-in-depth against handler
// misuse (M1 Codex review #F24). Offset defaults to 0.
type VEXDraftListFilter struct {
	CVEID    string
	Decision string
	Limit    int
	Offset   int
}

// Bounds applied by ListByProject. The handler layer has its own
// higher-precedence clamp + 400 reject (handler.DefaultListLimit /
// handler.MaxListLimit) — these constants exist so a misbehaving
// internal caller cannot bypass the handler bound by constructing a
// VEXDraftListFilter directly. Keep these values aligned with the
// handler constants; the package boundary stops us from importing the
// handler symbols directly, so the alignment is asserted by the F24
// regression tests in both packages.
const (
	vexDraftsListDefaultLimit = 100
	vexDraftsListMaxLimit     = 500
)

// VEXDraftDecisionUpdate is the input shape for UpdateDecision. It
// is a separate type from VEXDraft to make it impossible to acci-
// dentally over-write the AI fields (state / confidence / model
// hashes / evidence) when applying a human decision. The /vex/drafts
// handler should only ever be able to flip the decision lifecycle
// fields, not the AI evidence trail.
type VEXDraftDecisionUpdate struct {
	Decision     string    // required: 'approved' | 'edited' | 'rejected'
	DecisionBy   uuid.UUID // required: the user making the decision
	DecisionAt   time.Time // optional: defaults to NOW() if zero
	DecisionNote string    // optional human note
	// EditedState / EditedJustification / EditedDetail apply only
	// when Decision == 'edited'. They overwrite the AI draft fields.
	// For 'approved' / 'rejected' decisions they are ignored. Pointers
	// so the caller can distinguish "do not change" from "set to empty".
	// ※要確認: should an 'approved' decision also be able to overwrite
	// the detail? Design doc currently keeps approved == "AI text is
	// fine, ship it"; an operator who wants to tweak text must use
	// 'edited'. Sticking with that contract until UI feedback says
	// otherwise.
	EditedState         *string
	EditedJustification *string
	EditedDetail        *string
}

// VEXDraftsRepository persists rows in the vex_drafts table. Every
// read and write is tenant-scoped both by the RLS policy installed in
// migration 035 (USING + WITH CHECK on tenant_id) AND by an explicit
// `tenant_id = $N` clause in this file -- same belt + braces
// rationale as AdvisoryExcerptsRepository / ReachabilityResultsRepository /
// LLMCallsRepository.
type VEXDraftsRepository struct {
	db *sql.DB
}

func NewVEXDraftsRepository(db *sql.DB) *VEXDraftsRepository {
	return &VEXDraftsRepository{db: db}
}

// q routes the statement through the request-scoped transaction when
// one is attached to ctx; falls back to r.db otherwise. Joining the
// request tx is what makes `SET LOCAL app.current_tenant_id` visible
// to the INSERT/UPDATE below, which is what makes the RLS WITH CHECK
// pass for legitimate writes.
func (r *VEXDraftsRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// Insert writes one vex_drafts row. The triage runner (agent B) is
// the primary caller; the /vex/drafts seed-from-UI handler is a
// secondary caller that omits provider / model / hashes (those land
// as NULL).
//
// Validation:
//   - TenantID / ProjectID / ComponentID / VulnerabilityID must be
//     non-zero.
//   - CVEID and State must be non-empty. State is CHECK-constrained
//     at the DB layer; we validate locally so the error path is
//     identifiable without parsing pq error codes.
//   - Confidence (if non-nil) must be in [0, 1].
//   - Evidence MUST be a non-empty JSON array. This mirrors the
//     CHECK constraint at the DB layer -- catching it locally turns
//     a pq constraint error into a clearer Go error and short-
//     circuits a round-trip.
//
// If d.ID is the zero UUID, a fresh one is assigned and written
// back. If d.Decision is empty, it defaults to 'pending' to match
// the column default.
func (r *VEXDraftsRepository) Insert(ctx context.Context, d *VEXDraft) error {
	if d == nil {
		return fmt.Errorf("VEXDraftsRepository.Insert: nil VEXDraft")
	}
	if d.TenantID == uuid.Nil {
		return fmt.Errorf("VEXDraftsRepository.Insert: tenant_id is required (RLS + NOT NULL)")
	}
	if d.ProjectID == uuid.Nil {
		return fmt.Errorf("VEXDraftsRepository.Insert: project_id is required")
	}
	if d.ComponentID == uuid.Nil {
		return fmt.Errorf("VEXDraftsRepository.Insert: component_id is required")
	}
	if d.VulnerabilityID == uuid.Nil {
		return fmt.Errorf("VEXDraftsRepository.Insert: vulnerability_id is required")
	}
	if d.CVEID == "" {
		return fmt.Errorf("VEXDraftsRepository.Insert: cve_id is required")
	}
	if d.State == "" {
		return fmt.Errorf("VEXDraftsRepository.Insert: state is required (one of not_affected|affected|under_investigation|resolved)")
	}
	if d.Confidence != nil {
		v := *d.Confidence
		if v < 0 || v > 1 {
			return fmt.Errorf("VEXDraftsRepository.Insert: confidence %f out of range [0,1]", v)
		}
	}
	// Evidence-required gate. The DB CHECK enforces this too, but we
	// trip early so the error is "missing evidence" rather than
	// "check_violation on vex_drafts_evidence_check".
	if !hasNonEmptyJSONArray(d.Evidence) {
		return fmt.Errorf("VEXDraftsRepository.Insert: evidence is required (non-empty JSON array); PRODUCT_REBOOT_PLAN.md §8.5 \"no AI output without evidence\"")
	}
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	if d.Decision == "" {
		d.Decision = "pending"
	}

	const query = `
		INSERT INTO vex_drafts (
			id, tenant_id,
			project_id, sbom_id, component_id, vulnerability_id,
			cve_id,
			state, justification, detail, confidence,
			provider, model, prompt_hash, response_hash,
			evidence,
			advisory_excerpt_id, reachability_result_id, llm_call_id,
			decision, decision_by, decision_at, decision_note,
			created_by,
			created_at, updated_at
		) VALUES (
			$1, $2,
			$3, $4, $5, $6,
			$7,
			$8, $9, $10, $11,
			$12, $13, $14, $15,
			$16,
			$17, $18, $19,
			$20, $21, $22, $23,
			$24,
			NOW(), NOW()
		)
		RETURNING id, created_at, updated_at
	`

	err := r.q(ctx).QueryRowContext(ctx, query,
		d.ID, d.TenantID,
		d.ProjectID, nullableUUID(d.SBOMID), d.ComponentID, d.VulnerabilityID,
		d.CVEID,
		d.State, nullableString(d.Justification), nullableString(d.Detail), nullableFloat(d.Confidence),
		nullableString(d.Provider), nullableString(d.Model),
		nullableString(d.PromptHash), nullableString(d.ResponseHash),
		[]byte(d.Evidence),
		nullableUUID(d.AdvisoryExcerptID), nullableUUID(d.ReachabilityResultID), nullableUUID(d.LLMCallID),
		d.Decision, nullableUUID(d.DecisionBy), nullableTime(d.DecisionAt), nullableString(d.DecisionNote),
		nullableUUID(d.CreatedBy),
	).Scan(&d.ID, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert vex_drafts: %w", err)
	}
	return nil
}

// Get returns the single vex_drafts row for (tenant, id) or
// (nil, nil) if no row exists. tenantID MUST come from the
// authenticated session, never from a user-supplied body --
// otherwise this becomes a cross-tenant disclosure primitive.
func (r *VEXDraftsRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (*VEXDraft, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("VEXDraftsRepository.Get: tenant_id is required")
	}
	if id == uuid.Nil {
		return nil, fmt.Errorf("VEXDraftsRepository.Get: id is required")
	}

	const query = `
		SELECT id, tenant_id,
			project_id, sbom_id, component_id, vulnerability_id,
			cve_id,
			state, justification, detail, confidence,
			provider, model, prompt_hash, response_hash,
			evidence,
			advisory_excerpt_id, reachability_result_id, llm_call_id,
			decision, decision_by, decision_at, decision_note,
			created_by,
			created_at, updated_at
		FROM vex_drafts
		WHERE tenant_id = $1 AND id = $2
	`
	row := r.q(ctx).QueryRowContext(ctx, query, tenantID, id)
	d, err := scanVEXDraftRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query vex_drafts: %w", err)
	}
	return &d, nil
}

// ListByProject returns vex_drafts rows for one project, ordered by
// most-recently-created first for the triage queue UI. Optional
// filters: CVEID, Decision. tenantID MUST come from the
// authenticated session.
func (r *VEXDraftsRepository) ListByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter VEXDraftListFilter) ([]VEXDraft, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("VEXDraftsRepository.ListByProject: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return nil, fmt.Errorf("VEXDraftsRepository.ListByProject: project_id is required")
	}

	// #F24: defense-in-depth pagination bounds. The handler layer
	// already rejects ?limit=<huge> with 400 BEFORE this method runs,
	// but the repo is a reachable surface for any internal caller that
	// builds a VEXDraftListFilter directly (e.g. future report jobs,
	// triage runner re-list helpers). Without this clamp, a caller that
	// trusts user input upstream and forgets to bound it could still
	// trigger the DoS pattern #F24 closed at the handler.
	limit := filter.Limit
	if limit <= 0 {
		limit = vexDraftsListDefaultLimit
	}
	if limit > vexDraftsListMaxLimit {
		limit = vexDraftsListMaxLimit
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	// Build query incrementally so optional filters do not introduce
	// SQL injection vectors via string interpolation. Pattern matches
	// ReachabilityResultsRepository.ListByProject.
	args := []interface{}{tenantID, projectID}
	argIdx := 3
	where := "WHERE tenant_id = $1 AND project_id = $2"
	if filter.CVEID != "" {
		where += fmt.Sprintf(" AND cve_id = $%d", argIdx)
		args = append(args, filter.CVEID)
		argIdx++
	}
	if filter.Decision != "" {
		where += fmt.Sprintf(" AND decision = $%d", argIdx)
		args = append(args, filter.Decision)
		argIdx++
	}

	query := fmt.Sprintf(`
		SELECT id, tenant_id,
			project_id, sbom_id, component_id, vulnerability_id,
			cve_id,
			state, justification, detail, confidence,
			provider, model, prompt_hash, response_hash,
			evidence,
			advisory_excerpt_id, reachability_result_id, llm_call_id,
			decision, decision_by, decision_at, decision_note,
			created_by,
			created_at, updated_at
		FROM vex_drafts
		%s
		ORDER BY created_at DESC, id ASC
		LIMIT $%d OFFSET $%d
	`, where, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := r.q(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query vex_drafts by project: %w", err)
	}
	defer rows.Close()

	out := make([]VEXDraft, 0)
	for rows.Next() {
		d, err := scanVEXDraftRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan vex_drafts row: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate vex_drafts rows: %w", err)
	}
	return out, nil
}

// UpdateDecision applies a human decision to one vex_drafts row. The
// AI evidence trail (state / confidence / model hashes / evidence /
// FK pointers) is preserved UNLESS the decision is 'edited' and the
// caller supplies replacement fields -- in which case the chosen
// columns are overwritten in the same statement.
//
// Validation:
//   - tenantID / id / upd.Decision / upd.DecisionBy must all be set.
//   - Decision must be one of 'approved' | 'edited' | 'rejected'.
//     'pending' is rejected because Insert already defaults to it
//     and there is no UI affordance for "un-decide" a draft.
//
// Returns sql.ErrNoRows wrapped as a typed error when the (tenant, id)
// pair does not match an existing row -- this guards against the
// silent no-op where a handler thinks the decision landed but the
// id was wrong / belonged to a foreign tenant.
func (r *VEXDraftsRepository) UpdateDecision(ctx context.Context, tenantID, id uuid.UUID, upd VEXDraftDecisionUpdate) error {
	if tenantID == uuid.Nil {
		return fmt.Errorf("VEXDraftsRepository.UpdateDecision: tenant_id is required")
	}
	if id == uuid.Nil {
		return fmt.Errorf("VEXDraftsRepository.UpdateDecision: id is required")
	}
	if upd.DecisionBy == uuid.Nil {
		return fmt.Errorf("VEXDraftsRepository.UpdateDecision: decision_by is required (audit trail)")
	}
	switch upd.Decision {
	case "approved", "edited", "rejected":
		// ok
	case "", "pending":
		return fmt.Errorf("VEXDraftsRepository.UpdateDecision: decision must be one of approved|edited|rejected, got %q", upd.Decision)
	default:
		return fmt.Errorf("VEXDraftsRepository.UpdateDecision: unknown decision %q", upd.Decision)
	}

	decisionAt := upd.DecisionAt
	if decisionAt.IsZero() {
		decisionAt = time.Now().UTC()
	}

	// COALESCE($N, state) lets the caller supply NULL for "do not
	// change" -- only meaningful for the edited case but harmless
	// for approved/rejected (we pass nil from the Go side either
	// way). The decision lifecycle columns are unconditionally set
	// so an approved decision after a previous rejected one
	// overwrites the decision_at / decision_note correctly.
	const query = `
		UPDATE vex_drafts SET
			decision      = $3,
			decision_by   = $4,
			decision_at   = $5,
			decision_note = $6,
			state         = COALESCE($7, state),
			justification = COALESCE($8, justification),
			detail        = COALESCE($9, detail),
			updated_at    = NOW()
		WHERE tenant_id = $1 AND id = $2
	`

	res, err := r.q(ctx).ExecContext(ctx, query,
		tenantID, id,
		upd.Decision, upd.DecisionBy, decisionAt, nullableString(upd.DecisionNote),
		nullableStringPtr(upd.EditedState),
		nullableStringPtr(upd.EditedJustification),
		nullableStringPtr(upd.EditedDetail),
	)
	if err != nil {
		return fmt.Errorf("update vex_drafts decision: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update vex_drafts decision (RowsAffected): %w", err)
	}
	if n == 0 {
		// Same shape as sql.ErrNoRows so handlers can errors.Is-check.
		return fmt.Errorf("update vex_drafts decision: %w", sql.ErrNoRows)
	}
	return nil
}

// scanVEXDraftRow scans one vex_drafts row from either *sql.Row or
// *sql.Rows. Uses the shared rowScanner interface from
// advisory_excerpts.go.
func scanVEXDraftRow(rs rowScanner) (VEXDraft, error) {
	var (
		d             VEXDraft
		sbomID        sql.NullString
		justification sql.NullString
		detail        sql.NullString
		confidence    sql.NullFloat64
		provider      sql.NullString
		model         sql.NullString
		promptHash    sql.NullString
		responseHash  sql.NullString
		evidence      []byte
		advisoryID    sql.NullString
		reachID       sql.NullString
		llmCallID     sql.NullString
		decisionBy    sql.NullString
		decisionAt    sql.NullTime
		decisionNote  sql.NullString
		createdBy     sql.NullString
	)
	if err := rs.Scan(
		&d.ID, &d.TenantID,
		&d.ProjectID, &sbomID, &d.ComponentID, &d.VulnerabilityID,
		&d.CVEID,
		&d.State, &justification, &detail, &confidence,
		&provider, &model, &promptHash, &responseHash,
		&evidence,
		&advisoryID, &reachID, &llmCallID,
		&d.Decision, &decisionBy, &decisionAt, &decisionNote,
		&createdBy,
		&d.CreatedAt, &d.UpdatedAt,
	); err != nil {
		return d, err
	}
	if sbomID.Valid {
		if u, err := uuid.Parse(sbomID.String); err == nil {
			d.SBOMID = &u
		}
	}
	if justification.Valid {
		d.Justification = justification.String
	}
	if detail.Valid {
		d.Detail = detail.String
	}
	if confidence.Valid {
		v := confidence.Float64
		d.Confidence = &v
	}
	if provider.Valid {
		d.Provider = provider.String
	}
	if model.Valid {
		d.Model = model.String
	}
	if promptHash.Valid {
		d.PromptHash = promptHash.String
	}
	if responseHash.Valid {
		d.ResponseHash = responseHash.String
	}
	d.Evidence = bytesToJSON(evidence)
	if advisoryID.Valid {
		if u, err := uuid.Parse(advisoryID.String); err == nil {
			d.AdvisoryExcerptID = &u
		}
	}
	if reachID.Valid {
		if u, err := uuid.Parse(reachID.String); err == nil {
			d.ReachabilityResultID = &u
		}
	}
	if llmCallID.Valid {
		if u, err := uuid.Parse(llmCallID.String); err == nil {
			d.LLMCallID = &u
		}
	}
	if decisionBy.Valid {
		if u, err := uuid.Parse(decisionBy.String); err == nil {
			d.DecisionBy = &u
		}
	}
	if decisionAt.Valid {
		t := decisionAt.Time
		d.DecisionAt = &t
	}
	if decisionNote.Valid {
		d.DecisionNote = decisionNote.String
	}
	if createdBy.Valid {
		if u, err := uuid.Parse(createdBy.String); err == nil {
			d.CreatedBy = &u
		}
	}
	return d, nil
}

// hasNonEmptyJSONArray returns true when raw is a JSON array with at
// least one element. The vex_drafts.evidence DB CHECK has the same
// semantics; pre-validating here turns a pq constraint error into a
// clearer Go error.
func hasNonEmptyJSONArray(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return false
	}
	return len(arr) > 0
}

// nullableStringPtr converts a *string to a sql-driver value: nil
// pointer -> NULL (interpreted as "do not change" by COALESCE), set
// pointer -> the string value (including empty string, which the
// COALESCE then treats as a real overwrite to ”). Mirrors
// nullableUUID / nullableTime.
func nullableStringPtr(s *string) interface{} {
	if s == nil {
		return nil
	}
	return *s
}
