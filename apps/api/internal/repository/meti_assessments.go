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

// MetiAssessment is the in-process representation of one
// meti_assessments row (migration 039, PRODUCT_REBOOT_PLAN.md §13 M3,
// issue #41). Defined here rather than under internal/model/ to keep
// migration #41's surface area small; once internal/service/meti/
// stabilises the public shape (M3-2 / M3-3), this type may be lifted
// into internal/model alongside the other METI model types.
//
// json tags are present on every field because this struct is the
// wire shape the /meti/assessment handler (M3-4 / #37) serialises
// directly -- omitting tags here would mean the handler either has to
// define a parallel DTO (drift risk) or expose Go-style PascalCase
// keys to the Web UI. The M1 F28 review showed wire-shape drift
// between repository and handler causes silent UI breakage; we lock
// the JSON shape at the struct definition to prevent that.
// ※要確認: relocate to internal/model when service/meti/ stabilises
// the public shape.
type MetiAssessment struct {
	ID       uuid.UUID `json:"id"`
	TenantID uuid.UUID `json:"tenant_id"`

	// Soft reference -- see migration 039 header. project_id is
	// required.
	ProjectID uuid.UUID `json:"project_id"`

	// METI criterion identifier (catalog-driven, M3-3 / #39).
	CriterionID string `json:"criterion_id"`

	// METI 手引 ver 2.0 phase: env_setup | sbom_creation | sbom_operation.
	CriterionPhase string `json:"criterion_phase"`

	// Evaluator verdict: achieved | not_achieved | needs_review | not_applicable.
	Status string `json:"status"`

	// Evidence: JSONB array of {kind, ref} or {kind, value} citations.
	// NOT NULL at the DB layer; CHECK requires jsonb_array_length >= 0
	// (i.e. "must be a JSON array", empty arrays are explicitly OK for
	// not_applicable / needs_review rows). Repository defaults a
	// missing array to '[]' so the application never trips the NOT
	// NULL by omitting Evidence on a needs_review write.
	Evidence json.RawMessage `json:"evidence"`

	// Evaluator provenance. Semver string. Nullable for hand-seeded rows.
	EvaluatorVersion string `json:"evaluator_version,omitempty"`

	// When the evaluator wrote this row. Re-evaluation overwrites via
	// Upsert.
	EvaluatedAt time.Time `json:"evaluated_at"`

	// Operator override layer. Nil/empty when no override has been
	// applied. The override_status state-machine guard (F31 pattern)
	// at the OverrideStatus method ensures re-override goes through an
	// explicit clear-first path the handler controls.
	OverrideStatus string     `json:"override_status,omitempty"`
	OverrideBy     *uuid.UUID `json:"override_by,omitempty"`
	OverrideAt     *time.Time `json:"override_at,omitempty"`
	OverrideNote   string     `json:"override_note,omitempty"`

	// Operator-authored remediation plan. Independent from override.
	ImprovementAction string `json:"improvement_action,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// MetiAssessmentListFilter narrows ListByProject. Zero values mean
// "do not filter on this field"; Limit defaults to
// metiAssessmentsListDefaultLimit (100) and is clamped to
// metiAssessmentsListMaxLimit (500) as defense-in-depth against
// handler misuse (mirrors M1 F24 pattern).
type MetiAssessmentListFilter struct {
	CriterionPhase string
	Status         string
	HasOverride    *bool // nil = no filter, true = override_status IS NOT NULL, false = IS NULL
	Limit          int
	Offset         int
}

// Bounds applied by ListByProject. Mirrors the CRA / VEX constants.
// Aligned with the handler constants by convention; the package
// boundary stops us from importing the handler symbols directly, so
// any drift will surface in the handler-side F24-equivalent regression
// test once M3-4 (#37) lands.
const (
	metiAssessmentsListDefaultLimit = 100
	metiAssessmentsListMaxLimit     = 500
)

// MetiAssessmentOverrideInput is the input shape for OverrideStatus.
// It is a separate type from MetiAssessment to make it impossible to
// accidentally over-write the evaluator-owned fields (status /
// evidence / evaluator_version / evaluated_at) when applying an
// operator override. The /meti/assessment/:criterion_id/override
// handler (M3-4 / #37) should only ever be able to flip the override_*
// lifecycle fields and (optionally) the improvement_action plan.
//
// The OverrideStatus value is REQUIRED -- a clear-override operation
// is intentionally a separate handler path (M3-4 spec) to keep the
// audit trail explicit ("operator cleared override" is a distinct
// event from "operator set override to X").
type MetiAssessmentOverrideInput struct {
	OverrideStatus string    // required: 'achieved' | 'not_achieved' | 'needs_review' | 'not_applicable'
	OverrideBy     uuid.UUID // required: the user applying the override (audit trail)
	OverrideAt     time.Time // optional: defaults to NOW() if zero
	OverrideNote   string    // optional human note (handler-layer may require non-empty)

	// ImprovementAction applies when the operator wants to attach a
	// remediation plan alongside the override. Pointer so the caller
	// can distinguish "do not change" (nil) from "set to empty"
	// (pointer to ""). Mirrors the CRA EditedDraftText contract.
	ImprovementAction *string
}

// MetiAssessmentsRepository persists rows in the meti_assessments
// table. Every read and write is tenant-scoped both by the RLS policy
// installed in migration 039 (USING + WITH CHECK on tenant_id) AND by
// an explicit `tenant_id = $N` clause in this file -- same belt +
// braces rationale as AdvisoryExcerptsRepository /
// ReachabilityResultsRepository / LLMCallsRepository /
// VEXDraftsRepository / CRAReportsRepository.
type MetiAssessmentsRepository struct {
	db *sql.DB
}

func NewMetiAssessmentsRepository(db *sql.DB) *MetiAssessmentsRepository {
	return &MetiAssessmentsRepository{db: db}
}

// q routes the statement through the request-scoped transaction when
// one is attached to ctx; falls back to r.db otherwise. Joining the
// request tx is what makes `SET LOCAL app.current_tenant_id` visible
// to the INSERT/UPDATE below, which is what makes the RLS WITH CHECK
// pass for legitimate writes.
func (r *MetiAssessmentsRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// Upsert writes one meti_assessments row, ON CONFLICT
// (tenant_id, project_id, criterion_id) DO UPDATE so re-evaluation
// overwrites the previous evaluator verdict. The override_* fields
// are NOT touched by Upsert: a re-evaluation cycle preserves the
// operator's prior override (the override is meant to survive
// re-evaluation; if the operator wants to drop it, they go through
// the clear-override handler path -- M3-4 / #37).
//
// Validation:
//   - TenantID / ProjectID must be non-zero.
//   - CriterionID, CriterionPhase, Status must be non-empty. The
//     CHECK constraints at the DB layer also enforce the allow-lists;
//     we validate locally so the error path is identifiable without
//     parsing pq error codes.
//   - Evidence: a nil / empty json.RawMessage is normalised to '[]'
//     (NOT NULL at the DB) so callers can omit evidence for
//     not_applicable / needs_review rows without tripping the CHECK.
//     A non-array shape (object / scalar) is rejected locally because
//     jsonb_array_length raises on non-arrays at the DB and the local
//     guard turns the error into a clearer message.
//
// If a.ID is the zero UUID, a fresh one is assigned and written
// back. If a.Status is empty, it defaults to 'needs_review' to match
// the column default. EvaluatedAt defaults to NOW() at the DB if
// zero.
func (r *MetiAssessmentsRepository) Upsert(ctx context.Context, a *MetiAssessment) error {
	if a == nil {
		return fmt.Errorf("MetiAssessmentsRepository.Upsert: nil MetiAssessment")
	}
	if a.TenantID == uuid.Nil {
		return fmt.Errorf("MetiAssessmentsRepository.Upsert: tenant_id is required (RLS + NOT NULL)")
	}
	if a.ProjectID == uuid.Nil {
		return fmt.Errorf("MetiAssessmentsRepository.Upsert: project_id is required")
	}
	if a.CriterionID == "" {
		return fmt.Errorf("MetiAssessmentsRepository.Upsert: criterion_id is required")
	}
	if a.CriterionPhase == "" {
		return fmt.Errorf("MetiAssessmentsRepository.Upsert: criterion_phase is required (one of env_setup|sbom_creation|sbom_operation)")
	}
	if a.Status == "" {
		a.Status = "needs_review"
	}
	// Evidence: normalise nil / empty to '[]' so the NOT NULL DEFAULT
	// is satisfied by an explicit value. Non-array shapes are rejected.
	// jsonbOrEmptyArray (advisory_excerpts.go) handles the nil case;
	// we then guard against the non-array shapes the DB CHECK would
	// trip on.
	ev := jsonbOrEmptyArray(a.Evidence)
	if !isJSONArray(ev) {
		return fmt.Errorf("MetiAssessmentsRepository.Upsert: evidence must be a JSON array (got non-array shape); empty '[]' is OK for not_applicable / needs_review rows")
	}
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}

	// ON CONFLICT (tenant_id, project_id, criterion_id) DO UPDATE
	// rewrites the evaluator-owned columns ONLY. The override_*
	// columns + improvement_action are NOT mentioned in the SET clause
	// so a re-evaluation preserves the operator's prior override --
	// dropping the override is an explicit handler action (M3-4 / #37).
	// updated_at always moves to NOW(); created_at is preserved by
	// virtue of not being in the SET clause.
	const query = `
		INSERT INTO meti_assessments (
			id, tenant_id, project_id,
			criterion_id, criterion_phase,
			status, evidence,
			evaluator_version, evaluated_at,
			created_at, updated_at
		) VALUES (
			$1, $2, $3,
			$4, $5,
			$6, $7,
			$8, COALESCE($9, NOW()),
			NOW(), NOW()
		)
		ON CONFLICT (tenant_id, project_id, criterion_id) DO UPDATE SET
			criterion_phase   = EXCLUDED.criterion_phase,
			status            = EXCLUDED.status,
			evidence          = EXCLUDED.evidence,
			evaluator_version = EXCLUDED.evaluator_version,
			evaluated_at      = EXCLUDED.evaluated_at,
			updated_at        = NOW()
		RETURNING id, evaluated_at, created_at, updated_at
	`

	var evaluatedAtArg interface{}
	if a.EvaluatedAt.IsZero() {
		evaluatedAtArg = nil // -> COALESCE NOW()
	} else {
		evaluatedAtArg = a.EvaluatedAt
	}

	err := r.q(ctx).QueryRowContext(ctx, query,
		a.ID, a.TenantID, a.ProjectID,
		a.CriterionID, a.CriterionPhase,
		a.Status, ev,
		nullableString(a.EvaluatorVersion), evaluatedAtArg,
	).Scan(&a.ID, &a.EvaluatedAt, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upsert meti_assessments: %w", err)
	}
	return nil
}

// Get returns the single meti_assessments row for
// (tenant, project, criterion) or (nil, nil) if no row exists.
// tenantID MUST come from the authenticated session, never from a
// user-supplied body -- otherwise this becomes a cross-tenant
// disclosure primitive.
//
// Lookup is on the UNIQUE (tenant_id, project_id, criterion_id) key,
// not on id, because the dominant caller (the M3-4 handler) holds
// the composite key from the URL path and does not yet know the row's
// surrogate UUID.
func (r *MetiAssessmentsRepository) Get(ctx context.Context, tenantID, projectID uuid.UUID, criterionID string) (*MetiAssessment, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("MetiAssessmentsRepository.Get: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return nil, fmt.Errorf("MetiAssessmentsRepository.Get: project_id is required")
	}
	if criterionID == "" {
		return nil, fmt.Errorf("MetiAssessmentsRepository.Get: criterion_id is required")
	}

	const query = `
		SELECT id, tenant_id, project_id,
			criterion_id, criterion_phase,
			status, evidence,
			evaluator_version, evaluated_at,
			override_status, override_by, override_at, override_note,
			improvement_action,
			created_at, updated_at
		FROM meti_assessments
		WHERE tenant_id = $1 AND project_id = $2 AND criterion_id = $3
	`
	row := r.q(ctx).QueryRowContext(ctx, query, tenantID, projectID, criterionID)
	a, err := scanMetiAssessmentRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query meti_assessments: %w", err)
	}
	return &a, nil
}

// ListByProject returns meti_assessments rows for one project, ordered
// by (criterion_phase ASC, criterion_id ASC) so the UI's tabbed
// three-phase matrix can render deterministically without a client-
// side sort. tenantID MUST come from the authenticated session.
//
// Optional filters: CriterionPhase, Status, HasOverride. The
// CountByProject sibling MUST keep the WHERE shape identical so
// X-Total-Count and the page length adjudicate on the same units
// (M1 F29 regression class).
func (r *MetiAssessmentsRepository) ListByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter MetiAssessmentListFilter) ([]MetiAssessment, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("MetiAssessmentsRepository.ListByProject: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return nil, fmt.Errorf("MetiAssessmentsRepository.ListByProject: project_id is required")
	}

	// Defense-in-depth pagination bounds, same rationale as
	// VEXDraftsRepository.ListByProject (M1 #F24) and
	// CRAReportsRepository.ListByProject. The handler layer already
	// rejects ?limit=<huge> with 400 BEFORE this method runs, but the
	// repo is a reachable surface for any internal caller that builds
	// a MetiAssessmentListFilter directly (e.g. the M3-6 Evidence
	// Pack METI-section builder, issue #42). Without this clamp, a
	// caller that trusts user input upstream and forgets to bound it
	// could still trigger the DoS pattern.
	limit := filter.Limit
	if limit <= 0 {
		limit = metiAssessmentsListDefaultLimit
	}
	if limit > metiAssessmentsListMaxLimit {
		limit = metiAssessmentsListMaxLimit
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	where, args := buildMetiAssessmentWhere(tenantID, projectID, filter)
	argIdx := len(args) + 1

	query := fmt.Sprintf(`
		SELECT id, tenant_id, project_id,
			criterion_id, criterion_phase,
			status, evidence,
			evaluator_version, evaluated_at,
			override_status, override_by, override_at, override_note,
			improvement_action,
			created_at, updated_at
		FROM meti_assessments
		%s
		ORDER BY criterion_phase ASC, criterion_id ASC
		LIMIT $%d OFFSET $%d
	`, where, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := r.q(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query meti_assessments by project: %w", err)
	}
	defer rows.Close()

	out := make([]MetiAssessment, 0)
	for rows.Next() {
		a, err := scanMetiAssessmentRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan meti_assessments row: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate meti_assessments rows: %w", err)
	}
	return out, nil
}

// CountByProject returns the total meti_assessments row count matching
// the project + filter combination, ignoring pagination. M1 F28
// pattern: the /meti/assessment handler (M3-4, #37) emits this as the
// X-Total-Count header so the Web UI (M3-5, #38) can render
// "N / total 件" and trip a "more than one page" warning banner when
// total > limit.
//
// The filter shape MUST match ListByProject so the two queries return
// adjudicated cardinalities on the same units (avoiding the M1 #F29
// regression class where COUNT and SELECT used different WHERE
// shapes). buildMetiAssessmentWhere is the shared builder.
func (r *MetiAssessmentsRepository) CountByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter MetiAssessmentListFilter) (int, error) {
	if tenantID == uuid.Nil {
		return 0, fmt.Errorf("MetiAssessmentsRepository.CountByProject: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return 0, fmt.Errorf("MetiAssessmentsRepository.CountByProject: project_id is required")
	}

	where, args := buildMetiAssessmentWhere(tenantID, projectID, filter)
	query := fmt.Sprintf(`SELECT COUNT(*) FROM meti_assessments %s`, where)

	var n int
	if err := r.q(ctx).QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("count meti_assessments by project: %w", err)
	}
	return n, nil
}

// OverrideStatus applies one operator override to a meti_assessments
// row. The evaluator-owned fields (status / evidence /
// evaluator_version / evaluated_at) are preserved UNCONDITIONALLY --
// only the override_* lifecycle fields and (optionally)
// improvement_action are written.
//
// State-machine guard (M2 Codex review #F31 pattern): the UPDATE only
// matches rows whose current override_status IS NULL. A re-override
// attempt against an already-overridden row matches zero rows and
// returns wrapped sql.ErrNoRows so the handler can surface a 409
// ("already overridden") instead of silently swapping the operator
// verdict. Clear-then-re-override is an explicit M3-4 handler path so
// each transition emits its own audit_logs row.
//
// Lookup uses the UNIQUE (tenant_id, project_id, criterion_id) key
// because the M3-4 handler holds the composite key from the URL path.
//
// Validation:
//   - tenantID / projectID / criterionID / upd.OverrideBy must all be set.
//   - upd.OverrideStatus must be one of
//     'achieved' | 'not_achieved' | 'needs_review' | 'not_applicable'.
//     The empty string is rejected because "clear override" is a
//     separate handler path (M3-4).
//
// Returns wrapped sql.ErrNoRows when the UPDATE matches zero rows.
// After the F31 guard, that happens in either of two cases:
//  1. (tenant, project, criterion) does not match any existing row
//     (wrong key / foreign tenant).
//  2. The row exists but its current override_status IS NOT NULL
//     (already overridden -- re-override rejected; clear-first via a
//     separate handler path).
//
// Handlers that load the row first can disambiguate by inspecting the
// prior override; bare callers should treat ErrNoRows as "could not
// apply override" and surface a 409 to the operator.
func (r *MetiAssessmentsRepository) OverrideStatus(ctx context.Context, tenantID, projectID uuid.UUID, criterionID string, upd MetiAssessmentOverrideInput) error {
	if tenantID == uuid.Nil {
		return fmt.Errorf("MetiAssessmentsRepository.OverrideStatus: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return fmt.Errorf("MetiAssessmentsRepository.OverrideStatus: project_id is required")
	}
	if criterionID == "" {
		return fmt.Errorf("MetiAssessmentsRepository.OverrideStatus: criterion_id is required")
	}
	if upd.OverrideBy == uuid.Nil {
		return fmt.Errorf("MetiAssessmentsRepository.OverrideStatus: override_by is required (audit trail)")
	}
	switch upd.OverrideStatus {
	case "achieved", "not_achieved", "needs_review", "not_applicable":
		// ok
	case "":
		return fmt.Errorf("MetiAssessmentsRepository.OverrideStatus: override_status is required (use clear-override handler to drop an existing override)")
	default:
		return fmt.Errorf("MetiAssessmentsRepository.OverrideStatus: unknown override_status %q", upd.OverrideStatus)
	}

	overrideAt := upd.OverrideAt
	if overrideAt.IsZero() {
		overrideAt = time.Now().UTC()
	}

	// State-machine guard: WHERE override_status IS NULL. An already-
	// overridden row matches zero rows and ErrNoRows is returned so
	// the handler can surface 409. The literal NULL predicate is
	// intentionally inline (not a bind parameter) so the argument
	// count stays predictable and the mock-based unit tests do not
	// have to add a placeholder. M3 mirror of M2 Codex review #F31.
	const query = `
		UPDATE meti_assessments SET
			override_status    = $4,
			override_by        = $5,
			override_at        = $6,
			override_note      = $7,
			improvement_action = COALESCE($8, improvement_action),
			updated_at         = NOW()
		WHERE tenant_id = $1 AND project_id = $2 AND criterion_id = $3
		  AND override_status IS NULL
	`

	res, err := r.q(ctx).ExecContext(ctx, query,
		tenantID, projectID, criterionID,
		upd.OverrideStatus, upd.OverrideBy, overrideAt, nullableString(upd.OverrideNote),
		nullableStringPtr(upd.ImprovementAction),
	)
	if err != nil {
		return fmt.Errorf("update meti_assessments override: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update meti_assessments override (RowsAffected): %w", err)
	}
	if n == 0 {
		// Same shape as sql.ErrNoRows so handlers can errors.Is-check.
		return fmt.Errorf("update meti_assessments override: %w", sql.ErrNoRows)
	}
	return nil
}

// ClearOverride drops a prior operator override on a meti_assessments
// row, atomically guarded so only an already-overridden row is
// touched (M3 Codex review #F33 — without a clear path, an erroneous
// manual override is effectively a one-way trip that continues to win
// in dashboard + Evidence Pack output).
//
// The evaluator-owned fields (status / evidence / evaluator_version /
// evaluated_at) and improvement_action are preserved UNCONDITIONALLY
// — clearing the override does not erase the operator's remediation
// plan or re-run the evaluator. updated_at moves to NOW().
//
// State-machine guard (M3 mirror of F31 pattern): the UPDATE WHERE
// carries `AND override_status IS NOT NULL` so a row with no override
// (or one that was cleared by a concurrent request between a
// handler's pre-load and this call) matches zero rows. We surface a
// wrapped sql.ErrNoRows so the handler can map the no-op to a 404
// (no override to clear) or 409 (TOCTOU race) without parsing pq
// codes — same return contract as OverrideStatus.
//
// Validation:
//   - tenantID / projectID / criterionID must all be set.
//
// The audit row is the handler's responsibility — this repository
// method is intentionally narrow (just the UPDATE) so the handler
// captures the prior override metadata (override_by, override_at,
// override_note) from a pre-load before calling here, and writes
// them into the audit_logs row.
func (r *MetiAssessmentsRepository) ClearOverride(ctx context.Context, tenantID, projectID uuid.UUID, criterionID string) error {
	if tenantID == uuid.Nil {
		return fmt.Errorf("MetiAssessmentsRepository.ClearOverride: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return fmt.Errorf("MetiAssessmentsRepository.ClearOverride: project_id is required")
	}
	if criterionID == "" {
		return fmt.Errorf("MetiAssessmentsRepository.ClearOverride: criterion_id is required")
	}

	// State-machine guard: WHERE override_status IS NOT NULL. A row
	// with no override (already cleared, or never overridden) matches
	// zero rows and we return wrapped sql.ErrNoRows. The literal NULL
	// predicate is intentionally inline (not a bind parameter) so the
	// argument count stays predictable and the mock-based unit tests do
	// not have to add a placeholder. Mirrors the M2 #F31 pattern used
	// by OverrideStatus.
	const query = `
		UPDATE meti_assessments SET
			override_status = NULL,
			override_by     = NULL,
			override_at     = NULL,
			override_note   = NULL,
			updated_at      = NOW()
		WHERE tenant_id = $1 AND project_id = $2 AND criterion_id = $3
		  AND override_status IS NOT NULL
	`

	res, err := r.q(ctx).ExecContext(ctx, query, tenantID, projectID, criterionID)
	if err != nil {
		return fmt.Errorf("clear meti_assessments override: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("clear meti_assessments override (RowsAffected): %w", err)
	}
	if n == 0 {
		// Same shape as sql.ErrNoRows so handlers can errors.Is-check.
		return fmt.Errorf("clear meti_assessments override: %w", sql.ErrNoRows)
	}
	return nil
}

// buildMetiAssessmentWhere is the shared WHERE-clause builder for
// ListByProject and CountByProject. Returning the (where, args) pair
// keeps the two queries adjudicated on identical WHERE shapes, which
// is the M1 F29 regression-class guard against COUNT and SELECT
// drifting apart (e.g. one of them forgetting to apply a new filter).
func buildMetiAssessmentWhere(tenantID, projectID uuid.UUID, filter MetiAssessmentListFilter) (string, []interface{}) {
	args := []interface{}{tenantID, projectID}
	argIdx := 3
	where := "WHERE tenant_id = $1 AND project_id = $2"
	if filter.CriterionPhase != "" {
		where += fmt.Sprintf(" AND criterion_phase = $%d", argIdx)
		args = append(args, filter.CriterionPhase)
		argIdx++
	}
	if filter.Status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, filter.Status)
		argIdx++
	}
	if filter.HasOverride != nil {
		if *filter.HasOverride {
			where += " AND override_status IS NOT NULL"
		} else {
			where += " AND override_status IS NULL"
		}
	}
	return where, args
}

// isJSONArray returns true when raw is a syntactically valid JSON
// array (length may be zero -- the meti_assessments CHECK is
// jsonb_array_length >= 0, i.e. "must be an array"). Distinct from
// hasNonEmptyJSONArray (vex_drafts / cra_reports) which requires
// length > 0. METI rows for not_applicable / needs_review criteria
// legitimately carry evidence='[]'.
func isJSONArray(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var arr []json.RawMessage
	return json.Unmarshal(raw, &arr) == nil
}

// scanMetiAssessmentRow scans one meti_assessments row from either
// *sql.Row or *sql.Rows. Uses the shared rowScanner interface from
// advisory_excerpts.go.
func scanMetiAssessmentRow(rs rowScanner) (MetiAssessment, error) {
	var (
		a                 MetiAssessment
		evidence          []byte
		evaluatorVersion  sql.NullString
		overrideStatus    sql.NullString
		overrideBy        sql.NullString
		overrideAt        sql.NullTime
		overrideNote      sql.NullString
		improvementAction sql.NullString
	)
	if err := rs.Scan(
		&a.ID, &a.TenantID, &a.ProjectID,
		&a.CriterionID, &a.CriterionPhase,
		&a.Status, &evidence,
		&evaluatorVersion, &a.EvaluatedAt,
		&overrideStatus, &overrideBy, &overrideAt, &overrideNote,
		&improvementAction,
		&a.CreatedAt, &a.UpdatedAt,
	); err != nil {
		return a, err
	}
	a.Evidence = bytesToJSON(evidence)
	if evaluatorVersion.Valid {
		a.EvaluatorVersion = evaluatorVersion.String
	}
	if overrideStatus.Valid {
		a.OverrideStatus = overrideStatus.String
	}
	if overrideBy.Valid {
		if u, err := uuid.Parse(overrideBy.String); err == nil {
			a.OverrideBy = &u
		}
	}
	if overrideAt.Valid {
		t := overrideAt.Time
		a.OverrideAt = &t
	}
	if overrideNote.Valid {
		a.OverrideNote = overrideNote.String
	}
	if improvementAction.Valid {
		a.ImprovementAction = improvementAction.String
	}
	return a, nil
}
