package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
)

// LLMCall is the in-process representation of one llm_calls row
// (migration 032, LLM_PROVIDER_DESIGN.md §6.1). It is defined here rather
// than under internal/model/ to keep migration #20's surface area small;
// once internal/service/llm/ lands (agent B / issue scope), this type may
// be lifted into internal/model alongside the other LLM model types.
// ※要確認: relocate to internal/model when service/llm/audit.go is wired.
type LLMCall struct {
	ID              uuid.UUID
	TenantID        uuid.UUID
	UserID          *uuid.UUID
	Purpose         string
	Provider        string
	Model           string
	PromptHash      string
	PromptPreview   string
	ResponseHash    string
	ResponsePreview string
	ResponseBody    string

	InputTokens  int
	OutputTokens int
	CostUSD      float64
	DurationMs   int

	FinishReason string
	ErrorMessage string

	TriageTargetCVE         string
	TriageTargetComponentID *uuid.UUID
	CRAReportID             *uuid.UUID

	CreatedAt time.Time
}

// LLMCallListFilter narrows the List query. Zero values mean "do not
// filter on this field"; Limit defaults to 50, Offset to 0.
type LLMCallListFilter struct {
	Purpose  string
	Provider string
	Limit    int
	Offset   int
}

// LLMCallsRepository persists rows in the llm_calls audit table. Every
// read and write is tenant-scoped both by the RLS policy installed in
// migration 032 (USING + WITH CHECK on tenant_id) AND by an explicit
// `tenant_id = $N` clause in this file. Belt + braces: the RLS layer
// stops a missing/mismatched `app.current_tenant_id` GUC from leaking
// rows, and the explicit clause keeps tenant isolation working in any
// future scenario where someone disables RLS on this table (mirrors how
// audit_logs / api_keys / public_links handled their RLS removals in
// 028/029/030).
type LLMCallsRepository struct {
	db *sql.DB
}

func NewLLMCallsRepository(db *sql.DB) *LLMCallsRepository {
	return &LLMCallsRepository{db: db}
}

// q routes the statement through the request-scoped transaction when one
// is attached to ctx (Trust Rescue 9.1.2 / #3); falls back to r.db
// otherwise. Joining the request tx is what makes `SET LOCAL
// app.current_tenant_id` visible to the INSERT below, which is what makes
// the RLS WITH CHECK pass for legitimate writes.
func (r *LLMCallsRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// Insert writes one llm_calls row. Caller is responsible for hashing the
// prompt/response (the service/llm audit layer in agent B owns that
// logic). TenantID MUST be populated; an empty TenantID will be rejected
// by both the schema (NOT NULL) and the RLS policy.
//
// If c.ID is the zero UUID, a fresh one is assigned and written back to
// the supplied struct so callers can log the persisted id.
// If c.CreatedAt is zero, the column default (NOW()) is used and the
// resulting timestamp is read back.
func (r *LLMCallsRepository) Insert(ctx context.Context, c *LLMCall) error {
	if c == nil {
		return fmt.Errorf("LLMCallsRepository.Insert: nil LLMCall")
	}
	if c.TenantID == uuid.Nil {
		return fmt.Errorf("LLMCallsRepository.Insert: tenant_id is required (RLS + NOT NULL)")
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}

	const query = `
		INSERT INTO llm_calls (
			id, tenant_id, user_id,
			purpose, provider, model,
			prompt_hash, prompt_preview,
			response_hash, response_preview, response_body,
			input_tokens, output_tokens, cost_usd, duration_ms,
			finish_reason, error_message,
			triage_target_cve, triage_target_component_id, cra_report_id,
			created_at
		) VALUES (
			$1, $2, $3,
			$4, $5, $6,
			$7, $8,
			$9, $10, $11,
			$12, $13, $14, $15,
			$16, $17,
			$18, $19, $20,
			$21
		)
	`
	_, err := r.q(ctx).ExecContext(ctx, query,
		c.ID, c.TenantID, nullableUUID(c.UserID),
		c.Purpose, c.Provider, c.Model,
		c.PromptHash, nullableString(c.PromptPreview),
		c.ResponseHash, nullableString(c.ResponsePreview), nullableString(c.ResponseBody),
		c.InputTokens, c.OutputTokens, c.CostUSD, c.DurationMs,
		nullableString(c.FinishReason), nullableString(c.ErrorMessage),
		nullableString(c.TriageTargetCVE), nullableUUID(c.TriageTargetComponentID), nullableUUID(c.CRAReportID),
		c.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert llm_calls: %w", err)
	}
	return nil
}

// List returns llm_calls rows for the given tenant ordered by most-recent
// first. tenantID MUST come from the authenticated session, never from a
// user-supplied request body -- otherwise this becomes a cross-tenant
// information-disclosure primitive (same rule as AuditRepository.List
// after migration 029).
//
// The `WHERE tenant_id = $1` filter is doubly enforced by the RLS policy
// installed in migration 032, but is kept here as defense in depth.
func (r *LLMCallsRepository) List(ctx context.Context, tenantID uuid.UUID, filter LLMCallListFilter) ([]LLMCall, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("LLMCallsRepository.List: tenant_id is required")
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	// Build query incrementally so optional purpose / provider filters do
	// not introduce SQL injection vectors via string interpolation.
	args := []interface{}{tenantID}
	argIdx := 2
	where := "WHERE tenant_id = $1"
	if filter.Purpose != "" {
		where += fmt.Sprintf(" AND purpose = $%d", argIdx)
		args = append(args, filter.Purpose)
		argIdx++
	}
	if filter.Provider != "" {
		where += fmt.Sprintf(" AND provider = $%d", argIdx)
		args = append(args, filter.Provider)
		argIdx++
	}

	query := fmt.Sprintf(`
		SELECT
			id, tenant_id, user_id,
			purpose, provider, model,
			prompt_hash, prompt_preview,
			response_hash, response_preview, response_body,
			input_tokens, output_tokens, cost_usd, duration_ms,
			finish_reason, error_message,
			triage_target_cve, triage_target_component_id, cra_report_id,
			created_at
		FROM llm_calls
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := r.q(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list llm_calls: %w", err)
	}
	defer rows.Close()

	var out []LLMCall
	for rows.Next() {
		var (
			c             LLMCall
			userID        sql.NullString
			promptPreview sql.NullString
			respPreview   sql.NullString
			respBody      sql.NullString
			finishReason  sql.NullString
			errMessage    sql.NullString
			triageCVE     sql.NullString
			triageCompID  sql.NullString
			craReportID   sql.NullString
		)
		if err := rows.Scan(
			&c.ID, &c.TenantID, &userID,
			&c.Purpose, &c.Provider, &c.Model,
			&c.PromptHash, &promptPreview,
			&c.ResponseHash, &respPreview, &respBody,
			&c.InputTokens, &c.OutputTokens, &c.CostUSD, &c.DurationMs,
			&finishReason, &errMessage,
			&triageCVE, &triageCompID, &craReportID,
			&c.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan llm_calls row: %w", err)
		}
		if userID.Valid {
			if u, err := uuid.Parse(userID.String); err == nil {
				c.UserID = &u
			}
		}
		c.PromptPreview = promptPreview.String
		c.ResponsePreview = respPreview.String
		c.ResponseBody = respBody.String
		c.FinishReason = finishReason.String
		c.ErrorMessage = errMessage.String
		c.TriageTargetCVE = triageCVE.String
		if triageCompID.Valid {
			if u, err := uuid.Parse(triageCompID.String); err == nil {
				c.TriageTargetComponentID = &u
			}
		}
		if craReportID.Valid {
			if u, err := uuid.Parse(craReportID.String); err == nil {
				c.CRAReportID = &u
			}
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate llm_calls rows: %w", err)
	}
	return out, nil
}

// nullableUUID converts an optional UUID pointer to a sql-driver value
// that Postgres will treat as NULL when the pointer is nil. We pass the
// string form (with .Valid=false meaning NULL) rather than uuid.UUID
// directly so lib/pq does not try to coerce a zero-UUID into '00...00'.
func nullableUUID(u *uuid.UUID) interface{} {
	if u == nil {
		return nil
	}
	return *u
}

// nullableString returns nil for empty strings so optional TEXT columns
// land as NULL instead of ” (matches LLM_PROVIDER_DESIGN.md §6.1 intent
// where prompt_preview / response_preview / response_body / error_message
// are described as optional rather than empty-string-required).
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
