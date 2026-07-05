package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
)

// CRASubmission is the in-process representation of one cra_submissions
// row (migration 053, M33-A / F418). It is the human-attested record
// that an approved cra_reports row was submitted to an authority --
// the last-mile of "AI drafts, humans approve": the step AFTER approve.
// The product never auto-submits, so submitted_at is a time the
// operator attests, not a system-stamped send.
//
// json tags are present on every field because this struct is the wire
// shape the /cra-reports/:report_id/submissions handler (Wave B / F419)
// serialises directly -- omitting tags would force a parallel DTO
// (drift risk, the M1 F28 lesson) or expose Go PascalCase keys to the
// Web UI (Wave C) / CLI (Wave D). The optional pointer fields carry
// `omitempty` to match the CRAReport convention (decision_by /
// source_vex_draft_id) so a NULL column does not surface a JSON null.
type CRASubmission struct {
	ID       uuid.UUID `json:"id"`
	TenantID uuid.UUID `json:"tenant_id"`

	// The approved cra_reports row this submission attests to.
	CRAReportID uuid.UUID `json:"cra_report_id"`

	// The authority the report was submitted to. Free text.
	Authority string `json:"authority"`

	// Human-attested submission time (NOT NULL at the DB layer).
	SubmittedAt time.Time `json:"submitted_at"`

	// Who recorded the submission (soft reference; NULL for self-hosted
	// requests without a resolvable user id). No FK to users -- same
	// convention as cra_reports.created_by / decision_by.
	SubmittedBy *uuid.UUID `json:"submitted_by,omitempty"`

	// Optional authority-issued acknowledgement / tracking number.
	ReferenceNumber *string `json:"reference_number,omitempty"`

	// Optional operator free-text (e.g. which Art.14 milestone this
	// covers, or a correction note).
	Notes *string `json:"notes,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CRASubmissionInput is the write shape for Record. It is a separate
// type from CRASubmission so a caller cannot accidentally set the
// server-owned columns (id / created_at / updated_at) -- those are
// returned by the INSERT, never supplied. TenantID + CRAReportID are
// server-derived (session + path), Authority is required, and the
// three optional fields (SubmittedBy / ReferenceNumber / Notes) land as
// SQL NULL when nil.
type CRASubmissionInput struct {
	TenantID    uuid.UUID // required: RLS + NOT NULL; comes from the session
	CRAReportID uuid.UUID // required: NOT NULL; comes from the path :report_id
	Authority   string    // required: NOT NULL, non-empty
	SubmittedAt time.Time // human-attested; defaults to NOW() if zero

	SubmittedBy     *uuid.UUID // optional soft user reference
	ReferenceNumber *string    // optional authority tracking number
	Notes           *string    // optional operator free-text
}

// CRASubmissionsRepository persists rows in the cra_submissions table.
// Every read and write is tenant-scoped both by the RLS policy
// installed in migration 053 (USING + WITH CHECK on tenant_id) AND by
// an explicit `tenant_id = $N` clause in this file -- same belt +
// braces rationale as CRAReportsRepository / VEXDraftsRepository.
type CRASubmissionsRepository struct {
	db *sql.DB
}

func NewCRASubmissionsRepository(db *sql.DB) *CRASubmissionsRepository {
	return &CRASubmissionsRepository{db: db}
}

// q routes the statement through the request-scoped transaction when
// one is attached to ctx; falls back to r.db otherwise. Joining the
// request tx is what makes `SET LOCAL app.current_tenant_id` visible to
// the INSERT/SELECT below, which is what makes the RLS WITH CHECK pass
// for legitimate writes (identical helper to CRAReportsRepository.q).
func (r *CRASubmissionsRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// Record writes one cra_submissions row: a human-attested submission of
// an approved cra_reports row to an authority. The Wave B handler is
// the primary caller and drives it inside the same TenantTx that flips
// cra_reports.state -> 'submitted' and emits the cra_submission_recorded
// audit row (audit-or-nothing).
//
// tenant_id is written explicitly (belt-and-braces with the RLS WITH
// CHECK policy) so the row's tenant scope is pinned at both layers.
//
// Validation:
//   - TenantID / CRAReportID must be non-zero (RLS + NOT NULL FK).
//   - Authority must be non-empty (NOT NULL at the DB layer); we trip
//     locally so the error is "authority is required" rather than a pq
//     not-null violation.
//
// SubmittedAt defaults to NOW() (UTC) when zero, mirroring
// UpdateDecision's decision_at handling -- the column is NOT NULL and a
// zero Go time would otherwise land a year-1 timestamp.
//
// Returns the persisted row with id / created_at / updated_at filled in
// from the RETURNING clause; the input fields are echoed back so the
// caller has the full row without a follow-up SELECT.
func (r *CRASubmissionsRepository) Record(ctx context.Context, in CRASubmissionInput) (*CRASubmission, error) {
	if in.TenantID == uuid.Nil {
		return nil, fmt.Errorf("CRASubmissionsRepository.Record: tenant_id is required (RLS + NOT NULL)")
	}
	if in.CRAReportID == uuid.Nil {
		return nil, fmt.Errorf("CRASubmissionsRepository.Record: cra_report_id is required")
	}
	if in.Authority == "" {
		return nil, fmt.Errorf("CRASubmissionsRepository.Record: authority is required (NOT NULL)")
	}

	submittedAt := in.SubmittedAt
	if submittedAt.IsZero() {
		submittedAt = time.Now().UTC()
	}

	const query = `
		INSERT INTO cra_submissions (
			tenant_id,
			cra_report_id,
			authority,
			submitted_at,
			submitted_by,
			reference_number,
			notes,
			created_at, updated_at
		) VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			$7,
			NOW(), NOW()
		)
		RETURNING id, created_at, updated_at
	`

	out := &CRASubmission{
		TenantID:        in.TenantID,
		CRAReportID:     in.CRAReportID,
		Authority:       in.Authority,
		SubmittedAt:     submittedAt,
		SubmittedBy:     in.SubmittedBy,
		ReferenceNumber: in.ReferenceNumber,
		Notes:           in.Notes,
	}

	err := r.q(ctx).QueryRowContext(ctx, query,
		in.TenantID,
		in.CRAReportID,
		in.Authority,
		submittedAt,
		nullableUUID(in.SubmittedBy),
		nullableStringPtr(in.ReferenceNumber),
		nullableStringPtr(in.Notes),
	).Scan(&out.ID, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert cra_submissions: %w", err)
	}
	return out, nil
}

// ListByReport returns the submission timeline for one cra_reports row,
// ordered most-recently-submitted first. There is deliberately no
// uniqueness constraint on cra_submissions (migration 053 header):
// one incident produces many submissions over its Art.14 timeline
// (early_warning -> detailed_notification -> final_report + corrections),
// so this returns every event. tenantID MUST come from the
// authenticated session, never from a user-supplied body.
func (r *CRASubmissionsRepository) ListByReport(ctx context.Context, tenantID, craReportID uuid.UUID) ([]CRASubmission, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("CRASubmissionsRepository.ListByReport: tenant_id is required")
	}
	if craReportID == uuid.Nil {
		return nil, fmt.Errorf("CRASubmissionsRepository.ListByReport: cra_report_id is required")
	}

	const query = `
		SELECT id, tenant_id,
			cra_report_id,
			authority,
			submitted_at,
			submitted_by,
			reference_number,
			notes,
			created_at, updated_at
		FROM cra_submissions
		WHERE tenant_id = $1 AND cra_report_id = $2
		ORDER BY submitted_at DESC, id ASC
	`

	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, craReportID)
	if err != nil {
		return nil, fmt.Errorf("query cra_submissions by report: %w", err)
	}
	defer rows.Close()

	out := make([]CRASubmission, 0)
	for rows.Next() {
		s, err := scanCRASubmissionRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan cra_submissions row: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cra_submissions rows: %w", err)
	}
	return out, nil
}

// scanCRASubmissionRow scans one cra_submissions row from either
// *sql.Row or *sql.Rows. Uses the shared rowScanner interface from
// advisory_excerpts.go. Nullable columns (submitted_by /
// reference_number / notes) are decoded into the pointer fields, NULL
// leaving them nil.
func scanCRASubmissionRow(rs rowScanner) (CRASubmission, error) {
	var (
		s               CRASubmission
		submittedBy     sql.NullString
		referenceNumber sql.NullString
		notes           sql.NullString
	)
	if err := rs.Scan(
		&s.ID, &s.TenantID,
		&s.CRAReportID,
		&s.Authority,
		&s.SubmittedAt,
		&submittedBy,
		&referenceNumber,
		&notes,
		&s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		return s, err
	}
	if submittedBy.Valid {
		if u, err := uuid.Parse(submittedBy.String); err == nil {
			s.SubmittedBy = &u
		}
	}
	if referenceNumber.Valid {
		v := referenceNumber.String
		s.ReferenceNumber = &v
	}
	if notes.Valid {
		v := notes.String
		s.Notes = &v
	}
	return s, nil
}
