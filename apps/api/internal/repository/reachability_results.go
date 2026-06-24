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

// ReachabilityResult is the in-process representation of one
// reachability_results row (migration 034, PRODUCT_REBOOT_PLAN.md
// §8.1, issue #26). Defined here rather than under internal/model/ to
// keep migration #26's surface area small; the analyser service
// (#25, agent Z) may lift this into internal/model once the public
// shape stabilises.
// ※要確認: relocate to internal/model when service/reachability/
// lands its public types.
type ReachabilityResult struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	ProjectID   uuid.UUID
	ComponentID uuid.UUID

	CVEID     string
	Ecosystem string // optional; e.g. 'go', 'npm', 'maven', 'pypi'
	Status    string // 'not_present' | 'import_only' | 'reachable' | 'unknown'

	// Analyser-specific evidence: callgraph nodes for the Go analyser,
	// import-tree slices for the npm analyser, heuristic explanation
	// for the fallback. JSONB object on disk; nil maps to '{}' on
	// upsert.
	Evidence json.RawMessage

	// Calibrated confidence in [0.00, 1.00]. Pointer because some
	// analyser passes (e.g. callgraph-only) skip confidence scoring.
	Confidence *float64

	AnalyzerVersion string
	AnalyzedAt      *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// ReachabilityResultListFilter narrows ListByProject. Zero values
// mean "do not filter on this field"; Limit defaults to 200 (covers
// "list every CVE for this project" without paging in the common
// case), Offset to 0.
type ReachabilityResultListFilter struct {
	CVEID       string
	ComponentID *uuid.UUID
	Status      string
	Limit       int
	Offset      int
}

// ReachabilityResultsRepository persists rows in the
// reachability_results table. Every read and write is tenant-scoped
// both by the RLS policy installed in migration 034 (USING + WITH
// CHECK on tenant_id) AND by an explicit `tenant_id = $N` clause in
// this file -- same belt + braces rationale as
// AdvisoryExcerptsRepository and LLMCallsRepository.
type ReachabilityResultsRepository struct {
	db *sql.DB
}

func NewReachabilityResultsRepository(db *sql.DB) *ReachabilityResultsRepository {
	return &ReachabilityResultsRepository{db: db}
}

// q routes the statement through the request-scoped transaction when
// one is attached to ctx; falls back to r.db otherwise.
func (r *ReachabilityResultsRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// Upsert inserts or refreshes one reachability_results row keyed by
// (tenant_id, project_id, component_id, cve_id). "We re-ran the
// analyser on this triple" replaces the verdict and bumps updated_at.
//
// Validation:
//   - TenantID / ProjectID / ComponentID must be non-zero.
//   - CVEID and Status must be non-empty. Status is CHECK-constrained
//     at the DB layer; we validate locally so the error path is
//     identifiable without parsing pq error codes.
//   - Confidence (if non-nil) must be in [0, 1]. We do not coerce or
//     clamp here -- the analyser is the source of truth and a value
//     outside the range is a bug worth surfacing.
func (r *ReachabilityResultsRepository) Upsert(ctx context.Context, rr *ReachabilityResult) error {
	if rr == nil {
		return fmt.Errorf("ReachabilityResultsRepository.Upsert: nil ReachabilityResult")
	}
	if rr.TenantID == uuid.Nil {
		return fmt.Errorf("ReachabilityResultsRepository.Upsert: tenant_id is required (RLS + NOT NULL)")
	}
	if rr.ProjectID == uuid.Nil {
		return fmt.Errorf("ReachabilityResultsRepository.Upsert: project_id is required")
	}
	if rr.ComponentID == uuid.Nil {
		return fmt.Errorf("ReachabilityResultsRepository.Upsert: component_id is required")
	}
	if rr.CVEID == "" {
		return fmt.Errorf("ReachabilityResultsRepository.Upsert: cve_id is required")
	}
	if rr.Status == "" {
		return fmt.Errorf("ReachabilityResultsRepository.Upsert: status is required (one of not_present|import_only|reachable|unknown)")
	}
	if rr.Confidence != nil {
		v := *rr.Confidence
		if v < 0 || v > 1 {
			return fmt.Errorf("ReachabilityResultsRepository.Upsert: confidence %f out of range [0,1]", v)
		}
	}
	if rr.ID == uuid.Nil {
		rr.ID = uuid.New()
	}

	const query = `
		INSERT INTO reachability_results (
			id, tenant_id, project_id, component_id,
			cve_id, ecosystem, status,
			evidence, confidence,
			analyzer_version, analyzed_at,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9,
			$10, $11,
			NOW(), NOW()
		)
		ON CONFLICT (tenant_id, project_id, component_id, cve_id) DO UPDATE SET
			ecosystem        = EXCLUDED.ecosystem,
			status           = EXCLUDED.status,
			evidence         = EXCLUDED.evidence,
			confidence       = EXCLUDED.confidence,
			analyzer_version = EXCLUDED.analyzer_version,
			analyzed_at      = EXCLUDED.analyzed_at,
			updated_at       = NOW()
		RETURNING id, created_at, updated_at
	`

	err := r.q(ctx).QueryRowContext(ctx, query,
		rr.ID, rr.TenantID, rr.ProjectID, rr.ComponentID,
		rr.CVEID, nullableString(rr.Ecosystem), rr.Status,
		jsonbOrEmptyObject(rr.Evidence),
		nullableFloat(rr.Confidence),
		nullableString(rr.AnalyzerVersion),
		nullableTime(rr.AnalyzedAt),
	).Scan(&rr.ID, &rr.CreatedAt, &rr.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upsert reachability_results: %w", err)
	}
	return nil
}

// Get returns the single reachability_results row for
// (tenant, project, component, cve) or (nil, nil) if no row exists.
// Useful for the "did we already analyse this triple at this analyser
// version" check before re-running.
func (r *ReachabilityResultsRepository) Get(ctx context.Context, tenantID, projectID, componentID uuid.UUID, cveID string) (*ReachabilityResult, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("ReachabilityResultsRepository.Get: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return nil, fmt.Errorf("ReachabilityResultsRepository.Get: project_id is required")
	}
	if componentID == uuid.Nil {
		return nil, fmt.Errorf("ReachabilityResultsRepository.Get: component_id is required")
	}
	if cveID == "" {
		return nil, fmt.Errorf("ReachabilityResultsRepository.Get: cve_id is required")
	}

	const query = `
		SELECT id, tenant_id, project_id, component_id,
			cve_id, ecosystem, status,
			evidence, confidence,
			analyzer_version, analyzed_at,
			created_at, updated_at
		FROM reachability_results
		WHERE tenant_id = $1 AND project_id = $2 AND component_id = $3 AND cve_id = $4
	`
	row := r.q(ctx).QueryRowContext(ctx, query, tenantID, projectID, componentID, cveID)
	rr, err := scanReachabilityResultRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query reachability_results: %w", err)
	}
	return &rr, nil
}

// ListByProject returns reachability verdicts for one project, ordered
// by component_id then cve_id for stable test assertions. Optional
// filters: CVEID, ComponentID, Status. tenantID MUST come from the
// authenticated session.
func (r *ReachabilityResultsRepository) ListByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter ReachabilityResultListFilter) ([]ReachabilityResult, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("ReachabilityResultsRepository.ListByProject: tenant_id is required")
	}
	if projectID == uuid.Nil {
		return nil, fmt.Errorf("ReachabilityResultsRepository.ListByProject: project_id is required")
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	// Build query incrementally so optional filters do not introduce
	// SQL injection vectors via string interpolation. Pattern matches
	// LLMCallsRepository.List.
	args := []interface{}{tenantID, projectID}
	argIdx := 3
	where := "WHERE tenant_id = $1 AND project_id = $2"
	if filter.CVEID != "" {
		where += fmt.Sprintf(" AND cve_id = $%d", argIdx)
		args = append(args, filter.CVEID)
		argIdx++
	}
	if filter.ComponentID != nil && *filter.ComponentID != uuid.Nil {
		where += fmt.Sprintf(" AND component_id = $%d", argIdx)
		args = append(args, *filter.ComponentID)
		argIdx++
	}
	if filter.Status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, filter.Status)
		argIdx++
	}

	query := fmt.Sprintf(`
		SELECT id, tenant_id, project_id, component_id,
			cve_id, ecosystem, status,
			evidence, confidence,
			analyzer_version, analyzed_at,
			created_at, updated_at
		FROM reachability_results
		%s
		ORDER BY component_id ASC, cve_id ASC
		LIMIT $%d OFFSET $%d
	`, where, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := r.q(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query reachability_results by project: %w", err)
	}
	defer rows.Close()

	out := make([]ReachabilityResult, 0)
	for rows.Next() {
		rr, err := scanReachabilityResultRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan reachability_results row: %w", err)
		}
		out = append(out, rr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate reachability_results rows: %w", err)
	}
	return out, nil
}

func scanReachabilityResultRow(rs rowScanner) (ReachabilityResult, error) {
	var (
		rr         ReachabilityResult
		ecosystem  sql.NullString
		evidence   []byte
		confidence sql.NullFloat64
		analyzerV  sql.NullString
		analyzedAt sql.NullTime
	)
	if err := rs.Scan(
		&rr.ID, &rr.TenantID, &rr.ProjectID, &rr.ComponentID,
		&rr.CVEID, &ecosystem, &rr.Status,
		&evidence, &confidence,
		&analyzerV, &analyzedAt,
		&rr.CreatedAt, &rr.UpdatedAt,
	); err != nil {
		return rr, err
	}
	if ecosystem.Valid {
		rr.Ecosystem = ecosystem.String
	}
	rr.Evidence = bytesToJSON(evidence)
	if confidence.Valid {
		v := confidence.Float64
		rr.Confidence = &v
	}
	if analyzerV.Valid {
		rr.AnalyzerVersion = analyzerV.String
	}
	if analyzedAt.Valid {
		t := analyzedAt.Time
		rr.AnalyzedAt = &t
	}
	return rr, nil
}

// jsonbOrEmptyObject normalises a nil/empty json.RawMessage to the
// JSONB literal '{}' so the NOT NULL DEFAULT '{}'::JSONB column is
// always satisfied by an explicit value. Distinct from
// jsonbOrEmptyArray because reachability evidence is shaped as an
// object, not an array.
func jsonbOrEmptyObject(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("{}")
	}
	return []byte(raw)
}

// nullableFloat returns a sql-driver value that lands as NULL when
// f is nil. Mirrors nullableTime / nullableString.
func nullableFloat(f *float64) interface{} {
	if f == nil {
		return nil
	}
	return *f
}
