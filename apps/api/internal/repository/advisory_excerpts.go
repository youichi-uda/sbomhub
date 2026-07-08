package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/database"
)

// AdvisoryExcerpt is the in-process representation of one
// advisory_excerpts row (migration 033, PRODUCT_REBOOT_PLAN.md §8.5,
// issue #23). It is defined here rather than under internal/model/ to
// keep migration #23's surface area small; once
// internal/service/advisory/ lands (issue #24, agent Y), this type may
// be lifted into internal/model alongside the other advisory model
// types.
// ※要確認: relocate to internal/model when the advisory parser
// stabilises the public shape.
type AdvisoryExcerpt struct {
	ID       uuid.UUID
	TenantID uuid.UUID

	CVEID  string
	Source string // one of 'nvd' | 'ghsa' | 'jvn' | 'osv' (CHECK-enforced, migration 056)

	// Structured parser output. JSONB array shape on disk; the
	// in-process representation is json.RawMessage so callers can
	// either unmarshal into a typed struct or pass the bytes through
	// without rewriting. nil maps to '[]' on insert.
	VulnFuncs      json.RawMessage
	AffectedPaths  json.RawMessage
	RequiredConfig json.RawMessage
	RequiredEnv    json.RawMessage

	// Verbatim slice of advisory text the parser based the structured
	// fields on. Empty string is stored as SQL NULL (see header on
	// nullableString in llm_calls.go).
	RawExcerpt string

	FetchedAt *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// AdvisoryExcerptsRepository persists rows in the advisory_excerpts
// table. Every read and write is tenant-scoped both by the RLS policy
// installed in migration 033 (USING + WITH CHECK on tenant_id) AND by
// an explicit `tenant_id = $N` clause in this file. Belt + braces:
// the RLS layer stops a missing/mismatched `app.current_tenant_id`
// GUC from leaking rows, and the explicit clause keeps tenant
// isolation working in any future scenario where someone disables
// RLS on this table (mirrors how audit_logs / api_keys / public_links
// handled their RLS removals in 028/029/030).
type AdvisoryExcerptsRepository struct {
	db *sql.DB
}

func NewAdvisoryExcerptsRepository(db *sql.DB) *AdvisoryExcerptsRepository {
	return &AdvisoryExcerptsRepository{db: db}
}

// q routes the statement through the request-scoped transaction when
// one is attached to ctx; falls back to r.db otherwise. Joining the
// request tx is what makes `SET LOCAL app.current_tenant_id` visible
// to the INSERT below, which is what makes the RLS WITH CHECK pass
// for legitimate writes.
func (r *AdvisoryExcerptsRepository) q(ctx context.Context) database.Queryable {
	return database.Querier(ctx, r.db)
}

// Upsert inserts or refreshes one advisory_excerpts row keyed by
// (tenant_id, cve_id, source). The "we just re-pulled GHSA for this
// CVE" path replaces only the GHSA row and leaves NVD / JVN alone.
//
// Validation:
//   - TenantID, CVEID, Source must be non-empty / non-zero. Source is
//     also CHECK-constrained at the DB layer so a typo here surfaces as
//     a constraint violation, but we still validate locally so the
//     error path is identifiable without parsing pq error codes.
//
// ID/CreatedAt defaults:
//   - If e.ID is the zero UUID, a fresh one is assigned and written
//     back to the supplied struct.
//   - CreatedAt is left to the column default on INSERT; on UPDATE we
//     leave the existing value untouched. UpdatedAt is always set to
//     NOW() on either path so callers can sort by it.
func (r *AdvisoryExcerptsRepository) Upsert(ctx context.Context, e *AdvisoryExcerpt) error {
	if e == nil {
		return fmt.Errorf("AdvisoryExcerptsRepository.Upsert: nil AdvisoryExcerpt")
	}
	if e.TenantID == uuid.Nil {
		return fmt.Errorf("AdvisoryExcerptsRepository.Upsert: tenant_id is required (RLS + NOT NULL)")
	}
	if e.CVEID == "" {
		return fmt.Errorf("AdvisoryExcerptsRepository.Upsert: cve_id is required")
	}
	if e.Source == "" {
		return fmt.Errorf("AdvisoryExcerptsRepository.Upsert: source is required (one of nvd|ghsa|jvn|osv)")
	}
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}

	const query = `
		INSERT INTO advisory_excerpts (
			id, tenant_id, cve_id, source,
			vuln_funcs, affected_paths, required_config, required_env,
			raw_excerpt, fetched_at,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10,
			NOW(), NOW()
		)
		ON CONFLICT (tenant_id, cve_id, source) DO UPDATE SET
			vuln_funcs      = EXCLUDED.vuln_funcs,
			affected_paths  = EXCLUDED.affected_paths,
			required_config = EXCLUDED.required_config,
			required_env    = EXCLUDED.required_env,
			raw_excerpt     = EXCLUDED.raw_excerpt,
			fetched_at      = EXCLUDED.fetched_at,
			updated_at      = NOW()
		RETURNING id, created_at, updated_at
	`

	err := r.q(ctx).QueryRowContext(ctx, query,
		e.ID, e.TenantID, e.CVEID, e.Source,
		jsonbOrEmptyArray(e.VulnFuncs),
		jsonbOrEmptyArray(e.AffectedPaths),
		jsonbOrEmptyArray(e.RequiredConfig),
		jsonbOrEmptyArray(e.RequiredEnv),
		nullableString(e.RawExcerpt),
		nullableTime(e.FetchedAt),
	).Scan(&e.ID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upsert advisory_excerpts: %w", err)
	}
	return nil
}

// GetByCVE returns every advisory_excerpts row for the given (tenant,
// cve_id) tuple ordered by source for stable test assertions. Empty
// result is returned as a zero-length slice + nil error (not
// sql.ErrNoRows) so callers can iterate without nil-checking.
//
// tenantID MUST come from the authenticated session, never from a
// user-supplied request body -- otherwise this becomes a cross-tenant
// information-disclosure primitive.
func (r *AdvisoryExcerptsRepository) GetByCVE(ctx context.Context, tenantID uuid.UUID, cveID string) ([]AdvisoryExcerpt, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("AdvisoryExcerptsRepository.GetByCVE: tenant_id is required")
	}
	if cveID == "" {
		return nil, fmt.Errorf("AdvisoryExcerptsRepository.GetByCVE: cve_id is required")
	}

	const query = `
		SELECT id, tenant_id, cve_id, source,
			vuln_funcs, affected_paths, required_config, required_env,
			raw_excerpt, fetched_at,
			created_at, updated_at
		FROM advisory_excerpts
		WHERE tenant_id = $1 AND cve_id = $2
		ORDER BY source ASC
	`
	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, cveID)
	if err != nil {
		return nil, fmt.Errorf("query advisory_excerpts by cve: %w", err)
	}
	defer rows.Close()

	out := make([]AdvisoryExcerpt, 0)
	for rows.Next() {
		e, err := scanAdvisoryExcerpt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate advisory_excerpts rows: %w", err)
	}
	return out, nil
}

// GetBySource returns the single advisory_excerpts row for the
// (tenant, cve, source) tuple, or (nil, nil) if no row exists. Useful
// for the "did we already pull this feed" check the parser issues
// before re-fetching.
func (r *AdvisoryExcerptsRepository) GetBySource(ctx context.Context, tenantID uuid.UUID, cveID, source string) (*AdvisoryExcerpt, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("AdvisoryExcerptsRepository.GetBySource: tenant_id is required")
	}
	if cveID == "" {
		return nil, fmt.Errorf("AdvisoryExcerptsRepository.GetBySource: cve_id is required")
	}
	if source == "" {
		return nil, fmt.Errorf("AdvisoryExcerptsRepository.GetBySource: source is required")
	}

	const query = `
		SELECT id, tenant_id, cve_id, source,
			vuln_funcs, affected_paths, required_config, required_env,
			raw_excerpt, fetched_at,
			created_at, updated_at
		FROM advisory_excerpts
		WHERE tenant_id = $1 AND cve_id = $2 AND source = $3
	`
	row := r.q(ctx).QueryRowContext(ctx, query, tenantID, cveID, source)
	e, err := scanAdvisoryExcerptRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query advisory_excerpts by source: %w", err)
	}
	return &e, nil
}

// ListVulnFuncsByCVEs returns, for each requested CVE, the union of the
// vuln_funcs symbol strings across every advisory source row (nvd / ghsa /
// jvn / osv) the tenant holds for that CVE, keyed by cve_id (M43 Wave 1 / F465,
// issue #167: GET /reachability/targets enriches each target row with the
// advisory-declared vulnerable symbols so the CLI can run a symbol-level
// reachability walk instead of import-only analysis).
//
// Contract:
//   - CVEs with no advisory_excerpts rows (or whose rows carry no string
//     symbols) are simply absent from the returned map — callers treat a
//     missing key as "no symbols known".
//   - The per-CVE order is stable: the 'osv' row first, then the remaining
//     sources in lexicographic order (ghsa < jvn < nvd), and elements keep
//     their on-disk array order within each row. osv leads because it is
//     the source that carries the structured Go vulndb symbol lists, and
//     the handler caps delivery at 200 symbols per CVE — with plain
//     lexicographic order (osv last) a noisy free-text-derived source
//     could consume the whole cap and crowd the structured osv symbols
//     off the wire (M43 Phase D R2 finding 4). No de-duplication happens
//     here; the handler edge owns normalisation (trim / "()" strip /
//     shape filter / dedupe) as its single source of truth.
//   - vuln_funcs is written as a JSON array of strings by the scheduler
//     (stringsToJSONArray), but Upsert passes raw JSON through, so foreign
//     shapes are tolerated leniently: a non-array value skips the row and a
//     non-string element skips the element, rather than failing the whole
//     worklist read.
//   - An empty cveIDs slice short-circuits to an empty map with no SQL
//     issued.
//
// tenantID MUST come from the authenticated session (same warning as
// GetByCVE): rows are filtered by the explicit tenant clause AND by the
// migration 033 FORCE RLS policy when running inside a TenantTx.
func (r *AdvisoryExcerptsRepository) ListVulnFuncsByCVEs(ctx context.Context, tenantID uuid.UUID, cveIDs []string) (map[string][]string, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("AdvisoryExcerptsRepository.ListVulnFuncsByCVEs: tenant_id is required")
	}
	out := make(map[string][]string, len(cveIDs))
	if len(cveIDs) == 0 {
		return out, nil
	}

	// ORDER BY makes the union order deterministic across calls so the
	// handler's stable dedupe yields a reproducible wire order for the
	// CLI: the osv row leads (structured Go vulndb symbols must sit at the
	// head of the union so the handler's 200-symbol delivery cap trims
	// noisier sources, not them — M43 Phase D R2 finding 4), then the
	// remaining sources lexicographically (ghsa < jvn < nvd).
	const query = `
		SELECT cve_id, vuln_funcs
		FROM advisory_excerpts
		WHERE tenant_id = $1 AND cve_id = ANY($2)
		ORDER BY cve_id ASC, CASE WHEN source = 'osv' THEN 0 ELSE 1 END ASC, source ASC
	`
	rows, err := r.q(ctx).QueryContext(ctx, query, tenantID, pq.Array(cveIDs))
	if err != nil {
		return nil, fmt.Errorf("query advisory_excerpts vuln_funcs by cves: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cveID string
			raw   []byte
		)
		if err := rows.Scan(&cveID, &raw); err != nil {
			return nil, fmt.Errorf("scan advisory_excerpts vuln_funcs row: %w", err)
		}
		var elems []json.RawMessage
		if err := json.Unmarshal(raw, &elems); err != nil {
			// Lenient: a non-array vuln_funcs value (possible via raw
			// pass-through Upsert) must not 500 the CLI worklist read.
			continue
		}
		for _, elem := range elems {
			var s string
			if err := json.Unmarshal(elem, &s); err != nil {
				continue // non-string element: skip, keep the rest
			}
			out[cveID] = append(out[cveID], s)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate advisory_excerpts vuln_funcs rows: %w", err)
	}
	return out, nil
}

// rowScanner abstracts *sql.Row and *sql.Rows for shared scan helpers.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanAdvisoryExcerpt(rs rowScanner) (AdvisoryExcerpt, error) {
	return scanAdvisoryExcerptRow(rs)
}

func scanAdvisoryExcerptRow(rs rowScanner) (AdvisoryExcerpt, error) {
	var (
		e          AdvisoryExcerpt
		vulnFuncs  []byte
		affPaths   []byte
		reqConfig  []byte
		reqEnv     []byte
		rawExcerpt sql.NullString
		fetchedAt  sql.NullTime
	)
	if err := rs.Scan(
		&e.ID, &e.TenantID, &e.CVEID, &e.Source,
		&vulnFuncs, &affPaths, &reqConfig, &reqEnv,
		&rawExcerpt, &fetchedAt,
		&e.CreatedAt, &e.UpdatedAt,
	); err != nil {
		return e, err
	}
	e.VulnFuncs = bytesToJSON(vulnFuncs)
	e.AffectedPaths = bytesToJSON(affPaths)
	e.RequiredConfig = bytesToJSON(reqConfig)
	e.RequiredEnv = bytesToJSON(reqEnv)
	if rawExcerpt.Valid {
		e.RawExcerpt = rawExcerpt.String
	}
	if fetchedAt.Valid {
		t := fetchedAt.Time
		e.FetchedAt = &t
	}
	return e, nil
}

// jsonbOrEmptyArray normalises a nil/empty json.RawMessage to the
// JSONB literal '[]' so the NOT NULL DEFAULT '[]'::JSONB column is
// always satisfied by an explicit value rather than relying on the
// driver passing through DEFAULT. Returning a []byte (not string)
// lets lib/pq round-trip the bytes as JSONB rather than re-quoting.
func jsonbOrEmptyArray(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("[]")
	}
	return []byte(raw)
}

// bytesToJSON copies the driver-returned bytes into a fresh
// json.RawMessage. The copy is defensive: lib/pq reuses its scan
// buffer between rows, so retaining the slice directly would corrupt
// previously-returned rows on the next iteration.
func bytesToJSON(b []byte) json.RawMessage {
	if len(b) == 0 {
		return nil
	}
	out := make(json.RawMessage, len(b))
	copy(out, b)
	return out
}

// nullableTime returns a sql-driver value that lands as NULL when t
// is nil, mirroring the nullableString helper in llm_calls.go.
func nullableTime(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return *t
}
