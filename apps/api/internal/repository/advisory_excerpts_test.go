package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// TestAdvisoryExcerptsRepository_Upsert_PassesTenantID asserts that
// the INSERT statement binds tenant_id at position 2 and that the
// column ordering matches the migration 033 schema. The tenant_id
// position is load-bearing: it pairs with the RLS WITH CHECK clause --
// a mis-positioned bind would silently land tenant_id wrong, which
// the RLS layer would reject at runtime with a confusing error, or,
// worse, in a future world where RLS is removed, would leak rows
// across tenants.
func TestAdvisoryExcerptsRepository_Upsert_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewAdvisoryExcerptsRepository(db)
	tenantID := uuid.New()
	excerptID := uuid.New()
	fetched := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	now := time.Now().UTC()

	vulnFuncs := json.RawMessage(`[{"name":"html.Parse","package":"html/template"}]`)
	affectedPaths := json.RawMessage(`["internal/html/parse.go"]`)
	requiredConfig := json.RawMessage(`[]`)
	requiredEnv := json.RawMessage(`["DEBUG=true"]`)

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO advisory_excerpts")).
		WithArgs(
			excerptID,              // $1  id
			tenantID,               // $2  tenant_id
			"CVE-2025-12345",       // $3  cve_id
			"ghsa",                 // $4  source
			[]byte(vulnFuncs),      // $5  vuln_funcs
			[]byte(affectedPaths),  // $6  affected_paths
			[]byte(requiredConfig), // $7  required_config
			[]byte(requiredEnv),    // $8  required_env
			"raw advisory text",    // $9  raw_excerpt
			fetched,                // $10 fetched_at
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(excerptID, now, now))

	e := &AdvisoryExcerpt{
		ID:             excerptID,
		TenantID:       tenantID,
		CVEID:          "CVE-2025-12345",
		Source:         "ghsa",
		VulnFuncs:      vulnFuncs,
		AffectedPaths:  affectedPaths,
		RequiredConfig: requiredConfig,
		RequiredEnv:    requiredEnv,
		RawExcerpt:     "raw advisory text",
		FetchedAt:      &fetched,
	}
	if err := repo.Upsert(context.Background(), e); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestAdvisoryExcerptsRepository_Upsert_RejectsZeroTenant pins down
// the fail-fast contract: a zero TenantID is rejected before any SQL
// is issued. Mirrors LLMCallsRepository.Insert behaviour.
func TestAdvisoryExcerptsRepository_Upsert_RejectsZeroTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewAdvisoryExcerptsRepository(db)
	err = repo.Upsert(context.Background(), &AdvisoryExcerpt{
		// TenantID intentionally zero
		CVEID:  "CVE-2025-99999",
		Source: "nvd",
	})
	if err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestAdvisoryExcerptsRepository_Upsert_RejectsNil guards against a
// nil-pointer dereference on repo.Upsert(ctx, nil).
func TestAdvisoryExcerptsRepository_Upsert_RejectsNil(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewAdvisoryExcerptsRepository(db)
	if err := repo.Upsert(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil AdvisoryExcerpt, got nil")
	}
}

// TestAdvisoryExcerptsRepository_Upsert_RejectsEmptyRequiredFields
// pins down the parameter validation: cve_id and source are both
// required (and source is CHECK-constrained at the DB layer, but we
// validate locally so the error path is identifiable).
func TestAdvisoryExcerptsRepository_Upsert_RejectsEmptyRequiredFields(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewAdvisoryExcerptsRepository(db)
	tenantID := uuid.New()

	if err := repo.Upsert(context.Background(), &AdvisoryExcerpt{
		TenantID: tenantID,
		Source:   "nvd",
		// CVEID intentionally empty
	}); err == nil {
		t.Fatal("expected error for empty cve_id, got nil")
	}
	if err := repo.Upsert(context.Background(), &AdvisoryExcerpt{
		TenantID: tenantID,
		CVEID:    "CVE-2025-1",
		// Source intentionally empty
	}); err == nil {
		t.Fatal("expected error for empty source, got nil")
	}
}

// TestAdvisoryExcerptsRepository_Upsert_AssignsIDIfZero verifies that
// the repository allocates a UUID when the caller does not supply one
// and writes it back to the struct so callers can log it. Matches
// LLMCallsRepository convention.
func TestAdvisoryExcerptsRepository_Upsert_AssignsIDIfZero(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewAdvisoryExcerptsRepository(db)
	tenantID := uuid.New()
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO advisory_excerpts")).
		WithArgs(
			sqlmock.AnyArg(), // $1  id (generated)
			tenantID,         // $2  tenant_id
			"CVE-2025-1",     // $3  cve_id
			"nvd",            // $4  source
			[]byte("[]"),     // $5  vuln_funcs default
			[]byte("[]"),     // $6  affected_paths default
			[]byte("[]"),     // $7  required_config default
			[]byte("[]"),     // $8  required_env default
			nil,              // $9  raw_excerpt (empty -> NULL)
			nil,              // $10 fetched_at (nil)
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(uuid.New(), now, now))

	e := &AdvisoryExcerpt{
		TenantID: tenantID,
		CVEID:    "CVE-2025-1",
		Source:   "nvd",
	}
	if err := repo.Upsert(context.Background(), e); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if e.ID == uuid.Nil {
		t.Fatal("expected ID to be populated after Upsert, got uuid.Nil")
	}
	if e.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be populated after Upsert, got zero")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestAdvisoryExcerptsRepository_Upsert_WrapsDBError checks the
// repository surfaces the underlying driver error with context
// instead of swallowing it. Useful for the advisory parser service
// which decides whether to retry / drop based on the error type.
func TestAdvisoryExcerptsRepository_Upsert_WrapsDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewAdvisoryExcerptsRepository(db)
	tenantID := uuid.New()
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO advisory_excerpts")).
		WillReturnError(sql.ErrConnDone)

	err = repo.Upsert(context.Background(), &AdvisoryExcerpt{
		TenantID: tenantID,
		CVEID:    "CVE-2025-1",
		Source:   "nvd",
	})
	if err == nil || !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("expected wrapped sql.ErrConnDone, got %v", err)
	}
}

// TestAdvisoryExcerptsRepository_GetByCVE_PassesTenantID asserts that
// GetByCVE binds tenant_id at position 1 and cve_id at position 2.
// The tenant filter is the safety net for the case where migration
// 033's RLS policy is ever lifted (compare audit_logs / api_keys /
// public_links, all of which removed RLS in 028/029/030 and rely
// solely on WHERE tenant_id = $N clauses now).
func TestAdvisoryExcerptsRepository_GetByCVE_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewAdvisoryExcerptsRepository(db)
	tenantID := uuid.New()
	rowID := uuid.New()
	now := time.Now().UTC()

	rowCols := []string{
		"id", "tenant_id", "cve_id", "source",
		"vuln_funcs", "affected_paths", "required_config", "required_env",
		"raw_excerpt", "fetched_at",
		"created_at", "updated_at",
	}

	mock.ExpectQuery(`SELECT[\s\S]+FROM advisory_excerpts[\s\S]+WHERE tenant_id = \$1 AND cve_id = \$2`).
		WithArgs(tenantID, "CVE-2025-12345").
		WillReturnRows(sqlmock.NewRows(rowCols).AddRow(
			rowID, tenantID, "CVE-2025-12345", "nvd",
			[]byte(`["html.Parse"]`), []byte(`[]`), []byte(`[]`), []byte(`[]`),
			nil, nil,
			now, now,
		))

	out, err := repo.GetByCVE(context.Background(), tenantID, "CVE-2025-12345")
	if err != nil {
		t.Fatalf("GetByCVE: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 row, got %d", len(out))
	}
	if out[0].TenantID != tenantID {
		t.Errorf("expected tenant_id %s, got %s", tenantID, out[0].TenantID)
	}
	if string(out[0].VulnFuncs) != `["html.Parse"]` {
		t.Errorf("unexpected VulnFuncs: %s", out[0].VulnFuncs)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestAdvisoryExcerptsRepository_GetByCVE_RejectsZeroTenant mirrors
// the Upsert fail-fast: GetByCVE must refuse to issue a tenant-
// unscoped query, which would either return zero rows under RLS
// (silently confusing) or every row (catastrophic if RLS is off).
func TestAdvisoryExcerptsRepository_GetByCVE_RejectsZeroTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewAdvisoryExcerptsRepository(db)
	_, err = repo.GetByCVE(context.Background(), uuid.Nil, "CVE-2025-1")
	if err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestAdvisoryExcerptsRepository_ListVulnFuncsByCVEs_UnionsSources pins
// the M43 Wave 1 (F465) batch-read contract: one CVE with several source
// rows (ghsa + nvd here) yields the UNION of their vuln_funcs string
// arrays in row order (ORDER BY cve_id, source — asserted via the SQL
// regex), un-deduplicated (normalisation/dedupe is the handler edge's
// job); a requested CVE with no rows is simply absent from the map; and
// tenant_id is bound at position 1 with an explicit WHERE clause (the
// belt to migration 033's RLS braces, same rationale as GetByCVE).
func TestAdvisoryExcerptsRepository_ListVulnFuncsByCVEs_UnionsSources(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewAdvisoryExcerptsRepository(db)
	tenantID := uuid.New()
	cveIDs := []string{"CVE-2025-1", "CVE-2025-2"}

	mock.ExpectQuery(`SELECT cve_id, vuln_funcs[\s\S]+FROM advisory_excerpts[\s\S]+WHERE tenant_id = \$1 AND cve_id = ANY\(\$2\)[\s\S]+ORDER BY cve_id ASC, source ASC`).
		WithArgs(tenantID, pq.Array(cveIDs)).
		WillReturnRows(sqlmock.NewRows([]string{"cve_id", "vuln_funcs"}).
			AddRow("CVE-2025-1", []byte(`["xml.Unmarshal","Bar.baz()"]`)).
			AddRow("CVE-2025-1", []byte(`["html.Parse"]`)))
		// CVE-2025-2 has no advisory_excerpts rows at all.

	got, err := repo.ListVulnFuncsByCVEs(context.Background(), tenantID, cveIDs)
	if err != nil {
		t.Fatalf("ListVulnFuncsByCVEs: %v", err)
	}
	want1 := []string{"xml.Unmarshal", "Bar.baz()", "html.Parse"}
	if len(got["CVE-2025-1"]) != len(want1) {
		t.Fatalf("CVE-2025-1 funcs = %v, want %v", got["CVE-2025-1"], want1)
	}
	for i := range want1 {
		if got["CVE-2025-1"][i] != want1[i] {
			t.Errorf("CVE-2025-1 funcs[%d] = %q, want %q (row order must be preserved)", i, got["CVE-2025-1"][i], want1[i])
		}
	}
	if _, present := got["CVE-2025-2"]; present {
		t.Errorf("CVE-2025-2 present in map (%v); a CVE with no rows must be absent", got["CVE-2025-2"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestAdvisoryExcerptsRepository_ListVulnFuncsByCVEs_LenientDecode pins
// the lenient JSON handling: a row whose vuln_funcs is not a JSON array
// is skipped whole, and a non-string element inside an otherwise valid
// array is skipped individually — neither may fail the read (the CLI
// worklist must not 500 over one weird row written via raw-passthrough
// Upsert).
func TestAdvisoryExcerptsRepository_ListVulnFuncsByCVEs_LenientDecode(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewAdvisoryExcerptsRepository(db)
	tenantID := uuid.New()

	mock.ExpectQuery(regexp.QuoteMeta("FROM advisory_excerpts")).
		WithArgs(tenantID, pq.Array([]string{"CVE-2025-3"})).
		WillReturnRows(sqlmock.NewRows([]string{"cve_id", "vuln_funcs"}).
			AddRow("CVE-2025-3", []byte(`{"not":"an array"}`)).
			AddRow("CVE-2025-3", []byte(`["ok.Func",{"name":"html.Parse"},42,"also.Ok"]`)))

	got, err := repo.ListVulnFuncsByCVEs(context.Background(), tenantID, []string{"CVE-2025-3"})
	if err != nil {
		t.Fatalf("ListVulnFuncsByCVEs: %v", err)
	}
	want := []string{"ok.Func", "also.Ok"}
	if len(got["CVE-2025-3"]) != len(want) {
		t.Fatalf("CVE-2025-3 funcs = %v, want %v", got["CVE-2025-3"], want)
	}
	for i := range want {
		if got["CVE-2025-3"][i] != want[i] {
			t.Errorf("CVE-2025-3 funcs[%d] = %q, want %q", i, got["CVE-2025-3"][i], want[i])
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestAdvisoryExcerptsRepository_ListVulnFuncsByCVEs_RejectsZeroTenant
// mirrors the GetByCVE fail-fast: a tenant-unscoped batch read must be
// refused before any SQL is issued (RLS would blank it anyway, but the
// explicit refusal keeps the error identifiable AND keeps tenant
// isolation if RLS is ever lifted — compare audit_logs/api_keys 028-030).
func TestAdvisoryExcerptsRepository_ListVulnFuncsByCVEs_RejectsZeroTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewAdvisoryExcerptsRepository(db)
	_, err = repo.ListVulnFuncsByCVEs(context.Background(), uuid.Nil, []string{"CVE-2025-1"})
	if err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestAdvisoryExcerptsRepository_ListVulnFuncsByCVEs_EmptyInputNoSQL pins
// the short-circuit: an empty cveIDs slice returns an empty, non-nil map
// without touching the database (the handler calls unconditionally even
// for an empty worklist).
func TestAdvisoryExcerptsRepository_ListVulnFuncsByCVEs_EmptyInputNoSQL(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewAdvisoryExcerptsRepository(db)
	got, err := repo.ListVulnFuncsByCVEs(context.Background(), uuid.New(), nil)
	if err != nil {
		t.Fatalf("ListVulnFuncsByCVEs: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("expected empty non-nil map, got %v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestAdvisoryExcerptsRepository_ListVulnFuncsByCVEs_WrapsDBError checks
// the query error surfaces wrapped (not swallowed into an empty map,
// which the handler would misread as "no symbols known").
func TestAdvisoryExcerptsRepository_ListVulnFuncsByCVEs_WrapsDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewAdvisoryExcerptsRepository(db)
	mock.ExpectQuery(regexp.QuoteMeta("FROM advisory_excerpts")).
		WillReturnError(sql.ErrConnDone)

	_, err = repo.ListVulnFuncsByCVEs(context.Background(), uuid.New(), []string{"CVE-2025-1"})
	if err == nil || !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("expected wrapped sql.ErrConnDone, got %v", err)
	}
}

// TestAdvisoryExcerptsRepository_GetBySource_ReturnsNilOnNoRows pins
// down the (*AdvisoryExcerpt, error) contract: no rows -> (nil, nil),
// so callers can `if got == nil { /* fetch */ }` without sniffing
// sql.ErrNoRows.
func TestAdvisoryExcerptsRepository_GetBySource_ReturnsNilOnNoRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewAdvisoryExcerptsRepository(db)
	tenantID := uuid.New()

	mock.ExpectQuery(regexp.QuoteMeta("FROM advisory_excerpts")).
		WithArgs(tenantID, "CVE-2099-1", "jvn").
		WillReturnError(sql.ErrNoRows)

	got, err := repo.GetBySource(context.Background(), tenantID, "CVE-2099-1", "jvn")
	if err != nil {
		t.Fatalf("GetBySource: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil result, got %+v", got)
	}
}
