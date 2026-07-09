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
	vulnFuncsScoped := json.RawMessage(`[{"module":"github.com/a/b","vuln_funcs":["b.Parse"]}]`)
	affectedPaths := json.RawMessage(`["internal/html/parse.go"]`)
	requiredConfig := json.RawMessage(`[]`)
	requiredEnv := json.RawMessage(`["DEBUG=true"]`)

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO advisory_excerpts")).
		WithArgs(
			excerptID,               // $1  id
			tenantID,                // $2  tenant_id
			"CVE-2025-12345",        // $3  cve_id
			"ghsa",                  // $4  source
			[]byte(vulnFuncs),       // $5  vuln_funcs
			[]byte(vulnFuncsScoped), // $6  vuln_funcs_scoped (migration 057)
			[]byte(affectedPaths),   // $7  affected_paths
			[]byte(requiredConfig),  // $8  required_config
			[]byte(requiredEnv),     // $9  required_env
			"raw advisory text",     // $10 raw_excerpt
			fetched,                 // $11 fetched_at
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(excerptID, now, now))

	e := &AdvisoryExcerpt{
		ID:              excerptID,
		TenantID:        tenantID,
		CVEID:           "CVE-2025-12345",
		Source:          "ghsa",
		VulnFuncs:       vulnFuncs,
		VulnFuncsScoped: vulnFuncsScoped,
		AffectedPaths:   affectedPaths,
		RequiredConfig:  requiredConfig,
		RequiredEnv:     requiredEnv,
		RawExcerpt:      "raw advisory text",
		FetchedAt:       &fetched,
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
			[]byte("[]"),     // $6  vuln_funcs_scoped default (migration 057)
			[]byte("[]"),     // $7  affected_paths default
			[]byte("[]"),     // $8  required_config default
			[]byte("[]"),     // $9  required_env default
			nil,              // $10 raw_excerpt (empty -> NULL)
			nil,              // $11 fetched_at (nil)
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
		"vuln_funcs", "vuln_funcs_scoped", "affected_paths", "required_config", "required_env",
		"raw_excerpt", "fetched_at",
		"created_at", "updated_at",
	}

	mock.ExpectQuery(`SELECT[\s\S]+FROM advisory_excerpts[\s\S]+WHERE tenant_id = \$1 AND cve_id = \$2`).
		WithArgs(tenantID, "CVE-2025-12345").
		WillReturnRows(sqlmock.NewRows(rowCols).AddRow(
			rowID, tenantID, "CVE-2025-12345", "nvd",
			[]byte(`["html.Parse"]`), []byte(`[{"module":"stdlib","vuln_funcs":["html.Parse"]}]`), []byte(`[]`), []byte(`[]`), []byte(`[]`),
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
	if string(out[0].VulnFuncsScoped) != `[{"module":"stdlib","vuln_funcs":["html.Parse"]}]` {
		t.Errorf("unexpected VulnFuncsScoped: %s", out[0].VulnFuncsScoped)
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
// rows (osv + ghsa here, both WITHOUT module attribution — the legacy /
// prose shape) yields the UNION of their vuln_funcs string arrays in
// Unscoped in row order — osv rows FIRST, then the remaining sources
// lexicographically (M43 Phase D R2 finding 4; asserted via the ORDER BY
// regex) — un-deduplicated (normalisation/dedupe is the handler edge's
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

	// Rows arrive osv-first (the new ORDER BY puts source='osv' ahead of
	// the lexicographic tail) so the osv structured symbols occupy the
	// head of the union — the handler's 200-symbol delivery cap trims from
	// the tail, so osv symbols must survive ahead of noisier sources.
	mock.ExpectQuery(`SELECT cve_id, vuln_funcs, vuln_funcs_scoped[\s\S]+FROM advisory_excerpts[\s\S]+WHERE tenant_id = \$1 AND cve_id = ANY\(\$2\)[\s\S]+ORDER BY cve_id ASC, CASE WHEN source = 'osv' THEN 0 ELSE 1 END ASC, source ASC`).
		WithArgs(tenantID, pq.Array(cveIDs)).
		WillReturnRows(sqlmock.NewRows([]string{"cve_id", "vuln_funcs", "vuln_funcs_scoped"}).
			AddRow("CVE-2025-1", []byte(`["xml.Unmarshal","Bar.baz()"]`), []byte(`[]`)). // legacy osv row (pre-057: no scoped data)
			AddRow("CVE-2025-1", []byte(`["html.Parse"]`), []byte(`[]`)))                // ghsa row
		// CVE-2025-2 has no advisory_excerpts rows at all.

	got, err := repo.ListVulnFuncsByCVEs(context.Background(), tenantID, cveIDs)
	if err != nil {
		t.Fatalf("ListVulnFuncsByCVEs: %v", err)
	}
	want1 := []string{"xml.Unmarshal", "Bar.baz()", "html.Parse"}
	if len(got["CVE-2025-1"].Unscoped) != len(want1) {
		t.Fatalf("CVE-2025-1 funcs = %v, want %v", got["CVE-2025-1"].Unscoped, want1)
	}
	for i := range want1 {
		if got["CVE-2025-1"].Unscoped[i] != want1[i] {
			t.Errorf("CVE-2025-1 funcs[%d] = %q, want %q (row order must be preserved)", i, got["CVE-2025-1"].Unscoped[i], want1[i])
		}
	}
	if len(got["CVE-2025-1"].Scoped) != 0 {
		t.Errorf("CVE-2025-1 scoped = %v, want none ('[]' scoped rows serve unscoped — backwards compat)", got["CVE-2025-1"].Scoped)
	}
	if _, present := got["CVE-2025-2"]; present {
		t.Errorf("CVE-2025-2 present in map (%v); a CVE with no rows must be absent", got["CVE-2025-2"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestAdvisoryExcerptsRepository_ListVulnFuncsByCVEs_ScopedRowRouting pins
// the M43 Phase D round 8 (R8f) per-row routing rule:
//
//   - a row with a well-formed vuln_funcs_scoped contributes ONLY its
//     scoped entries — its flat vuln_funcs must NOT also land in Unscoped
//     (double-adding would re-broadcast every module's symbols to every
//     target row, silently undoing the scoping);
//   - a row without scoped data (nvd prose here, and legacy osv rows)
//     contributes its flat vuln_funcs to Unscoped as before;
//   - scoped entries keep row order and on-disk element order.
func TestAdvisoryExcerptsRepository_ListVulnFuncsByCVEs_ScopedRowRouting(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewAdvisoryExcerptsRepository(db)
	tenantID := uuid.New()

	mock.ExpectQuery(regexp.QuoteMeta("FROM advisory_excerpts")).
		WithArgs(tenantID, pq.Array([]string{"CVE-2025-7"})).
		WillReturnRows(sqlmock.NewRows([]string{"cve_id", "vuln_funcs", "vuln_funcs_scoped"}).
			// osv row (057 writer shape): flat = union of the scoped lists.
			AddRow("CVE-2025-7",
				[]byte(`["a.F","b.G"]`),
				[]byte(`[{"module":"github.com/mod/a","vuln_funcs":["a.F"]},{"module":"github.com/mod/b","vuln_funcs":["b.G"]}]`)).
			// nvd prose row: no module attribution.
			AddRow("CVE-2025-7", []byte(`["n.H"]`), []byte(`[]`)))

	got, err := repo.ListVulnFuncsByCVEs(context.Background(), tenantID, []string{"CVE-2025-7"})
	if err != nil {
		t.Fatalf("ListVulnFuncsByCVEs: %v", err)
	}
	entry := got["CVE-2025-7"]
	// Double-delivery prevention: the scoped row's flat union ("a.F","b.G")
	// must be absent from Unscoped.
	if len(entry.Unscoped) != 1 || entry.Unscoped[0] != "n.H" {
		t.Fatalf("Unscoped = %v, want [n.H] only (a scoped row's flat union must not leak into the unscoped delivery)", entry.Unscoped)
	}
	if len(entry.Scoped) != 2 {
		t.Fatalf("Scoped = %+v, want 2 module entries", entry.Scoped)
	}
	if entry.Scoped[0].Module != "github.com/mod/a" || len(entry.Scoped[0].Funcs) != 1 || entry.Scoped[0].Funcs[0] != "a.F" {
		t.Errorf("Scoped[0] = %+v, want {github.com/mod/a [a.F]}", entry.Scoped[0])
	}
	if entry.Scoped[1].Module != "github.com/mod/b" || len(entry.Scoped[1].Funcs) != 1 || entry.Scoped[1].Funcs[0] != "b.G" {
		t.Errorf("Scoped[1] = %+v, want {github.com/mod/b [b.G]}", entry.Scoped[1])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestAdvisoryExcerptsRepository_ListVulnFuncsByCVEs_ScopedLenientDecode
// pins the lenient posture on the NEW column (M43 Phase D R8f): a
// malformed scoped element (wrong shape / empty module / no string funcs)
// is skipped individually; a row whose scoped value decodes to ZERO
// well-formed entries (non-array, or all elements malformed) falls back to
// the legacy unscoped-flat contribution instead of failing the read or
// silently dropping the row.
func TestAdvisoryExcerptsRepository_ListVulnFuncsByCVEs_ScopedLenientDecode(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewAdvisoryExcerptsRepository(db)
	tenantID := uuid.New()

	mock.ExpectQuery(regexp.QuoteMeta("FROM advisory_excerpts")).
		WithArgs(tenantID, pq.Array([]string{"CVE-2025-8", "CVE-2025-9"})).
		WillReturnRows(sqlmock.NewRows([]string{"cve_id", "vuln_funcs", "vuln_funcs_scoped"}).
			// Broken elements inside an otherwise valid scoped array: the
			// non-object, the empty-module, the funcs-free and the
			// non-string-func entries are skipped; the last entry survives
			// (with its non-string func filtered out).
			AddRow("CVE-2025-8",
				[]byte(`["ok.Func"]`),
				[]byte(`["not-an-object",{"module":"","vuln_funcs":["x.Y"]},{"module":"github.com/no/funcs"},{"module":"github.com/only/junk","vuln_funcs":[42]},{"module":"github.com/mod/ok","vuln_funcs":["ok.Func",42]}]`)).
			// Scoped value not an array at all: the row falls back to
			// unscoped-flat (legacy routing).
			AddRow("CVE-2025-9", []byte(`["legacy.Func"]`), []byte(`{"not":"an array"}`)))

	got, err := repo.ListVulnFuncsByCVEs(context.Background(), tenantID, []string{"CVE-2025-8", "CVE-2025-9"})
	if err != nil {
		t.Fatalf("ListVulnFuncsByCVEs: %v", err)
	}
	e8 := got["CVE-2025-8"]
	if len(e8.Scoped) != 1 || e8.Scoped[0].Module != "github.com/mod/ok" ||
		len(e8.Scoped[0].Funcs) != 1 || e8.Scoped[0].Funcs[0] != "ok.Func" {
		t.Errorf("CVE-2025-8 Scoped = %+v, want the single well-formed {github.com/mod/ok [ok.Func]} entry", e8.Scoped)
	}
	if len(e8.Unscoped) != 0 {
		t.Errorf("CVE-2025-8 Unscoped = %v, want empty (a row with >=1 well-formed scoped entry routes scoped-only)", e8.Unscoped)
	}
	e9 := got["CVE-2025-9"]
	if len(e9.Unscoped) != 1 || e9.Unscoped[0] != "legacy.Func" {
		t.Errorf("CVE-2025-9 Unscoped = %v, want [legacy.Func] (non-array scoped value falls back to legacy flat routing)", e9.Unscoped)
	}
	if len(e9.Scoped) != 0 {
		t.Errorf("CVE-2025-9 Scoped = %+v, want none", e9.Scoped)
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
		WillReturnRows(sqlmock.NewRows([]string{"cve_id", "vuln_funcs", "vuln_funcs_scoped"}).
			AddRow("CVE-2025-3", []byte(`{"not":"an array"}`), []byte(`[]`)).
			AddRow("CVE-2025-3", []byte(`["ok.Func",{"name":"html.Parse"},42,"also.Ok"]`), []byte(`[]`)))

	got, err := repo.ListVulnFuncsByCVEs(context.Background(), tenantID, []string{"CVE-2025-3"})
	if err != nil {
		t.Fatalf("ListVulnFuncsByCVEs: %v", err)
	}
	want := []string{"ok.Func", "also.Ok"}
	if len(got["CVE-2025-3"].Unscoped) != len(want) {
		t.Fatalf("CVE-2025-3 funcs = %v, want %v", got["CVE-2025-3"].Unscoped, want)
	}
	for i := range want {
		if got["CVE-2025-3"].Unscoped[i] != want[i] {
			t.Errorf("CVE-2025-3 funcs[%d] = %q, want %q", i, got["CVE-2025-3"].Unscoped[i], want[i])
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
