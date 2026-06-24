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
)

// TestReachabilityResultsRepository_Upsert_PassesTenantID asserts the
// INSERT column ordering matches migration 034 and binds tenant_id at
// position 2 -- the same load-bearing position that the RLS WITH
// CHECK policy compares against.
func TestReachabilityResultsRepository_Upsert_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewReachabilityResultsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	componentID := uuid.New()
	rowID := uuid.New()
	analyzed := time.Date(2026, 6, 24, 9, 0, 0, 0, time.UTC)
	now := time.Now().UTC()
	conf := 0.87

	evidence := json.RawMessage(`{"callgraph_nodes":["pkg/foo.Bar"]}`)

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO reachability_results")).
		WithArgs(
			rowID,             // $1  id
			tenantID,          // $2  tenant_id
			projectID,         // $3  project_id
			componentID,       // $4  component_id
			"CVE-2025-99999",  // $5  cve_id
			"go",              // $6  ecosystem
			"reachable",       // $7  status
			[]byte(evidence),  // $8  evidence
			conf,              // $9  confidence
			"v0.1.0",          // $10 analyzer_version
			analyzed,          // $11 analyzed_at
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(rowID, now, now))

	rr := &ReachabilityResult{
		ID:              rowID,
		TenantID:        tenantID,
		ProjectID:       projectID,
		ComponentID:     componentID,
		CVEID:           "CVE-2025-99999",
		Ecosystem:       "go",
		Status:          "reachable",
		Evidence:        evidence,
		Confidence:      &conf,
		AnalyzerVersion: "v0.1.0",
		AnalyzedAt:      &analyzed,
	}
	if err := repo.Upsert(context.Background(), rr); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestReachabilityResultsRepository_Upsert_RejectsZeroTenant pins the
// fail-fast on missing tenant -- same rationale as the advisory_excerpts
// and llm_calls equivalents.
func TestReachabilityResultsRepository_Upsert_RejectsZeroTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewReachabilityResultsRepository(db)
	err = repo.Upsert(context.Background(), &ReachabilityResult{
		// TenantID intentionally zero
		ProjectID:   uuid.New(),
		ComponentID: uuid.New(),
		CVEID:       "CVE-2025-1",
		Status:      "unknown",
	})
	if err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestReachabilityResultsRepository_Upsert_RejectsNil guards the
// nil-pointer case.
func TestReachabilityResultsRepository_Upsert_RejectsNil(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewReachabilityResultsRepository(db)
	if err := repo.Upsert(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil ReachabilityResult, got nil")
	}
}

// TestReachabilityResultsRepository_Upsert_RejectsEmptyRequired pins
// the per-field validation. project_id / component_id / cve_id /
// status are all required; the CHECK constraint at the DB layer
// catches bad status values but a missing one is rejected locally
// for a clearer error message.
func TestReachabilityResultsRepository_Upsert_RejectsEmptyRequired(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewReachabilityResultsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	componentID := uuid.New()

	cases := []struct {
		name string
		rr   *ReachabilityResult
	}{
		{"no project_id", &ReachabilityResult{TenantID: tenantID, ComponentID: componentID, CVEID: "CVE-2025-1", Status: "unknown"}},
		{"no component_id", &ReachabilityResult{TenantID: tenantID, ProjectID: projectID, CVEID: "CVE-2025-1", Status: "unknown"}},
		{"no cve_id", &ReachabilityResult{TenantID: tenantID, ProjectID: projectID, ComponentID: componentID, Status: "unknown"}},
		{"no status", &ReachabilityResult{TenantID: tenantID, ProjectID: projectID, ComponentID: componentID, CVEID: "CVE-2025-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := repo.Upsert(context.Background(), tc.rr); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

// TestReachabilityResultsRepository_Upsert_RejectsConfidenceOutOfRange
// pins the [0,1] range check. The DB CHECK constraint also catches
// this but we validate locally so an analyser bug surfaces as a
// repository error, not a pq constraint error.
func TestReachabilityResultsRepository_Upsert_RejectsConfidenceOutOfRange(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewReachabilityResultsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	componentID := uuid.New()
	bad := 1.5

	if err := repo.Upsert(context.Background(), &ReachabilityResult{
		TenantID:    tenantID,
		ProjectID:   projectID,
		ComponentID: componentID,
		CVEID:       "CVE-2025-1",
		Status:      "reachable",
		Confidence:  &bad,
	}); err == nil {
		t.Fatal("expected error for confidence > 1, got nil")
	}

	worse := -0.1
	if err := repo.Upsert(context.Background(), &ReachabilityResult{
		TenantID:    tenantID,
		ProjectID:   projectID,
		ComponentID: componentID,
		CVEID:       "CVE-2025-1",
		Status:      "reachable",
		Confidence:  &worse,
	}); err == nil {
		t.Fatal("expected error for confidence < 0, got nil")
	}
}

// TestReachabilityResultsRepository_Upsert_AssignsIDIfZero verifies
// the repository allocates a UUID when none is supplied, and that
// optional fields (ecosystem, confidence, analyzer_version,
// analyzed_at) land as NULL rather than as their zero values.
func TestReachabilityResultsRepository_Upsert_AssignsIDIfZero(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewReachabilityResultsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	componentID := uuid.New()
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO reachability_results")).
		WithArgs(
			sqlmock.AnyArg(), // $1  id (generated)
			tenantID,         // $2  tenant_id
			projectID,        // $3  project_id
			componentID,      // $4  component_id
			"CVE-2025-1",     // $5  cve_id
			nil,              // $6  ecosystem (empty -> NULL)
			"unknown",        // $7  status
			[]byte("{}"),     // $8  evidence default
			nil,              // $9  confidence (nil)
			nil,              // $10 analyzer_version (empty -> NULL)
			nil,              // $11 analyzed_at (nil)
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(uuid.New(), now, now))

	rr := &ReachabilityResult{
		TenantID:    tenantID,
		ProjectID:   projectID,
		ComponentID: componentID,
		CVEID:       "CVE-2025-1",
		Status:      "unknown",
	}
	if err := repo.Upsert(context.Background(), rr); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if rr.ID == uuid.Nil {
		t.Fatal("expected ID to be populated after Upsert, got uuid.Nil")
	}
	if rr.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be populated after Upsert, got zero")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestReachabilityResultsRepository_Upsert_WrapsDBError ensures
// driver errors surface with context.
func TestReachabilityResultsRepository_Upsert_WrapsDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewReachabilityResultsRepository(db)
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO reachability_results")).
		WillReturnError(sql.ErrConnDone)

	err = repo.Upsert(context.Background(), &ReachabilityResult{
		TenantID:    uuid.New(),
		ProjectID:   uuid.New(),
		ComponentID: uuid.New(),
		CVEID:       "CVE-2025-1",
		Status:      "unknown",
	})
	if err == nil || !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("expected wrapped sql.ErrConnDone, got %v", err)
	}
}

// TestReachabilityResultsRepository_Get_ReturnsNilOnNoRows pins down
// the (*ReachabilityResult, error) contract for the "did we already
// analyse this" check.
func TestReachabilityResultsRepository_Get_ReturnsNilOnNoRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewReachabilityResultsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	componentID := uuid.New()

	mock.ExpectQuery(regexp.QuoteMeta("FROM reachability_results")).
		WithArgs(tenantID, projectID, componentID, "CVE-2099-1").
		WillReturnError(sql.ErrNoRows)

	got, err := repo.Get(context.Background(), tenantID, projectID, componentID, "CVE-2099-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil result, got %+v", got)
	}
}

// TestReachabilityResultsRepository_ListByProject_PassesTenantID
// asserts the WHERE clause binds tenant_id at $1, project_id at $2,
// and applies LIMIT/OFFSET defaults. Same belt-and-braces tenant
// isolation as LLMCallsRepository.List.
func TestReachabilityResultsRepository_ListByProject_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewReachabilityResultsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	componentID := uuid.New()
	rowID := uuid.New()
	now := time.Now().UTC()

	rowCols := []string{
		"id", "tenant_id", "project_id", "component_id",
		"cve_id", "ecosystem", "status",
		"evidence", "confidence",
		"analyzer_version", "analyzed_at",
		"created_at", "updated_at",
	}

	mock.ExpectQuery(`SELECT[\s\S]+FROM reachability_results[\s\S]+WHERE tenant_id = \$1 AND project_id = \$2`).
		WithArgs(tenantID, projectID, 200, 0).
		WillReturnRows(sqlmock.NewRows(rowCols).AddRow(
			rowID, tenantID, projectID, componentID,
			"CVE-2025-1", "go", "reachable",
			[]byte(`{"a":1}`), 0.9,
			"v0.1.0", now,
			now, now,
		))

	out, err := repo.ListByProject(context.Background(), tenantID, projectID, ReachabilityResultListFilter{})
	if err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 row, got %d", len(out))
	}
	if out[0].TenantID != tenantID {
		t.Errorf("expected tenant_id %s, got %s", tenantID, out[0].TenantID)
	}
	if out[0].Confidence == nil || *out[0].Confidence != 0.9 {
		t.Errorf("unexpected confidence: %v", out[0].Confidence)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestReachabilityResultsRepository_ListByProject_RejectsZeroTenant
// mirrors the read-side fail-fast.
func TestReachabilityResultsRepository_ListByProject_RejectsZeroTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewReachabilityResultsRepository(db)
	_, err = repo.ListByProject(context.Background(), uuid.Nil, uuid.New(), ReachabilityResultListFilter{})
	if err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestReachabilityResultsRepository_ListByProject_AppliesFilters
// covers the dynamic WHERE-builder: a typo in the $-index or a
// missing AND would silently fall back to "list everything for this
// project" and the bug would only surface in downstream analytics.
func TestReachabilityResultsRepository_ListByProject_AppliesFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewReachabilityResultsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	componentID := uuid.New()

	rowCols := []string{
		"id", "tenant_id", "project_id", "component_id",
		"cve_id", "ecosystem", "status",
		"evidence", "confidence",
		"analyzer_version", "analyzed_at",
		"created_at", "updated_at",
	}

	mock.ExpectQuery(`SELECT[\s\S]+FROM reachability_results[\s\S]+cve_id = \$3[\s\S]+component_id = \$4[\s\S]+status = \$5`).
		WithArgs(tenantID, projectID, "CVE-2025-1", componentID, "reachable", 10, 5).
		WillReturnRows(sqlmock.NewRows(rowCols))

	out, err := repo.ListByProject(context.Background(), tenantID, projectID, ReachabilityResultListFilter{
		CVEID:       "CVE-2025-1",
		ComponentID: &componentID,
		Status:      "reachable",
		Limit:       10,
		Offset:      5,
	})
	if err != nil {
		t.Fatalf("ListByProject with filters: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected 0 rows, got %d", len(out))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}
