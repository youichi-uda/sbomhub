package repository

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

func TestComponentRepository_Create(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewComponentRepository(db)

	tests := []struct {
		name      string
		component *model.Component
		setupMock func()
		wantErr   bool
	}{
		{
			name: "successful create with all fields",
			component: &model.Component{
				ID:        uuid.New(),
				SbomID:    uuid.New(),
				Name:      "lodash",
				Version:   "4.17.21",
				Type:      "library",
				Purl:      "pkg:npm/lodash@4.17.21",
				License:   "MIT",
				CreatedAt: time.Now(),
			},
			setupMock: func() {
				mock.ExpectExec("INSERT INTO components").
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), "lodash", "4.17.21", "library", "pkg:npm/lodash@4.17.21", "MIT", sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "successful create with minimal fields",
			component: &model.Component{
				ID:        uuid.New(),
				SbomID:    uuid.New(),
				Name:      "express",
				Version:   "4.18.2",
				Type:      "library",
				Purl:      "",
				License:   "",
				CreatedAt: time.Now(),
			},
			setupMock: func() {
				mock.ExpectExec("INSERT INTO components").
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), "express", "4.18.2", "library", "", "", sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "database error",
			component: &model.Component{
				ID:        uuid.New(),
				SbomID:    uuid.New(),
				Name:      "axios",
				Version:   "1.4.0",
				Type:      "library",
				CreatedAt: time.Now(),
			},
			setupMock: func() {
				mock.ExpectExec("INSERT INTO components").
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), "axios", "1.4.0", "library", "", "", sqlmock.AnyArg()).
					WillReturnError(errors.New("foreign key violation"))
			},
			wantErr: true,
		},
		{
			name: "duplicate component error",
			component: &model.Component{
				ID:        uuid.New(),
				SbomID:    uuid.New(),
				Name:      "react",
				Version:   "18.2.0",
				Type:      "library",
				CreatedAt: time.Now(),
			},
			setupMock: func() {
				mock.ExpectExec("INSERT INTO components").
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), "react", "18.2.0", "library", "", "", sqlmock.AnyArg()).
					WillReturnError(errors.New("duplicate key value violates unique constraint"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			err := repo.Create(context.Background(), tt.component)
			if (err != nil) != tt.wantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestComponentRepository_ListBySbom(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewComponentRepository(db)
	sbomID := uuid.New()
	compID1 := uuid.New()
	compID2 := uuid.New()
	now := time.Now()

	tests := []struct {
		name      string
		sbomID    uuid.UUID
		setupMock func()
		wantErr   bool
		wantCount int
		checkFunc func(t *testing.T, components []model.Component)
	}{
		{
			name:   "successful list with multiple components",
			sbomID: sbomID,
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"id", "sbom_id", "name", "version", "type", "purl", "license", "created_at"}).
					AddRow(compID1, sbomID, "axios", "1.4.0", "library", "pkg:npm/axios@1.4.0", "MIT", now).
					AddRow(compID2, sbomID, "react", "18.2.0", "library", "pkg:npm/react@18.2.0", "MIT", now)
				mock.ExpectQuery("SELECT id, sbom_id, name, version, type, purl, license, created_at FROM components WHERE sbom_id").
					WithArgs(sbomID).
					WillReturnRows(rows)
			},
			wantErr:   false,
			wantCount: 2,
			checkFunc: func(t *testing.T, components []model.Component) {
				if components[0].Name != "axios" {
					t.Errorf("expected first component name 'axios', got '%s'", components[0].Name)
				}
				if components[1].Name != "react" {
					t.Errorf("expected second component name 'react', got '%s'", components[1].Name)
				}
			},
		},
		{
			name:   "empty list for sbom with no components",
			sbomID: uuid.New(),
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"id", "sbom_id", "name", "version", "type", "purl", "license", "created_at"})
				mock.ExpectQuery("SELECT id, sbom_id, name, version, type, purl, license, created_at FROM components WHERE sbom_id").
					WithArgs(sqlmock.AnyArg()).
					WillReturnRows(rows)
			},
			wantErr:   false,
			wantCount: 0,
			checkFunc: nil,
		},
		{
			name:   "database query error",
			sbomID: uuid.New(),
			setupMock: func() {
				mock.ExpectQuery("SELECT id, sbom_id, name, version, type, purl, license, created_at FROM components WHERE sbom_id").
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(errors.New("connection refused"))
			},
			wantErr:   true,
			wantCount: 0,
			checkFunc: nil,
		},
		{
			name:   "scan error with invalid column type",
			sbomID: sbomID,
			setupMock: func() {
				// Use wrong column types to trigger scan error
				rows := sqlmock.NewRows([]string{"id", "sbom_id", "name", "version", "type", "purl", "license", "created_at"}).
					AddRow("not-a-uuid", sbomID, "lodash", "4.17.21", "library", "pkg:npm/lodash@4.17.21", "MIT", now)
				mock.ExpectQuery("SELECT id, sbom_id, name, version, type, purl, license, created_at FROM components WHERE sbom_id").
					WithArgs(sbomID).
					WillReturnRows(rows)
			},
			wantErr:   true,
			wantCount: 0,
			checkFunc: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			result, err := repo.ListBySbom(context.Background(), tt.sbomID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ListBySbom() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(result) != tt.wantCount {
				t.Errorf("ListBySbom() count = %d, want %d", len(result), tt.wantCount)
			}
			if tt.checkFunc != nil && result != nil {
				tt.checkFunc(t, result)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestComponentRepository_GetByID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewComponentRepository(db)
	compID := uuid.New()
	sbomID := uuid.New()
	now := time.Now()

	tests := []struct {
		name      string
		compID    uuid.UUID
		setupMock func()
		wantErr   bool
		checkFunc func(t *testing.T, c *model.Component)
	}{
		{
			name:   "successful get by id",
			compID: compID,
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"id", "sbom_id", "name", "version", "type", "purl", "license", "created_at"}).
					AddRow(compID, sbomID, "lodash", "4.17.21", "library", "pkg:npm/lodash@4.17.21", "MIT", now)
				mock.ExpectQuery("SELECT id, sbom_id, name, version, type, purl, license, created_at FROM components WHERE id").
					WithArgs(compID).
					WillReturnRows(rows)
			},
			wantErr: false,
			checkFunc: func(t *testing.T, c *model.Component) {
				if c.ID != compID {
					t.Errorf("expected ID %v, got %v", compID, c.ID)
				}
				if c.Name != "lodash" {
					t.Errorf("expected Name 'lodash', got '%s'", c.Name)
				}
				if c.Version != "4.17.21" {
					t.Errorf("expected Version '4.17.21', got '%s'", c.Version)
				}
				if c.Purl != "pkg:npm/lodash@4.17.21" {
					t.Errorf("expected Purl 'pkg:npm/lodash@4.17.21', got '%s'", c.Purl)
				}
				if c.License != "MIT" {
					t.Errorf("expected License 'MIT', got '%s'", c.License)
				}
			},
		},
		{
			name:   "component not found",
			compID: uuid.New(),
			setupMock: func() {
				mock.ExpectQuery("SELECT id, sbom_id, name, version, type, purl, license, created_at FROM components WHERE id").
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(sql.ErrNoRows)
			},
			wantErr:   true,
			checkFunc: nil,
		},
		{
			name:   "database error",
			compID: uuid.New(),
			setupMock: func() {
				mock.ExpectQuery("SELECT id, sbom_id, name, version, type, purl, license, created_at FROM components WHERE id").
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(errors.New("database unavailable"))
			},
			wantErr:   true,
			checkFunc: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			result, err := repo.GetByID(context.Background(), tt.compID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetByID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.checkFunc != nil && result != nil {
				tt.checkFunc(t, result)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestComponentRepository_GetVulnerabilities(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewComponentRepository(db)
	sbomID := uuid.New()
	vulnID1 := uuid.New()
	vulnID2 := uuid.New()
	now := time.Now()

	tests := []struct {
		name      string
		sbomID    uuid.UUID
		setupMock func()
		wantErr   bool
		wantCount int
		checkFunc func(t *testing.T, vulns []model.Vulnerability)
	}{
		{
			name:   "successful get vulnerabilities",
			sbomID: sbomID,
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"id", "cve_id", "description", "severity", "cvss_score", "epss_score", "epss_percentile", "source", "in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use", "published_at", "updated_at"}).
					AddRow(vulnID1, "CVE-2023-1234", "Critical vulnerability in lodash", "CRITICAL", 9.8, 0.42, 0.88, "NVD", true, now, now, false, now, now).
					AddRow(vulnID2, "CVE-2023-5678", "High severity XSS vulnerability", "HIGH", 7.5, 0.0, 0.0, "NVD", false, nil, nil, nil, now, now)
				mock.ExpectQuery("SELECT v.id, v.cve_id, v.description, v.severity, v.cvss_score").
					WithArgs(sbomID).
					WillReturnRows(rows)
			},
			wantErr:   false,
			wantCount: 2,
			checkFunc: func(t *testing.T, vulns []model.Vulnerability) {
				if vulns[0].CVEID != "CVE-2023-1234" {
					t.Errorf("expected first vuln CVE-2023-1234, got %s", vulns[0].CVEID)
				}
				if vulns[0].CVSSScore != 9.8 {
					t.Errorf("expected CVSS score 9.8, got %f", vulns[0].CVSSScore)
				}
				if !vulns[0].InKEV {
					t.Errorf("expected first vuln to be in KEV")
				}
				if vulns[1].Severity != "HIGH" {
					t.Errorf("expected HIGH severity, got %s", vulns[1].Severity)
				}
				if vulns[1].InKEV {
					t.Errorf("expected second vuln to not be in KEV")
				}
				// F446: epss_score/epss_percentile are scanned into the
				// model — a synced row (>0) sets the pointer, an un-synced
				// (0) row leaves it nil so the web badge stays suppressed.
				if vulns[0].EPSSScore == nil || *vulns[0].EPSSScore != 0.42 {
					t.Errorf("expected first vuln EPSSScore 0.42, got %v", vulns[0].EPSSScore)
				}
				if vulns[0].EPSSPercentile == nil || *vulns[0].EPSSPercentile != 0.88 {
					t.Errorf("expected first vuln EPSSPercentile 0.88, got %v", vulns[0].EPSSPercentile)
				}
				if vulns[1].EPSSScore != nil {
					t.Errorf("expected second vuln EPSSScore nil (un-synced), got %v", *vulns[1].EPSSScore)
				}
			},
		},
		{
			name:   "no vulnerabilities found",
			sbomID: uuid.New(),
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"id", "cve_id", "description", "severity", "cvss_score", "epss_score", "epss_percentile", "source", "in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use", "published_at", "updated_at"})
				mock.ExpectQuery("SELECT v.id, v.cve_id, v.description, v.severity, v.cvss_score").
					WithArgs(sqlmock.AnyArg()).
					WillReturnRows(rows)
			},
			wantErr:   false,
			wantCount: 0,
			checkFunc: nil,
		},
		{
			name:   "database error",
			sbomID: uuid.New(),
			setupMock: func() {
				mock.ExpectQuery("SELECT v.id, v.cve_id, v.description, v.severity, v.cvss_score").
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(errors.New("query failed"))
			},
			wantErr:   true,
			wantCount: 0,
			checkFunc: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			result, err := repo.GetVulnerabilities(context.Background(), tt.sbomID, "cvss")
			if (err != nil) != tt.wantErr {
				t.Errorf("GetVulnerabilities() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(result) != tt.wantCount {
				t.Errorf("GetVulnerabilities() count = %d, want %d", len(result), tt.wantCount)
			}
			if tt.checkFunc != nil && result != nil {
				tt.checkFunc(t, result)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestComponentRepository_ListComponentVulnerabilitiesBySbom(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewComponentRepository(db)
	sbomID := uuid.New()
	compID := uuid.New()

	tests := []struct {
		name      string
		sbomID    uuid.UUID
		setupMock func()
		wantErr   bool
		wantCount int
		checkFunc func(t *testing.T, results []model.ComponentVulnerability)
	}{
		{
			name:   "successful list component vulnerabilities",
			sbomID: sbomID,
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"component_id", "component_name", "component_version", "component_purl", "component_license", "cve_id", "severity"}).
					AddRow(compID, "lodash", "4.17.20", "pkg:npm/lodash@4.17.20", "MIT", "CVE-2021-23337", "HIGH").
					AddRow(compID, "lodash", "4.17.20", "pkg:npm/lodash@4.17.20", "MIT", "CVE-2020-8203", "HIGH")
				mock.ExpectQuery("SELECT c.id, c.name, c.version, c.purl, c.license, v.cve_id, v.severity").
					WithArgs(sbomID).
					WillReturnRows(rows)
			},
			wantErr:   false,
			wantCount: 2,
			checkFunc: func(t *testing.T, results []model.ComponentVulnerability) {
				if results[0].ComponentName != "lodash" {
					t.Errorf("expected component name 'lodash', got '%s'", results[0].ComponentName)
				}
				if results[0].CVEID != "CVE-2021-23337" {
					t.Errorf("expected CVE-2021-23337, got %s", results[0].CVEID)
				}
			},
		},
		{
			name:   "empty results",
			sbomID: uuid.New(),
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"component_id", "component_name", "component_version", "component_purl", "component_license", "cve_id", "severity"})
				mock.ExpectQuery("SELECT c.id, c.name, c.version, c.purl, c.license, v.cve_id, v.severity").
					WithArgs(sqlmock.AnyArg()).
					WillReturnRows(rows)
			},
			wantErr:   false,
			wantCount: 0,
			checkFunc: nil,
		},
		{
			name:   "database error",
			sbomID: uuid.New(),
			setupMock: func() {
				mock.ExpectQuery("SELECT c.id, c.name, c.version, c.purl, c.license, v.cve_id, v.severity").
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(errors.New("join failed"))
			},
			wantErr:   true,
			wantCount: 0,
			checkFunc: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			result, err := repo.ListComponentVulnerabilitiesBySbom(context.Background(), tt.sbomID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ListComponentVulnerabilitiesBySbom() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(result) != tt.wantCount {
				t.Errorf("ListComponentVulnerabilitiesBySbom() count = %d, want %d", len(result), tt.wantCount)
			}
			if tt.checkFunc != nil && result != nil {
				tt.checkFunc(t, result)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestNewComponentRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewComponentRepository(db)
	if repo == nil {
		t.Error("NewComponentRepository returned nil")
	}
	if repo.db != db {
		t.Error("NewComponentRepository did not set db correctly")
	}
}

func TestComponentRepository_Create_VariousTypes(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewComponentRepository(db)

	componentTypes := []struct {
		name     string
		compType string
		purl     string
	}{
		{"npm library", "library", "pkg:npm/express@4.18.2"},
		{"go module", "library", "pkg:golang/github.com/gin-gonic/gin@1.9.1"},
		{"docker image", "container", "pkg:docker/nginx@1.25"},
		{"python package", "library", "pkg:pypi/django@4.2"},
		{"maven artifact", "library", "pkg:maven/org.springframework/spring-core@5.3.29"},
	}

	for _, tc := range componentTypes {
		t.Run(tc.name, func(t *testing.T) {
			component := &model.Component{
				ID:        uuid.New(),
				SbomID:    uuid.New(),
				Name:      tc.name,
				Version:   "1.0.0",
				Type:      tc.compType,
				Purl:      tc.purl,
				License:   "MIT",
				CreatedAt: time.Now(),
			}

			mock.ExpectExec("INSERT INTO components").
				WithArgs(component.ID, component.TenantID, component.SbomID, tc.name, "1.0.0", tc.compType, tc.purl, "MIT", sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(1, 1))

			err := repo.Create(context.Background(), component)
			if err != nil {
				t.Errorf("Create() failed for %s: %v", tc.name, err)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestComponentRepository_ListBySbom_OrderedByName(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewComponentRepository(db)
	sbomID := uuid.New()
	now := time.Now()

	// Components should be returned ordered by name
	rows := sqlmock.NewRows([]string{"id", "sbom_id", "name", "version", "type", "purl", "license", "created_at"}).
		AddRow(uuid.New(), sbomID, "axios", "1.4.0", "library", "", "", now).
		AddRow(uuid.New(), sbomID, "lodash", "4.17.21", "library", "", "", now).
		AddRow(uuid.New(), sbomID, "react", "18.2.0", "library", "", "", now)

	mock.ExpectQuery("SELECT id, sbom_id, name, version, type, purl, license, created_at FROM components WHERE sbom_id").
		WithArgs(sbomID).
		WillReturnRows(rows)

	components, err := repo.ListBySbom(context.Background(), sbomID)
	if err != nil {
		t.Fatalf("ListBySbom() error: %v", err)
	}

	if len(components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(components))
	}

	expectedOrder := []string{"axios", "lodash", "react"}
	for i, expected := range expectedOrder {
		if components[i].Name != expected {
			t.Errorf("component at index %d: expected name '%s', got '%s'", i, expected, components[i].Name)
		}
	}
}

// TestComponentRepository_GetVulnerabilitiesPaginated_DistinctByVulnID_F29
// is the regression guard for M1 Codex review #F29 (high / data
// integrity).
//
// Symptom: the original implementation selected from
//
//	vulnerabilities v
//	JOIN component_vulnerabilities cv ON cv.vulnerability_id = v.id
//	JOIN components c ON c.id = cv.component_id
//	WHERE c.sbom_id = $1
//
// without a DISTINCT clause, so a single vulnerability linked to N
// components in the same SBOM produced N duplicate rows. The sibling
// CountVulnerabilities used COUNT(DISTINCT v.id), so a project where
// CVE-A was linked to (say) 100 components and CVE-B to 1 component
// returned an X-Total-Count of 2 but a 50-row default page that was
// entirely duplicate CVE-A rows — the Web UI banner condition
// `vulnTotalCount > vulnerabilities.length` (2 > 50 → false) stayed
// silent while CVE-B was inaccessible from the UI.
//
// Guard: the new implementation uses `WHERE EXISTS (...)` on the join
// table so the result has exactly one row per matched vulnerability.
// This test pins "EXISTS" in the SQL pattern via go-sqlmock's regex
// matcher — a future revert that re-introduces the unfiltered join
// would fail to match and trip this test before landing in production.
//
// We assert two scenarios:
//  1. A vulnerability linked to >50 components and a second linked to 1
//     would, under the old query, fill a default page with duplicate
//     rows of the first. The mocked response shape (2 distinct rows)
//     mirrors what the fixed query produces — paired with the SQL
//     regex pin, sqlmock will refuse to match the old join query and
//     surface the regression as "unexpected query".
//  2. The X-Total-Count cardinality (mirrored at the repository layer
//     via CountVulnerabilities) and the page row count are now adjudi-
//     cated on the same units (one row per vulnerability), so the UI
//     truncation banner cannot be silenced by duplicate rows.
func TestComponentRepository_GetVulnerabilitiesPaginated_DistinctByVulnID_F29(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewComponentRepository(db)
	sbomID := uuid.New()
	cveAID := uuid.New() // linked to 100 components
	cveBID := uuid.New() // linked to 1 component
	now := time.Now()

	// The load-bearing assertions are:
	//   - "EXISTS" in the SQL pattern (pins #F29 de-duplication strategy);
	//   - WithArgs(sbomID, 50, 0) (the handler's default-page contract
	//     remains: limit=50 here mirrors what the handler would clamp).
	// A regression that drops EXISTS for the old JOIN form would no longer
	// match this regex and surface as a sqlmock "unexpected query".
	mock.ExpectQuery(`FROM vulnerabilities v WHERE EXISTS.*LIMIT \$2 OFFSET \$3`).
		WithArgs(sbomID, 50, 0).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "cve_id", "description", "severity", "cvss_score",
			"epss_score", "epss_percentile", "source",
			"in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use",
			"published_at", "updated_at",
		}).
			AddRow(cveAID, "CVE-2024-AAAA", "high-fanout vuln", "CRITICAL", 9.8, 0.0, 0.0, "NVD",
				false, nil, nil, nil, now, now).
			AddRow(cveBID, "CVE-2024-BBBB", "single-component vuln", "HIGH", 7.5, 0.0, 0.0, "NVD",
				false, nil, nil, nil, now, now))

	got, err := repo.GetVulnerabilitiesPaginated(context.Background(), sbomID, 50, 0, "cvss")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesPaginated: %v", err)
	}
	// 2 distinct vulnerabilities — NOT 100 duplicates of CVE-A. Under the
	// pre-fix query the response shape would have been 50 rows of CVE-A
	// with CVE-B never reached.
	if len(got) != 2 {
		t.Fatalf("F29: expected 2 distinct vulnerabilities, got %d", len(got))
	}
	seen := map[uuid.UUID]int{}
	for _, v := range got {
		seen[v.ID]++
	}
	if seen[cveAID] != 1 {
		t.Errorf("F29: CVE-A must appear exactly once, got %d occurrences", seen[cveAID])
	}
	if seen[cveBID] != 1 {
		t.Errorf("F29: CVE-B must appear exactly once (would be 0 under the pre-fix duplicate-row query), got %d occurrences", seen[cveBID])
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestComponentRepository_GetVulnerabilitiesPaginated_SortOrderBy_F446 pins the
// M38 EPSS-sort switch: sort=="epss" must emit `ORDER BY v.epss_score DESC
// NULLS LAST, v.id` and any other value (incl. "" / "cvss") must keep
// `ORDER BY v.cvss_score DESC NULLS LAST, v.id`. The assertion is a
// go-sqlmock regex on the emitted SQL — non-vacuous vs a hardcoded single
// ORDER BY, because a regression that always sorted by cvss would fail the
// epss case (the epss ORDER BY regex would not match the cvss query and
// sqlmock returns "unexpected query"), and vice versa. The epss case also
// pins that epss_score/epss_percentile are scanned into the model (>0 sets
// the pointer, un-synced 0 leaves it nil).
func TestComponentRepository_GetVulnerabilitiesPaginated_SortOrderBy_F446(t *testing.T) {
	sbomID := uuid.New()
	now := time.Now()

	tests := []struct {
		name         string
		sortBy       string
		wantOrderBy  string // go-sqlmock regex the emitted SQL MUST contain
		wantEPSSScan bool   // assert the epss pointers are populated from the row
	}{
		{"epss sorts by epss_score", "epss", `ORDER BY v\.epss_score DESC NULLS LAST, v\.id`, true},
		{"cvss sorts by cvss_score", "cvss", `ORDER BY v\.cvss_score DESC NULLS LAST, v\.id`, false},
		{"empty defaults to cvss", "", `ORDER BY v\.cvss_score DESC NULLS LAST, v\.id`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()
			repo := NewComponentRepository(db)

			vulnID := uuid.New()
			// The load-bearing assertion: the ORDER BY branch specific to
			// this sortBy MUST appear in the emitted SQL. If the code chose
			// the wrong column, this regex would not match and sqlmock would
			// surface "unexpected query", failing the call below.
			mock.ExpectQuery(`FROM vulnerabilities v WHERE EXISTS.*`+tt.wantOrderBy+`.*LIMIT \$2 OFFSET \$3`).
				WithArgs(sbomID, 50, 0).
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "cve_id", "description", "severity", "cvss_score",
					"epss_score", "epss_percentile", "source",
					"in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use",
					"published_at", "updated_at",
				}).AddRow(vulnID, "CVE-2024-EPSS", "epss-sorted vuln", "CRITICAL", 9.1,
					0.55, 0.97, "NVD", false, nil, nil, nil, now, now))

			got, err := repo.GetVulnerabilitiesPaginated(context.Background(), sbomID, 50, 0, tt.sortBy)
			if err != nil {
				t.Fatalf("GetVulnerabilitiesPaginated(sort=%q): %v", tt.sortBy, err)
			}
			if len(got) != 1 {
				t.Fatalf("expected 1 vuln, got %d", len(got))
			}
			// epss_score/epss_percentile are always scanned (positional
			// alignment) regardless of the sort column; the row here carries
			// 0.55/0.97 so both pointers must be populated.
			if got[0].EPSSScore == nil || *got[0].EPSSScore != 0.55 {
				t.Errorf("expected scanned EPSSScore 0.55, got %v", got[0].EPSSScore)
			}
			if got[0].EPSSPercentile == nil || *got[0].EPSSPercentile != 0.97 {
				t.Errorf("expected scanned EPSSPercentile 0.97, got %v", got[0].EPSSPercentile)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet sqlmock expectations: %v", err)
			}
		})
	}
}

// TestComponentRepository_GetVulnerabilitiesPaginated_UnsyncedEPSSNil_F446 pins
// the `> 0` guard: a row whose COALESCE'd epss columns are 0 (un-synced) must
// leave the model pointers nil so the web EPSS badge stays suppressed.
func TestComponentRepository_GetVulnerabilitiesPaginated_UnsyncedEPSSNil_F446(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	repo := NewComponentRepository(db)

	sbomID := uuid.New()
	now := time.Now()
	mock.ExpectQuery(`FROM vulnerabilities v WHERE EXISTS.*LIMIT \$2 OFFSET \$3`).
		WithArgs(sbomID, 50, 0).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "cve_id", "description", "severity", "cvss_score",
			"epss_score", "epss_percentile", "source",
			"in_kev", "kev_date_added", "kev_due_date", "kev_ransomware_use",
			"published_at", "updated_at",
		}).AddRow(uuid.New(), "CVE-2024-NULL", "un-synced vuln", "LOW", 3.1,
			0.0, 0.0, "NVD", false, nil, nil, nil, now, now))

	got, err := repo.GetVulnerabilitiesPaginated(context.Background(), sbomID, 50, 0, "epss")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesPaginated: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(got))
	}
	if got[0].EPSSScore != nil {
		t.Errorf("un-synced (0) epss_score must scan to nil, got %v", *got[0].EPSSScore)
	}
	if got[0].EPSSPercentile != nil {
		t.Errorf("un-synced (0) epss_percentile must scan to nil, got %v", *got[0].EPSSPercentile)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestComponentRepository_Create_PassesTenantID locks the tenant_id column to
// position 2 of the INSERT. Symmetric guard to the sbom-side test: makes a
// silent reorder loud.
func TestComponentRepository_Create_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewComponentRepository(db)
	tenantID := uuid.New()
	sbomID := uuid.New()
	compID := uuid.New()
	createdAt := time.Now()

	mock.ExpectExec("INSERT INTO components").
		WithArgs(compID, tenantID, sbomID, "lodash", "4.17.21", "library", "pkg:npm/lodash@4.17.21", "MIT", createdAt).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = repo.Create(context.Background(), &model.Component{
		ID:        compID,
		TenantID:  tenantID,
		SbomID:    sbomID,
		Name:      "lodash",
		Version:   "4.17.21",
		Type:      "library",
		Purl:      "pkg:npm/lodash@4.17.21",
		License:   "MIT",
		CreatedAt: createdAt,
	})
	if err != nil {
		t.Fatalf("Create returned unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}
