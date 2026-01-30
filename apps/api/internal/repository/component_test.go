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
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "lodash", "4.17.21", "library", "pkg:npm/lodash@4.17.21", "MIT", sqlmock.AnyArg()).
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
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "express", "4.18.2", "library", "", "", sqlmock.AnyArg()).
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
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "axios", "1.4.0", "library", "", "", sqlmock.AnyArg()).
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
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "react", "18.2.0", "library", "", "", sqlmock.AnyArg()).
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
				rows := sqlmock.NewRows([]string{"id", "cve_id", "description", "severity", "cvss_score", "source", "published_at", "updated_at"}).
					AddRow(vulnID1, "CVE-2023-1234", "Critical vulnerability in lodash", "CRITICAL", 9.8, "NVD", now, now).
					AddRow(vulnID2, "CVE-2023-5678", "High severity XSS vulnerability", "HIGH", 7.5, "NVD", now, now)
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
				if vulns[1].Severity != "HIGH" {
					t.Errorf("expected HIGH severity, got %s", vulns[1].Severity)
				}
			},
		},
		{
			name:   "no vulnerabilities found",
			sbomID: uuid.New(),
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"id", "cve_id", "description", "severity", "cvss_score", "source", "published_at", "updated_at"})
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
			result, err := repo.GetVulnerabilities(context.Background(), tt.sbomID)
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
		name    string
		compType string
		purl    string
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
				WithArgs(component.ID, component.SbomID, tc.name, "1.0.0", tc.compType, tc.purl, "MIT", sqlmock.AnyArg()).
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
