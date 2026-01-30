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

func TestSbomRepository_Create(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewSbomRepository(db)

	tests := []struct {
		name      string
		sbom      *model.Sbom
		setupMock func()
		wantErr   bool
	}{
		{
			name: "successful create",
			sbom: &model.Sbom{
				ID:        uuid.New(),
				ProjectID: uuid.New(),
				Format:    "cyclonedx",
				Version:   "1.4",
				RawData:   []byte(`{"bomFormat":"CycloneDX"}`),
				CreatedAt: time.Now(),
			},
			setupMock: func() {
				mock.ExpectExec("INSERT INTO sboms").
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "cyclonedx", "1.4", sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "database error",
			sbom: &model.Sbom{
				ID:        uuid.New(),
				ProjectID: uuid.New(),
				Format:    "spdx",
				Version:   "2.3",
				RawData:   []byte(`{"spdxVersion":"SPDX-2.3"}`),
				CreatedAt: time.Now(),
			},
			setupMock: func() {
				mock.ExpectExec("INSERT INTO sboms").
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "spdx", "2.3", sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(errors.New("database connection failed"))
			},
			wantErr: true,
		},
		{
			name: "duplicate key error",
			sbom: &model.Sbom{
				ID:        uuid.New(),
				ProjectID: uuid.New(),
				Format:    "cyclonedx",
				Version:   "1.5",
				RawData:   []byte(`{}`),
				CreatedAt: time.Now(),
			},
			setupMock: func() {
				mock.ExpectExec("INSERT INTO sboms").
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "cyclonedx", "1.5", sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(errors.New("duplicate key value violates unique constraint"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			err := repo.Create(context.Background(), tt.sbom)
			if (err != nil) != tt.wantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestSbomRepository_GetLatest(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewSbomRepository(db)
	projectID := uuid.New()
	sbomID := uuid.New()
	createdAt := time.Now()

	tests := []struct {
		name      string
		projectID uuid.UUID
		setupMock func()
		wantErr   bool
		wantNil   bool
	}{
		{
			name:      "successful get latest",
			projectID: projectID,
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"id", "project_id", "format", "version", "raw_data", "created_at"}).
					AddRow(sbomID, projectID, "cyclonedx", "1.4", []byte(`{}`), createdAt)
				mock.ExpectQuery("SELECT id, project_id, format, version, raw_data, created_at FROM sboms").
					WithArgs(projectID).
					WillReturnRows(rows)
			},
			wantErr: false,
			wantNil: false,
		},
		{
			name:      "no rows found",
			projectID: uuid.New(),
			setupMock: func() {
				mock.ExpectQuery("SELECT id, project_id, format, version, raw_data, created_at FROM sboms").
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(sql.ErrNoRows)
			},
			wantErr: true,
			wantNil: true,
		},
		{
			name:      "database error",
			projectID: uuid.New(),
			setupMock: func() {
				mock.ExpectQuery("SELECT id, project_id, format, version, raw_data, created_at FROM sboms").
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(errors.New("connection reset"))
			},
			wantErr: true,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			result, err := repo.GetLatest(context.Background(), tt.projectID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetLatest() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (result == nil) != tt.wantNil {
				t.Errorf("GetLatest() result nil = %v, wantNil %v", result == nil, tt.wantNil)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestSbomRepository_GetByID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewSbomRepository(db)
	sbomID := uuid.New()
	projectID := uuid.New()
	createdAt := time.Now()

	tests := []struct {
		name      string
		sbomID    uuid.UUID
		setupMock func()
		wantErr   bool
		checkFunc func(t *testing.T, s *model.Sbom)
	}{
		{
			name:   "successful get by id",
			sbomID: sbomID,
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"id", "project_id", "format", "version", "raw_data", "created_at"}).
					AddRow(sbomID, projectID, "spdx", "2.3", []byte(`{"spdxVersion":"SPDX-2.3"}`), createdAt)
				mock.ExpectQuery("SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE id").
					WithArgs(sbomID).
					WillReturnRows(rows)
			},
			wantErr: false,
			checkFunc: func(t *testing.T, s *model.Sbom) {
				if s.ID != sbomID {
					t.Errorf("expected ID %v, got %v", sbomID, s.ID)
				}
				if s.Format != "spdx" {
					t.Errorf("expected Format spdx, got %s", s.Format)
				}
				if s.Version != "2.3" {
					t.Errorf("expected Version 2.3, got %s", s.Version)
				}
			},
		},
		{
			name:   "not found",
			sbomID: uuid.New(),
			setupMock: func() {
				mock.ExpectQuery("SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE id").
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(sql.ErrNoRows)
			},
			wantErr:   true,
			checkFunc: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			result, err := repo.GetByID(context.Background(), tt.sbomID)
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

func TestSbomRepository_ListByProject(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewSbomRepository(db)
	projectID := uuid.New()
	sbomID1 := uuid.New()
	sbomID2 := uuid.New()
	now := time.Now()

	tests := []struct {
		name      string
		projectID uuid.UUID
		setupMock func()
		wantErr   bool
		wantCount int
	}{
		{
			name:      "successful list with multiple sboms",
			projectID: projectID,
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"id", "project_id", "format", "version", "raw_data", "created_at"}).
					AddRow(sbomID1, projectID, "cyclonedx", "1.4", []byte(`{}`), now).
					AddRow(sbomID2, projectID, "spdx", "2.3", []byte(`{}`), now.Add(-time.Hour))
				mock.ExpectQuery("SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE project_id").
					WithArgs(projectID).
					WillReturnRows(rows)
			},
			wantErr:   false,
			wantCount: 2,
		},
		{
			name:      "empty list",
			projectID: uuid.New(),
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"id", "project_id", "format", "version", "raw_data", "created_at"})
				mock.ExpectQuery("SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE project_id").
					WithArgs(sqlmock.AnyArg()).
					WillReturnRows(rows)
			},
			wantErr:   false,
			wantCount: 0,
		},
		{
			name:      "database error",
			projectID: uuid.New(),
			setupMock: func() {
				mock.ExpectQuery("SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE project_id").
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(errors.New("query timeout"))
			},
			wantErr:   true,
			wantCount: 0,
		},
		{
			name:      "scan error with invalid column type",
			projectID: projectID,
			setupMock: func() {
				// Use wrong column types to trigger scan error
				rows := sqlmock.NewRows([]string{"id", "project_id", "format", "version", "raw_data", "created_at"}).
					AddRow("not-a-uuid", projectID, "cyclonedx", "1.4", []byte(`{}`), now)
				mock.ExpectQuery("SELECT id, project_id, format, version, raw_data, created_at FROM sboms WHERE project_id").
					WithArgs(projectID).
					WillReturnRows(rows)
			},
			wantErr:   true,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			result, err := repo.ListByProject(context.Background(), tt.projectID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ListByProject() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(result) != tt.wantCount {
				t.Errorf("ListByProject() count = %d, want %d", len(result), tt.wantCount)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestNewSbomRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewSbomRepository(db)
	if repo == nil {
		t.Error("NewSbomRepository returned nil")
	}
	if repo.db != db {
		t.Error("NewSbomRepository did not set db correctly")
	}
}

func TestSbomRepository_Create_ContextCancellation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewSbomRepository(db)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	sbom := &model.Sbom{
		ID:        uuid.New(),
		ProjectID: uuid.New(),
		Format:    "cyclonedx",
		Version:   "1.4",
		RawData:   []byte(`{}`),
		CreatedAt: time.Now(),
	}

	mock.ExpectExec("INSERT INTO sboms").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "cyclonedx", "1.4", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(context.Canceled)

	err = repo.Create(ctx, sbom)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestSbomRepository_GetLatest_ReturnsCorrectFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewSbomRepository(db)
	sbomID := uuid.New()
	projectID := uuid.New()
	createdAt := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	rawData := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`)

	rows := sqlmock.NewRows([]string{"id", "project_id", "format", "version", "raw_data", "created_at"}).
		AddRow(sbomID, projectID, "cyclonedx", "1.5", rawData, createdAt)
	mock.ExpectQuery("SELECT id, project_id, format, version, raw_data, created_at FROM sboms").
		WithArgs(projectID).
		WillReturnRows(rows)

	result, err := repo.GetLatest(context.Background(), projectID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ID != sbomID {
		t.Errorf("ID mismatch: got %v, want %v", result.ID, sbomID)
	}
	if result.ProjectID != projectID {
		t.Errorf("ProjectID mismatch: got %v, want %v", result.ProjectID, projectID)
	}
	if result.Format != "cyclonedx" {
		t.Errorf("Format mismatch: got %s, want cyclonedx", result.Format)
	}
	if result.Version != "1.5" {
		t.Errorf("Version mismatch: got %s, want 1.5", result.Version)
	}
	if string(result.RawData) != string(rawData) {
		t.Errorf("RawData mismatch: got %s, want %s", result.RawData, rawData)
	}
	if !result.CreatedAt.Equal(createdAt) {
		t.Errorf("CreatedAt mismatch: got %v, want %v", result.CreatedAt, createdAt)
	}
}
