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

func TestEOLRepository_New(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)
	if repo == nil {
		t.Error("NewEOLRepository returned nil")
	}
	if repo.db != db {
		t.Error("NewEOLRepository did not set db correctly")
	}
}

func TestEOLRepository_UpsertProduct(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)

	tests := []struct {
		name      string
		product   *model.EOLProduct
		setupMock func()
		wantErr   bool
	}{
		{
			name: "successful insert new product",
			product: &model.EOLProduct{
				ID:          uuid.New(),
				Name:        "python",
				Title:       "Python",
				Category:    "language",
				Link:        "https://python.org",
				TotalCycles: 10,
			},
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"id"}).AddRow(uuid.New())
				mock.ExpectQuery("INSERT INTO eol_products").
					WithArgs(sqlmock.AnyArg(), "python", "Python", "language", "https://python.org", 10).
					WillReturnRows(rows)
			},
			wantErr: false,
		},
		{
			name: "successful upsert existing product",
			product: &model.EOLProduct{
				ID:          uuid.New(),
				Name:        "nodejs",
				Title:       "Node.js",
				Category:    "runtime",
				Link:        "https://nodejs.org",
				TotalCycles: 20,
			},
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"id"}).AddRow(uuid.New())
				mock.ExpectQuery("INSERT INTO eol_products").
					WithArgs(sqlmock.AnyArg(), "nodejs", "Node.js", "runtime", "https://nodejs.org", 20).
					WillReturnRows(rows)
			},
			wantErr: false,
		},
		{
			name: "database error",
			product: &model.EOLProduct{
				ID:   uuid.New(),
				Name: "fail",
			},
			setupMock: func() {
				mock.ExpectQuery("INSERT INTO eol_products").
					WithArgs(sqlmock.AnyArg(), "fail", "", "", "", 0).
					WillReturnError(errors.New("database connection failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			err := repo.UpsertProduct(context.Background(), tt.product)
			if (err != nil) != tt.wantErr {
				t.Errorf("UpsertProduct() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestEOLRepository_GetProductByName(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)
	productID := uuid.New()
	now := time.Now()

	tests := []struct {
		name      string
		prodName  string
		setupMock func()
		wantErr   bool
		wantNil   bool
		checkFunc func(t *testing.T, p *model.EOLProduct)
	}{
		{
			name:     "successful get",
			prodName: "python",
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"id", "name", "title", "category", "link", "total_cycles", "created_at", "updated_at"}).
					AddRow(productID, "python", "Python", "language", "https://python.org", 15, now, now)
				mock.ExpectQuery("SELECT id, name, title, category, link, total_cycles, created_at, updated_at FROM eol_products WHERE name").
					WithArgs("python").
					WillReturnRows(rows)
			},
			wantErr: false,
			wantNil: false,
			checkFunc: func(t *testing.T, p *model.EOLProduct) {
				if p.Name != "python" {
					t.Errorf("expected name python, got %s", p.Name)
				}
				if p.Title != "Python" {
					t.Errorf("expected title Python, got %s", p.Title)
				}
				if p.TotalCycles != 15 {
					t.Errorf("expected 15 cycles, got %d", p.TotalCycles)
				}
			},
		},
		{
			name:     "not found",
			prodName: "nonexistent",
			setupMock: func() {
				mock.ExpectQuery("SELECT id, name, title, category, link, total_cycles, created_at, updated_at FROM eol_products WHERE name").
					WithArgs("nonexistent").
					WillReturnError(sql.ErrNoRows)
			},
			wantErr: false,
			wantNil: true,
		},
		{
			name:     "database error",
			prodName: "error",
			setupMock: func() {
				mock.ExpectQuery("SELECT id, name, title, category, link, total_cycles, created_at, updated_at FROM eol_products WHERE name").
					WithArgs("error").
					WillReturnError(errors.New("connection reset"))
			},
			wantErr: true,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			result, err := repo.GetProductByName(context.Background(), tt.prodName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetProductByName() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (result == nil) != tt.wantNil {
				t.Errorf("GetProductByName() nil = %v, wantNil %v", result == nil, tt.wantNil)
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

func TestEOLRepository_GetProductByID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)
	productID := uuid.New()
	now := time.Now()

	tests := []struct {
		name      string
		id        uuid.UUID
		setupMock func()
		wantErr   bool
		wantNil   bool
	}{
		{
			name: "successful get",
			id:   productID,
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"id", "name", "title", "category", "link", "total_cycles", "created_at", "updated_at"}).
					AddRow(productID, "nodejs", "Node.js", "runtime", "https://nodejs.org", 25, now, now)
				mock.ExpectQuery("SELECT id, name, title, category, link, total_cycles, created_at, updated_at FROM eol_products WHERE id").
					WithArgs(productID).
					WillReturnRows(rows)
			},
			wantErr: false,
			wantNil: false,
		},
		{
			name: "not found",
			id:   uuid.New(),
			setupMock: func() {
				mock.ExpectQuery("SELECT id, name, title, category, link, total_cycles, created_at, updated_at FROM eol_products WHERE id").
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(sql.ErrNoRows)
			},
			wantErr: false,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			result, err := repo.GetProductByID(context.Background(), tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetProductByID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (result == nil) != tt.wantNil {
				t.Errorf("GetProductByID() nil = %v, wantNil %v", result == nil, tt.wantNil)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestEOLRepository_ListProducts(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)
	now := time.Now()

	tests := []struct {
		name       string
		limit      int
		offset     int
		setupMock  func()
		wantErr    bool
		wantCount  int
		wantTotal  int
	}{
		{
			name:   "successful list with multiple products",
			limit:  10,
			offset: 0,
			setupMock: func() {
				mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))
				rows := sqlmock.NewRows([]string{"id", "name", "title", "category", "link", "total_cycles", "created_at", "updated_at"}).
					AddRow(uuid.New(), "python", "Python", "language", "", 10, now, now).
					AddRow(uuid.New(), "nodejs", "Node.js", "runtime", "", 20, now, now).
					AddRow(uuid.New(), "django", "Django", "framework", "", 5, now, now)
				mock.ExpectQuery("SELECT id, name, title, category, link, total_cycles, created_at, updated_at FROM eol_products").
					WithArgs(10, 0).
					WillReturnRows(rows)
			},
			wantErr:   false,
			wantCount: 3,
			wantTotal: 3,
		},
		{
			name:   "empty list",
			limit:  10,
			offset: 0,
			setupMock: func() {
				mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
				rows := sqlmock.NewRows([]string{"id", "name", "title", "category", "link", "total_cycles", "created_at", "updated_at"})
				mock.ExpectQuery("SELECT id, name, title, category, link, total_cycles, created_at, updated_at FROM eol_products").
					WithArgs(10, 0).
					WillReturnRows(rows)
			},
			wantErr:   false,
			wantCount: 0,
			wantTotal: 0,
		},
		{
			name:   "count query error",
			limit:  10,
			offset: 0,
			setupMock: func() {
				mock.ExpectQuery("SELECT COUNT").WillReturnError(errors.New("count failed"))
			},
			wantErr:   true,
			wantCount: 0,
			wantTotal: 0,
		},
		{
			name:   "list query error",
			limit:  10,
			offset: 0,
			setupMock: func() {
				mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))
				mock.ExpectQuery("SELECT id, name, title, category, link, total_cycles, created_at, updated_at FROM eol_products").
					WithArgs(10, 0).
					WillReturnError(errors.New("query failed"))
			},
			wantErr:   true,
			wantCount: 0,
			wantTotal: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			products, total, err := repo.ListProducts(context.Background(), tt.limit, tt.offset)
			if (err != nil) != tt.wantErr {
				t.Errorf("ListProducts() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if len(products) != tt.wantCount {
					t.Errorf("ListProducts() count = %d, want %d", len(products), tt.wantCount)
				}
				if total != tt.wantTotal {
					t.Errorf("ListProducts() total = %d, want %d", total, tt.wantTotal)
				}
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestEOLRepository_UpsertCycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)
	productID := uuid.New()
	eolDate := time.Date(2025, 10, 31, 0, 0, 0, 0, time.UTC)
	releaseDate := time.Date(2021, 10, 4, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		cycle     *model.EOLProductCycle
		setupMock func()
		wantErr   bool
	}{
		{
			name: "successful insert",
			cycle: &model.EOLProductCycle{
				ID:            uuid.New(),
				ProductID:     productID,
				Cycle:         "3.11",
				ReleaseDate:   &releaseDate,
				EOLDate:       &eolDate,
				LatestVersion: "3.11.7",
				IsLTS:         false,
				IsEOL:         false,
			},
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"id"}).AddRow(uuid.New())
				mock.ExpectQuery("INSERT INTO eol_product_cycles").
					WithArgs(sqlmock.AnyArg(), productID, "3.11", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						"3.11.7", false, false, false, "", sqlmock.AnyArg()).
					WillReturnRows(rows)
			},
			wantErr: false,
		},
		{
			name: "successful insert LTS cycle",
			cycle: &model.EOLProductCycle{
				ID:            uuid.New(),
				ProductID:     productID,
				Cycle:         "18",
				LatestVersion: "18.19.0",
				IsLTS:         true,
				IsEOL:         false,
			},
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"id"}).AddRow(uuid.New())
				mock.ExpectQuery("INSERT INTO eol_product_cycles").
					WithArgs(sqlmock.AnyArg(), productID, "18", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						"18.19.0", true, false, false, "", sqlmock.AnyArg()).
					WillReturnRows(rows)
			},
			wantErr: false,
		},
		{
			name: "database error",
			cycle: &model.EOLProductCycle{
				ID:        uuid.New(),
				ProductID: productID,
				Cycle:     "error",
			},
			setupMock: func() {
				mock.ExpectQuery("INSERT INTO eol_product_cycles").
					WithArgs(sqlmock.AnyArg(), productID, "error", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
						"", false, false, false, "", sqlmock.AnyArg()).
					WillReturnError(errors.New("constraint violation"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			err := repo.UpsertCycle(context.Background(), tt.cycle)
			if (err != nil) != tt.wantErr {
				t.Errorf("UpsertCycle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestEOLRepository_GetCyclesByProduct(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)
	productID := uuid.New()
	now := time.Now()
	eolDate := time.Date(2027, 10, 31, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		productID uuid.UUID
		setupMock func()
		wantErr   bool
		wantCount int
	}{
		{
			name:      "successful get multiple cycles",
			productID: productID,
			setupMock: func() {
				rows := sqlmock.NewRows([]string{
					"id", "product_id", "cycle", "release_date", "eol_date", "eos_date",
					"latest_version", "is_lts", "is_eol", "discontinued", "link", "support_end_date",
					"created_at", "updated_at",
				}).
					AddRow(uuid.New(), productID, "3.12", &now, &eolDate, nil, "3.12.1", false, false, false, "", nil, now, now).
					AddRow(uuid.New(), productID, "3.11", &now, &now, nil, "3.11.7", false, true, false, "", nil, now, now)
				mock.ExpectQuery("SELECT id, product_id, cycle, release_date, eol_date, eos_date").
					WithArgs(productID).
					WillReturnRows(rows)
			},
			wantErr:   false,
			wantCount: 2,
		},
		{
			name:      "empty list",
			productID: uuid.New(),
			setupMock: func() {
				rows := sqlmock.NewRows([]string{
					"id", "product_id", "cycle", "release_date", "eol_date", "eos_date",
					"latest_version", "is_lts", "is_eol", "discontinued", "link", "support_end_date",
					"created_at", "updated_at",
				})
				mock.ExpectQuery("SELECT id, product_id, cycle, release_date, eol_date, eos_date").
					WithArgs(sqlmock.AnyArg()).
					WillReturnRows(rows)
			},
			wantErr:   false,
			wantCount: 0,
		},
		{
			name:      "database error",
			productID: uuid.New(),
			setupMock: func() {
				mock.ExpectQuery("SELECT id, product_id, cycle, release_date, eol_date, eos_date").
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(errors.New("query failed"))
			},
			wantErr:   true,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			cycles, err := repo.GetCyclesByProduct(context.Background(), tt.productID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCyclesByProduct() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(cycles) != tt.wantCount {
				t.Errorf("GetCyclesByProduct() count = %d, want %d", len(cycles), tt.wantCount)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestEOLRepository_FindMatchingCycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)
	productID := uuid.New()
	cycleID := uuid.New()
	now := time.Now()
	eolDate := time.Date(2027, 10, 31, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		productID uuid.UUID
		version   string
		setupMock func()
		wantErr   bool
		wantNil   bool
		checkFunc func(t *testing.T, c *model.EOLProductCycle)
	}{
		{
			name:      "exact match",
			productID: productID,
			version:   "3.11",
			setupMock: func() {
				rows := sqlmock.NewRows([]string{
					"id", "product_id", "cycle", "release_date", "eol_date", "eos_date",
					"latest_version", "is_lts", "is_eol", "discontinued", "link", "support_end_date",
					"created_at", "updated_at",
				}).AddRow(cycleID, productID, "3.11", &now, &eolDate, nil, "3.11.7", false, false, false, "", nil, now, now)
				mock.ExpectQuery("SELECT id, product_id, cycle, release_date, eol_date, eos_date").
					WithArgs(productID, "3.11").
					WillReturnRows(rows)
			},
			wantErr: false,
			wantNil: false,
			checkFunc: func(t *testing.T, c *model.EOLProductCycle) {
				if c.Cycle != "3.11" {
					t.Errorf("expected cycle 3.11, got %s", c.Cycle)
				}
				if c.LatestVersion != "3.11.7" {
					t.Errorf("expected latest version 3.11.7, got %s", c.LatestVersion)
				}
			},
		},
		{
			name:      "prefix match (3.11.4 -> 3.11)",
			productID: productID,
			version:   "3.11.4",
			setupMock: func() {
				rows := sqlmock.NewRows([]string{
					"id", "product_id", "cycle", "release_date", "eol_date", "eos_date",
					"latest_version", "is_lts", "is_eol", "discontinued", "link", "support_end_date",
					"created_at", "updated_at",
				}).AddRow(cycleID, productID, "3.11", &now, &eolDate, nil, "3.11.7", false, false, false, "", nil, now, now)
				mock.ExpectQuery("SELECT id, product_id, cycle, release_date, eol_date, eos_date").
					WithArgs(productID, "3.11.4").
					WillReturnRows(rows)
			},
			wantErr: false,
			wantNil: false,
			checkFunc: func(t *testing.T, c *model.EOLProductCycle) {
				if c.Cycle != "3.11" {
					t.Errorf("expected cycle 3.11, got %s", c.Cycle)
				}
			},
		},
		{
			name:      "no matching cycle",
			productID: productID,
			version:   "99.99",
			setupMock: func() {
				mock.ExpectQuery("SELECT id, product_id, cycle, release_date, eol_date, eos_date").
					WithArgs(productID, "99.99").
					WillReturnError(sql.ErrNoRows)
			},
			wantErr: false,
			wantNil: true,
		},
		{
			name:      "database error",
			productID: productID,
			version:   "error",
			setupMock: func() {
				mock.ExpectQuery("SELECT id, product_id, cycle, release_date, eol_date, eos_date").
					WithArgs(productID, "error").
					WillReturnError(errors.New("query failed"))
			},
			wantErr: true,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			cycle, err := repo.FindMatchingCycle(context.Background(), tt.productID, tt.version)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindMatchingCycle() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (cycle == nil) != tt.wantNil {
				t.Errorf("FindMatchingCycle() nil = %v, wantNil %v", cycle == nil, tt.wantNil)
			}
			if tt.checkFunc != nil && cycle != nil {
				tt.checkFunc(t, cycle)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestEOLRepository_GetMappings(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)
	productID := uuid.New()
	now := time.Now()

	tests := []struct {
		name      string
		setupMock func()
		wantErr   bool
		wantCount int
	}{
		{
			name: "successful get mappings",
			setupMock: func() {
				rows := sqlmock.NewRows([]string{
					"id", "product_id", "component_pattern", "component_type", "purl_type", "priority", "is_active", "created_at",
				}).
					AddRow(uuid.New(), productID, "python", "library", "pypi", 100, true, now).
					AddRow(uuid.New(), productID, "cpython", "runtime", "pypi", 90, true, now)
				mock.ExpectQuery("SELECT id, product_id, component_pattern, component_type, purl_type, priority, is_active, created_at FROM eol_component_mappings").
					WillReturnRows(rows)
			},
			wantErr:   false,
			wantCount: 2,
		},
		{
			name: "empty mappings",
			setupMock: func() {
				rows := sqlmock.NewRows([]string{
					"id", "product_id", "component_pattern", "component_type", "purl_type", "priority", "is_active", "created_at",
				})
				mock.ExpectQuery("SELECT id, product_id, component_pattern, component_type, purl_type, priority, is_active, created_at FROM eol_component_mappings").
					WillReturnRows(rows)
			},
			wantErr:   false,
			wantCount: 0,
		},
		{
			name: "database error",
			setupMock: func() {
				mock.ExpectQuery("SELECT id, product_id, component_pattern, component_type, purl_type, priority, is_active, created_at FROM eol_component_mappings").
					WillReturnError(errors.New("query failed"))
			},
			wantErr:   true,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			mappings, err := repo.GetMappings(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("GetMappings() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(mappings) != tt.wantCount {
				t.Errorf("GetMappings() count = %d, want %d", len(mappings), tt.wantCount)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestEOLRepository_CreateMapping(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)
	productID := uuid.New()

	tests := []struct {
		name      string
		mapping   *model.EOLComponentMapping
		setupMock func()
		wantErr   bool
	}{
		{
			name: "successful create",
			mapping: &model.EOLComponentMapping{
				ID:               uuid.New(),
				ProductID:        productID,
				ComponentPattern: "flask",
				ComponentType:    "library",
				PurlType:         "pypi",
				Priority:         100,
				IsActive:         true,
			},
			setupMock: func() {
				mock.ExpectExec("INSERT INTO eol_component_mappings").
					WithArgs(sqlmock.AnyArg(), productID, "flask", "library", "pypi", 100, true).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "create with nil ID (auto-generate)",
			mapping: &model.EOLComponentMapping{
				ProductID:        productID,
				ComponentPattern: "django",
				ComponentType:    "framework",
				PurlType:         "pypi",
				Priority:         90,
				IsActive:         true,
			},
			setupMock: func() {
				mock.ExpectExec("INSERT INTO eol_component_mappings").
					WithArgs(sqlmock.AnyArg(), productID, "django", "framework", "pypi", 90, true).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			wantErr: false,
		},
		{
			name: "database error",
			mapping: &model.EOLComponentMapping{
				ID:               uuid.New(),
				ProductID:        productID,
				ComponentPattern: "error",
			},
			setupMock: func() {
				mock.ExpectExec("INSERT INTO eol_component_mappings").
					WithArgs(sqlmock.AnyArg(), productID, "error", "", "", 0, false).
					WillReturnError(errors.New("insert failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			err := repo.CreateMapping(context.Background(), tt.mapping)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateMapping() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestEOLRepository_SyncSettings(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)
	settingsID := uuid.New()
	now := time.Now()

	t.Run("GetSyncSettings success", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{
			"id", "enabled", "sync_interval_hours", "last_sync_at",
			"total_products", "total_cycles", "created_at", "updated_at",
		}).AddRow(settingsID, true, 24, &now, 50, 500, now, now)
		mock.ExpectQuery("SELECT id, enabled, sync_interval_hours, last_sync_at").
			WillReturnRows(rows)

		settings, err := repo.GetSyncSettings(context.Background())
		if err != nil {
			t.Errorf("GetSyncSettings() error = %v", err)
		}
		if settings == nil {
			t.Fatal("GetSyncSettings() returned nil")
		}
		if !settings.Enabled {
			t.Error("expected Enabled to be true")
		}
		if settings.SyncIntervalHours != 24 {
			t.Errorf("expected SyncIntervalHours 24, got %d", settings.SyncIntervalHours)
		}
		if settings.TotalProducts != 50 {
			t.Errorf("expected TotalProducts 50, got %d", settings.TotalProducts)
		}
	})

	t.Run("GetSyncSettings not found", func(t *testing.T) {
		mock.ExpectQuery("SELECT id, enabled, sync_interval_hours, last_sync_at").
			WillReturnError(sql.ErrNoRows)

		settings, err := repo.GetSyncSettings(context.Background())
		if err != nil {
			t.Errorf("GetSyncSettings() error = %v", err)
		}
		if settings != nil {
			t.Error("expected nil for no rows")
		}
	})

	t.Run("UpdateSyncSettings success", func(t *testing.T) {
		mock.ExpectExec("UPDATE eol_sync_settings SET").
			WithArgs(true, 12, sqlmock.AnyArg(), 60, 600, settingsID).
			WillReturnResult(sqlmock.NewResult(0, 1))

		settings := &model.EOLSyncSettings{
			ID:                settingsID,
			Enabled:           true,
			SyncIntervalHours: 12,
			LastSyncAt:        &now,
			TotalProducts:     60,
			TotalCycles:       600,
		}
		err := repo.UpdateSyncSettings(context.Background(), settings)
		if err != nil {
			t.Errorf("UpdateSyncSettings() error = %v", err)
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestEOLRepository_SyncLog(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)
	now := time.Now()

	t.Run("CreateSyncLog success", func(t *testing.T) {
		mock.ExpectExec("INSERT INTO eol_sync_logs").
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "running").
			WillReturnResult(sqlmock.NewResult(1, 1))

		log, err := repo.CreateSyncLog(context.Background())
		if err != nil {
			t.Errorf("CreateSyncLog() error = %v", err)
		}
		if log == nil {
			t.Fatal("CreateSyncLog() returned nil")
		}
		if log.Status != "running" {
			t.Errorf("expected status running, got %s", log.Status)
		}
	})

	t.Run("UpdateSyncLog success", func(t *testing.T) {
		logID := uuid.New()
		mock.ExpectExec("UPDATE eol_sync_logs SET").
			WithArgs(sqlmock.AnyArg(), "success", 10, 100, 500, "", logID).
			WillReturnResult(sqlmock.NewResult(0, 1))

		log := &model.EOLSyncLog{
			ID:                logID,
			CompletedAt:       &now,
			Status:            "success",
			ProductsSynced:    10,
			CyclesSynced:      100,
			ComponentsUpdated: 500,
		}
		err := repo.UpdateSyncLog(context.Background(), log)
		if err != nil {
			t.Errorf("UpdateSyncLog() error = %v", err)
		}
	})

	t.Run("GetLatestSyncLog success", func(t *testing.T) {
		logID := uuid.New()
		rows := sqlmock.NewRows([]string{
			"id", "started_at", "completed_at", "status", "products_synced",
			"cycles_synced", "components_updated", "error_message",
		}).AddRow(logID, now, &now, "success", 10, 100, 500, "")
		mock.ExpectQuery("SELECT id, started_at, completed_at, status, products_synced").
			WillReturnRows(rows)

		log, err := repo.GetLatestSyncLog(context.Background())
		if err != nil {
			t.Errorf("GetLatestSyncLog() error = %v", err)
		}
		if log == nil {
			t.Fatal("GetLatestSyncLog() returned nil")
		}
		if log.Status != "success" {
			t.Errorf("expected status success, got %s", log.Status)
		}
		if log.ProductsSynced != 10 {
			t.Errorf("expected ProductsSynced 10, got %d", log.ProductsSynced)
		}
	})

	t.Run("GetLatestSyncLog not found", func(t *testing.T) {
		mock.ExpectQuery("SELECT id, started_at, completed_at, status, products_synced").
			WillReturnError(sql.ErrNoRows)

		log, err := repo.GetLatestSyncLog(context.Background())
		if err != nil {
			t.Errorf("GetLatestSyncLog() error = %v", err)
		}
		if log != nil {
			t.Error("expected nil for no rows")
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestEOLRepository_UpdateComponentEOLStatus(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)
	componentID := uuid.New()
	productID := uuid.New()
	cycleID := uuid.New()
	eolDate := time.Date(2025, 10, 31, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		componentID uuid.UUID
		info        *model.ComponentEOLInfo
		setupMock   func()
		wantErr     bool
	}{
		{
			name:        "update to EOL status",
			componentID: componentID,
			info: &model.ComponentEOLInfo{
				Status:    model.EOLStatusEOL,
				ProductID: &productID,
				CycleID:   &cycleID,
				EOLDate:   &eolDate,
			},
			setupMock: func() {
				mock.ExpectExec("UPDATE components SET").
					WithArgs("eol", &productID, &cycleID, &eolDate, sqlmock.AnyArg(), componentID).
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			wantErr: false,
		},
		{
			name:        "update to active status",
			componentID: componentID,
			info: &model.ComponentEOLInfo{
				Status:    model.EOLStatusActive,
				ProductID: &productID,
				CycleID:   &cycleID,
			},
			setupMock: func() {
				mock.ExpectExec("UPDATE components SET").
					WithArgs("active", &productID, &cycleID, sqlmock.AnyArg(), sqlmock.AnyArg(), componentID).
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			wantErr: false,
		},
		{
			name:        "update to unknown status (nil product/cycle)",
			componentID: componentID,
			info: &model.ComponentEOLInfo{
				Status: model.EOLStatusUnknown,
			},
			setupMock: func() {
				mock.ExpectExec("UPDATE components SET").
					WithArgs("unknown", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), componentID).
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			wantErr: false,
		},
		{
			name:        "database error",
			componentID: componentID,
			info: &model.ComponentEOLInfo{
				Status: model.EOLStatusEOL,
			},
			setupMock: func() {
				mock.ExpectExec("UPDATE components SET").
					WithArgs("eol", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), componentID).
					WillReturnError(errors.New("update failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			err := repo.UpdateComponentEOLStatus(context.Background(), tt.componentID, tt.info)
			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateComponentEOLStatus() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestEOLRepository_GetEOLSummary(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)
	projectID := uuid.New()

	tests := []struct {
		name      string
		projectID uuid.UUID
		setupMock func()
		wantErr   bool
		checkFunc func(t *testing.T, s *model.EOLSummary)
	}{
		{
			name:      "successful get summary",
			projectID: projectID,
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"total", "active", "eol", "eos", "unknown"}).
					AddRow(100, 70, 10, 5, 15)
				mock.ExpectQuery("SELECT").
					WithArgs(projectID).
					WillReturnRows(rows)
			},
			wantErr: false,
			checkFunc: func(t *testing.T, s *model.EOLSummary) {
				if s.TotalComponents != 100 {
					t.Errorf("expected TotalComponents 100, got %d", s.TotalComponents)
				}
				if s.Active != 70 {
					t.Errorf("expected Active 70, got %d", s.Active)
				}
				if s.EOL != 10 {
					t.Errorf("expected EOL 10, got %d", s.EOL)
				}
				if s.EOS != 5 {
					t.Errorf("expected EOS 5, got %d", s.EOS)
				}
				if s.Unknown != 15 {
					t.Errorf("expected Unknown 15, got %d", s.Unknown)
				}
				if s.ProjectID != projectID {
					t.Errorf("expected ProjectID %v, got %v", projectID, s.ProjectID)
				}
			},
		},
		{
			name:      "empty project",
			projectID: uuid.New(),
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"total", "active", "eol", "eos", "unknown"}).
					AddRow(0, 0, 0, 0, 0)
				mock.ExpectQuery("SELECT").
					WithArgs(sqlmock.AnyArg()).
					WillReturnRows(rows)
			},
			wantErr: false,
			checkFunc: func(t *testing.T, s *model.EOLSummary) {
				if s.TotalComponents != 0 {
					t.Errorf("expected TotalComponents 0, got %d", s.TotalComponents)
				}
			},
		},
		{
			name:      "database error",
			projectID: uuid.New(),
			setupMock: func() {
				mock.ExpectQuery("SELECT").
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(errors.New("query failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			summary, err := repo.GetEOLSummary(context.Background(), tt.projectID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetEOLSummary() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.checkFunc != nil && summary != nil {
				tt.checkFunc(t, summary)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestEOLRepository_CountProducts(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)

	t.Run("count success", func(t *testing.T) {
		mock.ExpectQuery("SELECT COUNT").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(42))

		count, err := repo.CountProducts(context.Background())
		if err != nil {
			t.Errorf("CountProducts() error = %v", err)
		}
		if count != 42 {
			t.Errorf("expected 42, got %d", count)
		}
	})

	t.Run("count error", func(t *testing.T) {
		mock.ExpectQuery("SELECT COUNT").
			WillReturnError(errors.New("query failed"))

		_, err := repo.CountProducts(context.Background())
		if err == nil {
			t.Error("expected error")
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestEOLRepository_CountCycles(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)

	t.Run("count success", func(t *testing.T) {
		mock.ExpectQuery("SELECT COUNT").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(500))

		count, err := repo.CountCycles(context.Background())
		if err != nil {
			t.Errorf("CountCycles() error = %v", err)
		}
		if count != 500 {
			t.Errorf("expected 500, got %d", count)
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestEOLRepository_GetAllProductNames(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewEOLRepository(db)

	tests := []struct {
		name      string
		setupMock func()
		wantErr   bool
		wantCount int
	}{
		{
			name: "successful get all names",
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"name"}).
					AddRow("python").
					AddRow("nodejs").
					AddRow("django").
					AddRow("react")
				mock.ExpectQuery("SELECT name FROM eol_products").
					WillReturnRows(rows)
			},
			wantErr:   false,
			wantCount: 4,
		},
		{
			name: "empty list",
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"name"})
				mock.ExpectQuery("SELECT name FROM eol_products").
					WillReturnRows(rows)
			},
			wantErr:   false,
			wantCount: 0,
		},
		{
			name: "database error",
			setupMock: func() {
				mock.ExpectQuery("SELECT name FROM eol_products").
					WillReturnError(errors.New("query failed"))
			},
			wantErr:   true,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			names, err := repo.GetAllProductNames(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAllProductNames() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(names) != tt.wantCount {
				t.Errorf("GetAllProductNames() count = %d, want %d", len(names), tt.wantCount)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}
