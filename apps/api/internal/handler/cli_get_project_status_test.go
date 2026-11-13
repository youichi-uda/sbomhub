package handler

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// M66 residual (CLI route): GET /api/v1/cli/projects/:id answered 404 for every
// error, so a database outage read as "the project does not exist". Not found
// and another tenant's project stay 404; any other error is 500.
func TestCLIGetProject_StatusByError(t *testing.T) {
	tenantID, other := uuid.New(), uuid.New()
	projectRow := func() *sqlmock.Rows {
		return sqlmock.NewRows([]string{"id", "tenant_id", "name", "description", "created_at", "updated_at"})
	}
	cases := []struct {
		name     string
		getErr   error
		tenant   *uuid.UUID
		tidErr   error
		wantCode int
		wantBody string
	}{
		{name: "not found", getErr: sql.ErrNoRows, wantCode: http.StatusNotFound, wantBody: "project not found"},
		{name: "get fails", getErr: errors.New("pq: connection refused 10.0.0.5"), wantCode: http.StatusInternalServerError, wantBody: "failed to get project"},
		{name: "other tenant", tenant: &other, wantCode: http.StatusNotFound, wantBody: "project not found"},
		{name: "tenant lookup fails", tidErr: errors.New("pq: canceling statement due to statement timeout"), wantCode: http.StatusInternalServerError, wantBody: "failed to get project"},
		{name: "found", tenant: &tenantID, wantCode: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			projectID := uuid.New()
			get := mock.ExpectQuery(`(?s)FROM projects WHERE id = \$1`).WithArgs(projectID)
			if tc.getErr != nil {
				get.WillReturnError(tc.getErr)
			} else {
				now := time.Now()
				get.WillReturnRows(projectRow().AddRow(projectID, tenantID, "p", "", now, now))
				tid := mock.ExpectQuery(`SELECT tenant_id FROM projects WHERE id = \$1`).WithArgs(projectID)
				if tc.tidErr != nil {
					tid.WillReturnError(tc.tidErr)
				} else {
					tid.WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(*tc.tenant))
				}
			}
			h := NewCLIHandler(service.NewCLIService(repository.NewProjectRepository(db), nil, nil))
			e := newProjectTestEcho()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/cli/projects/"+projectID.String(), nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("id")
			c.SetParamValues(projectID.String())
			c.Set(middleware.ContextKeyTenantID, tenantID)
			if err := h.GetProject(c); err != nil {
				t.Fatalf("GetProject returned error: %v", err)
			}
			if rec.Code != tc.wantCode {
				t.Fatalf("status %d, want %d (body %s)", rec.Code, tc.wantCode, rec.Body)
			}
			if tc.wantBody != "" && !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("body %s, want %q", rec.Body, tc.wantBody)
			}
			if strings.Contains(rec.Body.String(), "pq:") {
				t.Fatalf("driver error leaked: %s", rec.Body)
			}
		})
	}
}
