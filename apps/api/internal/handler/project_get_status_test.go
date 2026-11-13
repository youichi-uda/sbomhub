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

// driveProjectGet runs ProjectHandler.Get for one project id against a
// sqlmock-backed real service whose single SELECT answers with rows or err.
func driveProjectGet(t *testing.T, rows *sqlmock.Rows, qerr error) *httptest.ResponseRecorder {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tenantID, projectID := uuid.New(), uuid.New()
	exp := mock.ExpectQuery(`(?s)FROM projects WHERE id = \$1 AND tenant_id = \$2`).WithArgs(projectID, tenantID)
	if qerr != nil {
		exp.WillReturnError(qerr)
	} else {
		exp.WillReturnRows(rows)
	}
	h := NewProjectHandler(service.NewProjectService(repository.NewProjectRepository(db)))

	e := newProjectTestEcho()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+projectID.String(), nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	c.Set(middleware.ContextKeyTenantID, tenantID)
	if err := h.Get(c); err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	return rec
}

// M66 residual: GET /api/v1/projects/:id answered 404 for every error, so a
// database outage read as "the project does not exist". Not found — including
// a project RLS hides (another tenant's), which reaches the handler as the same
// sql.ErrNoRows — stays 404; any other error is 500.
func TestProjectHandler_Get_NotFoundIs404(t *testing.T) {
	rec := driveProjectGet(t, nil, sql.ErrNoRows)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if got := errorBody(t, rec); got != "project not found" {
		t.Fatalf("error = %q", got)
	}
}

func TestProjectHandler_Get_DBErrorIs500(t *testing.T) {
	for _, qerr := range []error{
		errors.New("pq: canceling statement due to statement timeout"),
		sql.ErrConnDone,
		errors.New("dial tcp 10.0.0.5:5432: connect: connection refused"),
	} {
		rec := driveProjectGet(t, nil, qerr)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("%v: status = %d, want 500", qerr, rec.Code)
		}
		got := errorBody(t, rec)
		if got != "failed to get project" {
			t.Fatalf("%v: error = %q", qerr, got)
		}
		// The driver's text (hosts, statement details) stays in the log.
		if strings.Contains(rec.Body.String(), "pq:") || strings.Contains(rec.Body.String(), "10.0.0.5") {
			t.Fatalf("%v: body leaks the database error: %s", qerr, rec.Body.String())
		}
	}
}

func TestProjectHandler_Get_FoundIs200(t *testing.T) {
	now := time.Now()
	rec := driveProjectGet(t, sqlmock.NewRows([]string{"id", "name", "description", "created_at", "updated_at"}).
		AddRow(uuid.New(), "app", "", now, now), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"name":"app"`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}
