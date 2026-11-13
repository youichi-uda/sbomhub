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
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// GET /api/v1/projects/:id/sbom answered 404 for every error, so a database
// failure read as "this project has no SBOM" (the web turns 404 into null and
// shows "not scanned"). Only sql.ErrNoRows is 404; anything else is a generic
// 500 that does not leak the driver error.
func TestSbomGetLatest_StatusByError(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode int
		wantBody string
	}{
		{name: "no sbom", err: sql.ErrNoRows, wantCode: http.StatusNotFound, wantBody: "sbom not found"},
		{name: "db fails", err: errors.New("pq: connection refused 10.0.0.5"), wantCode: http.StatusInternalServerError, wantBody: "failed to get SBOM"},
		{name: "found", wantCode: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			projectID := uuid.New()
			q := mock.ExpectQuery(`FROM sboms WHERE project_id = \$1 ORDER BY created_at DESC LIMIT 1`).WithArgs(projectID)
			if tc.err != nil {
				q.WillReturnError(tc.err)
			} else {
				q.WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "format", "version", "raw_data", "created_at"}).
					AddRow(uuid.New(), projectID, "cyclonedx", "1.5", []byte("{}"), time.Now()))
			}
			sbomService := service.NewSbomService(repository.NewSbomRepository(db), repository.NewComponentRepository(db))
			h := NewSbomHandler(db, sbomService, nil, nil, nil)

			e := echo.New()
			rec := httptest.NewRecorder()
			c := e.NewContext(httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+projectID.String()+"/sbom", nil), rec)
			c.SetParamNames("id")
			c.SetParamValues(projectID.String())
			if err := h.Get(c); err != nil {
				t.Fatal(err)
			}
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.wantCode, rec.Body.String())
			}
			if tc.wantBody != "" && !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("body = %s, want %q", rec.Body.String(), tc.wantBody)
			}
			if strings.Contains(rec.Body.String(), "10.0.0.5") {
				t.Fatalf("body leaks driver error: %s", rec.Body.String())
			}
		})
	}
}
