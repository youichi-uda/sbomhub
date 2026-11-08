package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// Regressions found by the M65 E2E work: POST /api/v1/projects answered 500
// "failed to create project" for a 300-character name (projects.name is
// VARCHAR(255) -> pq 22001) and for a name containing NUL (PostgreSQL refuses
// U+0000 -> pq 22021), and DELETE /api/v1/projects/:id answered 500 for an id
// that does not exist.
//
// The handler is driven through a real echo with the production binder and a
// sqlmock-backed real service. A rejected request must not reach the database
// at all: sqlmock fails any statement it was not told to expect, which is how
// the pre-fix code (INSERT, then 500) fails these tests.

func newProjectTestEcho() *echo.Echo {
	e := echo.New()
	e.Binder = NewTextGuardBinder()
	return e
}

func driveProjectCreate(t *testing.T, body string) (*httptest.ResponseRecorder, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	h := NewProjectHandler(service.NewProjectService(repository.NewProjectRepository(db)))

	e := newProjectTestEcho()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(middleware.ContextKeyTenantID, uuid.New())
	if err := h.Create(c); err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	return rec, mock
}

func errorBody(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return m["error"]
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestProjectCreate_RejectsInvalidInputWith400(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"300-char name", mustJSON(t, map[string]string{"name": strings.Repeat("A", 300)}),
			"name must be at most 255 characters (got 300)"},
		{"256 multibyte chars", mustJSON(t, map[string]string{"name": strings.Repeat("名", 256)}),
			"name must be at most 255 characters (got 256)"},
		{"NUL in name (JSON escape)", `{"name":"Project\u0000Test"}`,
			`invalid request body: contains a NUL character (\u0000)`},
		{"NUL plus unit separator, as the E2E sends it", mustJSON(t, map[string]string{"name": "Project\x00Test\x1f1"}),
			`invalid request body: contains a NUL character (\u0000)`},
		{"unit separator alone", mustJSON(t, map[string]string{"name": "Project\x1fTest"}),
			"name must not contain control or line-break characters (U+001F)"},
		{"invalid UTF-8", "{\"name\":\"bad\xff\"}", "invalid request body: not valid UTF-8"},
		{"empty name", `{"name":""}`, "name is required"},
		{"blank name", `{"name":"   "}`, "name is required"},
		{"missing name", `{"description":"x"}`, "name is required"},
		{"description too long", mustJSON(t, map[string]string{"name": "ok", "description": strings.Repeat("d", 1001)}),
			"description must be at most 1000 characters (got 1001)"},
		{"NUL in description", `{"name":"ok","description":"a\u0000"}`, `contains a NUL character (\u0000)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, mock := driveProjectCreate(t, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s; want 400", rec.Code, rec.Body.String())
			}
			if got := errorBody(t, rec); !strings.Contains(got, tc.want) {
				t.Fatalf("error = %q, want it to contain %q", got, tc.want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProjectCreate_AcceptsBoundaryValues(t *testing.T) {
	cases := map[string]string{
		"255 multibyte chars":        mustJSON(t, map[string]string{"name": strings.Repeat("名", 255)}),
		"1000-char multiline desc":   mustJSON(t, map[string]string{"name": "ok", "description": strings.Repeat("ab\n", 333) + "x"}),
		"escaped backslash + u0000":  `{"name":"C:\\u0000dir"}`,
		"emoji and Japanese":         mustJSON(t, map[string]string{"name": "🚀 プロジェクト"}),
		"lone surrogate escape kept": `{"name":"a\ud800b"}`,
		"form feed in description":   `{"name":"ok","description":"page1\u000cpage2"}`,
		"escape char in description": `{"name":"ok","description":"\u001b[1mbold"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO projects`)).
				WillReturnResult(sqlmock.NewResult(0, 1))
			h := NewProjectHandler(service.NewProjectService(repository.NewProjectRepository(db)))
			e := newProjectTestEcho()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/projects", strings.NewReader(body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set(middleware.ContextKeyTenantID, uuid.New())
			if err := h.Create(c); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, body = %s; want 201", rec.Code, rec.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProjectDelete_NonExistentIs404(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM projects WHERE id = $1 AND tenant_id = $2`)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	h := NewProjectHandler(service.NewProjectService(repository.NewProjectRepository(db)))

	e := newProjectTestEcho()
	id := uuid.New()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/projects/"+id.String(), nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(id.String())
	c.Set(middleware.ContextKeyTenantID, uuid.New())
	if err := h.Delete(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s; want 404", rec.Code, rec.Body.String())
	}
	if got := errorBody(t, rec); got != "project not found" {
		t.Fatalf("error = %q", got)
	}
}

func TestProjectDelete_DBFailureStays500(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM projects`)).WillReturnError(errors.New("connection refused"))
	h := NewProjectHandler(service.NewProjectService(repository.NewProjectRepository(db)))

	e := newProjectTestEcho()
	id := uuid.New()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/projects/"+id.String(), nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(id.String())
	c.Set(middleware.ContextKeyTenantID, uuid.New())
	if err := h.Delete(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d; want 500", rec.Code)
	}
}

// The CLI routes create projects too: POST /cli/projects (JSON) and the
// create-on-first-upload path of POST /cli/upload (multipart, which does not go
// through the JSON binder at all).
func TestCLIProjectCreate_RejectsInvalidNameWith400(t *testing.T) {
	cases := map[string]string{
		"300-char name": mustJSON(t, map[string]string{"name": strings.Repeat("A", 300)}),
		"NUL in name":   `{"name":"a\u0000b"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			h := NewCLIHandler(service.NewCLIService(repository.NewProjectRepository(db), repository.NewSbomRepository(db), repository.NewComponentRepository(db)))
			e := newProjectTestEcho()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/cli/projects", strings.NewReader(body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.Set(middleware.ContextKeyTenantID, uuid.New())
			if err := h.CreateProject(c); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s; want 400", rec.Code, rec.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCLIUpload_RejectsInvalidProjectNameAndSBOMTextWith400(t *testing.T) {
	cases := []struct {
		name, project, sbom, want string
	}{
		{"NUL in multipart project_name", "a\x00b", `{"bomFormat":"CycloneDX","specVersion":"1.5"}`, "name must not contain a NUL character"},
		{"300-char project_name", strings.Repeat("p", 300), `{"bomFormat":"CycloneDX","specVersion":"1.5"}`, "at most 255 characters"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			h := NewCLIHandler(service.NewCLIService(repository.NewProjectRepository(db), repository.NewSbomRepository(db), repository.NewComponentRepository(db)))
			var buf bytes.Buffer
			w := multipart.NewWriter(&buf)
			_ = w.WriteField("project_name", tc.project)
			fw, _ := w.CreateFormFile("sbom", "sbom.json")
			_, _ = fw.Write([]byte(tc.sbom))
			_ = w.Close()
			req := httptest.NewRequest(http.MethodPost, "/cli/upload", &buf)
			req.Header.Set(echo.HeaderContentType, w.FormDataContentType())
			rec := httptest.NewRecorder()
			c := newProjectTestEcho().NewContext(req, rec)
			c.Set(middleware.ContextKeyTenantID, uuid.New())
			if err := h.Upload(c); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusBadRequest || !strings.Contains(errorBody(t, rec), tc.want) {
				t.Fatalf("status = %d, body = %s; want 400 containing %q", rec.Code, rec.Body.String(), tc.want)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
