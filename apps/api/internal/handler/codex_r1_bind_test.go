package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
)

// Codex R1 (Medium): CRA /reanalyse tolerated any bind error, so a body the
// TextGuardBinder refused (NUL / invalid UTF-8) left the override empty and
// the handler went on to run the (LLM-backed) runner with the source
// report's defaults. It must answer 400 and run nothing.
func TestCRAReportsHandler_Reanalyse_InvalidTextBodyIs400AndRunsNothing(t *testing.T) {
	h := newCRAHarness()
	rid := uuid.New()
	h.seedReport(rid, h.projectID)

	e := echo.New()
	e.Binder = NewTextGuardBinder()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+h.projectID.String()+"/cra-reports/"+rid.String()+"/reanalyse",
		strings.NewReader(`{"product_name":"x\u0000y"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id", "report_id")
	c.SetParamValues(h.projectID.String(), rid.String())
	h.ctxWithRole(c, model.RoleAdmin)

	if err := h.handler.Reanalyse(c); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "NUL") {
		t.Fatalf("status = %d, body = %s; want 400 naming the NUL", rec.Code, rec.Body.String())
	}
	if n := len(h.runner.captured); n != 0 {
		t.Fatalf("runner ran %d time(s) for a refused body", n)
	}
}

// Codex R1 (Low): respondBindError turned BodyLimit's 413 into a 400.
func TestProjectCreate_OversizedChunkedBodyKeeps413(t *testing.T) {
	e := newProjectTestEcho()
	e.Use(echomw.BodyLimit("1K"))
	ph := NewProjectHandler(nil) // the body limit trips in Bind, before the service
	e.POST("/api/v1/projects", func(c echo.Context) error {
		c.Set(middleware.ContextKeyTenantID, uuid.New())
		return ph.Create(c)
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects",
		strings.NewReader(`{"name":"`+strings.Repeat("a", 4096)+`"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, body = %s; want 413", rec.Code, rec.Body.String())
	}
}

// Codex R1 (Low): a project name is single-line, but Unicode line/paragraph
// separators and C1 controls (U+0085 NEXT LINE) passed. And (Low) the
// description rule refused storable controls such as form feed, which TEXT
// always accepted — description now refuses only what PostgreSQL cannot store.
func TestProjectCreate_UnicodeLineBreaksInNameAnd_ControlsInDescription(t *testing.T) {
	for name, body := range map[string]string{
		"U+0085 in name": `{"name":"before\u0085after"}`,
		"U+2028 in name": `{"name":"before after"}`,
		"U+2029 in name": `{"name":"before after"}`,
		"U+009B in name": `{"name":"before\u009bafter"}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec, mock := driveProjectCreate(t, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s; want 400", rec.Code, rec.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
