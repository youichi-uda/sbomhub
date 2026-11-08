package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
	"github.com/sbomhub/sbomhub/internal/validation"
)

type bindTarget struct {
	Name  string `json:"name"`
	Query string `query:"q"`
}

func bindWith(t *testing.T, method, ctype, body string) (bindTarget, error) {
	t.Helper()
	e := echo.New()
	e.Binder = NewTextGuardBinder()
	req := httptest.NewRequest(method, "/x?q=query", strings.NewReader(body))
	if ctype != "" {
		req.Header.Set(echo.HeaderContentType, ctype)
	}
	c := e.NewContext(req, httptest.NewRecorder())
	var v bindTarget
	err := c.Bind(&v)
	return v, err
}

func TestTextGuardBinder_RefusesNULAndInvalidUTF8(t *testing.T) {
	for name, body := range map[string]string{
		"nul escape":   `{"name":"a\u0000"}`,
		"invalid utf8": "{\"name\":\"a\xc3\"}",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := bindWith(t, http.MethodPost, "application/json; charset=utf-8", body)
			var he *echo.HTTPError
			if !errors.As(err, &he) || he.Code != http.StatusBadRequest {
				t.Fatalf("err = %v, want 400 HTTPError", err)
			}
			if !errors.Is(err, validation.ErrInvalidText) {
				t.Fatalf("err %v does not wrap ErrInvalidText", err)
			}
		})
	}
}

// The guard must not change what a valid body decodes to (the body is read
// once and replayed from memory), and must not touch non-JSON bodies, which
// DefaultBinder does not decode as JSON either.
func TestTextGuardBinder_PassesValidBodiesThroughUnchanged(t *testing.T) {
	v, err := bindWith(t, http.MethodPost, echo.MIMEApplicationJSON, `{"name":"日本語 \\u0000 🚀"}`)
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != `日本語 \u0000 🚀` {
		t.Fatalf("name = %q", v.Name)
	}
	// Query params still bound alongside the body (DefaultBinder.Bind binds
	// query only for GET/DELETE/HEAD; POST here -> body only).
	v, err = bindWith(t, http.MethodGet, "", "")
	if err != nil || v.Query != "query" {
		t.Fatalf("query bind: %+v, %v", v, err)
	}
	// A form body is not JSON: not inspected by the guard.
	if _, err := bindWith(t, http.MethodPost, echo.MIMEApplicationForm, "name=a%00b"); err != nil {
		t.Fatalf("form bind: %v", err)
	}
}

// BodyLimit answers 413 through the body reader; the guard must not turn
// that into a 400.
func TestTextGuardBinder_KeepsBodyLimit413(t *testing.T) {
	e := echo.New()
	e.Binder = NewTextGuardBinder()
	e.Use(middleware.BodyLimit("1K"))
	e.POST("/x", func(c echo.Context) error {
		var v bindTarget
		return c.Bind(&v)
	})
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"name":"`+strings.Repeat("a", 4096)+`"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.ContentLength = -1 // force the streaming limit reader
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

// The canonical SBOM route reads its raw body (no c.Bind), whatever the
// Content-Type. sboms.raw_data is JSONB and refuses U+0000, so an SBOM
// carrying one used to fail at the INSERT with 500. It must be a 400 that
// touches no repository.
func TestSBOMHandler_Upload_NULOrInvalidUTF8Is400(t *testing.T) {
	for name, body := range map[string]string{
		"nul escape in component name":      `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"lib\u0000x","version":"1"}]}`,
		"invalid utf8":                      "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"components\":[{\"name\":\"lib\xff\"}]}",
		"lone surrogate (jsonb refuses it)": `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[],"x":"\ud800"}`,
	} {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			h := NewSbomHandler(db, service.NewSbomService(
				repository.NewSbomRepository(db), repository.NewComponentRepository(db)), nil, nil, nil)
			rec := driveUpload(t, h, uuid.New(), body)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "failed to parse SBOM") {
				t.Fatalf("status = %d, body = %s; want 400 failed to parse SBOM", rec.Code, rec.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
