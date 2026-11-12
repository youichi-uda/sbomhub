package handler

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/validation"
)

type m71FormTarget struct {
	Name string `form:"name" json:"name"`
}

func m71FormContext(t *testing.T, body, ctype string) echo.Context {
	t.Helper()
	e := echo.New()
	e.JSONSerializer = NewTextGuardJSONSerializer()
	e.Binder = NewTextGuardBinder()
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, ctype)
	return e.NewContext(req, httptest.NewRecorder())
}

func m71Multipart(t *testing.T, fields map[string]string, file []byte) (string, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if file != nil {
		part, err := w.CreateFormFile("sbom", "sbom.bin")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(file); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String(), w.FormDataContentType()
}

func m71WantRefused(t *testing.T, err error, wantMsg string) {
	t.Helper()
	var he *echo.HTTPError
	if !errors.As(err, &he) || he.Code != http.StatusBadRequest {
		t.Fatalf("err = %v, want a 400 HTTPError", err)
	}
	if !errors.Is(err, validation.ErrInvalidText) {
		t.Fatalf("err %v does not wrap validation.ErrInvalidText", err)
	}
	if msg, _ := he.Message.(string); msg != wantMsg {
		t.Fatalf("message = %q, want %q", he.Message, wantMsg)
	}
}

// c.Bind of an urlencoded or multipart body refuses a value PostgreSQL
// cannot store, as the JSON serializer does for JSON bodies (M66).
func TestM71TextGuardBinder_RefusesFormText(t *testing.T) {
	t.Run("urlencoded NUL", func(t *testing.T) {
		c := m71FormContext(t, url.Values{"name": {"a\x00b"}}.Encode(), echo.MIMEApplicationForm)
		var v m71FormTarget
		m71WantRefused(t, c.Bind(&v), `form field "name" must not contain a NUL character`)
	})
	t.Run("urlencoded invalid UTF-8", func(t *testing.T) {
		c := m71FormContext(t, "name=%FF", echo.MIMEApplicationForm+"; charset=utf-8")
		var v m71FormTarget
		m71WantRefused(t, c.Bind(&v), `form field "name" is not valid UTF-8`)
	})
	t.Run("multipart value NUL", func(t *testing.T) {
		body, ct := m71Multipart(t, map[string]string{"name": "a\x00b"}, nil)
		c := m71FormContext(t, body, ct)
		var v m71FormTarget
		m71WantRefused(t, c.Bind(&v), `form field "name" must not contain a NUL character`)
	})
}

// A binary file part is not text: NUL and invalid bytes in it pass, and a
// clean form still binds exactly as echo's DefaultBinder binds it.
func TestM71TextGuardBinder_PassesFilesAndCleanForms(t *testing.T) {
	body, ct := m71Multipart(t, map[string]string{"name": "日本語 name"}, []byte{0x00, 0xff, 0xfe, 'x'})
	c := m71FormContext(t, body, ct)
	var v m71FormTarget
	if err := c.Bind(&v); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if v.Name != "日本語 name" {
		t.Fatalf("Name = %q", v.Name)
	}
	fh, err := c.FormFile("sbom")
	if err != nil {
		t.Fatalf("FormFile after Bind: %v", err)
	}
	if fh.Size != 4 {
		t.Fatalf("file size = %d, want 4", fh.Size)
	}

	c = m71FormContext(t, `{"name":"json"}`, echo.MIMEApplicationJSON)
	v = m71FormTarget{}
	if err := c.Bind(&v); err != nil || v.Name != "json" {
		t.Fatalf("JSON bind through the guard binder: %v, %+v", err, v)
	}
}

// checkFormText is what a handler that reads a form directly
// (c.FormValue / c.FormFile — CLIHandler.Upload) calls first.
func TestM71CheckFormText(t *testing.T) {
	body, ct := m71Multipart(t, map[string]string{"project_name": "p", "description": "d\x00"}, []byte("{}"))
	m71WantRefused(t, checkFormText(m71FormContext(t, body, ct)), `form field "description" must not contain a NUL character`)

	body, ct = m71Multipart(t, map[string]string{"project_name": "p"}, []byte{0, 0xff})
	if err := checkFormText(m71FormContext(t, body, ct)); err != nil {
		t.Fatalf("clean form with a binary file refused: %v", err)
	}
	if err := checkFormText(m71FormContext(t, "{\"a\":\"\x00\"}", echo.MIMEApplicationJSON)); err != nil {
		t.Fatalf("non-form body checked by checkFormText: %v", err)
	}
}

// POST /cli/upload reads its form directly; a NUL in any value part is
// refused before the project is resolved (the service is never called).
func TestM71CLIUpload_RefusesFormTextBeforeTheService(t *testing.T) {
	body, ct := m71Multipart(t, map[string]string{"project_name": "p", "description": "d\x00"}, []byte(`{"bomFormat":"CycloneDX"}`))
	c := m71FormContext(t, body, ct)
	c.Set(middleware.ContextKeyTenantID, uuid.New())
	h := NewCLIHandler(nil) // a nil service: reaching it would panic
	if err := h.Upload(c); err != nil {
		t.Fatalf("Upload returned %v", err)
	}
	rec := c.Response().Writer.(*httptest.ResponseRecorder)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `form field \"description\" must not contain a NUL character`) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}
