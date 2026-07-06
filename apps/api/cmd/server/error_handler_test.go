package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

// Without the wrapper, Echo's DefaultHTTPErrorHandler renders NewHTTPError's
// message verbatim, so a 5xx body would contain the raw error. These tests
// pin the F444 contract: 5xx messages are genericized (no leak), 4xx messages
// are preserved (validation feedback).

func TestSanitizingErrorHandler_5xxMessageGenericized(t *testing.T) {
	e := echo.New()
	e.HTTPErrorHandler = sanitizingErrorHandler(e.HTTPErrorHandler)

	const secret = `pq: relation "secret_table" does not exist`
	e.GET("/boom", func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusInternalServerError, secret)
	})

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("5xx body leaked the raw error: %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), http.StatusText(http.StatusInternalServerError)) {
		t.Fatalf("5xx body missing generic status text: %q", rec.Body.String())
	}
}

func TestSanitizingErrorHandler_RawErrorGenericized(t *testing.T) {
	e := echo.New()
	e.HTTPErrorHandler = sanitizingErrorHandler(e.HTTPErrorHandler)

	const secret = "raw driver failure: connection refused to 10.0.0.5:5432"
	e.GET("/raw", func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusBadGateway, secret)
	})

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/raw", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("5xx body leaked the raw error: %q", rec.Body.String())
	}
}

func TestSanitizingErrorHandler_InternalPromoted5xxGenericized(t *testing.T) {
	e := echo.New()
	e.HTTPErrorHandler = sanitizingErrorHandler(e.HTTPErrorHandler)

	// Echo promotes an *HTTPError Internal to the effective error, so an outer
	// 4xx wrapping an internal 5xx renders the internal (raw) message unless we
	// evaluate the promoted code. Pre-fix (outer-code-only check) this leaked.
	const secret = "pq: internal secret via SetInternal"
	e.GET("/nested", func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusBadRequest, "bad request").
			SetInternal(echo.NewHTTPError(http.StatusInternalServerError, secret))
	})

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nested", nil))

	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("internal-promoted 5xx leaked the raw error: %q", rec.Body.String())
	}
}

func TestSanitizingErrorHandler_4xxMessagePreserved(t *testing.T) {
	e := echo.New()
	e.HTTPErrorHandler = sanitizingErrorHandler(e.HTTPErrorHandler)

	const validationMsg = "invalid tracker type: bogus"
	e.GET("/bad", func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusBadRequest, validationMsg)
	})

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/bad", nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), validationMsg) {
		t.Fatalf("4xx validation message not preserved: %q", rec.Body.String())
	}
}
