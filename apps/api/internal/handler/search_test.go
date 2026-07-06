package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

// ----------------------------------------------------------------------------
// Handler-level fake for the search handler (F396). The handler is wired
// against the searchServiceAPI interface (see search.go) so these tests
// never touch a real DB or NVD client. The DB-error cases assert the
// handler returns 500 and does NOT echo the raw error string back to the
// client — pre-fix code returned 404 / 500 with err.Error() verbatim, so
// these fail on pre-fix code.
// ----------------------------------------------------------------------------

// dbSecretMarker is embedded in the fake's DB-ish errors so the leak
// assertions are meaningful: a sanitized response must never contain it.
const dbSecretMarker = "SECRET_DB_INTERNALS_dsn=postgres://u:p@h/db"

type fakeSearchService struct {
	cveResult  *model.CVESearchResult
	cveErr     error
	compResult *model.ComponentSearchResult
	compErr    error
}

func (f *fakeSearchService) SearchByCVE(_ context.Context, _ string) (*model.CVESearchResult, error) {
	return f.cveResult, f.cveErr
}

func (f *fakeSearchService) SearchByComponent(_ context.Context, _ string, _ string) (*model.ComponentSearchResult, error) {
	return f.compResult, f.compErr
}

func newSearchCtx(target string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

// SearchByCVE: a DB / unknown error must map to 500 with a generic body,
// never 404 and never the raw error. (pre-fix: 404 + err.Error())
func TestSearchHandler_SearchByCVE_DBError_Returns500_NoLeak(t *testing.T) {
	dbErr := errors.New("pq: connection refused " + dbSecretMarker)
	h := NewSearchHandler(&fakeSearchService{cveErr: dbErr})

	c, rec := newSearchCtx("/api/v1/search/cve?q=CVE-2024-1234")
	if err := h.SearchByCVE(c); err != nil {
		t.Fatalf("SearchByCVE returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("DB error status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), dbSecretMarker) {
		t.Errorf("500 body leaked raw DB error: %s", rec.Body.String())
	}
}

// SearchByCVE: an ErrCVENotFound (possibly wrapped) must map to 404.
func TestSearchHandler_SearchByCVE_NotFound_Returns404(t *testing.T) {
	notFound := fmt.Errorf("%w: %s", service.ErrCVENotFound, "CVE-2024-9999")
	h := NewSearchHandler(&fakeSearchService{cveErr: notFound})

	c, rec := newSearchCtx("/api/v1/search/cve?q=CVE-2024-9999")
	if err := h.SearchByCVE(c); err != nil {
		t.Fatalf("SearchByCVE returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("not-found status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

// SearchByCVE: an ErrInvalidCVEID (possibly wrapped) must map to 400.
// (pre-fix: 400 was NEVER returned — all errors became 404.)
func TestSearchHandler_SearchByCVE_InvalidFormat_Returns400(t *testing.T) {
	invalid := fmt.Errorf("%w: %s", service.ErrInvalidCVEID, "not-a-cve")
	h := NewSearchHandler(&fakeSearchService{cveErr: invalid})

	c, rec := newSearchCtx("/api/v1/search/cve?q=not-a-cve")
	if err := h.SearchByCVE(c); err != nil {
		t.Fatalf("SearchByCVE returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid-format status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// SearchByCVE: missing q → 400 (unchanged behaviour, keeps the guard covered).
func TestSearchHandler_SearchByCVE_MissingQuery_Returns400(t *testing.T) {
	h := NewSearchHandler(&fakeSearchService{})

	c, rec := newSearchCtx("/api/v1/search/cve")
	if err := h.SearchByCVE(c); err != nil {
		t.Fatalf("SearchByCVE returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing q status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// SearchByComponent: a DB / unknown error must map to 500 with a generic
// body, never the raw error. (pre-fix: 500 + err.Error() — the status was
// already 500, so the leak assertion is what fails on pre-fix code.)
func TestSearchHandler_SearchByComponent_DBError_Returns500_NoLeak(t *testing.T) {
	dbErr := errors.New("pq: query canceled " + dbSecretMarker)
	h := NewSearchHandler(&fakeSearchService{compErr: dbErr})

	c, rec := newSearchCtx("/api/v1/search/component?name=openssl")
	if err := h.SearchByComponent(c); err != nil {
		t.Fatalf("SearchByComponent returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("DB error status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), dbSecretMarker) {
		t.Errorf("500 body leaked raw DB error: %s", rec.Body.String())
	}
}

// SearchByComponent: missing name → 400 (unchanged behaviour).
func TestSearchHandler_SearchByComponent_MissingName_Returns400(t *testing.T) {
	h := NewSearchHandler(&fakeSearchService{})

	c, rec := newSearchCtx("/api/v1/search/component")
	if err := h.SearchByComponent(c); err != nil {
		t.Fatalf("SearchByComponent returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing name status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}
