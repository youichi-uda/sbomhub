package handler

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// ---------------------------------------------------------------------------
// M47R — "not found" and "the database is broken" are different answers.
//
// Three handlers came out of the M47 waves with the two collapsed into one
// status. Each is the same defect: a delete path that maps EVERY repository
// error to 404, so an operator who is trying to revoke access is told the
// thing they are revoking does not exist. The two failures need opposite
// reactions — a 404 means stop, a 500 means try again — and the sibling
// handler on the very same resource already said so.
//
// The tests below are unit-level (sqlmock) because the distinction is purely
// in the error mapping: what matters is which error the repository returns,
// not which rows a live database holds. The 0-row and driver-error branches
// of the repositories themselves are pinned by the M47 W2 integration suite.
// ---------------------------------------------------------------------------

func m47rEcho(method, path string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

// --- #3: DELETE /api/v1/apikeys/:key_id -----------------------------------

// TestM47R_APIKeyDeleteTenant_ErrorContract pins the tenant-level delete
// against its project-level sibling (APIKeyHandler.Delete), which since M47 W1
// answers 404 only for the scope sentinel and 500 for a failure of the scope
// query itself. The tenant-level twin mapped everything to 404.
//
// Why it matters beyond tidiness: revoking a key is the response to a
// suspected leak. If the DELETE times out and the console says "API key not
// found", the admin concludes the key is already gone and stops — while the
// key is still valid.
func TestM47R_APIKeyDeleteTenant_ErrorContract(t *testing.T) {
	tenantID := uuid.New()
	keyID := uuid.New()

	cases := []struct {
		name       string
		arrange    func(mock sqlmock.Sqlmock)
		wantStatus int
		why        string
	}{
		{
			name: "infrastructure failure is 500",
			arrange: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM api_keys`)).
					WithArgs(keyID, tenantID).
					WillReturnError(errors.New("pq: canceling statement due to statement timeout"))
			},
			wantStatus: http.StatusInternalServerError,
			why: "a driver failure told the caller the key does not exist, so a revocation " +
				"that never happened looks completed and is not retried",
		},
		{
			name: "no matching row is 404",
			arrange: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM api_keys`)).
					WithArgs(keyID, tenantID).
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
			wantStatus: http.StatusNotFound,
			why:        "repository.ErrAPIKeyNotFound (M47 W2) is the only 404",
		},
		{
			name: "successful delete is 204",
			arrange: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM api_keys`)).
					WithArgs(keyID, tenantID).
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			wantStatus: http.StatusNoContent,
			why:        "positive control",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer func() { _ = db.Close() }()
			tc.arrange(mock)

			h := newTestAPIKeyHandler(db)
			c, rec := m47rEcho(http.MethodDelete, "/api/v1/apikeys/"+keyID.String())
			c.SetParamNames("key_id")
			c.SetParamValues(keyID.String())
			c.Set(middleware.ContextKeyTenantID, tenantID)

			if err := h.DeleteTenant(c); err != nil {
				t.Fatalf("DeleteTenant returned unexpected error: %v", err)
			}
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d — %s; body=%s",
					rec.Code, tc.wantStatus, tc.why, rec.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet sqlmock expectations: %v", err)
			}
		})
	}
}

// --- #4: DELETE /api/v1/public-links/:id ----------------------------------

func m47rPublicLinkHandler(db *sql.DB) *PublicLinkHandler {
	return NewPublicLinkHandler(service.NewPublicLinkService(
		db,
		repository.NewPublicLinkRepository(db),
		repository.NewProjectRepository(db),
		repository.NewSbomRepository(db),
		repository.NewComponentRepository(db),
	))
}

// TestM47R_PublicLinkDelete_ErrorContract pins Delete against Update, which
// since M47 W1 collapses "unknown link" and "another tenant's link" into one
// 404 and answers 500 for infrastructure faults. Delete answered 500 for
// both, so the same resource had two contracts depending on the verb.
//
// The 404 does NOT reintroduce an existence oracle: it is the SAME answer for
// a link that does not exist and for one that belongs to somebody else, which
// is exactly the sentinel Update already returns.
func TestM47R_PublicLinkDelete_ErrorContract(t *testing.T) {
	tenantID := uuid.New()
	linkID := uuid.New()

	cases := []struct {
		name       string
		arrange    func(mock sqlmock.Sqlmock)
		wantStatus int
		why        string
	}{
		{
			name: "unknown or foreign link is 404",
			arrange: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM public_links`)).
					WithArgs(linkID, tenantID).
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
			wantStatus: http.StatusNotFound,
			why:        "matches PublicLinkHandler.Update's contract for the same resource",
		},
		{
			name: "infrastructure failure is 500",
			arrange: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM public_links`)).
					WithArgs(linkID, tenantID).
					WillReturnError(errors.New("pq: connection reset by peer"))
			},
			wantStatus: http.StatusInternalServerError,
			why:        "a share link that is still live must not be reported as gone",
		},
		{
			name: "successful delete is 204",
			arrange: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM public_links`)).
					WithArgs(linkID, tenantID).
					WillReturnResult(sqlmock.NewResult(0, 1))
			},
			wantStatus: http.StatusNoContent,
			why:        "positive control",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer func() { _ = db.Close() }()
			tc.arrange(mock)

			h := m47rPublicLinkHandler(db)
			c, rec := m47rEcho(http.MethodDelete, "/api/v1/public-links/"+linkID.String())
			c.SetParamNames("id")
			c.SetParamValues(linkID.String())
			c.Set(middleware.ContextKeyTenantID, tenantID)

			if err := h.Delete(c); err != nil {
				t.Fatalf("Delete returned unexpected error: %v", err)
			}
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d — %s; body=%s",
					rec.Code, tc.wantStatus, tc.why, rec.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet sqlmock expectations: %v", err)
			}
		})
	}
}
