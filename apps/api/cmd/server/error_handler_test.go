package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// ---------------------------------------------------------------------------
// The server-side 5xx log line must not carry error TEXT either.
//
// The F444 wrapper keeps raw error text out of the RESPONSE, but it used to
// log eff.Message and he.Internal verbatim. Error text is where credentials
// end up: a DSN with its password, an outbound URL with a token in its query
// or path, and *url.Error, which repeats the whole URL in its Error(). The
// access log (appmw.AccessLog, M63) logs only a classification for exactly
// that reason; these pin the same contract for this log line.
// ---------------------------------------------------------------------------

// captureDefaultSlog points slog's default logger at a JSON buffer for the
// duration of the test.
func captureDefaultSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// fiveXXRecords returns the decoded "http 5xx error" records in buf.
func fiveXXRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		if rec["msg"] == "http 5xx error" {
			out = append(out, rec)
		}
	}
	return out
}

func TestSanitizingErrorHandler_5xxLogCarriesNoErrorText(t *testing.T) {
	const (
		dsnPassword = "s3cr3t-db-pw"
		urlToken    = "tok-abc123-secret"
	)
	dsn := "postgres://sbomhub:" + dsnPassword + "@db.internal:5432/sbomhub"
	outbound := "https://hooks.example.com/services/" + urlToken + "?key=" + urlToken

	cases := []struct {
		name    string
		handler echo.HandlerFunc
		// wantClass is a fragment the classification must contain, so the
		// line still says which layer failed.
		wantClass string
	}{
		{
			name: "message string with a DSN",
			handler: func(c echo.Context) error {
				return echo.NewHTTPError(http.StatusInternalServerError, "connect "+dsn+": refused")
			},
			wantClass: "http_error code=500",
		},
		{
			name: "internal *url.Error repeating the URL",
			handler: func(c echo.Context) error {
				uerr := &url.Error{Op: "Post", URL: outbound, Err: errors.New("dial tcp: i/o timeout")}
				return echo.NewHTTPError(http.StatusBadGateway, "webhook failed").
					SetInternal(fmt.Errorf("deliver to %s: %w", outbound, uerr))
			},
			wantClass: "*url.Error",
		},
		{
			name: "message is itself an error",
			handler: func(c echo.Context) error {
				return echo.NewHTTPError(http.StatusInternalServerError,
					fmt.Errorf("open %s: %w", dsn, &url.Error{Op: "Get", URL: outbound, Err: errors.New("x")}))
			},
			wantClass: "http_error code=500",
		},
		{
			name: "promoted internal 5xx",
			handler: func(c echo.Context) error {
				return echo.NewHTTPError(http.StatusBadRequest, "bad").
					SetInternal(echo.NewHTTPError(http.StatusServiceUnavailable, "redis "+dsn))
			},
			wantClass: "http_error code=503",
		},
		{
			name: "plain error (echo answers 500)",
			handler: func(c echo.Context) error {
				return fmt.Errorf("query via %s: %w", dsn, &url.Error{Op: "Get", URL: outbound, Err: errors.New("x")})
			},
			wantClass: "*url.Error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureDefaultSlog(t)
			e := echo.New()
			e.HTTPErrorHandler = sanitizingErrorHandler(e.HTTPErrorHandler)
			e.GET("/api/v1/projects/:id/boom", tc.handler)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/p1/boom", nil)
			req.Header.Set(echo.HeaderXRequestID, "req-42")
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			if rec.Code < 500 {
				t.Fatalf("status = %d, want 5xx", rec.Code)
			}
			for _, secret := range []string{dsnPassword, urlToken, "db.internal", "hooks.example.com"} {
				if strings.Contains(buf.String(), secret) {
					t.Fatalf("5xx log leaked %q:\n%s", secret, buf.String())
				}
				if strings.Contains(rec.Body.String(), secret) {
					t.Fatalf("5xx body leaked %q: %s", secret, rec.Body.String())
				}
			}

			recs := fiveXXRecords(t, buf)
			if len(recs) != 1 {
				t.Fatalf("want exactly one 5xx record, got %d:\n%s", len(recs), buf.String())
			}
			r := recs[0]
			if r["route"] != "/api/v1/projects/:id/boom" {
				t.Errorf("route = %v, want the route template", r["route"])
			}
			if r["request_id"] != "req-42" {
				t.Errorf("request_id = %v, want req-42", r["request_id"])
			}
			if r["method"] != http.MethodGet {
				t.Errorf("method = %v", r["method"])
			}
			if got, _ := r["status"].(float64); int(got) != rec.Code {
				t.Errorf("status = %v, want %d", r["status"], rec.Code)
			}
			if class, _ := r["error"].(string); !strings.Contains(class, tc.wantClass) {
				t.Errorf("error = %q, want it to contain %q", class, tc.wantClass)
			}
			for _, gone := range []string{"detail", "internal"} {
				if _, ok := r[gone]; ok {
					t.Errorf("field %q must not be logged any more: %v", gone, r[gone])
				}
			}
		})
	}
}

// A 4xx is caller feedback and is not logged by this handler at all (the
// access log records it); only 5xx produce the record.
func TestSanitizingErrorHandler_4xxNotLoggedAs5xx(t *testing.T) {
	buf := captureDefaultSlog(t)
	e := echo.New()
	e.HTTPErrorHandler = sanitizingErrorHandler(e.HTTPErrorHandler)
	e.GET("/bad", func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusBadRequest, "nope")
	})
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/bad", nil))
	if n := len(fiveXXRecords(t, buf)); n != 0 {
		t.Fatalf("4xx produced %d 5xx records:\n%s", n, buf.String())
	}
}
