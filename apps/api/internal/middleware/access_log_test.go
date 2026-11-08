package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"
)

// accessLogServer builds an Echo wired like cmd/server/main.go: the trusted-
// proxy IP extractor, AccessLog outermost, Recover inside it. It counts how
// often the global error handler runs.
func accessLogServer(t *testing.T) (*echo.Echo, *bytes.Buffer, *int) {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	e := echo.New()
	ext, err := ClientIPExtractor("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	e.IPExtractor = ext
	handlerCalls := 0
	def := e.HTTPErrorHandler
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		handlerCalls++
		def(err, c)
	}
	e.Use(AccessLog(logger))
	e.Use(echomw.Recover())

	e.GET("/api/v1/projects/:id", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello")
	})
	e.GET("/api/v1/public/:token", func(c echo.Context) error {
		return c.String(http.StatusOK, "pub")
	})
	e.GET("/api/v1/public/:token/download", func(c echo.Context) error {
		return c.String(http.StatusOK, "file")
	})
	e.GET("/boom", func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusInternalServerError, "db down").
			SetInternal(errors.New("pq: secret detail"))
	})
	e.GET("/panic", func(c echo.Context) error {
		panic("kaboom")
	})
	e.GET("/forbidden", func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusForbidden, "no")
	})
	return e, &buf, &handlerCalls
}

func serveAndDecode(t *testing.T, e *echo.Echo, buf *bytes.Buffer, req *http.Request) (map[string]any, *httptest.ResponseRecorder) {
	t.Helper()
	buf.Reset()
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want exactly one access log line, got %d:\n%s", len(lines), buf.String())
	}
	var rec0 map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec0); err != nil {
		t.Fatalf("log line is not JSON: %v\n%s", err, lines[0])
	}
	return rec0, rec
}

func TestAccessLog_FieldsAndNoQueryString(t *testing.T) {
	e, buf, _ := accessLogServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/p1?api_key=SECRETQUERYVALUE&x=1", nil)
	req.RemoteAddr = "10.1.2.3:4567"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set(echo.HeaderXRequestID, "req-42")
	req.Header.Set("User-Agent", "ua-test")

	got, rec := serveAndDecode(t, e, buf, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(buf.String(), "SECRETQUERYVALUE") || strings.Contains(buf.String(), "api_key") {
		t.Fatalf("query string leaked into the access log: %s", buf.String())
	}
	want := map[string]any{
		"msg":        "http request",
		"level":      "INFO",
		"method":     "GET",
		"uri":        "/api/v1/projects/p1",
		"route":      "/api/v1/projects/:id",
		"status":     float64(200),
		"remote_ip":  "203.0.113.9", // from the trusted-proxy extractor, not the peer
		"host":       "example.com",
		"user_agent": "ua-test",
		"bytes_in":   float64(0), // a JSON number, as middleware.Logger emitted it
		"bytes_out":  float64(5),
		"request_id": "req-42",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %#v, want %#v", k, got[k], v)
		}
	}
	for _, k := range []string{"time", "latency", "latency_human"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing field %q", k)
		}
	}
	if _, ok := got["error"]; ok {
		t.Errorf("error field present on a successful request")
	}
}

func TestAccessLog_UntrustedPeerXFFIgnored(t *testing.T) {
	e, buf, _ := accessLogServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/p1", nil)
	req.RemoteAddr = "198.51.100.7:1111"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	got, _ := serveAndDecode(t, e, buf, req)
	if got["remote_ip"] != "198.51.100.7" {
		t.Fatalf("remote_ip = %v, want the untrusted peer address", got["remote_ip"])
	}
	if _, ok := got["request_id"]; ok {
		t.Fatalf("request_id logged without an X-Request-ID header")
	}
}

func TestAccessLog_PublicLinkTokenRedacted(t *testing.T) {
	const tok = "PUBLICTOKEN0123456789"
	cases := []struct {
		name, target, wantURI, wantRoute string
		wantStatus                       int
	}{
		{"matched", "/api/v1/public/" + tok, "/api/v1/public/[REDACTED]", "/api/v1/public/:token", 200},
		{"matched download", "/api/v1/public/" + tok + "/download?sig=x", "/api/v1/public/[REDACTED]", "/api/v1/public/:token/download", 200},
		{"unmatched suffix", "/api/v1/public/" + tok + "/nope", "/api/v1/public/[REDACTED]", "", 404},
		{"double slash", "//api/v1/public/" + tok, "//api/v1/public/[REDACTED]", "", 404},
		{"upper case", "/API/V1/PUBLIC/" + tok, "/API/V1/PUBLIC/[REDACTED]", "", 404},
		{"encoded slash", "/api/v1/public/ab%2F" + tok, "", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, buf, _ := accessLogServer(t)
			got, rec := serveAndDecode(t, e, buf, httptest.NewRequest(http.MethodGet, tc.target, nil))
			if strings.Contains(buf.String(), tok) {
				t.Fatalf("public-link token leaked: %s", buf.String())
			}
			if tc.wantURI != "" && got["uri"] != tc.wantURI {
				t.Errorf("uri = %v, want %v", got["uri"], tc.wantURI)
			}
			if tc.wantRoute != "" && got["route"] != tc.wantRoute {
				t.Errorf("route = %v, want %v", got["route"], tc.wantRoute)
			}
			if tc.wantStatus != 0 && rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

// The error handler must run exactly once per failed request (as with the old
// middleware.Logger); a second run would double-log every 5xx in
// sanitizingErrorHandler.
func TestAccessLog_ErrorHandledOnce(t *testing.T) {
	cases := []struct {
		path      string
		status    int
		level     string
		errSubstr string
	}{
		{"/boom", 500, "ERROR", "pq: secret detail"},
		// echo's Recover hands the panic to c.Error itself and returns nil,
		// so the access log sees the 500 but no error (as middleware.Logger did).
		{"/panic", 500, "ERROR", ""},
		{"/forbidden", 403, "INFO", "no"},
		{"/no-such-route", 404, "INFO", "Not Found"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			e, buf, calls := accessLogServer(t)
			got, rec := serveAndDecode(t, e, buf, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != tc.status {
				t.Fatalf("response status %d, want %d", rec.Code, tc.status)
			}
			if *calls != 1 {
				t.Fatalf("error handler ran %d times, want 1", *calls)
			}
			if got["status"] != float64(tc.status) {
				t.Errorf("logged status %v, want %d", got["status"], tc.status)
			}
			if got["level"] != tc.level {
				t.Errorf("level %v, want %s", got["level"], tc.level)
			}
			if s, _ := got["error"].(string); tc.errSubstr == "" && s != "" {
				t.Errorf("error = %q, want none", s)
			} else if !strings.Contains(s, tc.errSubstr) {
				t.Errorf("error = %q, want it to contain %q", s, tc.errSubstr)
			}
		})
	}
}

func TestAccessLog_ReturnsNilAfterHandling(t *testing.T) {
	var buf bytes.Buffer
	e := echo.New()
	mw := AccessLog(slog.New(slog.NewJSONHandler(&buf, nil)))
	h := mw(func(c echo.Context) error { return echo.ErrTeapot })
	c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder())
	if err := h(c); err != nil {
		t.Fatalf("AccessLog returned %v; the error was already handled and must not bubble", err)
	}
	if !c.Response().Committed || c.Response().Status != http.StatusTeapot {
		t.Fatalf("error was not handed to the error handler: committed=%v status=%d",
			c.Response().Committed, c.Response().Status)
	}
}

func TestAccessLog_BytesInIsNumeric(t *testing.T) {
	e, buf, _ := accessLogServer(t)
	e.POST("/echo", func(c echo.Context) error { return c.NoContent(http.StatusNoContent) })
	cases := map[string]struct {
		cl   string
		want float64
	}{
		"declared":  {"5", 5},
		"absent":    {"", 0},
		"malformed": {"abc", 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader("hello"))
			req.Header.Del(echo.HeaderContentLength)
			if tc.cl != "" {
				req.Header.Set(echo.HeaderContentLength, tc.cl)
			}
			got, _ := serveAndDecode(t, e, buf, req)
			if got["bytes_in"] != tc.want {
				t.Fatalf("bytes_in = %#v (%T), want JSON number %v", got["bytes_in"], got["bytes_in"], tc.want)
			}
		})
	}
}
