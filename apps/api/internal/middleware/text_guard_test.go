package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

// m71GuardServe routes one request through an echo instance that has only
// TextGuardParams installed (as cmd/server installs it, via e.Use, so routing
// has already happened) and reports the status, the body and whether the
// handler ran.
func m71GuardServe(t *testing.T, method, target string) (int, string, bool) {
	t.Helper()
	e := echo.New()
	e.Use(TextGuardParams())
	ran := false
	h := func(c echo.Context) error {
		ran = true
		return c.String(http.StatusOK, "ok")
	}
	e.GET("/things/:name", h)
	e.GET("/things/:name/sub/:other", h)
	e.GET("/files/*", h)
	e.GET("/search", h)
	e.POST("/search", h)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec.Code, rec.Body.String(), ran
}

func TestM71TextGuardParams_RefusesNULAndInvalidUTF8(t *testing.T) {
	cases := []struct {
		name, method, target, wantMsg string
	}{
		{"query NUL", http.MethodGet, "/search?name=a%00b", `query parameter "name" must not contain a NUL character`},
		{"query invalid UTF-8", http.MethodGet, "/search?name=%FF", `query parameter "name" is not valid UTF-8`},
		{"query lone surrogate (CESU bytes)", http.MethodGet, "/search?name=%ED%A0%80", `query parameter "name" is not valid UTF-8`},
		{"query second value", http.MethodGet, "/search?tag=ok&tag=%00", `query parameter "tag" must not contain a NUL character`},
		{"query on POST", http.MethodPost, "/search?x=%00", `query parameter "x" must not contain a NUL character`},
		{"query key NUL", http.MethodGet, "/search?a%00b=1", `a query parameter name must not contain a NUL character`},
		{"query key invalid UTF-8", http.MethodGet, "/search?%FF=1", `a query parameter name is not valid UTF-8`},
		{"path NUL", http.MethodGet, "/things/a%00b", `path parameter "name" must not contain a NUL character`},
		{"path invalid UTF-8", http.MethodGet, "/things/%FF", `path parameter "name" is not valid UTF-8`},
		{"second path param", http.MethodGet, "/things/ok/sub/%00", `path parameter "other" must not contain a NUL character`},
		{"wildcard path", http.MethodGet, "/files/a/%00", `path parameter "*" must not contain a NUL character`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body, ran := m71GuardServe(t, tc.method, tc.target)
			if code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", code, body)
			}
			if ran {
				t.Fatal("handler ran for a refused request")
			}
			var got map[string]string
			if err := json.Unmarshal([]byte(body), &got); err != nil {
				t.Fatalf("body is not the {\"error\": ...} JSON shape: %q", body)
			}
			if got["error"] != tc.wantMsg {
				t.Fatalf("error = %q, want %q", got["error"], tc.wantMsg)
			}
		})
	}
}

func TestM71TextGuardParams_PassesOrdinaryText(t *testing.T) {
	for _, target := range []string{
		"/search",
		"/search?name=log4j-core&version=2.14.1",
		"/search?q=%E6%97%A5%E6%9C%AC%E8%AA%9E",            // 日本語
		"/search?q=%F0%9F%98%80",                           // U+1F600 (a valid surrogate pair in UTF-16)
		"/search?q=a%09b%0Ac",                              // tab / newline: storable, left to the handler
		"/search?purl=pkg%3Anpm%2F%40scope%2Fname%401.0.0", // escaped reserved characters
		"/search?empty=&flag",
		"/things/sha256:abcd",
		"/things/a%2Fb", // escaped slash: echo keeps the raw value, which is plain text
		"/files/a/b/c.json",
	} {
		code, body, ran := m71GuardServe(t, http.MethodGet, target)
		if code != http.StatusOK || !ran {
			t.Errorf("%s: status %d ran=%v body %s, want 200 from the handler", target, code, ran, body)
		}
	}
}

// The refused value is never echoed back: the message names the parameter
// (a route-defined name, or a query key that is itself plain) and the reason.
func TestM71TextGuardParams_DoesNotEchoTheValue(t *testing.T) {
	_, body, _ := m71GuardServe(t, http.MethodGet, "/search?name=secret-token-%00")
	if strings.Contains(body, "secret-token") {
		t.Fatalf("body echoes the refused value: %s", body)
	}
	long := strings.Repeat("k", 100)
	_, body, _ = m71GuardServe(t, http.MethodGet, "/search?"+long+"=%00")
	if strings.Contains(body, long) {
		t.Fatalf("body echoes an over-long query key: %s", body)
	}
	_, body, _ = m71GuardServe(t, http.MethodGet, "/search?%3Cscript%3E=%00")
	if strings.Contains(body, "script") {
		t.Fatalf("body echoes a query key that is not a plain identifier: %s", body)
	}
}
