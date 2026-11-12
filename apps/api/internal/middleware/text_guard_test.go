package middleware

import (
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

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

// Codex R2 (Medium): the guard runs before authentication, so checking the
// query must not materialise it. A query of ~10,000 short pairs used to cost
// a map entry, a slice and a decoded string per pair (url.ParseQuery) on
// every unauthenticated request; the scan is now allocation-bounded.
func TestM71TextGuardParams_QueryScanDoesNotMaterialise(t *testing.T) {
	var sb strings.Builder
	// 9,999 pairs: under net/url's 10,000-parameter cap, so url.ParseQuery
	// really does build them all (above the cap it parses nothing).
	for i := 0; i < 9999; i++ {
		sb.WriteString("k")
		sb.WriteString(strconv.Itoa(i))
		sb.WriteString("=v%41&") // distinct keys, escaped values
	}
	sb.WriteString("z=%E6%97%A5")
	raw := sb.String()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/search", nil)
	req.URL.RawQuery = raw
	rec := httptest.NewRecorder()
	// A fresh context per run: echo caches the parsed query on the context.
	allocs := testing.AllocsPerRun(5, func() {
		if err := checkRequestParams(e.NewContext(req, rec), nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Logf("allocs=%.0f len=%d", allocs, len(raw))
	if allocs > 16 {
		t.Fatalf("checkRequestParams allocated %.0f times for a %d-byte query; want a small constant", allocs, len(raw))
	}
}

// The scanner refuses exactly what url.ParseQuery would hand a handler:
// pairs url.ParseQuery drops (bad escape, ';') are not inspected, and '+'
// decodes to a space.
func TestM71TextGuardParams_ScannerMatchesParseQuery(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		refused bool
	}{
		{"a=%00", true},
		{"a=ok&b=%00", true},
		{"%00=1", true},
		{"a=%ZZ%00", false},  // ParseQuery drops the pair (bad escape)
		{"a=%00;b=1", false}, // ParseQuery drops the pair (semicolon)
		{"a=b+c&d=%2B", false},
		{"a=%FF", true},
		{"a=%ED%A0%80", true},
		{"a", false},
		{"&&=&", false},
	} {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/search", nil)
		req.URL.RawQuery = tc.raw
		err := checkRequestParams(e.NewContext(req, httptest.NewRecorder()), nil)
		if (err != nil) != tc.refused {
			t.Errorf("%q: err = %v, want refused=%v", tc.raw, err, tc.refused)
		}
	}
}

// Differential check of the scanner against the url.ParseQuery path it
// replaced: over random queries built from the characters that matter, both
// refuse exactly the same inputs.
func TestM71TextGuardParams_ScannerAgreesWithParseQuery(t *testing.T) {
	alphabet := []string{"a", "b", "=", "&", ";", "+", "%", "0", "00", "%00", "%FF", "%ED%A0%80", "%E6%97%A5", "%Z", "%2", "\x00", "%41"}
	rng := rand.New(rand.NewPCG(71, 2))
	for n := 0; n < 20000; n++ {
		var sb strings.Builder
		for k := rng.IntN(8); k >= 0; k-- {
			sb.WriteString(alphabet[rng.IntN(len(alphabet))])
		}
		raw := sb.String()
		want := false
		vals, _ := url.ParseQuery(raw)
		for k, vs := range vals {
			if !utf8.ValidString(k) || strings.ContainsRune(k, 0) {
				want = true
			}
			for _, v := range vs {
				if !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
					want = true
				}
			}
		}
		if got := checkRawQuery(raw, nil) != nil; got != want {
			t.Fatalf("%q: scanner refused=%v, ParseQuery-based check refused=%v", raw, got, want)
		}
	}
}

// Codex R3 (Medium): a share-link password is only bcrypt-compared, never sent
// to PostgreSQL, and links created before M66 may have one containing U+0000.
// On the route that declares it opaque the value passes; its key, the other
// parameters, and the same key on any other route are still checked.
func TestM71TextGuardParams_OpaqueQueryParam(t *testing.T) {
	e := echo.New()
	e.Use(TextGuardParams(OpaqueQueryParam{Route: "/public/:token", Key: "password"}))
	h := func(c echo.Context) error { return c.String(http.StatusOK, c.QueryParam("password")) }
	e.GET("/public/:token", h)
	e.GET("/other", h)
	for _, tc := range []struct {
		target string
		want   int
	}{
		{"/public/tok?password=a%00b", http.StatusOK},
		{"/public/tok?password=%FF", http.StatusOK},
		{"/public/tok?password=a%00b&x=%00", http.StatusBadRequest},
		{"/public/a%00b?password=ok", http.StatusBadRequest},
		{"/other?password=a%00b", http.StatusBadRequest},
	} {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.target, nil))
		if rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d (body %s)", tc.target, rec.Code, tc.want, rec.Body.String())
		}
		if tc.want == http.StatusOK && rec.Body.String() != mustUnescapeQuery(t, tc.target) {
			t.Errorf("%s: handler saw %q", tc.target, rec.Body.String())
		}
	}
}

func mustUnescapeQuery(t *testing.T, target string) string {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("password")
}

// Codex R3 (Low): above net/url's parameter cap url.ParseQuery hands handlers
// (and the audit log) nothing, so the guard must not refuse what nobody reads;
// at the cap it checks every pair.
func TestM71TextGuardParams_ParameterCap(t *testing.T) {
	build := func(pairs int) string {
		return strings.Repeat("a=b&", pairs-1) + "z=%00"
	}
	for _, tc := range []struct {
		pairs   int
		refused bool
	}{{10000, true}, {10001, false}} {
		raw := build(tc.pairs)
		vals, _ := url.ParseQuery(raw)
		if got := checkRawQuery(raw, nil) != nil; got != tc.refused {
			t.Errorf("%d pairs: refused=%v, want %v (ParseQuery returned %d keys)", tc.pairs, got, tc.refused, len(vals))
		}
	}
}
