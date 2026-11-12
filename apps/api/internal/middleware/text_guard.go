package middleware

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/validation"
)

// TextGuardParams refuses, with 400 {"error": "..."}, a request whose path
// parameters or query string decode to text PostgreSQL cannot store: a value
// that contains U+0000 or is not valid UTF-8. (A UTF-16 surrogate encoded as
// UTF-8 bytes, e.g. %ED%A0%80, is not valid UTF-8 and is refused as such.)
//
// Why (M71): M66's handler.TextGuardJSONSerializer covers JSON bodies only.
// net/http and echo percent-decode the query string and path parameters, so
// `?name=a%00b` or `/eol/products/%FF` reached the handlers as text carrying a
// NUL or an invalid byte; PostgreSQL refused it (SQLSTATE 22021) and the
// request answered 500. Measured before this guard on the full server: 23 of
// the GET routes probed answered 500, among them component search, the audit
// log list and export, the EOL lookups, the CRA report / VEX draft / ticket /
// SSVC lists. Any audited GET did too, whatever the parameter: the Audit
// middleware records the query map in audit_logs.details (jsonb), the INSERT
// failed inside the request's tenant transaction, and the commit then failed.
//
// Where it runs: cmd/server installs it with e.Use, so it runs once per
// request after routing (the path parameters are known) and before every
// group middleware — authentication, the tenant transaction, rate limits and
// the audit log. It reads only the URL: no body, nothing echo would not
// already have parsed. A value that is ordinary text, including tab and
// newline, passes; field-specific rules stay with the handlers.
//
// Bodies are covered elsewhere: JSON by handler.TextGuardJSONSerializer,
// form and multipart values by handler.TextGuardBinder (when bound) and
// handler.checkFormText (when read directly).
//
// The response names the parameter and the reason, never the value. A query
// key is named only when it is itself a short plain identifier.
func TextGuardParams() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if err := checkRequestParams(c); err != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			}
			return next(c)
		}
	}
}

// checkRequestParams returns the first refusal (wrapping
// validation.ErrInvalidText), or nil.
func checkRequestParams(c echo.Context) error {
	names, values := c.ParamNames(), c.ParamValues()
	for i, name := range names {
		if i >= len(values) {
			break
		}
		if err := validation.CheckTextField("path parameter "+strconv.Quote(name), values[i], validation.TextRule{}); err != nil {
			return err
		}
	}
	return checkRawQuery(c.Request().URL.RawQuery)
}

// checkRawQuery checks every pair url.ParseQuery would decode, without
// building url.Values (Codex R2): the guard runs before authentication, and
// materialising a query of ~10,000 short pairs cost ~30,000 allocations per
// request. Each key and value is decoded into one reused buffer and checked
// there; a string is built only for the refusal message.
//
// It sees what a handler's c.QueryParam would see: a pair url.ParseQuery
// drops (it contains ';', or a key or value is not a valid escape) is skipped,
// '+' decodes to a space. It does not stop at net/url's 10,000-parameter cap
// (above which ParseQuery hands handlers nothing): checking more is harmless,
// and a GODEBUG raising the cap must not open a gap.
func checkRawQuery(raw string) error {
	var buf []byte
	for raw != "" {
		var pair string
		pair, raw, _ = strings.Cut(raw, "&")
		if pair == "" || strings.Contains(pair, ";") {
			continue
		}
		rawKey, rawVal, _ := strings.Cut(pair, "=")
		// Both halves are decoded before either is checked: url.ParseQuery
		// drops the whole pair when either fails to decode.
		var ok bool
		if buf, ok = queryUnescapeInto(buf[:0], rawKey); !ok {
			continue
		}
		keyLen := len(buf) // the value is decoded after the key, in the same buffer
		if buf, ok = queryUnescapeInto(buf, rawVal); !ok {
			continue
		}
		if !textStorable(buf[:keyLen]) {
			return validation.CheckTextField("a query parameter name", string(buf[:keyLen]), validation.TextRule{})
		}
		if val := buf[keyLen:]; !textStorable(val) {
			k := string(buf[:keyLen])
			field := "a query parameter"
			if PlainParamName(k) {
				field = "query parameter " + strconv.Quote(k)
			}
			return validation.CheckTextField(field, string(val), validation.TextRule{})
		}
	}
	return nil
}

// textStorable reports whether b is valid UTF-8 without U+0000 — what
// validation.CheckTextField accepts under an empty TextRule.
func textStorable(b []byte) bool {
	return utf8.Valid(b) && bytes.IndexByte(b, 0) < 0
}

// queryUnescapeInto appends the url.QueryUnescape decoding of s to dst. ok is
// false where url.QueryUnescape would fail (a '%' not followed by two hex
// digits).
func queryUnescapeInto(dst []byte, s string) ([]byte, bool) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '+':
			dst = append(dst, ' ')
		case '%':
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return dst, false
			}
			dst = append(dst, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
		default:
			dst = append(dst, c)
		}
	}
	return dst, true
}

// PlainParamName reports whether a client-supplied query or form key is safe
// to name in a response: 1-64 bytes of [A-Za-z0-9_.-] and brackets.
func PlainParamName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		case b == '_' || b == '-' || b == '.' || b == '[' || b == ']':
		default:
			return false
		}
	}
	return true
}
