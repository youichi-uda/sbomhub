package middleware

import (
	"context"
	"log/slog"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"

	"github.com/sbomhub/sbomhub/internal/redact"
)

// AccessLog is the HTTP access log: one slog record per request, replacing
// echo's deprecated middleware.Logger (deprecated since echo v4.16 in favour
// of middleware.RequestLogger, which this is built on).
//
// Fields (operators' log queries depend on these names):
//
//	method, uri, route, status, latency (ns), latency_human, remote_ip,
//	host, user_agent, bytes_in, bytes_out, request_id (only when an
//	X-Request-ID header is present), error (only when the handler failed)
//
// What changed from middleware.Logger, deliberately:
//
//   - The record is a slog JSON line (msg "http request") on the same stdout
//     stream as the rest of the server log, instead of echo's hand-built JSON
//     line. The old `id` field is now `request_id`.
//   - `uri` is the request PATH only. middleware.Logger logged RequestURI,
//     which includes the raw query string; a query string can carry
//     credentials (an API key or token pasted into a URL by a client), so it
//     is never logged now.
//   - Path segments that are secrets are redacted: the value of every route
//     parameter listed in accessLogSecretParams (the public-link `:token`),
//     and — so a mistyped URL that matched no route still does not leak —
//     everything after accessLogSecretPrefixes. middleware.Logger logged the
//     public-link token in clear.
//   - `route` (the matched route template, e.g. /api/v1/projects/:id) is new.
//   - `error` is scrubbed (see accessLogErrorText): every URL in it is cut to
//     scheme://host, then internal/redact removes Bearer tokens,
//     Authorization headers and auth-shaped name=value pairs.
//     middleware.Logger logged it verbatim.
//   - 5xx responses are logged at ERROR, everything else at INFO.
//
// Error handling matches middleware.Logger exactly: a handler error is passed
// to the global error handler (c.Error) here, so the logged status is the one
// the client received, and the error is then NOT returned up the chain. Echo
// would otherwise run the error handler a second time for the same error; the
// response is already committed so nothing is re-sent, but
// sanitizingErrorHandler would log every 5xx twice.
//
// The remote IP is c.RealIP(), i.e. whatever Echo#IPExtractor is configured
// (see ClientIPExtractor), the same value rate limiting and the audit log use.
func AccessLog(logger *slog.Logger) echo.MiddlewareFunc {
	inner := echomw.RequestLoggerWithConfig(echomw.RequestLoggerConfig{
		HandleError:      true,
		LogLatency:       true,
		LogRemoteIP:      true,
		LogHost:          true,
		LogMethod:        true,
		LogRoutePath:     true,
		LogRequestID:     true,
		LogUserAgent:     true,
		LogStatus:        true,
		LogError:         true,
		LogContentLength: true,
		LogResponseSize:  true,
		// LogURI is deliberately off (it is RequestURI, query included);
		// the path is derived below from c.Request().URL.Path.
		LogValuesFunc: func(c echo.Context, v echomw.RequestLoggerValues) error {
			// bytes_in stays a JSON number like middleware.Logger's. The
			// header is client-controlled: an absent or unparsable value is
			// logged as 0 (the old template wrote it raw, so "abc" produced
			// an invalid JSON line).
			bytesIn, err := strconv.ParseInt(v.ContentLength, 10, 64)
			if err != nil || bytesIn < 0 {
				bytesIn = 0
			}
			attrs := make([]slog.Attr, 0, 14)
			attrs = append(attrs,
				slog.String("method", v.Method),
				slog.String("uri", accessLogPath(c)),
				slog.String("route", v.RoutePath),
				slog.Int("status", v.Status),
				slog.Duration("latency", v.Latency),
				slog.String("latency_human", v.Latency.String()),
				slog.String("remote_ip", v.RemoteIP),
				slog.String("host", v.Host),
				slog.String("user_agent", v.UserAgent),
				slog.Int64("bytes_in", bytesIn),
				slog.Int64("bytes_out", v.ResponseSize),
			)
			if v.RequestID != "" {
				attrs = append(attrs, slog.String("request_id", v.RequestID))
			}
			if v.Error != nil {
				attrs = append(attrs, slog.String("error", accessLogErrorText(v.Error)))
			}
			level := slog.LevelInfo
			if v.Status >= 500 {
				level = slog.LevelError
			}
			logger.LogAttrs(context.Background(), level, "http request", attrs...)
			return nil
		},
	})
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		h := inner(next)
		return func(c echo.Context) error {
			// HandleError already handed any error to c.Error; swallowing it
			// here is what middleware.Logger did (see the doc comment).
			_ = h(c)
			return nil
		}
	}
}

// accessLogSecretParams are route parameter names whose values are bearer
// secrets and must never reach the access log.
var accessLogSecretParams = map[string]bool{
	"token": true,
}

// accessLogSecretPrefixes are lower-case path prefixes whose remainder holds a
// bearer secret whether or not the request matched a route. No trailing "/":
// a token glued to the prefix is redacted too (over-redacting an unrelated
// "/api/v1/publication..." path is the fail-closed side).
var accessLogSecretPrefixes = []string{
	"/api/v1/public",
}

const accessLogRedacted = "[REDACTED]"

// accessLogPath returns the request path (never the query string) with
// secret segments replaced by accessLogRedacted.
func accessLogPath(c echo.Context) string {
	p := c.Request().URL.Path
	if p == "" {
		p = "/"
	}
	segs := strings.Split(p, "/")

	// Route-parameter redaction: walk the matched template and the path in
	// step. Only single-segment ":name" parameters are positional; stop at a
	// "*" wildcard (it can span segments).
	if route := c.Path(); route != "" {
		tsegs := strings.Split(route, "/")
		for i, ts := range tsegs {
			if i >= len(segs) || strings.Contains(ts, "*") {
				break
			}
			if strings.HasPrefix(ts, ":") && accessLogSecretParams[ts[1:]] {
				segs[i] = accessLogRedacted
			}
		}
	}

	return redactSecretPrefixes(strings.Join(segs, "/"))
}

// redactSecretPrefixes removes everything after a secret prefix, wherever it
// appears and in any ASCII letter case. This covers a request that matched no
// route (a 404 on a mistyped public-link URL still carries the real token), a
// "//api/..." path, a token directly glued to the prefix, and a token
// containing an encoded "/" (URL.Path is decoded once, so it would otherwise
// span two segments). The matched route template is logged separately in
// `route`, so nothing an operator needs is lost.
//
// Case folding is ASCII-only and byte-for-byte, so an index found in the
// folded copy is valid in the original (strings.ToLower is not: it turns each
// invalid UTF-8 byte into a 3-byte U+FFFD and shifted the cut into the token).
//
// It fails closed: when the prefix shows up only after further
// percent-decoding (a double-encoded "%252F" separator survives URL.Path's
// single decode), the whole path is replaced, because there is no reliable
// offset to cut at. Decoding is lenient (a malformed escape cannot abort it)
// and bounded; running out of budget with escapes left also redacts.
func redactSecretPrefixes(p string) string {
	if i, ok := indexSecretPrefix(p); ok {
		if i < len(p) {
			if p[i] == '/' {
				return p[:i+1] + accessLogRedacted
			}
			return p[:i] + accessLogRedacted
		}
		return p
	}
	d := p
	for n := 0; ; n++ {
		// A canonical-equivalent spelling ("/api/./v1", "/api//v1",
		// "/x/../public", backslashes) hides the prefix from the literal
		// search above; check the cleaned form of every layer.
		if hasSecretRemainder(canonicalPath(d)) {
			return accessLogRedacted
		}
		u := lenientPercentDecode(d)
		if u == d {
			return p // fully decoded and no prefix in any form: nothing secret
		}
		if n == accessLogMaxDecodeLayers {
			return accessLogRedacted // still decodable past the budget
		}
		d = u
		if hasSecretRemainder(d) {
			return accessLogRedacted
		}
	}
}

// canonicalPath treats "\\" as a separator and resolves ".", ".." and empty
// segments, so equivalent spellings of a prefix compare equal.
func canonicalPath(p string) string {
	return path.Clean("/" + strings.ReplaceAll(p, "\\", "/"))
}

// hasSecretRemainder reports whether p contains a secret prefix followed by
// anything at all.
func hasSecretRemainder(p string) bool {
	i, ok := indexSecretPrefix(p)
	return ok && i < len(p)
}

// accessLogMaxDecodeLayers bounds the decode loop (each layer is O(len)). A
// path still holding decodable escapes past it is redacted whole, so depth is
// never a way around redaction.
const accessLogMaxDecodeLayers = 16

// lenientPercentDecode decodes every well-formed %XX escape and copies
// anything else (a malformed "%zz", a lone "%") through unchanged. Unlike
// url.PathUnescape it never fails, so one bad escape cannot stop the search.
func lenientPercentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b = append(b, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
			continue
		}
		b = append(b, s[i])
	}
	return string(b)
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// indexSecretPrefix returns the offset just past the first secret prefix in p
// (ASCII case-insensitive), and whether one was found.
func indexSecretPrefix(p string) (int, bool) {
	lower := asciiLower(p)
	for _, prefix := range accessLogSecretPrefixes {
		if i := strings.Index(lower, prefix); i >= 0 {
			return i + len(prefix), true
		}
	}
	return 0, false
}

// asciiLower lower-cases ASCII letters only, keeping every other byte (and so
// every offset) unchanged.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// accessLogURLStartRe finds the start of a URL with an explicit scheme.
var accessLogURLStartRe = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]*://`)

// accessLogErrorText renders a handler error for the access log without the
// credentials error text routinely carries. It fails closed on the main
// carrier, URLs: an outbound *url.Error, a webhook or a DSN keeps only
// scheme://host — userinfo, path, query and fragment are dropped whatever
// their names or shape (a Slack/Discord webhook secret is a path segment; a
// presigned URL's is an X-Amz-Signature parameter no name list anticipates).
// internal/redact (the audit log's scrubber) then removes Bearer tokens,
// Authorization headers and auth-shaped name=value pairs outside URLs. It
// works on the rendered string; the error chain is not modified.
func accessLogErrorText(err error) string {
	return redact.String(cutURLsToHost(err.Error()))
}

// cutURLsToHost replaces every scheme-bearing URL in s with scheme://host
// plus a redaction marker when anything followed the host.
//
// Where a URL ends is decided conservatively, because quotes and spaces can
// sit inside one: a URL that opens right after a double quote (Go renders
// URLs in errors with %q — *url.Error, url.Parse failures) runs to the
// closing unescaped quote, skipping \" escapes and spaces; any other URL
// runs to the next whitespace, so an apostrophe or quote inside it does not
// end it. Over-consuming a little trailing punctuation is the fail-closed
// side.
func cutURLsToHost(s string) string {
	var b strings.Builder
	rest := s
	for {
		loc := accessLogURLStartRe.FindStringIndex(rest)
		if loc == nil {
			b.WriteString(rest)
			return b.String()
		}
		start, i := loc[0], loc[1]
		quoted := start > 0 && rest[start-1] == '"'

		// Authority: up to the first byte that cannot be part of it.
		authEnd := i
		for authEnd < len(rest) && !strings.ContainsRune("/?#\\\"' \t\r\n", rune(rest[authEnd])) {
			authEnd++
		}
		host := rest[i:authEnd]
		if at := strings.LastIndexByte(host, '@'); at >= 0 {
			host = host[at+1:] // drop userinfo
		}

		// End of the URL.
		end := authEnd
		if quoted {
			for end < len(rest) && rest[end] != '"' {
				if rest[end] == '\\' {
					end++ // skip the escaped byte
				}
				end++
			}
			if end > len(rest) {
				end = len(rest)
			}
		} else {
			for end < len(rest) && !isASCIISpace(rest[end]) {
				end++
			}
		}

		// An "@" after the authority means the authority boundary is not
		// trustworthy (an unescaped "/" inside userinfo): keep no host.
		if strings.IndexByte(rest[authEnd:end], '@') >= 0 {
			host = accessLogRedacted
		}

		b.WriteString(rest[:start])
		b.WriteString(rest[start:loc[1]]) // scheme://
		b.WriteString(host)
		if end > authEnd || len(host) < authEnd-i {
			b.WriteString("/" + accessLogRedacted)
		}
		rest = rest[end:]
	}
}

func isASCIISpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}
