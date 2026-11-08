package middleware

import (
	"context"
	"log/slog"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"
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
				attrs = append(attrs, slog.String("error", v.Error.Error()))
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
// bearer secret whether or not the request matched a route.
var accessLogSecretPrefixes = []string{
	"/api/v1/public/",
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

	out := strings.Join(segs, "/")

	// Prefix redaction: everything after a secret prefix goes, wherever the
	// prefix appears and in any letter case. This covers a request that
	// matched no route (a 404 on a mistyped public-link URL still carries the
	// real token), a "//api/..." path, and a token containing an encoded "/"
	// (URL.Path is decoded, so it would otherwise span two segments). The
	// matched route template is logged separately in `route`, so nothing an
	// operator needs is lost.
	lower := strings.ToLower(out)
	for _, prefix := range accessLogSecretPrefixes {
		if i := strings.Index(lower, prefix); i >= 0 && len(out) > i+len(prefix) {
			out = out[:i+len(prefix)] + accessLogRedacted
			lower = strings.ToLower(out)
		}
	}
	return out
}
