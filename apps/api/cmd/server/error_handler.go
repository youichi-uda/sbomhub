package main

import (
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"

	appmw "github.com/sbomhub/sbomhub/internal/middleware"
)

// sanitizingErrorHandler wraps Echo's error handler so that no 5xx response
// ever exposes a raw internal/DB error string to the client (F444), and so
// that the server-side record of that 5xx carries no error text either.
//
// Echo's DefaultHTTPErrorHandler renders an *echo.HTTPError's Message straight
// into the response body. Handlers across the codebase produced 5xx errors via
// `echo.NewHTTPError(http.StatusInternalServerError, err.Error())` (e.g. the
// SSVC / KEV / EOL / issue-tracker endpoints), which leaked the raw driver /
// query error to the caller — an information-disclosure hole for a security /
// compliance product. Rather than edit every call site (and risk missing new
// ones), this wrapper is a single backstop: for ANY *echo.HTTPError with a 5xx
// code it replaces the client-facing message with the generic HTTP status text
// before delegating to next.
//
// The log line ("http 5xx error") deliberately holds no error TEXT — neither
// the HTTPError's Message nor its Internal error, nor a plain error's
// Error(). It used to log both verbatim. Error text is where credentials end
// up: a DSN with its password in a connect error, an outbound webhook / LLM /
// tracker URL with a token in its path or query, and *url.Error, whose
// Error() repeats the whole URL. The access log (appmw.AccessLog, M63)
// stopped logging error text after review rounds kept finding credentials in
// it in shapes no scrubber anticipated, and the same reasoning applies here,
// so this line reuses its classification (appmw.ErrorClass): the status and
// the Go type chain of the error (e.g. "http_error code=502
// internal=*fmt.wrapError > *url.Error > *net.OpError"), plus method, route
// template and request_id to find the request in the access log. Handlers
// that need the text for debugging must log it themselves, scrubbed, at the
// point where they know what it contains.
//
// A plain (non-*echo.HTTPError) error is answered 500 by echo and is logged
// the same way; before, it was not logged here at all.
//
// 4xx errors are left untouched and not logged here: their messages are
// caller-facing validation / not-found feedback that the client needs, and
// each handler owns that wording. The access log records them.
func sanitizingErrorHandler(next echo.HTTPErrorHandler) echo.HTTPErrorHandler {
	return func(err error, c echo.Context) {
		if c.Response().Committed {
			// echo's default handler renders nothing once the response is
			// committed: the client got what was already written, and the
			// access log records that status. Not a 5xx, so not logged as one
			// (Codex R1 Low).
			next(err, c)
			return
		}
		if he, ok := err.(*echo.HTTPError); ok {
			// Mirror Echo's DefaultHTTPErrorHandler: when Internal is itself an
			// *echo.HTTPError it is PROMOTED to the effective error (its code +
			// message are what get rendered). So evaluate the promoted error's
			// code, not just the outer one — otherwise an outer 4xx wrapping an
			// internal 5xx (NewHTTPError(400).SetInternal(NewHTTPError(500,
			// "pq: secret"))) would slip past and leak the internal message.
			eff := he
			if inner, ok := he.Internal.(*echo.HTTPError); ok {
				eff = inner
			}
			if eff.Code >= 500 {
				attrs := fiveXXLogAttrs(c, eff.Code, err)
				if msgErr, ok := eff.Message.(error); ok {
					attrs = append(attrs, "message_error", appmw.ErrorTypeChain(msgErr))
				}
				slog.Error("http 5xx error", attrs...)
				err = echo.NewHTTPError(eff.Code)
			}
		} else if err != nil {
			// echo's default handler answers any other error with a generic
			// 500 (it asserts *echo.HTTPError directly, so a wrapped one is a
			// 500 too). The response is already generic; only the log needs
			// to say it happened.
			slog.Error("http 5xx error", fiveXXLogAttrs(c, http.StatusInternalServerError, err)...)
		}
		next(err, c)
	}
}

// fiveXXLogAttrs is the text-free description of one failed request.
func fiveXXLogAttrs(c echo.Context, status int, err error) []any {
	attrs := []any{
		"method", c.Request().Method,
		"route", c.Path(),
		"status", status,
		"error", appmw.ErrorClass(err),
	}
	rid := c.Request().Header.Get(echo.HeaderXRequestID)
	if rid == "" {
		rid = c.Response().Header().Get(echo.HeaderXRequestID)
	}
	if rid != "" {
		attrs = append(attrs, "request_id", rid)
	}
	return attrs
}
