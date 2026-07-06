package main

import (
	"fmt"
	"log/slog"

	"github.com/labstack/echo/v4"
)

// sanitizingErrorHandler wraps Echo's error handler so that no 5xx response
// ever exposes a raw internal/DB error string to the client (F444).
//
// Echo's DefaultHTTPErrorHandler renders an *echo.HTTPError's Message straight
// into the response body. Handlers across the codebase produced 5xx errors via
// `echo.NewHTTPError(http.StatusInternalServerError, err.Error())` (e.g. the
// SSVC / KEV / EOL / issue-tracker endpoints), which leaked the raw driver /
// query error to the caller — an information-disclosure hole for a security /
// compliance product. Rather than edit every call site (and risk missing new
// ones), this wrapper is a single backstop: for ANY *echo.HTTPError with a 5xx
// code it logs the real detail server-side and replaces the client-facing
// message with the generic HTTP status text before delegating to next.
//
// 4xx errors are left untouched: their messages are caller-facing validation /
// not-found feedback that the client needs, and each handler owns that wording.
// Raw non-*echo.HTTPError values already render generically under Echo's
// default handler (StatusText, not err.Error()), so they need no special case.
func sanitizingErrorHandler(next echo.HTTPErrorHandler) echo.HTTPErrorHandler {
	return func(err error, c echo.Context) {
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
				slog.Warn("http 5xx error",
					"method", c.Request().Method,
					"path", c.Path(),
					"status", eff.Code,
					"detail", fmt.Sprintf("%v", eff.Message),
					"internal", he.Internal,
				)
				err = echo.NewHTTPError(eff.Code)
			}
		}
		next(err, c)
	}
}
