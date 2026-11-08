package handler

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/validation"
)

// TextGuardBinder is the API's echo.Binder (cmd/server sets e.Binder). It is
// the single choke point for JSON request bodies: every handler that decodes
// JSON does so through c.Bind (raw-body routes — SBOM upload and the signed
// webhooks — read the body themselves; the SBOM services run the same check,
// see service.checkSBOMText).
//
// Before decoding a JSON body it runs validation.CheckJSONText over the raw
// bytes and refuses, with 400 and a message saying why, a body that is not
// valid UTF-8 or that carries U+0000. PostgreSQL refuses U+0000 in text and
// jsonb, so such a value used to reach an INSERT and come back as a 500;
// invalid UTF-8 used to be stored as U+FFFD, i.e. not what the client sent.
//
// Why a Binder and not a middleware: c.Bind runs inside the handler, i.e.
// after authentication, so an unauthenticated request is never read into
// memory. A global middleware would have to buffer every body before the
// auth middleware had decided whether to read it at all.
//
// The body is read once (bounded by the server's BodyLimit) and handed to
// echo.DefaultBinder from memory, so decoding behaviour is otherwise exactly
// echo's.
type TextGuardBinder struct {
	echo.DefaultBinder
}

// NewTextGuardBinder returns the binder cmd/server installs as e.Binder.
func NewTextGuardBinder() *TextGuardBinder { return &TextGuardBinder{} }

// Bind implements echo.Binder.
func (b *TextGuardBinder) Bind(i interface{}, c echo.Context) error {
	if err := guardJSONBody(c); err != nil {
		return err
	}
	return b.DefaultBinder.Bind(i, c)
}

// BindBody guards the body the same way for callers that bind the body alone.
func (b *TextGuardBinder) BindBody(c echo.Context, i interface{}) error {
	if err := guardJSONBody(c); err != nil {
		return err
	}
	return b.DefaultBinder.BindBody(c, i)
}

// guardJSONBody checks a JSON request body in place. It applies exactly where
// echo.DefaultBinder decodes JSON: a body is present and the Content-Type
// starts with application/json.
func guardJSONBody(c echo.Context) error {
	req := c.Request()
	if req.ContentLength == 0 || req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	if !strings.HasPrefix(req.Header.Get(echo.HeaderContentType), echo.MIMEApplicationJSON) {
		return nil
	}
	raw, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	// Hand back what was read even on error, so the decoder reports the same
	// failure it would have.
	req.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil {
		// BodyLimit's reader already answers 413 as an *echo.HTTPError; keep it.
		var he *echo.HTTPError
		if errors.As(err, &he) {
			return he
		}
		return echo.NewHTTPError(http.StatusBadRequest, "failed to read request body").SetInternal(err)
	}
	if terr := validation.CheckJSONText(raw); terr != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body: "+terr.Error()).SetInternal(terr)
	}
	return nil
}

// respondBindError writes the 400 for a failed c.Bind. A body refused by
// TextGuardBinder gets its specific message (what is wrong and at which
// offset); any other bind failure keeps the generic "invalid request body".
func respondBindError(c echo.Context, err error) error {
	if errors.Is(err, validation.ErrInvalidText) {
		var he *echo.HTTPError
		if errors.As(err, &he) {
			if msg, ok := he.Message.(string); ok {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": msg})
			}
		}
	}
	return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
}
