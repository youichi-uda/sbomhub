package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/validation"
)

// TextGuardJSONSerializer is the API's echo.JSONSerializer (cmd/server sets
// e.JSONSerializer). Its Deserialize is the single choke point for JSON
// request bodies: echo's DefaultBinder calls it — and only it — to decode a
// JSON body, every handler that decodes JSON does so through c.Bind
// (raw-body routes — SBOM upload and the signed webhooks — read the body
// themselves; the SBOM services run the same check, see
// service.checkSBOMText). Serialize (responses) is echo's, unchanged.
//
// Deserialize refuses, with 400 and a message saying why, a JSON value that
// is not valid UTF-8, carries U+0000 (raw or \u0000) or an unpaired UTF-16
// surrogate escape (validation.CheckJSONText). PostgreSQL refuses U+0000 in
// text and jsonb, and a lone surrogate in jsonb, so such a value used to reach
// an INSERT and come back as a 500; invalid UTF-8 and lone surrogates used to
// be stored as U+FFFD, i.e. not what the client sent.
//
// Why here and not in a Binder or a middleware (Codex R5): echo reaches
// Deserialize only after authentication (c.Bind runs in the handler), after
// path / query binding has succeeded, and only for the exact media type
// application/json — so nothing is read that echo would not have read. It
// reads exactly one JSON value, as echo's decoder does, so a client that
// sends a complete value and then never finishes the body is answered
// instead of pinning the handler. The value's raw bytes are checked, then
// decoded with encoding/json as before (same error mapping as echo's
// DefaultJSONSerializer).
type TextGuardJSONSerializer struct {
	echo.DefaultJSONSerializer
}

// NewTextGuardJSONSerializer returns the serializer cmd/server installs.
func NewTextGuardJSONSerializer() *TextGuardJSONSerializer { return &TextGuardJSONSerializer{} }

// Deserialize implements echo.JSONSerializer.
func (s *TextGuardJSONSerializer) Deserialize(c echo.Context, i interface{}) error {
	var raw json.RawMessage
	if err := json.NewDecoder(c.Request().Body).Decode(&raw); err != nil {
		return mapJSONDecodeError(err)
	}
	if terr := validation.CheckJSONText(raw); terr != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body: "+terr.Error()).SetInternal(terr)
	}
	if err := json.Unmarshal(raw, i); err != nil {
		return mapJSONDecodeError(err)
	}
	return nil
}

// mapJSONDecodeError maps a decode error exactly as echo's
// DefaultJSONSerializer does; anything else (BodyLimit's 413 HTTPError, an
// unexpected EOF) is returned as is and DefaultBinder.BindBody wraps a
// non-HTTPError into 400.
func mapJSONDecodeError(err error) error {
	if ute, ok := err.(*json.UnmarshalTypeError); ok {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Unmarshal type error: expected=%v, got=%v, field=%v, offset=%v", ute.Type, ute.Value, ute.Field, ute.Offset)).SetInternal(err)
	} else if se, ok := err.(*json.SyntaxError); ok {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Syntax error: offset=%v, error=%v", se.Offset, se.Error())).SetInternal(err)
	}
	return err
}

// respondBindError writes the 400 for a failed c.Bind. A body refused by
// TextGuardJSONSerializer gets its specific message (what is wrong and at which
// offset); a non-400 HTTPError (BodyLimit's 413) is returned as is; any other
// bind failure keeps the generic "invalid request body".
func respondBindError(c echo.Context, err error) error {
	// BodyLimit's 413 (and any other non-400 status the binder chose) is
	// kept: an over-long body is not a malformed one.
	var limit *echo.HTTPError
	if errors.As(err, &limit) && limit.Code != http.StatusBadRequest {
		return limit
	}
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

// isRefusedBody reports whether a c.Bind error means the request must be
// answered even by a handler that otherwise tolerates a missing or malformed
// body: the text guard refused it, or BodyLimit did (413).
func isRefusedBody(err error) bool {
	if errors.Is(err, validation.ErrInvalidText) {
		return true
	}
	var he *echo.HTTPError
	return errors.As(err, &he) && he.Code == http.StatusRequestEntityTooLarge
}

// TextGuardBinder is the API's echo.Binder (cmd/server sets e.Binder). It is
// echo's DefaultBinder with one addition: before binding, an
// application/x-www-form-urlencoded or multipart/form-data body has its
// field names and values checked like a JSON body (checkFormText), so a form
// value carrying U+0000 or invalid UTF-8 is refused with the same 400
// ("form field \"x\" ...") instead of reaching PostgreSQL (M71).
//
// Path parameters and the query string, which DefaultBinder also binds, are
// checked for every request by middleware.TextGuardParams; JSON bodies by
// TextGuardJSONSerializer. Like the serializer, this runs only when a handler
// calls c.Bind, i.e. after authentication.
type TextGuardBinder struct {
	echo.DefaultBinder
}

// NewTextGuardBinder returns the binder cmd/server installs.
func NewTextGuardBinder() *TextGuardBinder { return &TextGuardBinder{} }

// Bind implements echo.Binder.
func (b *TextGuardBinder) Bind(i interface{}, c echo.Context) error {
	if err := checkFormText(c); err != nil {
		return err
	}
	return b.DefaultBinder.Bind(i, c)
}

// checkFormText checks the field names and values of a form body. A handler
// that reads a form without c.Bind (c.FormValue / c.FormFile: CLIHandler.Upload)
// calls it first. Non-form requests, and bodyless ones, pass untouched.
//
// Only value parts are text. A multipart file part (one with a filename) is
// in MultipartForm.File, not in the values checked here, so binary file
// content — an SBOM upload — is never inspected. The form is parsed exactly as
// echo would parse it for the handler (c.FormParams, cached on the request),
// so nothing is read twice. A body that does not parse is refused here, with
// the status echo.DefaultBinder gives it.
func checkFormText(c echo.Context) error {
	req := c.Request()
	if req.ContentLength == 0 {
		return nil
	}
	ctype := req.Header.Get(echo.HeaderContentType)
	if !strings.HasPrefix(ctype, echo.MIMEApplicationForm) && !strings.HasPrefix(ctype, echo.MIMEMultipartForm) {
		return nil
	}
	params, err := c.FormParams()
	if err != nil {
		// Answered exactly as echo.DefaultBinder answers it (Codex R1): an
		// HTTPError (BodyLimit's 413) as is, anything else as 400. It must not
		// be swallowed: net/http caches the partially parsed form, so a later
		// parse by echo would succeed and the handler would run on defaults.
		var he *echo.HTTPError
		if errors.As(err, &he) {
			return he
		}
		return echo.NewHTTPError(http.StatusBadRequest, err.Error()).SetInternal(err)
	}
	for key, vals := range params {
		if terr := validation.CheckTextField("a form field name", key, validation.TextRule{}); terr != nil {
			return echo.NewHTTPError(http.StatusBadRequest, terr.Error()).SetInternal(terr)
		}
		field := "a form field"
		if middleware.PlainParamName(key) {
			field = "form field " + strconv.Quote(key)
		}
		for _, v := range vals {
			if terr := validation.CheckTextField(field, v, validation.TextRule{}); terr != nil {
				return echo.NewHTTPError(http.StatusBadRequest, terr.Error()).SetInternal(terr)
			}
		}
	}
	return nil
}
