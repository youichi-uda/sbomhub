package llm

import (
	"errors"
	"net/url"
	"regexp"
)

// apiKeyQueryParamPattern matches ?key=... / &api_key=... / ?access_token=...
// substrings that some providers (notably Google's Gemini REST API) have
// historically used for inline authentication. The Go `net/http` transport
// returns errors as `*url.Error` and its `Error()` method renders the full
// URL — including the query string — into the message, which means a
// `connection refused` / `dial tcp ... no route to host` error from a Gemini
// call wrapped at `p.client.Do` would otherwise leak the BYOK key verbatim
// into:
//
//   - the rewrapped error returned by the provider,
//   - `llm_calls.error_message` (persisted by the triage runner),
//   - the HTTP 500 JSON body returned to the client (handler maps any
//     unrecognised runner error to `{"error": err.Error()}`).
//
// Three of those leak paths together let a single transport hiccup expose
// the tenant's paid Gemini key to a logged-in user with /triage POST
// permission — graded High / borderline Critical in M1 Codex review #F13.
//
// SBOMHub now authenticates Gemini via the `x-goog-api-key` header (see
// gemini.go), so the URL no longer contains the key in normal operation.
// This regex is the defense-in-depth scrubber that catches:
//
//   - regressions where someone reintroduces ?key= auth,
//   - third-party libraries that build URLs with auth-shaped params,
//   - debug / log formatters that print the raw query string.
//
// Pattern: capture the leading separator (?/&) and the auth-shaped key
// name so the replacement can preserve them, then replace the value with
// `[REDACTED]`. The value-side character class stops at the next query
// separator (`&`), end-of-string, whitespace, or a double-quote (the
// stringified URL inside `*url.Error` is wrapped in quotes).
//
// ※要確認: `access_token` is added speculatively to cover OAuth-style
// callers; if Google or any other provider standardises on a different
// query name in future (e.g. `bearer`) the list MUST be extended.
var apiKeyQueryParamPattern = regexp.MustCompile(
	`([?&])(key|api_key|api-key|apikey|access_token)=[^&"\s]*`,
)

// RedactProviderError scrubs API-key-shaped material from a provider
// transport error before it is wrapped, persisted, or returned to a
// client.
//
// The function operates in two layers:
//
//  1. If the chain contains a `*url.Error`, its `URL` field is rewritten
//     to drop the query string and fragment. The `*url.Error` value is
//     mutated in place because Go's error-wrapping convention does not
//     give us a portable way to "rebuild" the same chain with a
//     substituted leaf — every downstream `errors.As(_, &urlErr)` caller
//     should see the scrubbed URL too, and that's the safer default for
//     a security-sensitive scrubber.
//
//  2. The rendered error string is then run through
//     apiKeyQueryParamPattern as defense-in-depth in case the chain
//     contains a non-`*url.Error` that nonetheless echoed the URL into
//     its own message (custom HTTP middleware, third-party transport
//     wrappers, etc.).
//
// If no redaction is necessary (no `*url.Error`, no auth-shaped query
// substring) the original error is returned unchanged so call-site
// `errors.Is` / `errors.As` sentinels keep matching against the same
// instance. Otherwise the redacted message is wrapped in a
// `*redactedError` that exposes `Unwrap` so the original chain remains
// reachable for sentinel checks.
//
// Returning `nil` for a `nil` input lets the caller use
// `RedactProviderError(err)` unconditionally without a nil guard.
func RedactProviderError(err error) error {
	if err == nil {
		return nil
	}

	// Layer 1: scrub *url.Error.URL in place. errors.As walks the chain
	// and sets `urlErr` to the first matching node; mutating that node's
	// URL field is observable from any later errors.As caller, which is
	// exactly what we want here.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		urlErr.URL = redactURLString(urlErr.URL)
	}

	// Layer 2: scrub the rendered text for any auth-shaped query
	// substrings that survived layer 1 (e.g. a wrapper that printed the
	// raw URL into its own message).
	rendered := err.Error()
	scrubbed := apiKeyQueryParamPattern.ReplaceAllString(rendered, "${1}${2}=[REDACTED]")
	if scrubbed == rendered {
		// Nothing further to do — layer 1 may have already cleaned the
		// underlying url.Error, but the rendered form is already safe.
		return err
	}
	return &redactedError{msg: scrubbed, cause: err}
}

// redactedError carries a scrubbed message plus the original cause so
// `errors.Is` / `errors.As` against sentinels in the original chain still
// resolve. Only `Error()` and `Unwrap()` are implemented — callers that
// reach for `errors.As(err, &urlErr)` get the (already-mutated) URL leaf
// via the wrapped chain.
type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.cause }

// redactURLString returns the input URL with its query string and
// fragment stripped. If the raw string cannot be parsed (malformed URL,
// custom scheme) we fall back to a static placeholder so the API key
// cannot leak through a parse-failure shortcut.
func redactURLString(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "[REDACTED-URL]"
	}
	if u.RawQuery == "" && u.Fragment == "" {
		return u.String()
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
