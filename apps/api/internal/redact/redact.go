// Package redact is a dependency-free leaf package that scrubs
// secret-shaped material out of strings, errors, and audit-detail maps.
//
// It exists so that BOTH the LLM provider layer
// (internal/service/llm/error_redact.go, which wraps transport errors
// before they are persisted or returned to a client) AND the audit-log
// repository choke point (internal/repository/audit.go, which scrubs
// every audit_logs.details map before INSERT) can share exactly one
// implementation of "what a secret looks like" without importing each
// other. The package MUST stay a leaf — it imports only the standard
// library — so it can be imported from anywhere in the tree without
// creating a cycle.
//
// Design contract: PATTERN-SCOPED redaction only. We redact the VALUE of
// a small set of UNAMBIGUOUS secret shapes (auth query params, Bearer
// tokens, Authorization headers, DSN passwords, and api-key-shaped URL
// query strings inside *url.Error). We do NOT do field-name blacklisting
// and we do NOT blanket-replace. Anything that does not match a clear
// secret shape is returned byte-for-byte unchanged. This is deliberate:
// the primary consumer is the compliance audit trail, and over-redaction
// would corrupt evidence (cve_id values, resource UUIDs, provider/model
// names, and free-form AI-drafted / human-authored justification prose
// must all survive verbatim — they do, because none of them match a
// secret shape).
package redact

import (
	"errors"
	"net/url"
	"regexp"
)

// placeholder is the fixed token every secret VALUE is replaced with.
const placeholder = "[REDACTED]"

// urlPlaceholder is used when a URL string cannot be parsed for the
// query/fragment strip in Error's layer 1, so the raw (possibly
// key-bearing) URL cannot leak through a parse-failure shortcut.
const urlPlaceholder = "[REDACTED-URL]"

var (
	// queryAuthParamPattern matches auth-shaped `name=value` query
	// parameters — the classic REST-API inline-credential leak, e.g.
	// Google's historical `...:generateContent?key=<BYOK key>`. It
	// captures the leading separator + param name + `=` in group 1 so
	// the replacement preserves the parameter name and only the VALUE is
	// redacted. The value class stops at the next query separator (`&`),
	// a double-quote (the stringified URL inside *url.Error is quoted),
	// or whitespace. Case-insensitive so `?KEY=` / `?Api_Key=` variants
	// cannot bypass it.
	//
	// Name list (unambiguous auth params only): key, api_key, api-key,
	// apikey, access_token, token, secret, password, passwd, pwd.
	queryAuthParamPattern = regexp.MustCompile(
		`(?i)([?&](?:key|api[_-]?key|access_token|token|secret|password|passwd|pwd)=)[^&"\s]*`,
	)

	// bearerTokenPattern matches an RFC 6750 Bearer token wherever it
	// appears (`Authorization: Bearer <tok>`, a logged header dump, a
	// stringified request). Group 1 keeps the `Bearer ` prefix; the
	// token value is redacted.
	bearerTokenPattern = regexp.MustCompile(
		`(?i)(bearer\s+)[A-Za-z0-9._\-]+`,
	)

	// authHeaderPattern matches an `Authorization: <value>` header line
	// and redacts the first value token. For a `Bearer`/`Basic` value
	// the value token is `Bearer`/`Basic`; bearerTokenPattern (applied
	// first in String) has already collapsed `Bearer <tok>` to `Bearer
	// [REDACTED]`, so this arm exists to catch bare-credential forms such
	// as `Authorization: sk-abc123`.
	authHeaderPattern = regexp.MustCompile(
		`(?i)(authorization:\s*)\S+`,
	)

	// dsnPasswordPattern matches the PASSWORD component of a connection
	// string / URL with embedded userinfo credentials
	// (`scheme://user:PASSWORD@host`, e.g. `postgres://u:secret@h`). It
	// captures `scheme://user:` in group 1 and the trailing `@` in group
	// 2 so only the password between them is redacted; scheme, user, and
	// host are preserved. The `@` anchor is what makes this specific to
	// real userinfo credentials — an ordinary `scheme://host:port/path`
	// URL (no `@`) never matches.
	dsnPasswordPattern = regexp.MustCompile(
		`([a-zA-Z][a-zA-Z0-9+.\-]*://[^:/?#@\s]*:)[^@/?#\s]+(@)`,
	)
)

// String scrubs secret-shaped substrings from a plain string, returning
// the sanitised copy. A string containing no secret shape is returned
// unchanged (byte-for-byte). This is the single choke-point scrubber the
// audit repository applies to every string value in every audit_logs
// detail map.
func String(s string) string {
	if s == "" {
		return s
	}
	s = queryAuthParamPattern.ReplaceAllString(s, "${1}"+placeholder)
	// Bearer before Authorization: so `Authorization: Bearer <tok>`
	// collapses the token via the Bearer arm rather than leaving `<tok>`
	// dangling after the single-token Authorization match.
	s = bearerTokenPattern.ReplaceAllString(s, "${1}"+placeholder)
	s = authHeaderPattern.ReplaceAllString(s, "${1}"+placeholder)
	s = dsnPasswordPattern.ReplaceAllString(s, "${1}"+placeholder+"${2}")
	return s
}

// Details returns a deep-scrubbed COPY of an audit detail map. Every
// string value reachable through nested maps and slices — including the
// url.Values query map recorded by the audit middleware — is passed
// through String; non-string leaves (numbers, booleans, timestamps,
// stringified UUIDs already handled as strings, nil) are copied verbatim.
//
// The input map is never mutated: a caller's Details map is safe to reuse
// after this call. A nil input returns nil so json.Marshal renders the
// same `null` it produced before the choke point existed.
func Details(details map[string]interface{}) map[string]interface{} {
	if details == nil {
		return nil
	}
	out := make(map[string]interface{}, len(details))
	for k, v := range details {
		out[k] = scrubValue(v)
	}
	return out
}

// scrubValue recursively scrubs a single detail value, returning a copy
// with String applied to every string leaf. Container types are rebuilt
// (never mutated in place); scalar / unknown types are returned as-is.
func scrubValue(v interface{}) interface{} {
	switch val := v.(type) {
	case string:
		return String(val)
	case []string:
		out := make([]string, len(val))
		for i, s := range val {
			out[i] = String(s)
		}
		return out
	case url.Values:
		out := make(url.Values, len(val))
		for k, ss := range val {
			out[k] = scrubStringSlice(ss)
		}
		return out
	case map[string][]string:
		out := make(map[string][]string, len(val))
		for k, ss := range val {
			out[k] = scrubStringSlice(ss)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(val))
		for k, s := range val {
			out[k] = String(s)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, vv := range val {
			out[k] = scrubValue(vv)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, vv := range val {
			out[i] = scrubValue(vv)
		}
		return out
	default:
		return v
	}
}

func scrubStringSlice(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = String(s)
	}
	return out
}

// Error scrubs API-key-shaped and other secret-shaped material from a
// provider transport error before it is wrapped, persisted, or returned
// to a client. It is the generalised successor to the LLM package's
// former RedactProviderError.
//
// Two layers:
//
//  1. If the chain contains a *url.Error, its URL field is rewritten to
//     drop the query string and fragment (where the inline `?key=` auth
//     material lives). The *url.Error value is mutated in place because
//     Go's error-wrapping convention gives no portable way to rebuild the
//     same chain with a substituted leaf — every downstream
//     errors.As(_, &urlErr) caller should see the scrubbed URL too, which
//     is the safer default for a security-sensitive scrubber.
//
//  2. The rendered error string is then run through String as
//     defense-in-depth, catching any non-*url.Error node that echoed a
//     secret into its own message (custom transport wrappers, DSNs,
//     Authorization headers, Bearer tokens, etc.).
//
// If no redaction is necessary the original error is returned unchanged
// so call-site errors.Is / errors.As sentinels keep matching the same
// instance. Otherwise the scrubbed message is wrapped in a *redactedError
// that exposes Unwrap so the original chain remains reachable. nil input
// returns nil so callers can wrap unconditionally.
func Error(err error) error {
	if err == nil {
		return nil
	}

	// Layer 1: scrub *url.Error.URL in place.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		urlErr.URL = redactURLString(urlErr.URL)
	}

	// Layer 2: scrub the rendered text for any secret-shaped substrings
	// that survived (or were never in) a *url.Error node.
	rendered := err.Error()
	scrubbed := String(rendered)
	if scrubbed == rendered {
		return err
	}
	return &redactedError{msg: scrubbed, cause: err}
}

// redactedError carries a scrubbed message plus the original cause so
// errors.Is / errors.As against sentinels in the original chain still
// resolve.
type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.cause }

// redactURLString returns the input URL with its query string and
// fragment stripped. A parse failure falls back to a static placeholder
// so a malformed URL cannot leak its key through a parse-error shortcut.
func redactURLString(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return urlPlaceholder
	}
	if u.RawQuery == "" && u.Fragment == "" {
		return u.String()
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
