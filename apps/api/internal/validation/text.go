package validation

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// ErrInvalidText is the sentinel every text-validation failure in this file
// wraps. Callers map it to HTTP 400 via errors.Is; Error() is a message that
// is safe to return to the client verbatim (it never echoes the input).
//
// Why these checks exist: PostgreSQL refuses U+0000 in text, varchar and
// jsonb (SQLSTATE 22021 / 22P05), so a NUL that reaches an INSERT surfaces as
// a 500. Invalid UTF-8 never reaches the database — encoding/json silently
// replaces each invalid byte with U+FFFD — which stores something other than
// what the client sent; refusing it is the honest answer.
var ErrInvalidText = errors.New("invalid text")

type textError struct{ msg string }

func (e *textError) Error() string { return e.msg }
func (e *textError) Unwrap() error { return ErrInvalidText }

func textErrorf(format string, args ...any) error {
	return &textError{msg: fmt.Sprintf(format, args...)}
}

// nulEscape is the only JSON spelling of U+0000 inside a string: the escape
// letter must be a lower-case 'u' (RFC 8259 §7) and every hex digit is '0',
// so there is no case variant to look for.
var nulEscape = []byte(`\u0000`)

// CheckJSONText reports whether a JSON document would decode to text that
// PostgreSQL can store and that equals what the client sent: the bytes must be
// valid UTF-8, and the document must not contain U+0000, either as a raw byte
// or as the escape \u0000.
//
// It does not validate JSON syntax (the decoder does that next) and it is
// deliberately not a tokenizer: a `\u0000` is counted only when the backslash
// in front of it is itself unescaped (an odd run of backslashes), so the
// legitimate text `\\u0000` — a literal backslash followed by "u0000" — passes.
// Outside a string a backslash is a syntax error anyway, so treating it as a
// NUL there changes nothing but the message.
//
// The message describes the problem without a subject ("not valid UTF-8 ...",
// "contains a NUL character ..."); callers prefix what was checked.
//
// Cost: one utf8.Valid pass plus a bytes.Index search, both linear and
// allocation-free; the escape-run walk only runs at each `\u0000` candidate.
func CheckJSONText(b []byte) error {
	if !utf8.Valid(b) {
		return textErrorf("not valid UTF-8 (first invalid byte at offset %d)", firstInvalidUTF8(b))
	}
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return textErrorf("contains a NUL byte at offset %d; NUL is not allowed in text", i)
	}
	for off := 0; ; {
		i := bytes.Index(b[off:], nulEscape)
		if i < 0 {
			return nil
		}
		i += off
		run := 0
		for j := i; j >= 0 && b[j] == '\\'; j-- {
			run++
		}
		if run%2 == 1 {
			return textErrorf(`contains a NUL character (\u0000) at offset %d; NUL is not allowed in text`, i)
		}
		off = i + 1
	}
}

func firstInvalidUTF8(b []byte) int {
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size <= 1 {
			return i
		}
		i += size
	}
	return -1
}

// TextRule describes what one user-supplied string field may contain.
type TextRule struct {
	// Required refuses an empty or whitespace-only value.
	Required bool
	// MaxChars is the maximum length in Unicode code points — the unit
	// PostgreSQL's VARCHAR(n) counts in a UTF-8 database. 0 means unlimited.
	MaxChars int
	// SingleLine also refuses every other C0 control character (U+0001-U+001F,
	// including tab and newline) and DEL. For names and identifiers. Without
	// it tab, LF and CR are allowed and the remaining C0 controls are still
	// refused.
	SingleLine bool
}

// CheckTextField validates one user-supplied string field. The returned error
// wraps ErrInvalidText and names the field, e.g.
// `name must be at most 255 characters (got 300)`.
//
// Every value is refused when it is not valid UTF-8 or contains U+0000, whatever
// the rule: PostgreSQL cannot store the NUL, and a string that arrived through a
// path other than a JSON body (a multipart form value, say) never had its
// invalid bytes replaced by the JSON decoder.
func CheckTextField(field, value string, rule TextRule) error {
	if !utf8.ValidString(value) {
		return textErrorf("%s is not valid UTF-8", field)
	}
	if rule.Required && strings.TrimSpace(value) == "" {
		return textErrorf("%s is required", field)
	}
	for _, r := range value {
		switch {
		case r == 0:
			return textErrorf("%s must not contain a NUL character", field)
		case r == '\t' || r == '\n' || r == '\r':
			if rule.SingleLine {
				return textErrorf("%s must not contain control characters (tab, newline)", field)
			}
		case r < 0x20 || r == 0x7f:
			return textErrorf("%s must not contain control characters (U+%04X)", field, r)
		}
	}
	if rule.MaxChars > 0 {
		if n := utf8.RuneCountInString(value); n > rule.MaxChars {
			return textErrorf("%s must be at most %d characters (got %d)", field, rule.MaxChars, n)
		}
	}
	return nil
}
