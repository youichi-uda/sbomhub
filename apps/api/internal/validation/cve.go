// Package validation holds the canonical input validators shared across the
// API boundary. It is a leaf package (stdlib only) so any handler, service or
// client can depend on it without introducing an import cycle.
package validation

import (
	"errors"
	"regexp"
	"strings"
)

// ErrInvalidCVEID is the sentinel returned by ValidateCVEID when the input is
// not a well-formed CVE identifier. Callers map it to HTTP 400 via errors.Is.
var ErrInvalidCVEID = errors.New("invalid CVE ID format")

// cveIDPattern is the single source of truth for the CVE ID grammar.
//
// Anchored (^...$) so the whole string must match — a partial match inside a
// larger, possibly hostile string (e.g. "CVE-2021-44228 OR 1=1") is rejected.
//
// The sequence part is `\d{4,}` — FOUR OR MORE digits, unbounded. This is
// deliberate and load-bearing: real modern CVEs exceed four sequence digits
// (CVE-2021-44228 is 5-digit; 7-digit IDs like CVE-2023-1234567 exist). A
// `\d{4}$` (exactly four) pattern would wrongly reject valid CVEs and MUST NOT
// be used.
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// ValidateCVEID normalizes and validates a CVE identifier.
//
// It trims surrounding whitespace and upper-cases the input (so "cve-2021-44228"
// is accepted), then matches it against the anchored canonical grammar. On
// success it returns the normalized (trimmed, upper-cased) ID and a nil error;
// on failure it returns ("", ErrInvalidCVEID).
func ValidateCVEID(s string) (string, error) {
	normalized := strings.ToUpper(strings.TrimSpace(s))
	if !cveIDPattern.MatchString(normalized) {
		return "", ErrInvalidCVEID
	}
	return normalized, nil
}

// IsValidCVEID reports whether s is a well-formed CVE identifier after the same
// trim + upper-case normalization ValidateCVEID applies. Convenience predicate
// for call sites that do not need the normalized value.
func IsValidCVEID(s string) bool {
	_, err := ValidateCVEID(s)
	return err == nil
}
