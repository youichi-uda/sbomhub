package pkgversion

import (
	"fmt"
	"strconv"
	"strings"
)

// RPMVerCmp is rpm's rpmvercmp (rpmio/rpmvercmp.c, rpm >= 4.15 with the caret
// operator), comparing ONE version or release string:
//
//   - characters other than ASCII letters, digits, '~' and '^' are
//     separators and only delimit segments;
//   - '~' sorts before everything, including the end of the string
//     ("1.0~rc1" < "1.0");
//   - '^' sorts after the end of the string but before any further segment
//     ("1.0" < "1.0^git1" < "1.0.1");
//   - a segment is a maximal run of digits or of letters; a numeric segment
//     is newer than an alphabetic one, numeric segments compare as numbers
//     (leading zeros ignored), alphabetic ones with strcmp;
//   - when every segment compared equal, the string with segments left over
//     is newer.
//
// It reproduces rpm byte for byte, including that a non-ASCII byte is a
// separator; ParseRPMEVR refuses non-ASCII input so that this oddity never
// decides anything in this codebase.
func RPMVerCmp(a, b string) int {
	if a == b {
		return 0
	}
	one, two := a, b
	for len(one) > 0 || len(two) > 0 {
		one = strings.TrimLeftFunc(one, isRPMSeparator)
		two = strings.TrimLeftFunc(two, isRPMSeparator)

		// Tilde: sorts before everything else.
		if strings.HasPrefix(one, "~") || strings.HasPrefix(two, "~") {
			if !strings.HasPrefix(one, "~") {
				return 1
			}
			if !strings.HasPrefix(two, "~") {
				return -1
			}
			one, two = one[1:], two[1:]
			continue
		}
		// Caret: like tilde, except that the end of a string sorts BEFORE it.
		if strings.HasPrefix(one, "^") || strings.HasPrefix(two, "^") {
			if one == "" {
				return -1
			}
			if two == "" {
				return 1
			}
			if !strings.HasPrefix(one, "^") {
				return 1
			}
			if !strings.HasPrefix(two, "^") {
				return -1
			}
			one, two = one[1:], two[1:]
			continue
		}
		if one == "" || two == "" {
			break
		}

		var seg1, seg2 string
		isNum := isDigit(one[0])
		if isNum {
			seg1, one = splitRun(one, isDigit)
			seg2, two = splitRun(two, isDigit)
		} else {
			seg1, one = splitRun(one, isAlpha)
			seg2, two = splitRun(two, isAlpha)
		}
		if seg2 == "" {
			// Different segment types: numeric is newer than alphabetic.
			if isNum {
				return 1
			}
			return -1
		}
		if isNum {
			seg1 = strings.TrimLeft(seg1, "0")
			seg2 = strings.TrimLeft(seg2, "0")
			if len(seg1) != len(seg2) {
				if len(seg1) > len(seg2) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(seg1, seg2); c != 0 {
			return c
		}
	}
	if one == "" && two == "" {
		return 0
	}
	if one == "" {
		return -1
	}
	return 1
}

func isRPMSeparator(r rune) bool {
	if r >= 0x80 {
		return true // rpm's risalnum is ASCII-only
	}
	c := byte(r) //nolint:gosec // r < 0x80 was checked above: no truncation
	return !isAlnum(c) && c != '~' && c != '^'
}

func splitRun(s string, in func(byte) bool) (run, rest string) {
	i := 0
	for i < len(s) && in(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

// RPMEVR is a parsed rpm [epoch:]version-release.
type RPMEVR struct {
	Epoch int
	// HasEpoch: the epoch was stated. rpm compares a missing epoch as 0; the
	// flag lets a caller notice an SBOM that may have dropped it.
	HasEpoch bool
	Version  string
	Release  string
}

// ParseRPMEVR parses "[epoch:]version-release". The release is what follows
// the LAST '-' (as rpm's parseEVR splits it). A version or release that is
// empty or has a character outside RPM's set (letters, digits, "._+~^") is an
// error; so is an EVR without a release, because comparing a full EVR
// against a release-less one has no single answer (rpm's dependency
// comparison treats a missing release as matching any).
// maxRPMEpoch: rpm keeps the epoch as an unsigned 32-bit value (Codex M70
// R43 Low-2), unlike dpkg's signed INT_MAX.
const maxRPMEpoch = 1<<32 - 1

func ParseRPMEVR(s string) (RPMEVR, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return RPMEVR{}, fmt.Errorf("%w: empty", ErrInvalidVersion)
	}
	var e RPMEVR
	rest := s
	if i := strings.IndexByte(s, ':'); i >= 0 {
		ep := s[:i]
		if !allDigits(ep) {
			return RPMEVR{}, fmt.Errorf("%w: %q has a bad epoch", ErrInvalidVersion, s)
		}
		n, err := strconv.ParseUint(ep, 10, 64)
		if err != nil || n > maxRPMEpoch {
			return RPMEVR{}, fmt.Errorf("%w: %q epoch out of range", ErrInvalidVersion, s)
		}
		e.Epoch, e.HasEpoch = int(n), true
		rest = s[i+1:]
	}
	i := strings.LastIndexByte(rest, '-')
	if i < 0 {
		return RPMEVR{}, fmt.Errorf("%w: %q has no release", ErrInvalidVersion, s)
	}
	e.Version, e.Release = rest[:i], rest[i+1:]
	for _, part := range []struct{ name, v string }{{"version", e.Version}, {"release", e.Release}} {
		if part.v == "" {
			return RPMEVR{}, fmt.Errorf("%w: %q has an empty %s", ErrInvalidVersion, s, part.name)
		}
		for j := 0; j < len(part.v); j++ {
			c := part.v[j]
			// RPM's character set for VERSION / RELEASE (rpm-version(7)):
			// letters, digits, '.', '_', '+', '~', '^'. Anything else would be
			// a separator to rpmvercmp ("1>9" == "1.9"), Codex M70 R20 High-1.
			if !isAlnum(c) && strings.IndexByte("._+~^", c) < 0 {
				return RPMEVR{}, fmt.Errorf("%w: %q has %q in the %s", ErrInvalidVersion, s, c, part.name)
			}
		}
	}
	return e, nil
}

// Compare orders two EVRs: epoch numerically, then version, then release,
// each with RPMVerCmp (rpm's rpmVersionCompare).
func (a RPMEVR) Compare(b RPMEVR) int {
	switch {
	case a.Epoch < b.Epoch:
		return -1
	case a.Epoch > b.Epoch:
		return 1
	}
	if c := RPMVerCmp(a.Version, b.Version); c != 0 {
		return c
	}
	return RPMVerCmp(a.Release, b.Release)
}

// String renders the EVR.
func (a RPMEVR) String() string {
	if a.HasEpoch {
		return strconv.Itoa(a.Epoch) + ":" + a.Version + "-" + a.Release
	}
	return a.Version + "-" + a.Release
}

// CompareRPMEVR parses and compares two EVR strings.
func CompareRPMEVR(a, b string) (int, error) {
	ea, err := ParseRPMEVR(a)
	if err != nil {
		return 0, err
	}
	eb, err := ParseRPMEVR(b)
	if err != nil {
		return 0, err
	}
	return ea.Compare(eb), nil
}
