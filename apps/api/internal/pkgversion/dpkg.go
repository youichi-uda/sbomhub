// Package pkgversion compares distribution package versions with the
// distribution's own ordering: dpkg (Debian, Ubuntu) and rpm (AlmaLinux, Rocky
// Linux, RHEL, Fedora, SUSE).
//
// # Why this exists (M70)
//
// The NVD CPE matcher (service/nvd_cpe.go, M60) compares only plain
// dotted-numeric versions; a distro package version such as "1.1.1k-1" or
// "1:3.0.7-27.el9" is never plain, so every CVE on a distro package was kept as
// nvd_cpe_unverified. The distro's own fixed-version data is written in the
// distro's own version syntax, and comparing against it needs the distro's own
// ordering. A version these functions cannot parse is an ERROR, never an
// ordering: the caller then keeps the M60 label (a comparator gap costs a
// label, never a finding).
//
// Standard library only. The candidate modules (knqyf263/go-deb-version and
// knqyf263/go-rpm-version, MIT) have no tagged release, so a pinned version
// would be a pseudo-version of an untagged branch; each algorithm is under a
// hundred lines and is pinned here by the upstream projects' own test vectors.
package pkgversion

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrInvalidVersion is wrapped by every parse error.
var ErrInvalidVersion = errors.New("pkgversion: invalid version")

// Dpkg is a parsed Debian package version: [epoch:]upstream_version[-debian_revision]
// (Debian Policy §5.6.12).
type Dpkg struct {
	Epoch int
	// HasEpoch: the string carried an explicit epoch ("0:1.0" or "1:1.0").
	// The comparison treats a missing epoch as 0, exactly as dpkg does; the
	// flag lets a caller notice when only ONE side states a non-zero epoch,
	// which is how an SBOM tool that dropped the epoch would look.
	HasEpoch bool
	Upstream string
	// Revision is "" when the version has none; dpkg compares that equal to
	// "0" (Policy: "absence of the debian_revision is equivalent to a
	// debian_revision of 0").
	Revision string
}

// maxEpoch mirrors dpkg's bound (parseversion rejects an epoch > INT_MAX).
const maxEpoch = 1<<31 - 1

// ParseDpkg parses a version with dpkg's own rules (lib/dpkg/parsehelp.c
// parseversion): surrounding blanks are ignored; the epoch is the digits
// before the FIRST ':'; the revision is what follows the LAST '-'; the upstream
// version must be non-empty and start with a digit; upstream characters are
// [A-Za-z0-9.+~-:] and revision characters [A-Za-z0-9.+~]. Anything else is an
// error, including embedded blanks and non-ASCII.
func ParseDpkg(s string) (Dpkg, error) {
	s = strings.Trim(s, " \t\n\r")
	if s == "" {
		return Dpkg{}, fmt.Errorf("%w: empty", ErrInvalidVersion)
	}
	if strings.ContainsAny(s, " \t\n\r") {
		return Dpkg{}, fmt.Errorf("%w: %q contains a blank", ErrInvalidVersion, s)
	}
	var v Dpkg
	rest := s
	if i := strings.IndexByte(s, ':'); i >= 0 {
		ep := s[:i]
		if ep == "" || !allDigits(ep) {
			return Dpkg{}, fmt.Errorf("%w: %q has a bad epoch", ErrInvalidVersion, s)
		}
		n, err := strconv.ParseUint(ep, 10, 64)
		if err != nil || n > maxEpoch {
			return Dpkg{}, fmt.Errorf("%w: %q epoch out of range", ErrInvalidVersion, s)
		}
		v.Epoch, v.HasEpoch = int(n), true
		rest = s[i+1:]
		if rest == "" {
			return Dpkg{}, fmt.Errorf("%w: %q has nothing after the epoch", ErrInvalidVersion, s)
		}
	}
	v.Upstream = rest
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		v.Upstream, v.Revision = rest[:i], rest[i+1:]
		if v.Revision == "" {
			return Dpkg{}, fmt.Errorf("%w: %q has an empty revision", ErrInvalidVersion, s)
		}
	}
	if v.Upstream == "" {
		return Dpkg{}, fmt.Errorf("%w: %q has an empty upstream version", ErrInvalidVersion, s)
	}
	if !isDigit(v.Upstream[0]) {
		return Dpkg{}, fmt.Errorf("%w: %q does not start with a digit", ErrInvalidVersion, s)
	}
	for i := 0; i < len(v.Upstream); i++ {
		c := v.Upstream[i]
		if !isAlnum(c) && strings.IndexByte(".-+~:", c) < 0 {
			return Dpkg{}, fmt.Errorf("%w: %q has %q in the upstream version", ErrInvalidVersion, s, c)
		}
	}
	for i := 0; i < len(v.Revision); i++ {
		c := v.Revision[i]
		if !isAlnum(c) && strings.IndexByte(".+~", c) < 0 {
			return Dpkg{}, fmt.Errorf("%w: %q has %q in the revision", ErrInvalidVersion, s, c)
		}
	}
	return v, nil
}

// Compare orders two parsed versions: epoch numerically, then the upstream
// version, then the revision, each with dpkg's verrevcmp.
func (a Dpkg) Compare(b Dpkg) int {
	switch {
	case a.Epoch < b.Epoch:
		return -1
	case a.Epoch > b.Epoch:
		return 1
	}
	if c := verrevcmp(a.Upstream, b.Upstream); c != 0 {
		return c
	}
	return verrevcmp(a.Revision, b.Revision)
}

// String renders the version as dpkg would print it.
func (a Dpkg) String() string {
	var b strings.Builder
	if a.HasEpoch {
		b.WriteString(strconv.Itoa(a.Epoch))
		b.WriteByte(':')
	}
	b.WriteString(a.Upstream)
	if a.Revision != "" {
		b.WriteByte('-')
		b.WriteString(a.Revision)
	}
	return b.String()
}

// CompareDpkg parses and compares two version strings.
func CompareDpkg(a, b string) (int, error) {
	va, err := ParseDpkg(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseDpkg(b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}

// dpkgOrder is dpkg's order(): a digit sorts as 0 (the digit runs are compared
// separately), a letter as itself, '~' before everything including the end of
// the string, any other character after all letters, and the end of the
// string as 0.
func dpkgOrder(c byte, end bool) int {
	switch {
	case end:
		return 0
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

// verrevcmp is dpkg's lib/dpkg/version.c verrevcmp: alternate non-digit runs
// (compared character by character with dpkgOrder) and digit runs (compared
// numerically, leading zeros ignored).
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			var ac, bc int
			if i < len(a) {
				ac = dpkgOrder(a[i], false)
			} else {
				ac = dpkgOrder(0, true)
			}
			if j < len(b) {
				bc = dpkgOrder(b[j], false)
			} else {
				bc = dpkgOrder(0, true)
			}
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return s != ""
}
