package service

// CPE-based NVD matching (M60).
//
// # Why
//
// Before M60 both scanners matched by keyword. Measured against the live NVD
// API on 2026-11-08 for a Syft SBOM of realistic components, NVD's
// keywordSearch on "<name> <version>" (which ANDs the terms) returned 0
// records for log4j-core 2.14.1 (Log4Shell missed), tomcat-embed-core 9.0.30,
// golang.org/x/net v0.7.0, gin v1.7.0, openssl 1.1.1k-1 (Debian) and the
// kernel: the version string has to appear in the CVE DESCRIPTION, and it
// rarely does. A CPE query asks NVD's affected-configuration data instead.
//
// # How a component is matched
//
//  1. Up to nvdMaxCPECandidates distinct part:vendor:product candidates are
//     taken from the CPE names the SBOM declared, in SBOM order. Syft's
//     FIRST candidate is often not NVD's product (measured: log4j-core ->
//     apache:log4j-core, NVD uses apache:log4j, Syft's third candidate).
//  2. For a candidate with a plain dotted-numeric version, NVD is asked
//     `cpeName=<part:vendor:product:version:*...>` (exact name, NVD evaluates
//     the version ranges server-side); the walk pages exactly like the
//     keyword walk (same truncation and page-identity checks; its own page
//     budget, nvdCPEMaxPagesPerComponent, sized for a full kernel).
//  3. Every returned CVE is VERIFIED locally against its configurations
//     (verifyCPEMatch). Measured: cpeName for openssl 1.1.1k returned 47
//     CVEs, 5 of them only because openssl appears as a vulnerable=false
//     PLATFORM in an AND configuration (Mutt CVE-2009-1390 etc., httpd
//     CVE-2019-0190). Those are not openssl vulnerabilities.
//     A VERSION comparison may exclude a CVE only when the component version
//     and every version the criterion involves are plain dotted-numeric (M60
//     decision 1, option B; criterionContains). Anything else keeps the CVE
//     as nvd_cpe_unverified. Measured on log4j: NVD's own cpeName answer for
//     "2.0-beta9" omitted Log4Shell, so for non-plain versions neither a
//     local comparator nor NVD's server-side one is trusted to exclude.
//  4. A cpeName answer of ZERO is never taken as "clean": NVD answers 0, with
//     no error, for a product it has never heard of (measured:
//     apache:log4j-core), for a known product whose version is unaffected,
//     AND for a version written differently from NVD's encoding of the
//     release (2.0-beta9 vs NVD's 2.0 + update beta9; Codex M60 R10). The
//     product-level walk (`virtualMatchString=cpe:2.3:part:vendor:product`),
//     verified locally, decides instead: zero records -> unknown product,
//     try the next candidate; otherwise the locally verified records are the
//     answer. Versions that are not plain dotted numbers skip the cpeName
//     query altogether (lookupCPECandidate).
//  5. No candidate names a product NVD knows -> fall back to the keyword
//     search, and the links are labelled nvd_keyword (low confidence). A wrong
//     CPE therefore never turns into a silent "clean".

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/sbomhub/sbomhub/internal/cache"
	"github.com/sbomhub/sbomhub/internal/model"
)

// nvdMaxCPECandidates bounds how many distinct part:vendor:product
// candidates of ONE component are tried. Each unknown candidate costs two
// requests (the cpeName query and the product probe). Measured on Syft 1.46.0
// output (2026-11-08): maven / go packages carry 1-3 candidates and the NVD
// product was within the first 3 in every case; Debian packages carry up to
// 18, all generated from the package name (linux-image-5.10.0-8-amd64), none
// of them an NVD product — trying all 18 would be 36 wasted requests.
const nvdMaxCPECandidates = 3

// cpeName is the parsed, UNESCAPED form of a CPE name's leading attributes.
type cpeName struct {
	Part    string
	Vendor  string
	Product string
	Version string
	Update  string
}

// parseCPE parses a CPE 2.3 formatted string (`cpe:2.3:a:vendor:product:...`,
// backslash-escaped) or a CPE 2.2 URI (`cpe:/a:vendor:product:...`,
// percent-encoded). Attribute values are returned unescaped and lower-cased.
func parseCPE(s string) (cpeName, bool) {
	s = strings.TrimSpace(s)
	var fields []string
	// The scheme is case-insensitive (SPDX 2.2's CPE 2.2 locator pattern
	// accepts "cPE:/A:..."; Codex M60 R2 Medium-2). Attribute values are
	// lower-cased below anyway.
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "cpe:2.3:"):
		// A formatted string has exactly 11 attributes and no dangling
		// escape; a truncated one is not a CPE (Codex M60 R8 Medium) — as
		// a criterion it would read as "every version".
		var ok bool
		fields, ok = splitCPE23(s[len("cpe:2.3:"):])
		if !ok || len(fields) != 11 {
			return cpeName{}, false
		}
		for _, f := range fields {
			if f == "" { // no empty attributes in a formatted string (Codex M60 R13 Medium)
				return cpeName{}, false
			}
		}
	case strings.HasPrefix(lower, "cpe:/"):
		raw := strings.Split(s[len("cpe:/"):], ":")
		if len(raw) < 3 || len(raw) > 7 { // part:vendor:product[:version[:update[:edition[:language]]]]
			return cpeName{}, false
		}
		for _, f := range raw {
			// %01 / %02 are the CPE 2.2 URI wildcards ('?' and '*'): not one
			// concrete product (Codex M60 R17 Medium).
			lf := strings.ToLower(f)
			if strings.Contains(lf, "%01") || strings.Contains(lf, "%02") {
				return cpeName{}, false
			}
			if lf == "%2a" || lf == "%2d" { // encoded lone "*" / "-": literal
				u, _ := url.PathUnescape(f)
				fields = append(fields, cpeLiteralMark+u)
				continue
			}
			u, err := url.PathUnescape(f)
			if err != nil {
				return cpeName{}, false
			}
			fields = append(fields, u)
		}
	default:
		return cpeName{}, false
	}
	get := func(i int) string {
		if i < len(fields) {
			return strings.ToLower(fields[i])
		}
		return ""
	}
	n := cpeName{Part: get(0), Vendor: get(1), Product: get(2), Version: get(3), Update: get(4)}
	if n.Part != "a" && n.Part != "o" && n.Part != "h" {
		return cpeName{}, false
	}
	if !cpeConcrete(n.Vendor) || !cpeConcrete(n.Product) {
		return cpeName{}, false
	}
	return n, true
}

// splitCPE23 splits a CPE 2.3 formatted string body on unescaped colons and
// removes the backslash escapes. ok is false for a dangling escape.
//
// It follows the NIST CPE 2.3 formatted-string rules strictly enough that a
// malformed name cannot turn into a DIFFERENT valid identity (Codex M60 R17
// Medium): a backslash may only quote a non-alphanumeric character other than
// '_'; unquoted characters are limited to letters, digits, '_', '-', '.';
// and an unquoted '*' or '?' is accepted only as the whole value ANY ("*").
// A partial wildcard ("widget*") names many products, not one, so it is
// rejected rather than queried as a literal.
func splitCPE23(s string) ([]string, bool) {
	var out []string
	var b strings.Builder
	esc := false
	unquotedStar := false // this field holds an UNQUOTED '*'
	quotedRunes := 0      // escaped characters in this field
	endField := func() bool {
		v := b.String()
		if unquotedStar && v != "*" {
			return false // a partial wildcard such as "widget*"
		}
		if quotedRunes == 1 && (v == "*" || v == "-") {
			// A QUOTED lone "*" / "-" is a literal value, not ANY / NA
			// (Codex M60 R19 Low).
			v = cpeLiteralMark + v
		}
		out = append(out, v)
		b.Reset()
		unquotedStar = false
		quotedRunes = 0
		return true
	}
	for _, r := range s {
		switch {
		case esc:
			if r < 0x80 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_') {
				return nil, false // "\q": an illegal escape
			}
			b.WriteRune(r)
			esc = false
			quotedRunes++
		case r == '\\':
			esc = true
		case r == ':':
			if !endField() {
				return nil, false
			}
		case r < 0x80 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.'):
			b.WriteRune(r)
		case r == '*':
			unquotedStar = true
			b.WriteRune(r)
		default:
			return nil, false // unquoted punctuation or '?'
		}
	}
	if esc || !endField() {
		return nil, false
	}
	return out, true
}

// cpeLiteralMark prefixes a field that was a QUOTED lone "*" or "-": a
// literal value, distinct from the logical ANY / NA. escapeCPE23 restores the
// quoting.
const cpeLiteralMark = "\x00"

// cpeConcrete is false for the logical values ANY ("*") and NA ("-") and for
// an empty attribute.
func cpeConcrete(v string) bool {
	return v != "" && v != "*" && v != "-"
}

// escapeCPE23 re-escapes an attribute value for a CPE 2.3 formatted string:
// everything other than letters, digits, '_', '-' and '.' is backslash-quoted.
func escapeCPE23(v string) string {
	if strings.HasPrefix(v, cpeLiteralMark) {
		return `\` + v[len(cpeLiteralMark):] // a quoted lone "*" or "-"
	}
	var b strings.Builder
	for _, r := range v {
		if r < 0x80 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.') {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('\\')
		b.WriteRune(r)
	}
	return b.String()
}

// cpeCandidate is one part:vendor:product to try for a component, with the
// version the component will be matched at.
type cpeCandidate struct {
	part, vendor, product string
	version               string
	// update is the CPE `update` attribute when the SBOM's CPE pinned one
	// ("beta9" in log4j:2.0:beta9), else "". It is part of the release the
	// CPE names (Codex M60 R1 High-1).
	update string
	// updateNA: the SBOM's CPE said update NA ("2.0:-"), i.e. the final
	// release. update "" with updateNA false is ANY: the release is not
	// pinned (Codex M60 R11 High).
	updateNA bool
	// raw is the version as the SBOM stated it, before normaliseCPEVersion
	// (no "v", distro revision or "+build" stripping). Whether a local
	// comparison may EXCLUDE a CVE is decided on this value: see plain.
	raw string
}

// plain reports whether the candidate's version may take part in a local
// comparison that EXCLUDES a CVE (M60 decision 1, option B): the version as the
// SBOM stated it is plain dotted-numeric (isPlainVersion) and the CPE pins no
// update. Distro revisions, "+build" metadata, letters and qualifiers all make
// it non-plain, however obvious their ordering may look — every scheme-specific
// ordering rule tried in Codex M60 R2-R13 had another counter-example.
func (c cpeCandidate) plain() bool {
	return c.update == "" && isPlainVersion(c.raw)
}

// isPlainVersion: digits separated by single '.', optionally after one leading
// 'v'/'V'. Nothing else.
func isPlainVersion(v string) bool {
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') {
		v = v[1:]
	}
	if v == "" {
		return false
	}
	prevDot := true
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			prevDot = false
		case r == '.' && !prevDot:
			prevDot = true
		default:
			return false
		}
	}
	return !prevDot
}

// effectiveVersion is the release the candidate names, in the single-string
// form SBOM versions use: "2.0-beta9" for version 2.0 + update beta9.
func (c cpeCandidate) effectiveVersion() string {
	if c.update != "" {
		return c.version + "-" + c.update
	}
	return c.version
}

// query is the exact CPE name sent as cpeName. Every attribute after the
// version is ANY: measured on 2026-11-08, cpeName for lodash 4.17.20 with
// target_sw=node.js and with target_sw=* both returned the same 5 CVEs, and
// a wildcard cannot exclude a criterion the SBOM's guess got wrong.
func (c cpeCandidate) query() string {
	update := "*"
	if c.update != "" {
		update = escapeCPE23(c.update)
	}
	return "cpe:2.3:" + c.part + ":" + escapeCPE23(c.vendor) + ":" + escapeCPE23(c.product) + ":" +
		escapeCPE23(c.version) + ":" + update + ":*:*:*:*:*:*"
}

// identity is what the candidate's answer depends on: the query plus the
// update tri-state. NA and ANY send the same query but verify differently
// (Codex M60 R11), so they must not share a cache entry or a work item
// (Codex M60 R12 High).
//
// The comparison mode is part of it too (Codex M60 R14 High-1): plain "2.31"
// and distro "2.31-13" send the same query, but only the plain one may
// exclude by comparison, so its verified answer is narrower.
func (c cpeCandidate) identity() string {
	id := c.query()
	if c.updateNA {
		id += "|na"
	}
	if !c.plain() {
		id += "|nonplain"
	}
	return id
}

// productQuery is the version-less virtualMatchString used to ask whether NVD
// knows the product at all.
func (c cpeCandidate) productQuery() string {
	return "cpe:2.3:" + c.part + ":" + escapeCPE23(c.vendor) + ":" + escapeCPE23(c.product)
}

// productKey is the candidate's product identity for dedupe and for the
// negative cache. It is the ESCAPED form (productQuery), not the unescaped
// fields joined with ':' — a quoted colon is valid CPE syntax and NVD has
// such products, so the joined form let `mailcow\:mailcow` + `_dockerized`
// and `mailcow` + `mailcow\:_dockerized` share one identity, and one tenant
// could cache "unknown product" for another's (Codex M60 R4 High).
func (c cpeCandidate) productKey() string { return c.productQuery() }

// distroPurlTypes are purl types whose versions carry a distro revision (and
// possibly an epoch) on top of the upstream version.
var distroPurlTypes = map[string]bool{"deb": true, "rpm": true, "apk": true, "alpm": true}

// purlType returns the purl's type ("maven", "deb", ...) or "".
func purlType(purl string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(purl), "pkg:")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, "/@?#"); i >= 0 {
		rest = rest[:i]
	}
	return strings.ToLower(rest)
}

// isDistroComponent reports whether the component is a distro package.
func isDistroComponent(purl string) bool { return distroPurlTypes[purlType(purl)] }

// normaliseCPEVersion turns an SBOM version into the version NVD's
// configurations are written in.
//
//   - A leading "v" before a digit is dropped (Go modules). Measured: cpeName
//     golang:networking:v0.7.0 -> 0 CVEs, :0.7.0 -> 2.
//   - For a distro package the epoch ("1:") and the distro revision (after the
//     LAST "-": Debian "1.1.1k-1+deb11u2", RPM "2.17-326.el7", Alpine
//     "1.1.1k-r0") are dropped, leaving the upstream version. This is what
//     makes a distro package matchable at all, and it is also why such links
//     are labelled nvd_cpe_distro: a backported fix does not change the
//     upstream version.
func normaliseCPEVersion(v string, distro bool) string {
	v = strings.TrimSpace(v)
	// Build metadata takes no part in ordering (compareVersions ignores it)
	// and names no CPE, so it is not sent in the query either: Go's
	// "v2.0.0+incompatible" is NVD's 2.0.0 (Codex M60 R9 High-1).
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if distro {
		if i := strings.Index(v, ":"); i > 0 && isDigits(v[:i]) {
			v = v[i+1:]
		}
		if i := strings.LastIndex(v, "-"); i > 0 {
			v = v[:i]
		}
	}
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	return v
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// cpeCandidates derives the candidates for one component. The version is the
// CPE's own version attribute when it is concrete (that is what the SBOM
// author asserted), otherwise the component version; either way normalised.
// A candidate without any version is dropped — a version-less cpeName would
// match every version of the product.
func cpeCandidates(cpes []string, compVersion, purl string) []cpeCandidate {
	distro := isDistroComponent(purl)
	var out []cpeCandidate
	seen := make(map[string]struct{})
	for _, raw := range cpes {
		n, ok := parseCPE(raw)
		if !ok {
			continue
		}
		if n.Version == "-" {
			// NA: the SBOM asserts a version-less thing. Substituting the
			// component version would invent a CPE it did not assert
			// (Codex M60 R6 Medium).
			continue
		}
		// raw is the version exactly as stated — whitespace included — and
		// decides whether a comparison may exclude (Codex M60 R19 Medium);
		// only the query value is trimmed.
		v, raw, update, updateNA := strings.TrimSpace(compVersion), compVersion, "", false
		if cpeConcrete(n.Version) {
			v, raw = n.Version, n.Version
		}
		// The update attribute is the SBOM's assertion whatever the version
		// attribute says: "widget:*:beta" + component version 2.0 is 2.0 +
		// beta (Codex M60 R15 High).
		if cpeConcrete(n.Update) {
			update = n.Update
		}
		updateNA = n.Update == "-"
		v = normaliseCPEVersion(v, distro)
		if !cpeConcrete(v) {
			continue
		}
		c := cpeCandidate{part: n.Part, vendor: n.Vendor, product: n.Product, version: strings.ToLower(v), update: update, updateNA: updateNA, raw: raw}
		if _, dup := seen[c.productKey()]; dup {
			continue
		}
		seen[c.productKey()] = struct{}{}
		out = append(out, c)
		if len(out) == nvdMaxCPECandidates {
			break
		}
	}
	return out
}

// NVD configuration structures (CVE API 2.0 `configurations`).
type NVDConfiguration struct {
	Operator string          `json:"operator"`
	Negate   bool            `json:"negate"`
	Nodes    []NVDConfigNode `json:"nodes"`
}

type NVDConfigNode struct {
	Operator string        `json:"operator"`
	Negate   bool          `json:"negate"`
	CpeMatch []NVDCPEMatch `json:"cpeMatch"`
}

type NVDCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
	// vulnerableMissing: the decoded JSON had no `vulnerable` (or null).
	// Only an EXPLICIT false is platform evidence that may drop a CVE
	// (Codex M60 R14 High-2); a missing one is undecidable.
	vulnerableMissing bool
}

// UnmarshalJSON records whether `vulnerable` was present.
func (m *NVDCPEMatch) UnmarshalJSON(b []byte) error {
	type plain NVDCPEMatch
	var aux struct {
		plain
		Vulnerable *bool `json:"vulnerable"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*m = NVDCPEMatch(aux.plain)
	m.Vulnerable = aux.Vulnerable != nil && *aux.Vulnerable
	m.vulnerableMissing = aux.Vulnerable == nil
	return nil
}

// cpeVerdict is the outcome of checking one CVE against one candidate.
type cpeVerdict int

const (
	// cpeRejected: NVD's configurations hold no vulnerable criterion for this
	// product whose version spec contains the component version.
	cpeRejected cpeVerdict = iota
	// cpeMatched: at least one vulnerable criterion for this product contains
	// the version.
	cpeMatched
	// cpeUndecidable: a vulnerable criterion for this product exists but the
	// version comparison could not be decided locally (unparseable or
	// incomparable versions). NVD's own server-side evaluation returned the
	// CVE, so it is KEPT — dropping it would turn our comparator's limits
	// into silent false negatives.
	cpeUndecidable
)

// verifyCPEMatch checks a CVE NVD returned for a cpeName query against the
// CVE's own configurations.
//
// Only vulnerable=true criteria count: a vulnerable=false criterion is a
// platform the vulnerable thing runs ON (measured: 5 of 47 openssl 1.1.1k
// answers). AND configurations ("X running on Y") count when the component is
// the vulnerable X — the platform half cannot be known from an SBOM, so
// requiring it would drop real findings. Negated nodes/configurations are
// never used as positive evidence.
//
// Rejection requires POSITIVE evidence (Codex M60 R1 High-2): a criterion for
// this product that is not vulnerable, or whose version spec excludes the
// component. A CVE whose configurations are absent, or never mention the
// product, cannot be verified either way — NVD's own cpeName evaluation
// selected it, so it is kept as undecidable rather than silently dropped (and
// then cached as a clean answer).
func verifyCPEMatch(cve NVDCVE, c cpeCandidate) cpeVerdict {
	undecidable := false
	sawProduct := false
	sawNegatedProduct := false
	for _, cfg := range cve.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CpeMatch {
				crit, ok := parseCPE(m.Criteria)
				if !ok || crit.Part != c.part || crit.Vendor != c.vendor || crit.Product != c.product {
					continue
				}
				if cfg.Negate || node.Negate {
					sawNegatedProduct = true
					continue
				}
				sawProduct = true
				if m.vulnerableMissing {
					undecidable = true
					continue
				}
				if !m.Vulnerable {
					continue
				}
				switch v := criterionContains(crit, m, c); v {
				case cpeMatched:
					return cpeMatched
				case cpeUndecidable:
					undecidable = true
				}
			}
		}
	}
	switch {
	case undecidable:
		return cpeUndecidable
	case !sawProduct && !sawNegatedProduct:
		// The configurations never name the product: no evidence either way.
		return cpeUndecidable
	}
	// Named only as a vulnerable=false platform, or only under negated
	// branches ("NOT running on X"): configuration evidence that this is not
	// the product's own vulnerability (Codex M60 R21 High).
	return cpeRejected
}

// criterionContains decides whether one vulnerable criterion covers the
// candidate.
//
// M60 decision 1 (option B): a CVE may be EXCLUDED by a version comparison only
// when the component version and every version the criterion involves are
// plain dotted-numeric. Any other comparison is undecidable — the CVE is kept
// as nvd_cpe_unverified and the answer is not cached. A gap in the comparison
// can therefore never drop a CVE; it can only lower a label.
func criterionContains(crit cpeName, m NVDCPEMatch, c cpeCandidate) cpeVerdict {
	switch crit.Update {
	case "", "*", "-":
	default:
		// The criterion pins an update ("2.0:beta9", "*:beta"): not plain,
		// whatever its version attribute (Codex M60 R14 Medium).
		return cpeUndecidable
	}
	if crit.Version == "-" {
		// NA: a version-less thing. Not a comparison this code may decide.
		return cpeUndecidable
	}
	hasAnyBound := m.VersionStartIncluding != "" || m.VersionStartExcluding != "" ||
		m.VersionEndIncluding != "" || m.VersionEndExcluding != ""
	if cpeConcrete(crit.Version) {
		if hasAnyBound {
			// A concrete version AND range bounds: every version involved
			// counts, and deciding on the version attribute alone would
			// ignore the bounds (Codex M60 R16 Medium).
			return cpeUndecidable
		}
		// update is ANY or NA here. NA names the final release; a candidate
		// with update ANY and a plain version is taken to BE the final
		// release and matches (Codex M60 R12 Medium-1, declined: the
		// inclusive direction; a pre-release writes its qualifier into the
		// version string, which then is not plain and so is undecidable).
		cmp, ok := compareVersions(c.raw, crit.Version)
		switch {
		case !ok || !c.plain():
			return cpeUndecidable
		case cmp == 0:
			return cpeMatched
		}
		return cpeRejected
	}
	// version "*": every version, or a range.
	bounds := []struct {
		v    string
		pass func(int) bool
	}{
		{m.VersionStartIncluding, func(c int) bool { return c >= 0 }},
		{m.VersionStartExcluding, func(c int) bool { return c > 0 }},
		{m.VersionEndIncluding, func(c int) bool { return c <= 0 }},
		{m.VersionEndExcluding, func(c int) bool { return c < 0 }},
	}
	hasBound := false
	for _, b := range bounds {
		if b.v == "" {
			continue
		}
		hasBound = true
		if !isPlainVersion(b.v) {
			return cpeUndecidable // every bound involved must be plain
		}
	}
	if !hasBound {
		if crit.Update == "-" && (c.update != "" || (!c.updateNA && !c.plain())) {
			// "*:-" is every FINAL release; it does not prove anything about
			// a candidate pinning an update (Codex M60 R15 Medium), nor about
			// a non-plain version not explicitly NA — whether "2.0-beta9" is
			// a final release is not decidable (Codex M60 R24 Medium).
			return cpeUndecidable
		}
		return cpeMatched // all versions: no comparison involved
	}
	if !c.plain() {
		return cpeUndecidable
	}
	for _, b := range bounds {
		if b.v == "" {
			continue
		}
		cmp, ok := compareVersions(c.raw, b.v)
		if !ok {
			return cpeUndecidable
		}
		if !b.pass(cmp) {
			return cpeRejected
		}
	}
	return cpeMatched
}

// compareVersions orders two PLAIN dotted-numeric versions (isPlainVersion),
// treating missing trailing segments as zero ("1.0" == "1.0.0"). ok is false
// for anything else: this function is the only place a version comparison
// can exclude a CVE, so it decides nothing it cannot decide for every scheme.
func compareVersions(a, b string) (int, bool) {
	if !isPlainVersion(a) || !isPlainVersion(b) {
		return 0, false
	}
	trim := func(v string) []string {
		if v[0] == 'v' || v[0] == 'V' {
			v = v[1:]
		}
		return strings.Split(v, ".")
	}
	sa, sb := trim(a), trim(b)
	for i := 0; i < len(sa) || i < len(sb); i++ {
		x, y := "0", "0"
		if i < len(sa) {
			x = sa[i]
		}
		if i < len(sb) {
			y = sb[i]
		}
		if c := compareNumeric(x, y); c != 0 {
			return c, true
		}
	}
	return 0, true
}

func compareNumeric(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// nvdCPECacheName / nvdNoCPECacheName are the cache identities of the CPE
// path. Both hash a length-prefixed input like nvdCacheName (same injectivity
// argument), and their schema prefixes ("m60c." / "m60n.") share no prefix
// with each other or with the keyword path's "m55.", so the three key spaces
// are disjoint within this build. Older builds compose every key as
// `NVDCachePrefix + nvdCacheName(...)` = "nvdv2:m55.<hex>" (M55..M59) or use
// the legacy "nvd:vuln:" prefix (pre-M55), so neither can write a key here.
const (
	nvdCPECacheSchema   = "m60d." // m60c. keyed answers without the comparison mode (R14)
	nvdNoCPECacheSchema = "m60n."
)

// nvdCPECacheName keys a VERIFIED answer for one candidate at one version.
// The entry holds only CVEs that passed verifyCPEMatch; an EMPTY entry means
// "NVD knows this product and none of its CVEs covers this version".
func nvdCPECacheName(c cpeCandidate) string {
	q := c.identity()
	sum := sha256.Sum256([]byte(strconv.Itoa(len(q)) + ":" + q))
	return nvdCPECacheSchema + hex.EncodeToString(sum[:])
}

// nvdNoCPECacheName keys the negative fact "NVD's configurations name no
// CVE for this part:vendor:product". Its only effect is to skip the
// candidate, which ends in the keyword fallback — a poisoned or stale entry
// lowers a component's match CONFIDENCE, it cannot make it read as clean.
func nvdNoCPECacheName(c cpeCandidate) string {
	k := c.productKey()
	sum := sha256.Sum256([]byte(strconv.Itoa(len(k)) + ":" + k))
	return nvdNoCPECacheSchema + hex.EncodeToString(sum[:])
}

// nvdWorkKey is the deduplication key of one component: everything its lookup
// depends on — the name and version (keyword fallback), the CPE candidates
// ACTUALLY tried, in order, and whether it is a distro package. Built from the
// candidates rather than the stored CPE list, so components that differ only
// in CPEs past the candidate cap share one lookup (Codex M60 R2 Low-1).
func nvdWorkKey(name, version string, cpes []string, purl string) nvdComponentKey {
	var b strings.Builder
	for _, c := range cpeCandidates(cpes, version, purl) {
		q := c.identity()
		b.WriteString(strconv.Itoa(len(q)))
		b.WriteByte(':')
		b.WriteString(q)
	}
	// Distro-ness only changes the lookup when there are candidates (it
	// selects the version normalisation and the nvd_cpe_distro label); a
	// keyword-only item is the same walk either way (Codex M60 R3 Low).
	return nvdComponentKey{Name: name, Version: version, CPEKey: b.String(), Distro: b.Len() > 0 && isDistroComponent(purl)}
}

// matchMethodFor is the label a CPE-path link gets.
func matchMethodFor(distro bool) model.MatchMethod {
	if distro {
		return model.MatchNVDCPEDistro
	}
	return model.MatchNVDCPE
}

// String is for logs.
func (c cpeCandidate) String() string {
	return fmt.Sprintf("%s:%s:%s@%s", c.part, c.vendor, c.product, c.effectiveVersion())
}

// lookupComponent resolves one work item: the CPE path first, the keyword
// fallback when no candidate names a product NVD knows.
//
// The worker loop has already paid ONE pacer tick for this item, which covers
// exactly its first request; every later request (another candidate, the
// product probe, the keyword fallback) pays its own. That keeps the pool's
// invariant from M55: at most one NVD request per tick, whatever the mix.
func (s *NVDService) lookupComponent(ctx context.Context, item nvdWorkItem, pace nvdPacer) (nvdLookup, error) {
	spent, rejected := 0, 0 // across candidates, decided or not (Codex M60 R25 Low)
	for _, c := range item.candidates {
		l, decided, err := s.lookupCPECandidate(ctx, c, item.distro, pace, spent > 0)
		spent += l.requests
		rejected += l.cpeRejected
		if err != nil {
			return nvdLookup{requests: spent}, err
		}
		if decided {
			l.requests = spent
			l.cpeRejected = rejected
			// An answer that cost requests is not a cache hit, even if
			// its last step was (Codex M60 R4 Low): CacheHits promises
			// "no HTTP request".
			l.fromCache = l.fromCache && spent == 0
			return l, nil
		}
	}
	l, err := s.keywordLookup(ctx, item.key.Name, item.key.Version, pace, spent > 0)
	l.requests += spent
	l.cpeRejected = rejected
	l.fromCache = l.fromCache && spent == 0
	l.method = model.MatchNVDKeyword
	l.keywordFallback = len(item.candidates) > 0
	return l, err
}

// lookupCPECandidate asks NVD about one candidate. decided=false means "NVD
// has no CVE configured for this part:vendor:product; try the next candidate"
// and is the ONLY outcome that moves on — a fetch error is returned as an
// error, never treated as "unknown product", so a network failure cannot be
// laundered into a keyword-only (or clean) result.
func (s *NVDService) lookupCPECandidate(ctx context.Context, c cpeCandidate, distro bool, pace nvdPacer, paceFirst bool) (nvdLookup, bool, error) {
	method := matchMethodFor(distro)

	if s.cache != nil {
		if entry, err := s.cache.Get(ctx, nvdCPECacheName(c), ""); err != nil {
			slog.Debug("cache get error", "cpe", c.String(), "error", err)
		} else if entry != nil {
			if vulns, usable := cachedNVDVulns(entry, c.productKey(), c.version); usable {
				return nvdLookup{vulns: vulns, fromCache: true, method: method}, true, nil
			}
		}
		if entry, err := s.cache.Get(ctx, nvdNoCPECacheName(c), ""); err == nil && entry != nil {
			return nvdLookup{}, false, nil
		}
	}

	// Step 1: the exact cpeName query, only for a plain dotted-numeric
	// version (Codex M60 R10 High-1). Its answer depends on the version being
	// written exactly as NVD writes the release; for anything with letters or
	// qualifiers that encoding is ambiguous (NVD stores 2.0-beta9 as version
	// 2.0 + update beta9), so such versions go straight to step 2.
	spent := 0
	fellThrough := 0 // records the cpeName answer rejected before falling through
	if c.plain() {
		q := url.Values{}
		q.Set("cpeName", c.query())
		res, err := s.walkNVD(ctx, q, pace, paceFirst, nvdCPEMaxPagesPerComponent)
		spent += res.pages
		if err != nil && !partialWalk(ctx, &res, "cpe "+c.String(), err) {
			return nvdLookup{requests: spent}, false, err
		}
		if res.total > 0 || len(res.entries) > 0 {
			out := s.verifyCPEAnswer(res, c, method)
			// An answer in which the product only ever appears as a
			// vulnerable=false platform says nothing about the product's own
			// CVEs (Codex M60 R17 High): step 2 decides instead.
			// But anything the answer KEEPS (an unverifiable record) is
			// returned, not discarded by the fall-through (Codex M60 R20).
			fellThrough = out.cpeRejected
			if out.productEvidence > 0 || len(out.vulns) > 0 || res.truncated {
				out.requests = spent
				if !out.uncacheable {
					s.cacheVulns(ctx, nvdCPECacheName(c), c.String(), out.vulns)
				}
				return out, true, nil
			}
		}
		// A zero is NOT taken as "clean": it is equally the answer for a
		// version encoded differently from NVD's. Step 2 decides.
	}

	// Step 2: the product-level walk (virtualMatchString=part:vendor:product,
	// CPE page budget, truncation reported as for every walk), verified
	// locally against each record's configurations. Zero records means NVD
	// configures no CVE for this product: try the next candidate. Otherwise
	// "none at this version" comes from local verification of NVD's own
	// configurations, never from an encoding-dependent zero. For a product
	// with up to nvdPageSize CVEs this costs the one request the old
	// one-record probe did.
	pq := url.Values{}
	pq.Set("virtualMatchString", c.productQuery())
	res, err := s.walkNVD(ctx, pq, pace, paceFirst || spent > 0, nvdCPEMaxPagesPerComponent)
	spent += res.pages
	if err != nil && !partialWalk(ctx, &res, "cpe "+c.String(), err) {
		return nvdLookup{requests: spent}, false, err
	}
	if res.total == 0 && len(res.entries) == 0 {
		s.cacheVulns(ctx, nvdNoCPECacheName(c), c.String(), nil)
		return nvdLookup{requests: spent}, false, nil
	}
	// The answer must be ABOUT the product (Codex M60 R6 High-3): a mirror
	// that ignored virtualMatchString would otherwise make an unknown
	// product "known" and every record unverifiable noise.
	if !recordNamesProduct(res.entries, c) {
		return nvdLookup{requests: spent}, false, fmt.Errorf("nvd: product query for %s answered with records that do not name the product; "+
			"cannot tell whether NVD knows it", c.productQuery())
	}
	out := s.verifyCPEAnswer(res, c, method)
	if out.productEvidence == 0 && len(out.vulns) == 0 && !res.truncated {
		// NVD names this product only as a vulnerable=false platform: no CVE
		// is configured FOR it, which is "unknown product" for our purpose —
		// a wrong early Syft guess must not end the candidate walk with a
		// cached empty answer (Codex M60 R17 High). A truncated walk might
		// hold such evidence on an unfetched page, so it stays decided and
		// is reported as truncated.
		s.cacheVulns(ctx, nvdNoCPECacheName(c), c.String(), nil)
		return nvdLookup{requests: spent, cpeRejected: fellThrough + out.cpeRejected}, false, nil
	}
	out.requests = spent
	out.cpeRejected += fellThrough
	if !out.uncacheable {
		s.cacheVulns(ctx, nvdCPECacheName(c), c.String(), out.vulns)
	}
	return out, true, nil
}

// partialWalk decides whether a page walk that failed partway is kept as a
// TRUNCATED answer: only when at least one page validated, and the context is
// either still live (a page failed) or ended by the SCAN DEADLINE (M62). Any
// other cancellation stays an error. Found by the M60 decision-2 end-to-end
// run: a 35.8 s kernel page past the client timeout made the whole kernel
// lookup a partial fetch failure — 0 findings, not escalated. A truncated
// answer IS escalated (the scan reports failed) and never cached, and the
// pages' findings are kept.
func partialWalk(ctx context.Context, res *nvdSearchResult, what string, err error) bool {
	if len(res.entries) == 0 {
		return false
	}
	if ctx.Err() != nil && !scanDeadlineFired(ctx) {
		return false
	}
	res.truncated = true
	res.partialFailure = true
	if res.total <= res.fetched {
		res.total = res.fetched + 1 // at least one record is known to be missing
	}
	slog.Warn("nvd: page walk failed partway; keeping the pages already read and reporting the answer truncated",
		"query", what, "pages", res.pages, "fetched", res.fetched, "total", res.total,
		"deadline_exceeded", scanDeadlineFired(ctx), "error", err)
	return true
}

// productHasVulnerableEvidence reports whether any criterion of the record
// names the candidate's product as vulnerable (or without saying, which is
// not evidence of the opposite).
//
// Negated configurations and nodes are skipped, as in verifyCPEMatch (Codex
// M60 R18 High).
func productHasVulnerableEvidence(cve NVDCVE, c cpeCandidate) bool {
	for _, cfg := range cve.Configurations {
		if cfg.Negate {
			continue
		}
		for _, n := range cfg.Nodes {
			if n.Negate {
				continue
			}
			for _, m := range n.CpeMatch {
				crit, ok := parseCPE(m.Criteria)
				if ok && crit.Part == c.part && crit.Vendor == c.vendor && crit.Product == c.product &&
					(m.Vulnerable || m.vulnerableMissing) {
					return true
				}
			}
		}
	}
	return false
}

// verifyCPEAnswer keeps the records of one walk that verifyCPEMatch does not
// reject, labelling each, and carries the walk's completeness.
func (s *NVDService) verifyCPEAnswer(res nvdSearchResult, c cpeCandidate, method model.MatchMethod) nvdLookup {
	out := nvdLookup{
		truncated:      res.truncated,
		shifted:        res.shifted,
		total:          res.total,
		fetched:        res.fetched,
		method:         method,
		pageBudget:     res.pageBudget,
		partialFailure: res.partialFailure,
	}
	for i, e := range res.entries {
		if productHasVulnerableEvidence(e.CVE, c) {
			out.productEvidence++
		}
		switch verifyCPEMatch(e.CVE, c) {
		case cpeMatched:
			out.vulns = append(out.vulns, res.vulns[i])
			out.methods = append(out.methods, method)
		case cpeUndecidable:
			// Kept (NVD selected it for this CPE), but NOT labelled as
			// verified (Codex M60 R2 Medium-1).
			out.vulns = append(out.vulns, res.vulns[i])
			out.methods = append(out.methods, model.MatchNVDCPEUnverified)
			out.cpeUndecidable++
		case cpeRejected:
			out.cpeRejected++
		}
	}
	// Same rule as the keyword path: a truncated answer is never cached, or
	// the truncation would be reported once and then laundered for a TTL.
	// Nor is an answer holding an unverified CVE: the cache carries no
	// per-CVE provenance, so a hit would relabel it as verified.
	out.uncacheable = res.truncated || out.cpeUndecidable > 0
	return out
}

// recordNamesProduct reports whether any configuration criterion of the
// given records names the candidate's part:vendor:product.
func recordNamesProduct(entries []NVDVulnEntry, c cpeCandidate) bool {
	for _, e := range entries {
		for _, cfg := range e.CVE.Configurations {
			for _, n := range cfg.Nodes {
				for _, m := range n.CpeMatch {
					if crit, ok := parseCPE(m.Criteria); ok &&
						crit.Part == c.part && crit.Vendor == c.vendor && crit.Product == c.product {
						return true
					}
				}
			}
		}
	}
	return false
}

// cacheVulns writes one cache record (best effort, like the keyword path).
func (s *NVDService) cacheVulns(ctx context.Context, cacheName, label string, vulns []model.Vulnerability) {
	if s.cache == nil {
		return
	}
	cachedVulns := make([]cache.CachedVuln, len(vulns))
	for i, v := range vulns {
		cachedVulns[i] = cache.CachedVuln{
			CVEID:       v.CVEID,
			Description: v.Description,
			Severity:    v.Severity,
			CVSSScore:   v.CVSSScore,
			PublishedAt: v.PublishedAt,
		}
	}
	if err := s.cache.Set(ctx, cacheName, "", cachedVulns); err != nil {
		slog.Debug("cache set error", "key", label, "error", err)
	}
}
