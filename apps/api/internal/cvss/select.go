// Package cvss is the ONE place that decides which CVSS assessment of a CVE
// SBOMHub stores (M67).
//
// # The rule
//
//  1. Version: v3.1 > v3.0 > v4.0 > v2. An unrecognised version ranks below
//     all of them.
//  2. Within one version, NVD's own ("Primary") assessment over CNA /
//     third-party ("Secondary") ones (M54 / M57).
//  3. Within the same version and primacy, the more severe assessment, then
//     the higher score. The result therefore never depends on the order a
//     feed listed its assessments in (NVD's order is not significant).
//
// v3.x outranks v4.0 by product decision (2026-11-09): it matches NVD's own
// display, JVN iPedia and Dependency-Track, and v4.0 coverage is still
// sparse — most v4.0 assessments NVD carries are a CNA's Secondary beside
// NVD's own v3.1 Primary. Before M67 the CVE sync preferred v4.0 and the
// scanner v3.x, so the same CVE's stored severity depended on which path
// wrote it last (measured on the recorded M60 fixtures: CVE-2026-34479 was
// v4.0 6.9 MEDIUM from the sync and v3.1 7.5 HIGH from the scanner).
//
// # Severity
//
// The stored severity is derived from the chosen assessment: the band its
// score falls in on its own version's scale, or the severity it states when
// that is harsher. A score that is not a CVSS base score (NaN, infinite,
// outside 0..10) is dropped and the stated severity kept. An assessment with
// neither a usable score nor a recognised severity is not a candidate.
//
// Every writer of vulnerabilities.cvss_score / severity / cvss_version goes
// through Select: the NVD scanner and search (service/nvd.go), the CVE sync
// and the monthly catalogue reconcile (scheduler/cve_sync.go,
// scheduler/cve_reconcile.go) and the JVN scanner (service/jvn.go).
package cvss

import (
	"math"
	"strings"
)

// Version is a canonical CVSS version as stored in vulnerabilities.cvss_version.
// The empty Version means "not recognised" and is stored as NULL.
type Version string

const (
	V31 Version = "3.1"
	V30 Version = "3.0"
	V40 Version = "4.0"
	V2  Version = "2.0"
)

// rank is the version precedence. Unknown is 0, below every known version.
func (v Version) rank() int {
	switch v {
	case V31:
		return 4
	case V30:
		return 3
	case V40:
		return 2
	case V2:
		return 1
	default:
		return 0
	}
}

// Ptr returns the version as a nullable column value: nil for "".
func (v Version) Ptr() *string {
	if v == "" {
		return nil
	}
	s := string(v)
	return &s
}

// ParseVersion canonicalises a version label from a feed ("3.1", " 3.0 ",
// "2"). Anything it does not recognise returns "".
func ParseVersion(s string) Version {
	switch strings.TrimSpace(s) {
	case "3.1":
		return V31
	case "3.0":
		return V30
	case "4.0", "4":
		return V40
	case "2.0", "2":
		return V2
	default:
		return ""
	}
}

// Assessment is one CVSS assessment as a feed published it.
type Assessment struct {
	Version Version
	// Primary is NVD's `type: Primary`. Feeds without the notion (JVN) leave
	// it false for every entry.
	Primary bool
	// Score is the base score, nil when absent.
	Score *float64
	// Severity is the qualitative rating the feed states, in any case
	// ("HIGH", "High", "h"); empty when the feed states none (NVD v2's
	// cvssData).
	Severity string
}

// Selection is what is stored for a CVE.
type Selection struct {
	// Version is "" when nothing was chosen or the chosen assessment's
	// version is not recognised.
	Version Version
	// Score is nil when the CVE is unscored, or the chosen assessment's score
	// was not a usable base score. 0.0 is a real score ("None").
	Score *float64
	// Severity is CRITICAL / HIGH / MEDIUM / LOW / NONE, or UNKNOWN when there
	// is no usable assessment.
	Severity string
	// primary is carried for Select's own comparisons only.
	primary bool
}

// Select applies the rule in the package comment.
func Select(as []Assessment) Selection {
	best := Selection{Severity: Unknown}
	found := false
	for _, a := range as {
		c, ok := candidate(a)
		if !ok {
			continue
		}
		if !found || better(c, best, true) {
			best, found = c, true
		}
	}
	best.primary = false
	return best
}

// Outranks reports whether a should replace b when two independent records
// for one CVE compete (two JVN advisories citing it): version precedence,
// then rating, then score. Equality keeps the incumbent b.
func Outranks(a, b Selection) bool {
	return better(a, b, false)
}

func candidate(a Assessment) (Selection, bool) {
	score := a.Score
	if score != nil && !SaneScore(*score) {
		score = nil
	}
	sev := Reconcile(a.Version, a.Severity, score)
	if score == nil && sev == Unknown {
		return Selection{}, false
	}
	var s *float64
	if score != nil {
		v := *score
		s = &v
	}
	return Selection{Version: a.Version, Score: s, Severity: sev, primary: a.Primary}, true
}

func better(a, b Selection, usePrimary bool) bool {
	if ra, rb := a.Version.rank(), b.Version.rank(); ra != rb {
		return ra > rb
	}
	if usePrimary && a.primary != b.primary {
		return a.primary
	}
	if ra, rb := severityRank[a.Severity], severityRank[b.Severity]; ra != rb {
		return ra > rb
	}
	switch {
	case a.Score != nil && b.Score != nil:
		return *a.Score > *b.Score
	case a.Score != nil:
		return true
	default:
		return false
	}
}

// Unknown is the severity stored when no usable assessment exists.
const Unknown = "UNKNOWN"

var severityRank = map[string]int{
	"CRITICAL": 5,
	"HIGH":     4,
	"MEDIUM":   3,
	"LOW":      2,
	"NONE":     1,
}

// SaneScore rejects values a CVSS base score cannot take. NaN in particular
// would poison every comparison it takes part in.
func SaneScore(s float64) bool {
	return !math.IsNaN(s) && !math.IsInf(s, 0) && s >= 0 && s <= 10
}

// NormaliseSeverity maps a stated rating to the stored vocabulary, UNKNOWN
// when it is not one.
func NormaliseSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "c":
		return "CRITICAL"
	case "high", "h":
		return "HIGH"
	case "medium", "m":
		return "MEDIUM"
	case "low", "l":
		return "LOW"
	case "none", "n":
		return "NONE"
	default:
		return Unknown
	}
}

// Band is the rating a score implies on its version's scale. v2 has three
// bands, no CRITICAL and no NONE (0.0-3.9 is Low, as NVD rates it); v3.x,
// v4.0 — and an unrecognised version, so the failure direction is the harsher
// rating — have five.
func Band(v Version, score float64) string {
	if v == V2 {
		switch {
		case score >= 7.0:
			return "HIGH"
		case score >= 4.0:
			return "MEDIUM"
		default:
			return "LOW"
		}
	}
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "NONE"
	}
}

// Reconcile is the severity stored for one assessment: the harsher of its
// stated rating and its score's band. score must already be sane or nil.
func Reconcile(v Version, stated string, score *float64) string {
	s := NormaliseSeverity(stated)
	if score == nil {
		return s
	}
	if b := Band(v, *score); severityRank[b] > severityRank[s] {
		return b
	}
	return s
}
