// Package advisory provides structured extraction of advisory metadata from
// upstream sources (NVD, GitHub Security Advisories, JVN).
//
// The output of each parser is a single ParsedAdvisory value that downstream
// triage logic (M1-5) feeds into the LLM as context plus persists to the
// advisory_excerpts table (migration 033, owned by Agent X) for evidence
// pointer lookups.
//
// Design notes:
//
//   - Parsers are intentionally heuristic. When confidence is low we return
//     empty slices and rely on RawExcerpt being a verbatim copy of the upstream
//     description, so the LLM stage can still ground its answers. This is the
//     MVP contract from PRODUCT_REBOOT_PLAN §7.1 step 1.
//
//   - No LLM call happens inside this package. The LLM provider is only invoked
//     by the M1-4 triage runner, not by the parser.
//
//   - This package does not import a repository directly. Persistence is the
//     caller's responsibility; the ExcerptStore interface below documents the
//     minimal contract a repository must satisfy so we can wire it up in M1-5
//     without a circular import.
package advisory

import (
	"context"
	"strings"
	"time"
)

// Source identifies which upstream supplied the advisory text. Stored verbatim
// in the advisory_excerpts.source column.
type Source string

const (
	SourceNVD  Source = "nvd"
	SourceGHSA Source = "ghsa"
	SourceJVN  Source = "jvn"
)

// IsValid reports whether s is one of the recognised advisory sources.
func (s Source) IsValid() bool {
	switch s {
	case SourceNVD, SourceGHSA, SourceJVN:
		return true
	}
	return false
}

// ParsedAdvisory is the common structured form of an advisory regardless of
// upstream source. Slice fields are nil-safe (callers should treat nil and
// empty as equivalent). All fields are best-effort; downstream code must
// tolerate any of them being empty.
type ParsedAdvisory struct {
	// CVEID is the canonical CVE identifier (CVE-YYYY-NNNN...). For GHSA
	// advisories that lack a CVE assignment, this falls back to the GHSA ID.
	// For JVN entries without a CVE alias, this falls back to the JVNDB ID.
	CVEID string

	// Source records which upstream produced the underlying record.
	Source Source

	// VulnFuncs is the list of fully-qualified function symbols the upstream
	// flagged as vulnerable (e.g. "encoding/json.Unmarshal", "express.urlencoded").
	// Populated from GHSA's vulnerable_functions field or via regex extraction
	// from the description ("the vulnerable function `X` ...").
	VulnFuncs []string

	// AffectedPaths is the list of source paths or files referenced by the
	// advisory as containing the bug.
	AffectedPaths []string

	// RequiredConfig is the list of configuration switches the advisory says
	// are required for the bug to be exploitable (e.g. "trusted_proxies = *").
	RequiredConfig []string

	// RequiredEnv is the list of environment variables the advisory says are
	// required (e.g. "DEBUG=1", "NODE_ENV=development").
	RequiredEnv []string

	// RawExcerpt is the verbatim upstream description (or best-available text).
	// This is what the LLM is grounded on when structured fields are empty.
	RawExcerpt string

	// FetchedAt is the time the parser produced this record. Mirrors the
	// advisory_excerpts.fetched_at column.
	FetchedAt time.Time
}

// Normalize trims whitespace, de-duplicates string slices, and drops empty
// entries. Returns the receiver for chaining. Safe to call on a nil
// ParsedAdvisory — it is a no-op.
func (p *ParsedAdvisory) Normalize() *ParsedAdvisory {
	if p == nil {
		return p
	}
	p.CVEID = strings.TrimSpace(p.CVEID)
	p.RawExcerpt = strings.TrimSpace(p.RawExcerpt)
	p.VulnFuncs = dedupeStrings(p.VulnFuncs)
	p.AffectedPaths = dedupeStrings(p.AffectedPaths)
	p.RequiredConfig = dedupeStrings(p.RequiredConfig)
	p.RequiredEnv = dedupeStrings(p.RequiredEnv)
	if p.FetchedAt.IsZero() {
		p.FetchedAt = time.Now().UTC()
	}
	return p
}

// IsEmpty reports whether the parser failed to extract anything beyond the
// raw excerpt. Callers may use this to decide whether to bother persisting,
// though the default (per §8.5: "evidence なしの出力は保存しない") is to persist
// anyway as long as RawExcerpt is non-empty — the excerpt itself is evidence.
func (p *ParsedAdvisory) IsEmpty() bool {
	if p == nil {
		return true
	}
	return len(p.VulnFuncs) == 0 &&
		len(p.AffectedPaths) == 0 &&
		len(p.RequiredConfig) == 0 &&
		len(p.RequiredEnv) == 0
}

// Parser is the common interface every source-specific parser implements.
// Input is an opaque payload — the concrete type depends on the source
// (see nvd.go / ghsa.go / jvn.go for the accepted types). Each parser uses
// type assertion / switch to extract its real argument.
//
// Returning (nil, nil) signals "advisory missing or empty" and is not an error.
type Parser interface {
	Parse(ctx context.Context, payload any) (*ParsedAdvisory, error)
	Source() Source
}

// ExcerptStore is the minimal persistence interface advisory_excerpts.
// Repository owns the concrete implementation in #23 (Agent X), this package
// only declares the contract so the M1-5 triage runner can wire them together
// without circular imports. ※要確認: signature may change once Agent X lands
// the repository; keep this in sync after merge.
type ExcerptStore interface {
	UpsertExcerpt(ctx context.Context, tenantID string, p *ParsedAdvisory) error
	GetExcerpt(ctx context.Context, tenantID, cveID string, source Source) (*ParsedAdvisory, error)
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		t := strings.TrimSpace(v)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
