// Package advisorytext holds the small, byte-stable rendering and
// content-classification helpers that the triage (M1) and CRA (M2) prompt
// builders both apply to advisory_excerpts rows.
//
// These helpers used to live as hand-kept duplicates in
// service/triage/runner.go and service/cra/runner.go, pinned only by
// "Mirrored in service/cra — keep the two in sync" doc comments (M43/M44
// sync debt). M45 Wave 2 C3 extracts them here so the two prompt renders
// are structurally guaranteed to share one implementation: a drift can no
// longer land silently in one copy. The package is a leaf (stdlib only),
// so both service packages can import it without an import cycle.
//
// Byte-stability matters: the triage and CRA runners hash their rendered
// prompts (prompt_hash in the llm_calls audit row), so any change to how a
// small in-budget payload renders would ripple into the audit trail. The
// contracts below (verbatim passthrough at or under budget; the exact
// " …(+N more)" elision marker; the "...(truncated)" tail) are load-bearing
// and are pinned by advisorytext_test.go plus the two runners' render tests.
package advisorytext

import (
	"encoding/json"
	"fmt"
	"strings"
)

// VulnFuncsPromptBudget caps the rendered vuln_funcs / affected_paths JSON
// per advisory row in the triage and CRA prompts (M43 Phase D; R2 finding
// 3 extended it to affected_paths on the triage side). Advisory unions can
// carry hundreds of symbols (OSV / Go vulndb structured lists) and an
// unbounded render bloats the prompt and drowns the reachability evidence
// the model must weigh. Storage and the /reachability/targets wire keep
// their own caps; only the prompt render truncates here. Sized to sit
// alongside the existing truncate(..., 600) excerpt / truncate(..., 400)
// evidence budgets in the runners.
const VulnFuncsPromptBudget = 800

// Truncate returns s unchanged when it is at most n bytes, otherwise the
// first n bytes followed by the "...(truncated)" marker so the prompt
// reader can tell an elided value from a genuinely short one. Operates on
// raw bytes (not runes) to match the prompt-size budget it enforces.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

// RenderVulnFuncs renders an advisory string-array JSON payload (vuln_funcs
// / affected_paths) for the prompt, keeping whole JSON elements until
// budget bytes are used and appending " …(+N more)" for the elided tail
// (so the model knows the list is incomplete rather than exhaustive).
// Payloads at or under budget pass through byte-for-byte — prompt_hash
// stability for the common small case. An over-budget payload that does
// not parse as a string array (foreign shape tolerated leniently,
// mirroring the repository read) falls back to the plain byte Truncate
// used elsewhere in the prompt.
func RenderVulnFuncs(raw json.RawMessage, budget int) string {
	if len(raw) <= budget {
		return string(raw)
	}
	var funcs []string
	if err := json.Unmarshal(raw, &funcs); err != nil {
		return Truncate(string(raw), budget)
	}
	var b strings.Builder
	b.WriteByte('[')
	kept := 0
	for _, f := range funcs {
		enc, err := json.Marshal(f)
		if err != nil {
			continue
		}
		add := len(enc)
		if kept > 0 {
			add++ // separating comma
		}
		if b.Len()+add+1 > budget { // +1 for the closing bracket
			break
		}
		if kept > 0 {
			b.WriteByte(',')
		}
		b.Write(enc)
		kept++
	}
	b.WriteByte(']')
	if n := len(funcs) - kept; n > 0 {
		fmt.Fprintf(&b, " …(+%d more)", n)
	}
	return b.String()
}

// JSONArrayEmpty reports whether raw carries no JSON array content: nil /
// empty bytes, JSON null, or the empty array literal. Postgres JSONB
// canonicalises the on-disk value to exactly `[]` (and the repository
// normalises nil to '[]' on write), so a byte comparison suffices; foreign
// shapes (raw pass-through Upsert) count as content — lenient, mirroring
// the repository read — so they are never silently treated as absent.
func JSONArrayEmpty(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null" || s == "[]"
}

// ContentFree reports whether an advisory row carries no usable content:
// rawExcerpt empty AND every supplied structured array empty (per
// JSONArrayEmpty). It is the shared judgement behind the triage and CRA
// dropContentFreeExcerpts filters — the row-type-specific loop stays in
// each runner (their row structs differ), but the classification lives
// here so the two cannot drift.
//
// Content-free rows exist by design: the M43 OSV vuln_funcs sync writes a
// negative TOMBSTONE row (source='osv', vuln_funcs '[]', raw_excerpt NULL)
// for a definitive upstream miss so the freshness window can negative-cache
// it. Such a row must not count as grounding, must not render a
// content-free advisory line into the prompt, and must not become an
// advisory_excerpt citation — the callers drop it at the load edge.
func ContentFree(rawExcerpt string, arrays ...json.RawMessage) bool {
	if rawExcerpt != "" {
		return false
	}
	for _, a := range arrays {
		if !JSONArrayEmpty(a) {
			return false
		}
	}
	return true
}
