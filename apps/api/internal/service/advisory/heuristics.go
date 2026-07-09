package advisory

import (
	"regexp"
	"strings"
	"unicode"
)

// Heuristic regular expressions shared across NVD / GHSA / JVN parsers.
//
// These are deliberately conservative — high precision, modest recall.
// When recall is the bottleneck the LLM stage (M1-4) sees RawExcerpt and can
// fill the gap. We pay for false positives here in the form of bad evidence
// pointers, which would mislead human reviewers; that's worse than no pointer.
var (
	// reBacktickFunc matches things like:
	//   the vulnerable function `pkg.Foo`
	//   the vulnerable function ``Bar.baz()``
	//   vulnerable function: `Foo`
	//   affected function `xml.Unmarshal`
	reBacktickFunc = regexp.MustCompile(
		"(?i)(?:vulnerable|affected|unsafe|insecure)\\s+function[s]?[\\s:]*`+([A-Za-z_][A-Za-z0-9_./()$<>:-]+)`+",
	)

	// reFunctionInPackage matches things like:
	//   function `Foo` in `mypkg`
	//   the `Foo()` method of class `Bar`
	reMethodCall = regexp.MustCompile(
		"`([A-Za-z_][A-Za-z0-9_./]*\\.[A-Za-z_][A-Za-z0-9_]*(?:\\([^)]*\\))?)`",
	)

	// reAffectedPath matches things like:
	//   in file `src/foo/bar.go`
	//   the file `lib/transport.js`
	//   located in `cmd/server/main.go`
	//   affects `package.json`
	reAffectedPath = regexp.MustCompile(
		"(?i)(?:in|at|file|path|located in|affects?)[\\s:]+`([A-Za-z0-9._/\\-]+\\.[A-Za-z0-9]+)`",
	)

	// reRequiredConfig matches things like:
	//   when `trusted_proxies` is set to `*`
	//   by setting `allow_unsafe_html = true`
	//   if the `enable_admin` option is enabled
	//   only when configured with `--allow-root`
	// The leading char class allows '-' so we catch CLI-flag style options too.
	reRequiredConfig = regexp.MustCompile(
		"(?i)(?:when|if|requires?|only with|only when|by setting|configured with|with the)[^.`\\n]{0,80}`([A-Za-z_\\-][A-Za-z0-9_\\-\\.]*(?:\\s*=\\s*[A-Za-z0-9_*\\-\"']+)?)`",
	)

	// reRequiredEnv matches things like:
	//   when `DEBUG=1`
	//   if `NODE_ENV` is set to "development"
	//   requires `GIN_MODE=debug`
	// Note: env vars are conventionally UPPER_SNAKE_CASE so we tighten the
	// character class to reduce overlap with reRequiredConfig.
	reRequiredEnv = regexp.MustCompile(
		"(?:^|[^A-Z0-9_])`?([A-Z][A-Z0-9_]{2,})`?\\s*(?:=\\s*[A-Za-z0-9_\"']+|(?:\\s+(?:env(?:ironment)?\\s+variable|is\\s+set))?)",
	)

	// reEnvKeywordContext gates reRequiredEnv hits — we only count an env-var
	// candidate when the surrounding sentence explicitly mentions an env(ironment)
	// variable. We intentionally do NOT match bare "ENV"/"env" because plenty of
	// English advisory prose uses "env" as shorthand for "environment" with no
	// variable in sight (e.g. "in a sandboxed env"), which produced false
	// positives in fixtures.
	reEnvKeywordContext = regexp.MustCompile(
		"(?i)(?:environment|env)\\s+variable",
	)
)

// extractVulnFuncs pulls candidate function symbols out of free text.
// Returns deduplicated, trimmed values. Always safe with empty input.
func extractVulnFuncs(text string) []string {
	if text == "" {
		return nil
	}
	var out []string
	for _, m := range reBacktickFunc.FindAllStringSubmatch(text, -1) {
		if len(m) >= 2 {
			out = append(out, strings.TrimSpace(m[1]))
		}
	}
	// Secondary signal: any backtick-quoted dotted call that looks like a
	// method invocation, but only if the surrounding sentence carries an
	// explicit "vulnerable"/"affected"/"unsafe"/"crash" hint to avoid pulling
	// in incidental references.
	if containsAny(text, []string{"vulnerable", "affected", "unsafe", "insecure", "crash", "panic", "remote code"}) {
		for _, m := range reMethodCall.FindAllStringSubmatch(text, -1) {
			if len(m) >= 2 {
				out = append(out, strings.TrimSpace(m[1]))
			}
		}
	}
	return dedupeStrings(out)
}

// extractAffectedPaths pulls candidate file paths out of free text.
func extractAffectedPaths(text string) []string {
	if text == "" {
		return nil
	}
	var out []string
	for _, m := range reAffectedPath.FindAllStringSubmatch(text, -1) {
		if len(m) >= 2 {
			out = append(out, strings.TrimSpace(m[1]))
		}
	}
	return dedupeStrings(out)
}

// extractRequiredConfig pulls configuration keys/values that must be present
// for the bug to fire.
func extractRequiredConfig(text string) []string {
	if text == "" {
		return nil
	}
	var out []string
	for _, m := range reRequiredConfig.FindAllStringSubmatch(text, -1) {
		if len(m) >= 2 {
			candidate := strings.TrimSpace(m[1])
			// Skip values that look more like env vars (UPPER_SNAKE_CASE) —
			// extractRequiredEnv handles those.
			if isLikelyEnvVar(candidate) {
				continue
			}
			out = append(out, candidate)
		}
	}
	return dedupeStrings(out)
}

// extractRequiredEnv pulls environment variable references that the advisory
// claims are required for exploitation.
func extractRequiredEnv(text string) []string {
	if text == "" {
		return nil
	}
	// Only scan sentences/paragraphs that explicitly call out an env(ironment)
	// variable. This is a high-precision / low-recall gate — fixtures show that
	// without it we pull every UPPER_SNAKE backtick token, which produces
	// misleading evidence pointers.
	var out []string
	for _, chunk := range splitSentences(text) {
		if !reEnvKeywordContext.MatchString(chunk) {
			continue
		}
		for _, m := range reRequiredEnv.FindAllStringSubmatch(chunk, -1) {
			if len(m) >= 2 {
				candidate := strings.TrimSpace(m[1])
				if !isLikelyEnvVar(candidate) {
					continue
				}
				out = append(out, candidate)
			}
		}
	}
	return dedupeStrings(out)
}

// ============================================================================
// M44 Wave 2 (F470): npm-tuned vulnerable-function extraction.
//
// npm has NO structured symbol source (OSV npm records carry a null
// ecosystem_specific; the GHSA REST vulnerable_functions field is populated
// for 0/100 recent npm advisories — 2026-07-10 recon), so the only symbol
// signal is GHSA markdown prose. npm prose differs from the Go/NVD shapes the
// extractors above target in two ways:
//
//   - the dominant form is a BARE export name ("The function `defaultsDeep`
//     allows …") — the Go-oriented reBacktickFunc demands a
//     "vulnerable/affected … function" qualifier that real npm advisories
//     almost never use (2/100 — 2026-07-10 recon), and reMethodCall demands a
//     dot;
//   - backticks are also npm prose's habitat for file names (`handler.ts`),
//     config keys, URLs, versions, and package names, so accepting every
//     backtick token collapses precision.
//
// The npm extractor therefore accepts a token through exactly two gates:
//
//  1. FUNCTION ADJACENCY: the words "function(s)"/"method(s)" immediately
//     precede or follow the backtick token (no vulnerable-qualifier
//     required). Bare names are accepted here — adjacency IS the context.
//  2. DOTTED + VULNERABILITY CONTEXT: a dotted call chain (`_.merge`,
//     `auth.api.removeUser`) whose surrounding ±100-byte window carries an
//     explicit vulnerability keyword. A window is used instead of
//     splitSentences because sentence splitting cuts on EVERY '.' —
//     including the dots inside the token itself.
//
// Every candidate then passes npmFunctionToken: JS-identifier-shaped
// dot-parts (1..3, '$' allowed), one trailing call-parens group stripped,
// file-extension tails (`handler.ts`, `config.json`) dropped, single-rune
// bare tokens (`_`, `$` — bindings, not functions) dropped. Output is
// deduped (first-seen order) and capped at npmVulnFuncsPerAdvisoryCap.
//
// Known precision limits (deliberate, documented): dotted non-function
// tokens inside keyword-bearing windows (config keys like
// `server.allowedHosts`, property accesses like `headers.location` next to
// the word "vulnerable") still pass gate 2. Fixture measurement (2026-07-10,
// 100 recent npm GHSA advisories): ~47% of advisories yield ≥1 token with
// mixed precision — the CLI's binding-aware matching and the LLM triage
// stage are the downstream defence, same posture as the extractors above.
var (
	// reNpmFuncBefore: "function `defaultsDeep`", "methods: `a`, …".
	reNpmFuncBefore = regexp.MustCompile(
		"(?i)\\b(?:functions?|methods?)\\s*:?\\s*`+([A-Za-z_$][A-Za-z0-9_$.]*(?:\\([^)]*\\))?)`+",
	)
	// reNpmFuncAfter: "the `merge` function", "`escape()` method".
	reNpmFuncAfter = regexp.MustCompile(
		"(?i)`+([A-Za-z_$][A-Za-z0-9_$.]*(?:\\([^)]*\\))?)`+\\s*(?:functions?|methods?)\\b",
	)
	// reNpmDottedBacktick: `x.y` / `x.y.z` call chains (2..3 dot-parts), the
	// shape gate 2 admits under a vulnerability-keyword window.
	reNpmDottedBacktick = regexp.MustCompile(
		"`+([A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*){1,2}(?:\\([^)]*\\))?)`+",
	)
)

// npmVulnContextKeywords gates reNpmDottedBacktick hits (gate 2): the token's
// surrounding window must carry an explicit vulnerability signal. Kept tight
// on purpose — every entry admits noise as well as signal.
var npmVulnContextKeywords = []string{
	"vulnerable", "affected", "unsafe", "insecure", "exploit",
	"crash", "panic", "remote code", "pollut", "injection",
}

// npmNonFunctionExtensions drops backtick tokens that are file names: their
// dot-parts are individually JS-identifier-shaped (`handler.ts` → handler,
// ts) so only the extension tail identifies them.
var npmNonFunctionExtensions = map[string]struct{}{
	"js": {}, "jsx": {}, "ts": {}, "tsx": {}, "mjs": {}, "cjs": {},
	"mts": {}, "cts": {}, "json": {}, "md": {}, "yml": {}, "yaml": {},
	"lock": {}, "html": {}, "css": {}, "txt": {}, "map": {},
}

const (
	// npmVulnFuncsPerAdvisoryCap bounds one advisory's extraction, aligned
	// with the scheduler's per-CVE selector cap
	// (osvVulnFuncsMaxSymbolsPerCVE = 200) so a degenerate advisory cannot
	// balloon downstream storage.
	npmVulnFuncsPerAdvisoryCap = 200

	// npmContextWindowBytes is gate 2's keyword search radius around a
	// dotted-token match. 100 bytes ≈ one prose clause on each side; byte
	// (not rune) slicing may cut a multibyte rune at the edges, which is
	// harmless for the ASCII keyword scan.
	npmContextWindowBytes = 100
)

// ExtractVulnFuncsNpm pulls candidate vulnerable-function tokens out of npm
// advisory prose (GHSA markdown / OSV summary+details). Returns deduplicated
// tokens in first-seen order (adjacency hits before window-gated dotted
// hits), capped at npmVulnFuncsPerAdvisoryCap. Always safe with empty input.
//
// Exported (unlike the extractors above) because its production caller is
// the scheduler's OSV pass (M44 F470), not this package's parsers.
func ExtractVulnFuncsNpm(text string) []string {
	if text == "" {
		return nil
	}
	var out []string
	add := func(raw string) {
		if tok, ok := npmFunctionToken(raw); ok {
			out = append(out, tok)
		}
	}
	for _, m := range reNpmFuncBefore.FindAllStringSubmatch(text, -1) {
		if len(m) >= 2 {
			add(m[1])
		}
	}
	for _, m := range reNpmFuncAfter.FindAllStringSubmatch(text, -1) {
		if len(m) >= 2 {
			add(m[1])
		}
	}
	for _, idx := range reNpmDottedBacktick.FindAllStringSubmatchIndex(text, -1) {
		if len(idx) < 4 || idx[2] < 0 {
			continue
		}
		lo := idx[0] - npmContextWindowBytes
		if lo < 0 {
			lo = 0
		}
		hi := idx[1] + npmContextWindowBytes
		if hi > len(text) {
			hi = len(text)
		}
		if !containsAny(text[lo:hi], npmVulnContextKeywords) {
			continue
		}
		add(text[idx[2]:idx[3]])
	}
	deduped := dedupeStrings(out)
	if len(deduped) > npmVulnFuncsPerAdvisoryCap {
		deduped = deduped[:npmVulnFuncsPerAdvisoryCap]
	}
	return deduped
}

// npmFunctionToken normalises and shape-filters one backtick candidate:
// strips one trailing call-parens group, then requires 1..3 dot-parts, each
// JS-identifier-shaped, with file-extension tails and single-rune bare
// tokens rejected. Path/URL/version shapes never reach here (the capture
// regexes exclude '/', ':' and digit-leading parts) but the parts check
// re-rejects them anyway — callers may feed tokens from other sources.
func npmFunctionToken(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if i := strings.IndexByte(s, '('); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if s == "" {
		return "", false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return "", false
	}
	for _, p := range parts {
		if !isJSIdentifierShaped(p) {
			return "", false
		}
	}
	if len(parts) == 1 && len([]rune(s)) < 2 {
		return "", false // `_` / `$` — a namespace binding, not a function
	}
	if len(parts) >= 2 {
		if _, isExt := npmNonFunctionExtensions[strings.ToLower(parts[len(parts)-1])]; isExt {
			return "", false
		}
	}
	return s, true
}

// isJSIdentifierShaped reports whether s is one JavaScript identifier: first
// rune a letter/underscore/'$', rest letters/digits/underscores/'$'; Unicode
// letters allowed (mirrors the Go-identifier helpers used by the Go
// extraction, widened by '$').
func isJSIdentifierShaped(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_' || r == '$' || unicode.IsLetter(r):
		case i > 0 && unicode.IsDigit(r):
		default:
			return false
		}
	}
	return true
}

func isLikelyEnvVar(s string) bool {
	if len(s) < 3 {
		return false
	}
	// Must start with an uppercase letter or underscore and contain only
	// uppercase letters, digits, and underscores (i.e. POSIX env-var shape).
	// We also accept an inline `=value` assignment.
	if eq := strings.IndexByte(s, '='); eq >= 0 {
		return isLikelyEnvVar(strings.TrimSpace(s[:eq]))
	}
	for i, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r == '_':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func containsAny(s string, needles []string) bool {
	lower := strings.ToLower(s)
	for _, n := range needles {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}

// splitSentences chops text on '.', '!', '?', and newlines. This is intentionally
// crude — for our purposes the LLM does the real NLP, we just want the regex
// to operate on bounded contexts.
func splitSentences(text string) []string {
	if text == "" {
		return nil
	}
	out := []string{}
	cur := strings.Builder{}
	flush := func() {
		s := strings.TrimSpace(cur.String())
		if s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	for _, r := range text {
		cur.WriteRune(r)
		if r == '.' || r == '!' || r == '?' || r == '\n' {
			flush()
		}
	}
	flush()
	return out
}
