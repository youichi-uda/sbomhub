package advisory

import (
	"regexp"
	"strings"
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
