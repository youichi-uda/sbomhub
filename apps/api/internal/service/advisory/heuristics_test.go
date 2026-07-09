package advisory

import (
	"fmt"
	"strings"
	"testing"
)

func TestExtractVulnFuncs(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{
			"explicit_vulnerable_function",
			"The vulnerable function `pkg.Foo` mishandles input.",
			[]string{"pkg.Foo"},
		},
		{
			"affected_function",
			"affected function `xml.Unmarshal`",
			[]string{"xml.Unmarshal"},
		},
		{
			"backtick_method_with_keyword",
			"This is vulnerable: `net/http.Server.Serve()` crashes when fed long headers.",
			[]string{"net/http.Server.Serve()"},
		},
		{
			"plain_backtick_without_keyword_ignored",
			"You can fix it by calling `runtime.Goexit()` afterwards.",
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractVulnFuncs(tt.in)
			if !equalStringSlice(got, tt.want) {
				t.Errorf("got %v want %v", got, tt.want)
			}
		})
	}
}

func TestExtractAffectedPaths(t *testing.T) {
	in := "See file `src/foo/bar.go` and also affects `cmd/server/main.go`."
	got := extractAffectedPaths(in)
	wantAny := []string{"src/foo/bar.go", "cmd/server/main.go"}
	for _, w := range wantAny {
		if !containsString(got, w) {
			t.Errorf("missing %q in %v", w, got)
		}
	}
}

func TestExtractRequiredEnv(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			"backtick_assignment",
			"Only triggers when the environment variable `DEBUG=1` is set.",
			[]string{"DEBUG"},
		},
		{
			"upper_snake_env_keyword",
			"This requires `GO_ENABLE_FOO` env variable.",
			[]string{"GO_ENABLE_FOO"},
		},
		{
			"lowercase_ignored",
			"Set `enable_admin` to true.",
			nil,
		},
		{
			"no_env_context",
			"`SOMETHING` is referenced but not as an env var.",
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRequiredEnv(tt.in)
			if !equalStringSlice(got, tt.want) {
				t.Errorf("got %v want %v", got, tt.want)
			}
		})
	}
}

func TestExtractRequiredConfig(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantHit string
	}{
		{
			"by_setting",
			"by setting `allow_unsafe_html = true` you expose users",
			"allow_unsafe_html = true",
		},
		{
			"when_clause",
			"when `trusted_proxies` is set to wildcard",
			"trusted_proxies",
		},
		{
			"requires_flag",
			"requires the `--allow-root` flag",
			"--allow-root",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRequiredConfig(tt.in)
			if !containsString(got, tt.wantHit) {
				t.Errorf("got %v want contains %q", got, tt.wantHit)
			}
		})
	}
}

func TestIsLikelyEnvVar(t *testing.T) {
	cases := map[string]bool{
		"DEBUG":                true,
		"GO_DEBUG":             true,
		"NODE_ENV":             true,
		"NODE_ENV=development": true,
		"camelCase":            false,
		"lower":                false,
		"AB":                   false, // too short
		"":                     false,
	}
	for in, want := range cases {
		if got := isLikelyEnvVar(in); got != want {
			t.Errorf("isLikelyEnvVar(%q) = %v want %v", in, got, want)
		}
	}
}

func TestDedupeStrings(t *testing.T) {
	in := []string{"a", "a", "", " b ", "b"}
	got := dedupeStrings(in)
	want := []string{"a", "b"}
	if !equalStringSlice(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
	if dedupeStrings(nil) != nil {
		t.Error("nil input should yield nil output")
	}
}

// ============================================================================
// M44 Wave 2 (F470): npm-tuned prose extraction. GHSA/OSV npm advisories name
// vulnerable functions ONLY in markdown prose (no structured symbol source
// exists for npm), so the npm extractor accepts the shapes npm prose actually
// uses — bare export names (`defaultsDeep`), `pkg.method`, `_.method` — while
// gating on function context to keep precision.
// ============================================================================

func TestExtractVulnFuncsNpm(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{
			// Real GHSA-jf85-cpcp-j695 (lodash CVE-2019-10744) prose shape:
			// the bare export name adjacent to "function" must be accepted
			// WITHOUT a "vulnerable ... function" qualifier (the qualifier
			// requirement matched 2/100 real npm advisories — 2026-07-10
			// recon); the backticked PACKAGE name (`lodash`) and the
			// incidental `Object` reference must not leak in.
			"lodash_function_adjacent_bare_name",
			"Versions of `lodash` before 4.17.12 are vulnerable to Prototype Pollution. " +
				"The function `defaultsDeep` allows a malicious user to modify the prototype of `Object` " +
				"via {constructor: {prototype: {...}}} causing the addition of properties on all objects.",
			[]string{"defaultsDeep"},
		},
		{
			"function_word_after_backtick",
			"The `merge` function is vulnerable to prototype pollution.",
			[]string{"merge"},
		},
		{
			"method_word_with_call_parens_stripped",
			"the `escape()` method mishandles HTML entities",
			[]string{"escape"},
		},
		{
			// Dotted call chains are accepted when vulnerability keywords
			// appear near the token (function/method adjacency not required).
			"dotted_chain_with_context",
			"A crafted request to `auth.api.removeUser` allows unauthorized deletion in affected versions.",
			[]string{"auth.api.removeUser"},
		},
		{
			"lodash_underscore_binding",
			"Affected versions allow attackers to modify object properties via `_.merge`.",
			[]string{"_.merge"},
		},
		{
			// Non-function property access without function/vulnerability
			// context must be dropped (the headers.location class of noise —
			// 2026-07-10 recon).
			"property_access_without_context",
			"The redirect handler copies the request URL into `headers.location` before returning it.",
			nil,
		},
		{
			"url_dropped",
			"See `https://example.com/advisories/123` for details. This is vulnerable.",
			nil,
		},
		{
			"version_dropped",
			"Upgrade to `4.17.21` to fix this vulnerable behavior.",
			nil,
		},
		{
			// File names survive the JS-identifier shape check (handler + ts
			// are identifiers) so the extension denylist must drop them.
			"file_names_dropped",
			"The vulnerable code lives in `handler.ts` and `config.json`.",
			nil,
		},
		{
			"contextless_backtick_dropped",
			"Use `defaultsDeep` when merging configuration objects.",
			nil,
		},
		{
			"four_part_selector_dropped",
			"the vulnerable function `a.b.c.d` is exported",
			nil,
		},
		{
			"single_char_bare_token_dropped",
			"the `_` function is vulnerable",
			nil,
		},
		{
			"dedupe_across_rules",
			"The `merge` function is vulnerable. Calling the `merge` method is unsafe.",
			[]string{"merge"},
		},
		{
			"dollar_identifier_accepted",
			"The `$.extend` function is vulnerable to prototype pollution.",
			[]string{"$.extend"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractVulnFuncsNpm(tt.in)
			if !equalStringSlice(got, tt.want) {
				t.Errorf("got %v want %v", got, tt.want)
			}
		})
	}
}

// TestExtractVulnFuncsNpm_Cap pins the per-advisory output bound (aligned
// with the scheduler's 200-selector per-CVE cap): a degenerate advisory
// cannot balloon the extraction.
func TestExtractVulnFuncsNpm_Cap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 250; i++ {
		fmt.Fprintf(&b, "The function `fn%03d` is vulnerable. ", i)
	}
	got := ExtractVulnFuncsNpm(b.String())
	if len(got) != 200 {
		t.Fatalf("extracted %d tokens, want capped at 200", len(got))
	}
	if got[0] != "fn000" || got[199] != "fn199" {
		t.Errorf("cap must keep first-seen order: got[0]=%q got[199]=%q", got[0], got[199])
	}
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
