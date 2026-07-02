package handler

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestLLMProviderRegistryParity_F318 is the second horizontal replication
// of anti-pattern 58 (emit / registry parity in dual-list systems)
// outside the audit dimension (F271 Action / F281 Resource) and outside
// the Plan feature dimension (F299, the first horizontal replication —
// see model/plan_parity_test.go). The dual (in fact three-way) list
// here is the LLM Provider registry, which appears in three source
// files that must all agree on the set of provider identifiers:
//
//	(Go allowlist)  apps/api/internal/handler/settings_llm.go
//	                `supportedLLMProviders` map — the request-body
//	                validation set the Update handler consults so an
//	                arbitrary string cannot land in the DB.
//
//	(Go factory)    apps/api/internal/service/llm/factory.go
//	                `NewProviderFromEnv` + `NewProviderFromConfigWithAzure`
//	                switch arms — the construction dispatch that turns a
//	                provider string into a concrete Provider impl.
//
//	(Web dropdown)  apps/web/src/app/[locale]/(dashboard)/settings/llm/page.tsx
//	                `PROVIDERS` array literal — the UI select options
//	                and the client-side zod enum validator.
//
// (Plus a documentation touch-point:
//
//	(Go doc)        apps/api/internal/service/llm/provider.go
//	                Provider.Name() doc-comment listing the identifiers
//	                each build variant exposes.)
//
// If any two of these drift, one of the following silent breakage
// shapes results:
//
//   - handler map extended without factory switches: the API accepts a
//     provider string that then fails hard at Provider construction
//     time (500 at first LLM call).
//   - factory switches extended without handler map: the Update
//     endpoint rejects a provider the operator's env / DB row is happy
//     to construct (400 UI, working backend).
//   - web PROVIDERS extended without Go: the UI dropdown shows a
//     provider the backend rejects on save (400).
//   - Go extended without web PROVIDERS: the operator has to hand-edit
//     the DB row (or hit the API directly) because the dropdown does
//     not surface the option.
//
// Directions (F276 factuality trade-off, same pattern as F271 / F281 /
// F299):
//
//	(1) Direction 1 — Go registry ↔ factory switches: the key set of
//	    supportedLLMProviders must exactly equal the union of the
//	    `case "..."` arms parsed out of NewProviderFromEnv and
//	    NewProviderFromConfigWithAzure in factory.go. Two additional
//	    "intentional exclusion" allowlists document the two smaller
//	    switches that legitimately do not cover every provider
//	    (apiKeyEnvCandidates excludes ollama; embeddingModelFromEnv
//	    excludes anthropic + azure_openai — see the const block below
//	    for the F# reasons).
//
//	(2) Direction 2 — Go registry ↔ web PROVIDERS: the key set of
//	    supportedLLMProviders must exactly equal the string array
//	    literal parsed out of apps/web/src/app/[locale]/(dashboard)/
//	    settings/llm/page.tsx. Read-only file-system probe; the Go
//	    test does not modify the .tsx file.
//
//	(3) Direction 3 — doc factuality: the Provider.Name() doc-comment
//	    in provider.go must list exactly the OSS 5 + SaaS
//	    (managed_gemini) + disabled sentinel, in a shape a future
//	    reviewer can cross-check against this test.
//
// What THIS test DOES catch:
//
//   - Any provider added to supportedLLMProviders without adding to
//     NewProviderFromEnv / NewProviderFromConfigWithAzure switches
//     (silent 500-at-first-call shape).
//   - Any factory switch arm added without registering in
//     supportedLLMProviders (silent 400-on-save shape).
//   - Any web PROVIDERS array drift from the Go registry (silent UI
//     drift shape).
//   - provider.go Provider.Name() doc-comment drift from the actual
//     Go/SaaS registry surface (docstring factuality — F276 lineage,
//     see the M17 F266 + M18 F276 + M19 F284/F285/F295 + M20 F303/
//     F306/F310/F317 continuous wave).
//
// What THIS test does NOT catch (documented factuality trade-off,
// mirrors the F276 note on F271 / F281 / F299):
//
//   - Wire-value stability of a provider string. Both sides use the
//     same identifier; a coordinated rename ("openai" → "OpenAI") on
//     all four surfaces in the same PR would pass this test even
//     though it would break every operator's persisted config on
//     upgrade. Policing wire-value stability is out of scope for this
//     parity test (same trade-off as F271 / F281 / F299 documented).
//   - SaaS-only registry drift outside the //go:build saas tag.
//     managed_gemini's construction path lives in managed_gemini.go
//     which the OSS build cannot see; parity there is enforced by the
//     SaaS build's own tests (out of scope for this OSS-tagged test).
//   - Provider capability drift, e.g. embedding endpoint changes on
//     one provider — that is a capability descriptor concern
//     (provider.Capabilities()) not a registry-parity concern.
//   - The two smaller factory switches (apiKeyEnvCandidates,
//     embeddingModelFromEnv) that intentionally cover only a subset
//     of providers — these are handled through the exclusion
//     allowlists below, with F# reasons attached so a future wave
//     that changes their coverage tripped is a visible, deliberate
//     decision rather than a silent test-suite mutation.
//
// Adding a new LLM provider going forward: add the identifier to
// supportedLLMProviders in settings_llm.go AND to both factory switches
// in factory.go AND to the PROVIDERS array in page.tsx AND to the
// Provider.Name() doc-comment in provider.go. Add the identifier to no
// allowlist. Do not silence this test.
func TestLLMProviderRegistryParity_F318(t *testing.T) {
	// ------- Set-up: the authoritative Go registry -------

	registry := make(map[string]bool, len(supportedLLMProviders))
	for k := range supportedLLMProviders {
		registry[k] = true
	}
	if len(registry) == 0 {
		t.Fatalf("F318 setup: supportedLLMProviders is empty; either " +
			"the map was accidentally cleared or the test's " +
			"initialisation is broken. Aborting to avoid vacuously " +
			"passing all direction checks.")
	}

	// ------- Direction 1: Go registry ↔ factory switches -------

	factoryDir := factoryFileDir(t)
	factorySrc := readFileString(t, filepath.Join(factoryDir, "factory.go"))

	envSwitch := extractProviderCaseArms(t, factorySrc,
		`func NewProviderFromEnv`, "NewProviderFromEnv")
	cfgSwitch := extractProviderCaseArms(t, factorySrc,
		`func NewProviderFromConfigWithAzure`, "NewProviderFromConfigWithAzure")

	// Each of the two full switches must equal supportedLLMProviders exactly.
	assertSetEqual(t, "F318 direction 1 (NewProviderFromEnv ↔ registry)",
		envSwitch, registry)
	assertSetEqual(t, "F318 direction 1 (NewProviderFromConfigWithAzure ↔ registry)",
		cfgSwitch, registry)

	// Documented intentional exclusions for the two smaller switches
	// that legitimately cover only a subset of providers. Each entry
	// carries an F# reason so a future wave that changes coverage
	// tripped is a visible, deliberate decision.
	apiKeyKnownExclusions := map[string]string{
		"ollama": "F318: ollama uses a local HTTP endpoint (OLLAMA_HOST) " +
			"and requires no API key — apiKeyEnvCandidates is only " +
			"consulted for providers that require an API key.",
	}
	embeddingKnownExclusions := map[string]string{
		"anthropic": "F318: Anthropic Claude does not expose an embedding " +
			"API in the OSS build (Embed returns ErrNotImplemented in " +
			"anthropic.go); embeddingModelFromEnv therefore intentionally " +
			"omits it.",
		"azure_openai": "F318: Azure OpenAI embedding routes through a " +
			"separate deployment resolved via azureEmbeddingFromEnv() " +
			"(factory.go L424) rather than embeddingModelFromEnv, so it " +
			"is intentionally excluded from the latter's switch arms.",
	}

	apiKeySwitch := extractProviderCaseArms(t, factorySrc,
		`func apiKeyEnvCandidates`, "apiKeyEnvCandidates")
	assertSubsetWithExclusions(t,
		"F318 direction 1 (apiKeyEnvCandidates ⊆ registry, with documented exclusions)",
		apiKeySwitch, registry, apiKeyKnownExclusions)

	embeddingSwitch := extractProviderCaseArms(t, factorySrc,
		`func embeddingModelFromEnv`, "embeddingModelFromEnv")
	assertSubsetWithExclusions(t,
		"F318 direction 1 (embeddingModelFromEnv ⊆ registry, with documented exclusions)",
		embeddingSwitch, registry, embeddingKnownExclusions)

	// ------- Direction 2: Go registry ↔ web PROVIDERS -------

	webPath := webLLMPageAbs(t)
	webSrc, err := os.ReadFile(webPath)
	if err != nil {
		t.Fatalf("F318 direction 2 setup: cannot read web page.tsx at %s: %v",
			webPath, err)
	}
	webProviders := extractWebPROVIDERS(t, string(webSrc), webPath)
	assertSetEqual(t, "F318 direction 2 (web PROVIDERS ↔ Go registry)",
		webProviders, registry)

	// ------- Direction 3: doc factuality -------

	providerSrc := readFileString(t, filepath.Join(factoryDir, "provider.go"))
	assertProviderDocFactuality(t, providerSrc, registry)
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// factoryFileDir returns the absolute path of the directory that holds
// factory.go / provider.go regardless of the working directory the test
// was launched from. runtime.Caller anchors on this file's location.
func factoryFileDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("F318 setup: runtime.Caller failed")
	}
	// this file: apps/api/internal/handler/settings_llm_parity_test.go
	// target:    apps/api/internal/service/llm/
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile),
		"..", "service", "llm"))
}

// webLLMPageAbs returns the absolute path of the web settings/llm/page.tsx
// dropdown source, again anchored on this test file's location so the
// resolution is independent of the working directory.
func webLLMPageAbs(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("F318 setup: runtime.Caller failed")
	}
	// this file: apps/api/internal/handler/settings_llm_parity_test.go
	// target:    apps/web/src/app/[locale]/(dashboard)/settings/llm/page.tsx
	//   handler/ → internal/ (..) → api/ (..) → apps/ (..) → web/...
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile),
		"..", "..", "..", "web", "src", "app",
		"[locale]", "(dashboard)", "settings", "llm", "page.tsx"))
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("F318 setup: read %s: %v", path, err)
	}
	return string(raw)
}

// caseArmRe matches `case "identifier":` inside a Go switch. The
// identifier is captured. Anchored to the beginning of a line (after
// arbitrary whitespace) so it does not accidentally match strings
// inside doc comments that happen to include `case "..."`.
//
// F331 (M22-2, F326 close): the identifier char class is
// `[a-z0-9_\-]+`, not the pre-F331 `[a-z_]+` — a future provider
// identifier containing a digit or a hyphen (e.g. "llama3",
// "gemini-cli") would have been silently invisible to the pre-F331
// scan, making the parity assertion vacuously pass on the missed
// arm instead of tripping on the drift.
var caseArmRe = regexp.MustCompile(`(?m)^\s*case\s+"([a-z0-9_\-]+)":`)

// extractProviderCaseArms slices factory.go from the start of the
// named function to the next top-level `func ` (or EOF) and returns
// the set of provider identifiers appearing in `case "..":` arms
// inside that slice.
//
// This intentionally does NOT try to be a Go parser — the goal is a
// robust "grep in a bounded window" that survives whitespace / comment
// changes but fails loudly if the function's boundary shape changes
// in a way this simple slice cannot track. If the anchor is missed,
// the returned set will be empty and the assertSetEqual downstream
// will surface a large diff pointing straight at the source-scan
// problem.
func extractProviderCaseArms(t *testing.T, src, anchor, name string) map[string]bool {
	t.Helper()
	start := strings.Index(src, anchor)
	if start < 0 {
		t.Fatalf("F318 direction 1 setup: cannot locate %s anchor %q in "+
			"factory.go — the function may have been renamed or the "+
			"parity test needs its anchor updated.", name, anchor)
	}
	body := src[start:]
	// End the slice at the next top-level `func ` occurrence.
	if end := strings.Index(body[len(anchor):], "\nfunc "); end >= 0 {
		body = body[:len(anchor)+end]
	}
	matches := caseArmRe.FindAllStringSubmatch(body, -1)
	out := make(map[string]bool, len(matches))
	for _, m := range matches {
		out[m[1]] = true
	}
	return out
}

// assertSetEqual fails the test with a stable, sorted diff when two
// string sets are not equal.
func assertSetEqual(t *testing.T, label string, got, want map[string]bool) {
	t.Helper()
	missing := diffKeys(want, got)
	extra := diffKeys(got, want)
	if len(missing) == 0 && len(extra) == 0 {
		return
	}
	t.Errorf("%s: sets differ.\n  missing (in registry but not in scan): %v\n"+
		"  extra   (in scan but not in registry): %v",
		label, missing, extra)
}

// assertSubsetWithExclusions asserts that `got` is a subset of `want`,
// and that every member of `want` NOT covered by `got` appears in
// `exclusions` (which carries an F# reason string per excluded key).
// Used for the two smaller factory switches that legitimately do not
// cover every provider.
func assertSubsetWithExclusions(
	t *testing.T,
	label string,
	got, want map[string]bool,
	exclusions map[string]string,
) {
	t.Helper()
	// Every got key must appear in want.
	for k := range got {
		if !want[k] {
			t.Errorf("%s: switch case %q is not registered in "+
				"supportedLLMProviders — either add it to the registry "+
				"or remove the case arm.", label, k)
		}
	}
	// Every want key missing from got must appear in exclusions.
	for k := range want {
		if got[k] {
			continue
		}
		reason, ok := exclusions[k]
		if !ok {
			t.Errorf("%s: registry provider %q is not covered by this "+
				"switch and has no documented exclusion. Either add a "+
				"case arm for it or add an exclusions entry with an F# "+
				"reason explaining why the switch legitimately omits "+
				"this provider.", label, k)
			continue
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("%s: exclusion for provider %q has an empty reason "+
				"string; every exclusion must carry an F# reason for "+
				"future auditors.", label, k)
		}
	}
	// Every exclusion key must correspond to a real registry provider
	// (so a stale exclusion for a removed provider is caught).
	for k := range exclusions {
		if !want[k] {
			t.Errorf("%s: exclusion allowlist references provider %q "+
				"which is not in supportedLLMProviders — the allowlist "+
				"is stale and should be pruned.", label, k)
		}
	}
	// F324 (M21 Phase D R2, completeness — bidirectional stale-exclusion
	// detection): every exclusion entry must also refer to a provider
	// that is genuinely NOT covered by this switch. If the switch has
	// since been EXPANDED to cover an excluded provider (e.g. a future
	// wave adds `case "ollama":` to apiKeyEnvCandidates or a switch arm
	// to embeddingModelFromEnv), the exclusion entry becomes silently
	// obsolete: the F# reason no longer applies and the caller's claim
	// "this switch legitimately does not cover ollama" is factually
	// wrong. Pre-F324 assertSubsetWithExclusions only caught the
	// registry-shrink direction (a provider deleted from the registry
	// leaves a stale exclusion), matching the F318 head docstring's
	// four silent-drift shape claim only partially. F324 adds the
	// switch-expansion direction so both drift shapes trip CI. The
	// F271 shrink-pattern discipline (documented-exception allowlists
	// should shrink over time) is enforced in both directions: an
	// exclusion for a case the switch has since covered must be
	// removed, mirroring the parity contract's "grow deliberately,
	// shrink silently" rule.
	for k := range exclusions {
		if got[k] {
			t.Errorf("%s: exclusion allowlist entry for provider %q "+
				"is stale — the switch NOW covers this provider (case "+
				"arm present in `got`), so the F# reason for excluding "+
				"it no longer applies. Remove the exclusion entry so "+
				"the parity contract stays factually accurate.", label, k)
		}
	}
}

// diffKeys returns keys in a that are not in b, sorted for stable output.
func diffKeys(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// webProvidersRe extracts the string array literal from
//
//	const PROVIDERS = ["openai", "anthropic", ...] as const;
//
// in the web page.tsx. The outer capture is the raw comma-separated
// list including quotes; extractWebPROVIDERS parses that into a set.
var webProvidersRe = regexp.MustCompile(
	`(?s)const\s+PROVIDERS\s*=\s*\[([^\]]+)\]\s*as\s+const\s*;`)

// webQuotedRe extracts one quoted provider identifier from the
// PROVIDERS array literal body. F331 (M22-2, F326 close): the char
// class matches caseArmRe's `[a-z0-9_\-]+` so a digit- or
// hyphen-bearing provider identifier is scanned identically on the
// Go-factory and web-dropdown sides — a class mismatch between the
// two parsers would make one side silently drop the identifier and
// surface as a confusing one-sided parity diff.
var webQuotedRe = regexp.MustCompile(`"([a-z0-9_\-]+)"`)

// extractWebPROVIDERS finds the const PROVIDERS declaration in the
// supplied .tsx source and returns the set of quoted identifiers it
// enumerates. Fails loudly if the declaration is not found — a rename
// of the const (or a syntax change on the surrounding `as const`
// clause) is a review-required change that must update this parser.
func extractWebPROVIDERS(t *testing.T, src, path string) map[string]bool {
	t.Helper()
	m := webProvidersRe.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("F318 direction 2 setup: cannot locate `const PROVIDERS "+
			"= [...] as const;` in %s. Either the constant was renamed "+
			"or the surrounding syntax changed; update this parser.",
			path)
	}
	inner := m[1]
	quoted := webQuotedRe.FindAllStringSubmatch(inner, -1)
	if len(quoted) == 0 {
		t.Fatalf("F318 direction 2 setup: PROVIDERS array literal in %s "+
			"contained no quoted identifiers matching /\"[a-z0-9_\\-]+\"/. "+
			"Either the identifier syntax changed or the array is "+
			"empty — both need review.", path)
	}
	out := make(map[string]bool, len(quoted))
	for _, q := range quoted {
		out[q[1]] = true
	}
	return out
}

// assertProviderDocFactuality checks that the Provider.Name() doc
// comment in provider.go lists exactly the OSS registry + the SaaS
// managed_gemini + the disabled sentinel, in a shape a future reviewer
// can cross-check against this test.
//
// The check is deliberately loose on ordering / punctuation (regex
// with `/` separators) and tight on membership (every OSS provider
// from the registry must appear as a token, plus managed_gemini and
// disabled). This catches a wave that adds a provider to the registry
// but forgets to update the doc-comment (F276 factuality lineage
// continued into M21-1).
func assertProviderDocFactuality(t *testing.T, providerSrc string, registry map[string]bool) {
	t.Helper()
	// Locate the Provider interface's Name() doc comment via an
	// anchor-terminated slice (F331, M22-2, F326 close): the window
	// opens at the doc comment's first line and closes at the
	// `Name() string` declaration that terminates it. Pre-F331 the
	// window was a fixed 1200-byte back-slice from `Name() string`,
	// which would silently truncate the HEAD of the comment once
	// fixture growth (new providers / build variants added to the
	// identifier list) pushed the comment past 1200 bytes — a
	// missing-token false positive shape (the token is present in the
	// comment but outside the scanned window). Anchor-terminated
	// slicing tracks the comment's actual extent regardless of its
	// byte size; if either anchor is rephrased the test fails loudly
	// here instead of scanning the wrong window (same fail-loud
	// discipline as extractProviderCaseArms).
	const docStartAnchor = "// Name returns the provider identifier"
	docStart := strings.Index(providerSrc, docStartAnchor)
	if docStart < 0 {
		t.Fatalf("F318 direction 3 setup: cannot locate the Name() doc "+
			"comment start anchor %q in provider.go — the doc comment's "+
			"first line may have been rephrased; update this anchor.",
			docStartAnchor)
	}
	const docEndAnchor = "Name() string"
	relEnd := strings.Index(providerSrc[docStart:], docEndAnchor)
	if relEnd < 0 {
		t.Fatalf("F318 direction 3 setup: cannot locate the `Name() " +
			"string` end anchor after the doc comment start anchor in " +
			"provider.go — the interface may have been reshaped; update " +
			"this anchor pair.")
	}
	window := providerSrc[docStart : docStart+relEnd]

	// Every registered OSS provider must appear as a bare token in
	// the doc window.
	for provider := range registry {
		if !docHasToken(window, provider) {
			t.Errorf("F318 direction 3 failure: provider.go Name() doc "+
				"comment does not mention OSS provider %q. Update the "+
				"comment to list every provider the registry exposes.",
				provider)
		}
	}
	// The SaaS-only identifier and the sentinel must also appear so
	// the comment factually describes the full Name() surface across
	// build variants.
	if !docHasToken(window, "managed_gemini") {
		t.Errorf("F318 direction 3 failure: provider.go Name() doc " +
			"comment does not mention SaaS-only identifier " +
			"`managed_gemini`. Either update the comment or, if the " +
			"SaaS build no longer exposes this identifier, update this " +
			"test.")
	}
	if !docHasToken(window, "disabled") {
		t.Errorf("F318 direction 3 failure: provider.go Name() doc " +
			"comment does not mention the `disabled` sentinel returned " +
			"by DisabledProvider.Name(). Update the comment to describe " +
			"the full Name() surface.")
	}
}

// docHasToken returns true when `token` appears as a bare word in
// `src`, tolerant of surrounding whitespace, `/`, or punctuation. The
// check trims the src to a simple "contains token" but bounded by
// non-identifier boundary characters so `gemini` does not falsely
// match `managed_gemini`.
func docHasToken(src, token string) bool {
	// Cheap boundary check: prepend and append a space and require the
	// token to appear surrounded by either a slash, a space, or common
	// separator punctuation.
	//
	// This is intentionally simple rather than a full word-boundary
	// regex — the doc comment is authored prose and we do not want to
	// require exact punctuation. False negatives (missing token) are
	// caught by the assertion; false positives are unlikely because
	// the identifiers are highly specific ("azure_openai", etc.).
	re := regexp.MustCompile(`(^|[\s/(,\.])` + regexp.QuoteMeta(token) + `([\s/),\.]|$)`)
	return re.MatchString(src)
}
