// Command llm-bench compares Managed AI vs Local LLM quality on a fixed
// VEX-triage evaluation set so M4 can satisfy the PRODUCT_REBOOT_PLAN.md
// §13 M4 完了条件: "Managed AI と Local LLM の品質差が測定できる".
//
// The tool reads a JSON fixture (test/fixtures/llm-bench/cve-20-50.json
// by default), reuses the *exact* runtime triage prompt
// (triage.VEXTriageSystemPrompt + triage.BuildPrompt) so the bench
// measures the same prompt the production runner sends, and fans out
// to one or more configured BYOK providers. Results are emitted as
// JSON Lines (one line per (provider, case) pair) and optionally a
// markdown aggregation table to stderr.
//
// The bench is intentionally DB-write-free (no llm_calls / vex_drafts
// rows): comparing managed vs local quality must not pollute the
// per-tenant audit log with synthetic eval-set runs. F19's 2-stage
// shape (bounded ctx + concurrency cap) is preserved; F25's fan-out
// cap is applied via --max-cases.
//
// Usage:
//
//	go run ./cmd/llm-bench \
//	    --providers openai,anthropic,gemini,ollama \
//	    --eval-set test/fixtures/llm-bench/cve-20-50.json \
//	    --max-cases 20 --markdown --out result.jsonl
//
// Env (per provider):
//
//	OPENAI_API_KEY                    # openai
//	ANTHROPIC_API_KEY                 # anthropic
//	GOOGLE_API_KEY                    # gemini
//	SBOMHUB_LLM_API_KEY or            # azure_openai (key; canonical wins,
//	AZURE_OPENAI_API_KEY              #   AZURE_OPENAI_API_KEY is an alias)
//	SBOMHUB_LLM_AZURE_ENDPOINT or     # azure_openai (endpoint; canonical
//	AZURE_OPENAI_ENDPOINT             #   wins, AZURE_OPENAI_ENDPOINT alias)
//	SBOMHUB_LLM_AZURE_DEPLOYMENT or   # azure_openai (deployment; canonical
//	AZURE_OPENAI_DEPLOYMENT or        #   wins, then each Microsoft-documented
//	AZURE_OPENAI_DEPLOYMENT_NAME or   #   alias is consulted in turn (F59):
//	AZURE_OPENAI_CHAT_DEPLOYMENT_NAME #   bare > _NAME > CHAT_DEPLOYMENT_NAME)
//	SBOMHUB_LLM_AZURE_API_VERSION or  # azure_openai (api-version, optional;
//	AZURE_OPENAI_API_VERSION          #   canonical wins, alias fallback)
//	SBOMHUB_LLM_OLLAMA_URL or         # ollama (URL; canonical wins,
//	OLLAMA_HOST                       #   OLLAMA_HOST is an alias)
//	SBOMHUB_LLM_BENCH_OLLAMA_MODEL    # ollama (model, required)
//
// Exit codes (F42):
//
//	0  success
//	2  usage / flag validation error
//	3  fixture / config validation error
//	4  no providers available (no BYOK env configured)
//	5  execution / output failure (e.g. JSONL write failed)
//
// The same exit-code table is also surfaced via `llm-bench --help`
// (F48) so operators / CI pipelines do not have to read this comment
// to dispatch on failure mode.
//
// Reference: M4_AGENT_PROMPT_TEMPLATE.md §1.K (Provider 実装規律, F19, F25).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// allProviderNames lists every provider the bench knows how to spin up
// from env. "all" expands to this list (Ollama included; if Ollama is
// not reachable the per-case call surfaces a per-row error rather than
// blocking the whole run).
var allProviderNames = []string{"openai", "anthropic", "gemini", "azure_openai", "ollama"}

// Version / Commit / Date are populated by the release build via -ldflags
// "-X main.Version=... -X main.Commit=... -X main.Date=...". The defaults
// keep `go run ./cmd/llm-bench --version` working in source checkouts.
//
// M5 #54 (M5-2): goreleaser publishes a standalone `llm-bench` archive per
// release tag so sbomhub-cli's `sbomhub llm bench` wrapper can download a
// pre-built binary instead of `go run`-ing against a mounted sbomhub OSS
// source tree. The wrapper greps `--version` to decide whether the
// downloaded binary matches the expected release; do not rename or
// remove these fields without bumping the wrapper contract.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// firstNonEmptyEnv walks env names in canonical-first precedence and
// returns the first non-empty trimmed value (or "" if none set).
// Mirrors factory.resolveAPIKey / factory.resolveAzureField (M4 Codex
// review #F47 / #F52) so the bench's env contract matches what the
// runtime factory reads.
//
// ※要確認: the factory's own helpers are unexported. Exporting them
// would let the bench DRY this, but the bench's env contract also
// includes SBOMHUB_LLM_BENCH_<NAME>_MODEL overrides that have no
// runtime equivalent, so a 1:1 reuse isn't quite right. A small local
// helper keeps the bench env contract self-contained.
func firstNonEmptyEnv(names ...string) string {
	for _, name := range names {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v
		}
	}
	return ""
}

// cliFlags is the parsed command-line surface. Kept as a single struct
// so unit tests can drive the bench without re-parsing os.Args.
type cliFlags struct {
	providers      string
	evalSet        string
	maxCases       int
	out            string
	markdown       bool
	verbose        bool
	timeoutSec     int
	maxConcurrency int
	// showVersion is the M5 #54 fast-path: when --version is passed the
	// bench prints "llm-bench <Version> (<Commit>) built <Date>" on
	// stdout and exits 0 without touching providers, fixtures, or env.
	// sbomhub-cli's wrapper uses this to validate the downloaded binary
	// matches the expected release tag (M5-2 contract).
	showVersion bool
}

// parseFlags wires the CLI surface and parses argv into *cliFlags.
//
// F48 (M4 Codex review): the FlagSet's output is wired to the caller-
// supplied stderr writer (was io.Discard) and the Usage hook prints the
// flag list followed by the F42 exit-code contract. Without this, the
// package doc's exit-code table was discoverable only by reading the
// source — `llm-bench --help` printed nothing, so operators and CI
// pipelines had to scrape stderr text to map failure modes. Help is
// detected by realMain via errors.Is(err, flag.ErrHelp) and treated as
// a successful (exit 0) invocation.
func parseFlags(args []string, stderr io.Writer) (*cliFlags, error) {
	fs := flag.NewFlagSet("llm-bench", flag.ContinueOnError)
	fs.SetOutput(stderr) // F48: stderr (was io.Discard) so --help / parse errors print Usage.

	f := &cliFlags{}
	fs.StringVar(&f.providers, "providers", "all",
		"comma-separated provider names (openai,anthropic,gemini,azure_openai,ollama) or 'all'")
	fs.StringVar(&f.evalSet, "eval-set", "",
		"path to eval-set JSON fixture (required)")
	fs.IntVar(&f.maxCases, "max-cases", 50,
		"F25 fan-out cap: maximum eval cases per provider (default 50)")
	fs.StringVar(&f.out, "out", "",
		"path to JSONL output file (default: stdout)")
	fs.BoolVar(&f.markdown, "markdown", false,
		"emit an aggregation markdown table on stderr")
	fs.BoolVar(&f.verbose, "verbose", false,
		"enable debug-level slog output")
	fs.IntVar(&f.timeoutSec, "timeout", 60,
		"F19 bounded-context cap per LLM call, in seconds (default 60)")
	fs.IntVar(&f.maxConcurrency, "max-concurrency", 4,
		"max parallel LLM calls across all (provider, case) pairs (default 4)")
	// M5 #54 (M5-2): --version exits 0 after printing the ldflags-injected
	// release identity. Wired as a normal bool flag so it composes with
	// flag.ErrHelp / parseFlags' existing error contract; realMain
	// short-circuits on it after parse succeeds so we do not require
	// --eval-set just to print the version.
	fs.BoolVar(&f.showVersion, "version", false,
		"print release version (set by goreleaser ldflags) and exit 0")

	// F48: Usage prints flag list + F42 exit-code contract so operators
	// can map exit codes without reading the source. Kept in sync with
	// the exitOK / exitUsageError / ... constants below — if you add a
	// new exit code, add a line here too.
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: llm-bench [flags]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Compare Managed AI vs Local LLM quality on a fixed VEX-triage eval-set.")
		fmt.Fprintln(stderr, "Results are emitted as JSON Lines (one row per (provider, case) pair).")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Flags:")
		fs.PrintDefaults()
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Exit codes (F42):")
		fmt.Fprintln(stderr, "  0  Success")
		fmt.Fprintln(stderr, "  2  Usage / flag validation error")
		fmt.Fprintln(stderr, "  3  Fixture / config validation error")
		fmt.Fprintln(stderr, "  4  No providers available (env not set for any provider)")
		fmt.Fprintln(stderr, "  5  Execution / output failure (e.g. JSONL write failed)")
	}

	if err := fs.Parse(args); err != nil {
		// flag.ErrHelp is returned when --help / -h is seen with
		// ContinueOnError; realMain detects it and exits 0. We keep the
		// wrap with %w so errors.Is downstream still matches.
		return nil, fmt.Errorf("parse flags: %w", err)
	}
	// M5 #54 (M5-2): --version is a fast-path that bypasses the rest of
	// the validation chain (eval-set / max-cases / timeout / concurrency
	// are irrelevant when only the build identity is requested). realMain
	// observes f.showVersion right after parseFlags returns and exits 0.
	if f.showVersion {
		return f, nil
	}
	if f.evalSet == "" {
		return nil, fmt.Errorf("--eval-set is required")
	}
	if f.maxCases <= 0 {
		return nil, fmt.Errorf("--max-cases must be > 0 (got %d)", f.maxCases)
	}
	if f.timeoutSec <= 0 {
		return nil, fmt.Errorf("--timeout must be > 0 (got %d)", f.timeoutSec)
	}
	if f.maxConcurrency <= 0 {
		return nil, fmt.Errorf("--max-concurrency must be > 0 (got %d)", f.maxConcurrency)
	}
	return f, nil
}

// resolveProviderNames expands "all" and validates each requested name
// against allProviderNames. Names are normalised to lower-case and
// deduped while preserving the order in allProviderNames so the
// JSONL / markdown output is deterministic regardless of CLI input.
func resolveProviderNames(raw string) ([]string, error) {
	requested := []string{}
	for _, p := range strings.Split(raw, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		requested = append(requested, p)
	}
	if len(requested) == 0 {
		return nil, fmt.Errorf("no provider names supplied")
	}
	if len(requested) == 1 && requested[0] == "all" {
		// Return a copy so callers can mutate without poisoning the const.
		out := make([]string, len(allProviderNames))
		copy(out, allProviderNames)
		return out, nil
	}
	// Validate each requested name + dedupe by re-projecting through the
	// canonical order so output is stable. This matters because the
	// markdown aggregation prints rows in slice order and a determinism
	// regression would silently re-order historical bench reports.
	known := map[string]bool{}
	for _, p := range allProviderNames {
		known[p] = true
	}
	seen := map[string]bool{}
	for _, p := range requested {
		if !known[p] {
			return nil, fmt.Errorf("unknown provider %q (expected one of %s, or 'all')",
				p, strings.Join(allProviderNames, ","))
		}
		seen[p] = true
	}
	out := []string{}
	for _, p := range allProviderNames {
		if seen[p] {
			out = append(out, p)
		}
	}
	return out, nil
}

// providerSpec captures the env-resolved BYOK config for one provider.
// model defaults are handled inside llm.NewProviderFromConfigWithAzure
// (each provider has its own sensible default; we pass through the env
// override when present).
type providerSpec struct {
	name            string
	model           string
	apiKey          string
	azureEndpoint   string
	azureDeployment string
	azureAPIVersion string
	ollamaURL       string
	skipReason      string // non-empty → provider was requested but cannot run; bench logs warning + skips
}

// resolveProviderSpec reads env for one provider. The env names follow
// the existing sbomhub OSS contract (project CLAUDE.md > LLM Provider
// Policy): OPENAI_API_KEY / ANTHROPIC_API_KEY / GOOGLE_API_KEY. For
// Ollama the base URL may be supplied via SBOMHUB_LLM_OLLAMA_URL
// (canonical, factory-internal — see llm.EnvOllamaURL) or OLLAMA_HOST
// (Ollama project's official env, accepted here as an alias for
// operator muscle-memory); SBOMHUB_LLM_OLLAMA_URL wins when both are
// set. Azure OpenAI uses the SBOMHUB_LLM_AZURE_* trio that the factory
// already validates (no separate bench env contract).
//
// Per-provider model overrides come from SBOMHUB_LLM_BENCH_<NAME>_MODEL
// so a bench run can target a specific managed-vs-local pair without
// polluting the runtime SBOMHUB_LLM_MODEL env (which the dev server
// also reads).
//
// Returns a spec with skipReason set when a required env var is missing.
// The bench logs the skip + moves on rather than aborting the whole run
// — the operator may legitimately want to compare only the two
// providers they have keys for.
func resolveProviderSpec(name string) providerSpec {
	spec := providerSpec{name: name}
	envModel := strings.TrimSpace(os.Getenv("SBOMHUB_LLM_BENCH_" + strings.ToUpper(name) + "_MODEL"))
	spec.model = envModel
	switch name {
	case "openai":
		spec.apiKey = strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
		if spec.apiKey == "" {
			spec.skipReason = "OPENAI_API_KEY is not set"
		}
	case "anthropic":
		spec.apiKey = strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
		if spec.apiKey == "" {
			spec.skipReason = "ANTHROPIC_API_KEY is not set"
		}
	case "gemini":
		spec.apiKey = strings.TrimSpace(os.Getenv("GOOGLE_API_KEY"))
		if spec.apiKey == "" {
			spec.skipReason = "GOOGLE_API_KEY is not set"
		}
	case "azure_openai":
		// F53 alignment with F47 + F52: each Azure field walks the same
		// canonical-first precedence the runtime factory uses, so an
		// Azure-only operator who set the Microsoft-documented envs
		// (AZURE_OPENAI_API_KEY + AZURE_OPENAI_ENDPOINT +
		// AZURE_OPENAI_API_VERSION + AZURE_OPENAI_DEPLOYMENT) can bench
		// without also exporting the SBOMHUB_LLM_* canonical envs. Pre-F53
		// the bench only read SBOMHUB_LLM_AZURE_* so the same operator
		// got "azure_openai skipped: SBOMHUB_LLM_API_KEY is not set"
		// and an exit-4 even though their Azure-side config was complete.
		//
		// F59: deployment now also accepts AZURE_OPENAI_DEPLOYMENT_NAME
		// (Microsoft Learn AKS OpenAI quickstart) and
		// AZURE_OPENAI_CHAT_DEPLOYMENT_NAME (Azure Agent Framework).
		// The list must stay in lockstep with factory.go's
		// azureFieldEnvCandidates("deployment") — adding a new variant
		// in one place without the other reintroduces the "factory
		// resolves, bench skips" split-brain F53 was meant to fix.
		spec.apiKey = firstNonEmptyEnv("SBOMHUB_LLM_API_KEY", llm.EnvAzureAPIKey)
		spec.azureEndpoint = firstNonEmptyEnv(llm.EnvAzureEndpoint, llm.EnvAzureEndpointAlias)
		spec.azureAPIVersion = firstNonEmptyEnv(llm.EnvAzureAPIVersion, llm.EnvAzureAPIVersionAlias)
		spec.azureDeployment = firstNonEmptyEnv(
			llm.EnvAzureDeployment,
			llm.EnvAzureDeploymentAlias,
			llm.EnvAzureDeploymentNameAlias,
			llm.EnvAzureChatDeploymentNameAlias,
		)
		if spec.apiKey == "" {
			spec.skipReason = "neither SBOMHUB_LLM_API_KEY nor " + llm.EnvAzureAPIKey + " is set"
		} else if spec.azureEndpoint == "" {
			spec.skipReason = "neither " + llm.EnvAzureEndpoint + " nor " + llm.EnvAzureEndpointAlias + " is set"
		} else if spec.azureDeployment == "" {
			// F59: skipReason names every deployment env the bench
			// consulted so an operator who typo'd one of the four
			// names can diff against their shell env. The list MUST
			// match the firstNonEmptyEnv call above byte-for-byte.
			spec.skipReason = "none of " + strings.Join([]string{
				llm.EnvAzureDeployment,
				llm.EnvAzureDeploymentAlias,
				llm.EnvAzureDeploymentNameAlias,
				llm.EnvAzureChatDeploymentNameAlias,
			}, ", ") + " is set"
		}
	case "ollama":
		// Ollama is local; no API key. Model is required (no auto-detect
		// in the factory either — see factory.go ※要確認).
		//
		// F41 fix: precedence is SBOMHUB_LLM_OLLAMA_URL (canonical env
		// the factory reads, see llm.EnvOllamaURL) > OLLAMA_HOST (Ollama
		// project's official env, retained as an alias for operator
		// muscle-memory) > factory default (http://localhost:11434).
		// Before F41 the bench only read OLLAMA_HOST and exported it,
		// but the factory's ollamaBaseURLFromEnv only reads
		// SBOMHUB_LLM_OLLAMA_URL, so the value was silently dropped.
		spec.ollamaURL = strings.TrimSpace(os.Getenv(llm.EnvOllamaURL))
		if spec.ollamaURL == "" {
			spec.ollamaURL = strings.TrimSpace(os.Getenv("OLLAMA_HOST"))
		}
		if spec.ollamaURL == "" {
			// Match the factory default so a stock `ollama serve` on
			// localhost works out of the box.
			spec.ollamaURL = "http://localhost:11434"
		}
		if spec.model == "" {
			spec.skipReason = "SBOMHUB_LLM_BENCH_OLLAMA_MODEL is not set (no auto-detect; set e.g. qwen2.5-coder:7b)"
		}
	default:
		spec.skipReason = "unknown provider"
	}
	return spec
}

// buildProvider materialises an llm.Provider from a spec. The factory
// helper (NewProviderFromConfigWithAzure) is the same one the runtime
// resolver uses, so the bench exercises the production provider
// construction path verbatim.
//
// SECURITY: spec.apiKey is the raw secret. We do NOT log it.
func buildProvider(spec providerSpec) (llm.Provider, error) {
	// Ollama is the only provider that needs its base URL fed in via
	// env at factory call time (the factory's NewProviderFromConfig
	// re-reads SBOMHUB_LLM_OLLAMA_URL via ollamaBaseURLFromEnv — see
	// factory.go). For all other providers the existing env-driven
	// defaults are sufficient.
	//
	// F41 fix: write to the canonical env (llm.EnvOllamaURL) the factory
	// reads, not OLLAMA_HOST. The previous Setenv("OLLAMA_HOST", ...)
	// was a silent no-op because ollamaBaseURLFromEnv never consults
	// OLLAMA_HOST, so the operator's non-default base URL was discarded
	// and Ollama always hit http://localhost:11434.
	if spec.name == "ollama" && spec.ollamaURL != "" {
		_ = os.Setenv(llm.EnvOllamaURL, spec.ollamaURL)
	}
	return llm.NewProviderFromConfigWithAzure(
		spec.name, spec.model, spec.apiKey,
		spec.azureEndpoint, spec.azureDeployment, spec.azureAPIVersion,
	)
}

// Exit codes (F42). Documented in the package doc so operators /
// CI pipelines can distinguish failure modes without parsing the
// stderr message. Anything outside this list is a bug.
const (
	exitOK              = 0
	exitUsageError      = 2 // flag parse, missing required flag, unknown provider name
	exitConfigError     = 3 // fixture load / schema validation failure
	exitNoProviders     = 4 // every requested provider skipped (no BYOK env configured)
	exitExecutionFailed = 5 // provider run / output write failure (JSONL write, etc.)
)

// exitError carries the typed exit code F42 introduced. main() reads
// .Code to choose the os.Exit value; tests inspect .Code to assert the
// classification rather than scraping stderr text.
//
// A nil *exitError means success — callers should check `if ee != nil`,
// not `if ee.Err != nil`, because that's a typed-nil trap.
type exitError struct {
	Code int
	Err  error
}

func (e *exitError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *exitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func newExitError(code int, err error) *exitError {
	if err == nil {
		return nil
	}
	return &exitError{Code: code, Err: err}
}

func main() {
	if ee := realMain(os.Args[1:], os.Stdout, os.Stderr); ee != nil {
		fmt.Fprintln(os.Stderr, "llm-bench:", ee.Err)
		os.Exit(ee.Code)
	}
}

// realMain is the test-friendly entry point. It takes stdout / stderr
// explicitly so unit tests can capture both streams without redirecting
// os.Stdout / os.Stderr globally.
//
// Returns nil on success, or a typed *exitError whose Code matches the
// contract in the package doc (F42). Callers must use the typed-nil
// pattern (`if ee := realMain(...); ee != nil`) not `err != nil`.
func realMain(args []string, stdout, stderr io.Writer) *exitError {
	flags, err := parseFlags(args, stderr)
	if err != nil {
		// F48: --help / -h is a successful invocation. flag.Parse already
		// printed the Usage text (via the FlagSet's Usage hook), so we
		// just exit 0 without surfacing an error or echoing the wrap.
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return newExitError(exitUsageError, err)
	}
	// M5 #54 (M5-2): --version is the goreleaser-injected release identity.
	// Printed to stdout (the F48 help text goes to stderr; --version is a
	// machine-parseable contract sbomhub-cli's wrapper greps, so the stream
	// choice matters). Exit 0; do not consult fixture / providers.
	if flags.showVersion {
		fmt.Fprintf(stdout, "llm-bench %s (%s) built %s\n", Version, Commit, Date)
		return nil
	}

	// Wire slog so per-case warnings (skipped providers, transport
	// errors) surface on stderr regardless of where the JSONL stream
	// lands.
	level := slog.LevelInfo
	if flags.verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))

	providerNames, err := resolveProviderNames(flags.providers)
	if err != nil {
		// Unknown / empty provider names are a CLI usage problem, not
		// a fixture problem — distinguish so CI can route the failure.
		return newExitError(exitUsageError, err)
	}

	// Load + cap the eval-set BEFORE building providers so a bad
	// fixture is surfaced before we spend API calls. F25 fan-out cap
	// is applied by capCases.
	cases, err := loadEvalSet(flags.evalSet)
	if err != nil {
		return newExitError(exitConfigError, fmt.Errorf("load eval-set %s: %w", flags.evalSet, err))
	}
	cases = capCases(cases, flags.maxCases)
	logger.Info("eval-set loaded", "path", flags.evalSet, "case_count", len(cases))

	// Materialise providers (skips missing-key entries with a warning).
	providers := []namedProvider{}
	for _, name := range providerNames {
		spec := resolveProviderSpec(name)
		if spec.skipReason != "" {
			logger.Warn("skipping provider (BYOK env not configured)",
				"provider", name, "reason", spec.skipReason)
			continue
		}
		p, err := buildProvider(spec)
		if err != nil {
			logger.Warn("skipping provider (factory error)",
				"provider", name, "error", err)
			continue
		}
		// DisabledProvider is the factory's fallback when env validation
		// fails (e.g. azure_openai with missing endpoint). The bench
		// surfaces this the same way as skipReason.
		if _, ok := p.(*llm.DisabledProvider); ok {
			logger.Warn("skipping provider (factory returned DisabledProvider)",
				"provider", name)
			continue
		}
		providers = append(providers, namedProvider{name: name, provider: p, model: spec.model})
	}
	if len(providers) == 0 {
		return newExitError(exitNoProviders, fmt.Errorf("no providers available: set at least one of OPENAI_API_KEY / ANTHROPIC_API_KEY / GOOGLE_API_KEY / (SBOMHUB_LLM_API_KEY|AZURE_OPENAI_API_KEY)+(SBOMHUB_LLM_AZURE_ENDPOINT|AZURE_OPENAI_ENDPOINT)+(SBOMHUB_LLM_AZURE_DEPLOYMENT|AZURE_OPENAI_DEPLOYMENT|AZURE_OPENAI_DEPLOYMENT_NAME|AZURE_OPENAI_CHAT_DEPLOYMENT_NAME) / SBOMHUB_LLM_BENCH_OLLAMA_MODEL"))
	}

	// Decide JSONL sink. We default to stdout so the operator can pipe
	// directly into jq; --out overrides for repeatable runs.
	var jsonlSink io.Writer = stdout
	if flags.out != "" {
		f, err := os.Create(flags.out)
		if err != nil {
			// File creation is an output-side failure (disk full,
			// permission, parent missing). Exit 5 keeps it distinct
			// from "no providers" / fixture errors.
			return newExitError(exitExecutionFailed, fmt.Errorf("create --out file: %w", err))
		}
		defer f.Close()
		jsonlSink = f
	}

	// F19: bounded ctx + concurrency cap. The bench drives the
	// concurrency limiter itself rather than reusing the triage
	// runner's TxManager (which is DB-coupled). Each (provider, case)
	// pair is one bounded-ctx call.
	ctx := context.Background()
	timeout := time.Duration(flags.timeoutSec) * time.Second
	results, err := runBench(ctx, logger, providers, cases, runOptions{
		Timeout:        timeout,
		MaxConcurrency: flags.maxConcurrency,
		JSONLWriter:    jsonlSink,
	})
	if err != nil {
		// runBench returns non-nil only for unrecoverable execution
		// failures (e.g. JSONL writer broke mid-run — see F43). Per-call
		// transport errors are folded into CaseResult.Error and do NOT
		// surface here.
		return newExitError(exitExecutionFailed, fmt.Errorf("run bench: %w", err))
	}

	if flags.markdown {
		// Aggregation table goes to stderr so it does not contaminate
		// the JSONL stream on stdout. Operators that only want the
		// table can run with --out /dev/null --markdown.
		summary := aggregate(results)
		fmt.Fprintln(stderr, renderMarkdown(summary, len(cases)))
	}

	logger.Info("bench complete",
		"provider_count", len(providers),
		"case_count", len(cases),
		"result_count", len(results))
	return nil
}
