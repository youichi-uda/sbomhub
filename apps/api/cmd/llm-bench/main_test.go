package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// fakeProvider is a Provider stub that returns canned per-case
// responses. The bench's per-case logic looks up the case_id inside
// the rendered prompt (BuildPrompt includes the CVE id, which we use
// as the routing key) to pick which canned response to emit.
type fakeProvider struct {
	name        string
	model       string
	responses   map[string]string // CVEID → JSON body to return
	err         error
	inputTokens int
	outputTokens int
}

var _ llm.Provider = (*fakeProvider)(nil)

func (f *fakeProvider) Name() string                  { return f.name }
func (f *fakeProvider) Model() string                 { return f.model }
func (f *fakeProvider) Capabilities() llm.Capabilities { return llm.Capabilities{} }
func (f *fakeProvider) Embed(_ context.Context, _ llm.EmbedRequest) (*llm.EmbedResponse, error) {
	return nil, llm.ErrNotImplemented
}

func (f *fakeProvider) Complete(_ context.Context, req llm.CompleteRequest) (*llm.CompleteResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	// Extract the CVE id from the user prompt — triage.BuildPrompt
	// prints "CVE: <id>" on the first line, which is our routing key.
	body := ""
	for _, m := range req.Messages {
		if strings.Contains(m.Content, "CVE:") {
			body = m.Content
			break
		}
	}
	cveID := ""
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "CVE:") {
			cveID = strings.TrimSpace(strings.TrimPrefix(line, "CVE:"))
			break
		}
	}
	resp, ok := f.responses[cveID]
	if !ok {
		// Default: emit an under_investigation verdict with one
		// llm_rationale evidence pointer so ParseLLMResponse + the
		// evidence-validator both pass.
		resp = `{"state":"under_investigation","confidence":0.5,"detail":"no canned response","evidence":[{"kind":"llm_rationale","description":"fake provider default","source":"llm"}]}`
	}
	return &llm.CompleteResponse{
		Content:      resp,
		InputTokens:  f.inputTokens,
		OutputTokens: f.outputTokens,
		Model:        f.model,
	}, nil
}

// TestParseFlags exercises the flag surface, including the required
// --eval-set guard.
func TestParseFlags(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		f, err := parseFlags([]string{"--eval-set", "x.json"})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if f.providers != "all" {
			t.Errorf("default providers = %q, want all", f.providers)
		}
		if f.maxCases != 50 {
			t.Errorf("default max-cases = %d, want 50", f.maxCases)
		}
		if f.maxConcurrency != 4 {
			t.Errorf("default max-concurrency = %d, want 4", f.maxConcurrency)
		}
		if f.timeoutSec != 60 {
			t.Errorf("default timeout = %d, want 60", f.timeoutSec)
		}
	})
	t.Run("eval-set required", func(t *testing.T) {
		_, err := parseFlags([]string{})
		if err == nil {
			t.Fatal("expected error when --eval-set missing")
		}
	})
	t.Run("max-cases must be positive", func(t *testing.T) {
		_, err := parseFlags([]string{"--eval-set", "x", "--max-cases", "0"})
		if err == nil {
			t.Fatal("expected error when --max-cases=0")
		}
	})
	t.Run("max-concurrency must be positive", func(t *testing.T) {
		_, err := parseFlags([]string{"--eval-set", "x", "--max-concurrency", "-1"})
		if err == nil {
			t.Fatal("expected error when --max-concurrency=-1")
		}
	})
	t.Run("timeout must be positive", func(t *testing.T) {
		_, err := parseFlags([]string{"--eval-set", "x", "--timeout", "0"})
		if err == nil {
			t.Fatal("expected error when --timeout=0")
		}
	})
}

// TestResolveProviderNames pins canonical ordering — the markdown
// table determinism guarantee depends on this.
func TestResolveProviderNames(t *testing.T) {
	t.Run("all expands", func(t *testing.T) {
		got, err := resolveProviderNames("all")
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"openai", "anthropic", "gemini", "azure_openai", "ollama"}
		if !equalSlice(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
	t.Run("dedupes and re-projects to canonical order", func(t *testing.T) {
		// Even when the operator supplies ollama before openai, the
		// output preserves allProviderNames order. Markdown table
		// columns then stay byte-equal across CLI invocations.
		got, err := resolveProviderNames("ollama,openai,openai")
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"openai", "ollama"}
		if !equalSlice(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
	t.Run("rejects unknown provider", func(t *testing.T) {
		_, err := resolveProviderNames("openai,acme")
		if err == nil {
			t.Fatal("expected error for unknown provider")
		}
	})
	t.Run("rejects empty input", func(t *testing.T) {
		_, err := resolveProviderNames("")
		if err == nil {
			t.Fatal("expected error for empty providers list")
		}
	})
}

func equalSlice[T comparable](a, b []T) bool {
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

// TestLoadEvalSet covers the happy path + each validation branch.
func TestLoadEvalSet(t *testing.T) {
	dir := t.TempDir()

	t.Run("valid fixture loads", func(t *testing.T) {
		path := writeFixture(t, dir, "ok.json", `{
			"version": 1,
			"cases": [
				{
					"case_id": "case-1",
					"cve_id": "CVE-2024-0001",
					"advisory_excerpt": "RCE via deserialization in foo.Bar()",
					"component_name": "foo",
					"component_version": "1.2.3",
					"ecosystem": "go",
					"code_reachability": {"reachable": false, "evidence": ["foo.Bar not in import closure"]},
					"expected_state": "not_affected"
				}
			]
		}`)
		cases, err := loadEvalSet(path)
		if err != nil {
			t.Fatalf("loadEvalSet: %v", err)
		}
		if len(cases) != 1 {
			t.Fatalf("expected 1 case, got %d", len(cases))
		}
		if cases[0].ExpectedState != "not_affected" {
			t.Errorf("unexpected expected_state: %q", cases[0].ExpectedState)
		}
	})

	t.Run("empty case list is rejected", func(t *testing.T) {
		path := writeFixture(t, dir, "empty.json", `{"version":1,"cases":[]}`)
		_, err := loadEvalSet(path)
		if err == nil {
			t.Fatal("expected error for empty cases")
		}
	})

	t.Run("invalid expected_state is rejected", func(t *testing.T) {
		path := writeFixture(t, dir, "badstate.json", `{
			"version":1,
			"cases":[{
				"case_id":"c","cve_id":"CVE-X","advisory_excerpt":"x",
				"component_name":"n","ecosystem":"go",
				"code_reachability":{"reachable":false,"evidence":[]},
				"expected_state":"maybe"
			}]
		}`)
		_, err := loadEvalSet(path)
		if err == nil {
			t.Fatal("expected error for unknown expected_state")
		}
	})

	t.Run("missing required field is rejected", func(t *testing.T) {
		path := writeFixture(t, dir, "missingid.json", `{
			"version":1,
			"cases":[{
				"cve_id":"CVE-X","advisory_excerpt":"x",
				"component_name":"n","ecosystem":"go",
				"code_reachability":{"reachable":false,"evidence":[]},
				"expected_state":"not_affected"
			}]
		}`)
		_, err := loadEvalSet(path)
		if err == nil {
			t.Fatal("expected error for missing case_id")
		}
	})
}

func writeFixture(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// TestCapCases enforces the F25 fan-out cap is applied as a truncation
// rather than a sample (determinism requirement).
func TestCapCases(t *testing.T) {
	in := []EvalCase{{CaseID: "a"}, {CaseID: "b"}, {CaseID: "c"}}
	got := capCases(in, 2)
	if len(got) != 2 || got[0].CaseID != "a" || got[1].CaseID != "b" {
		t.Errorf("capCases truncation broken: %+v", got)
	}
	// cap >= len is a no-op.
	got = capCases(in, 5)
	if len(got) != 3 {
		t.Errorf("expected no-op for cap >= len, got len=%d", len(got))
	}
	// cap <= 0 is a no-op (cap is optional from the caller side).
	got = capCases(in, 0)
	if len(got) != 3 {
		t.Errorf("expected no-op for cap=0, got len=%d", len(got))
	}
}

// TestRunBench exercises the end-to-end orchestration with a fake
// provider so we cover bounded ctx, JSONL writer concurrency, and the
// error-fold path without touching real APIs.
func TestRunBench(t *testing.T) {
	cases := []EvalCase{
		{
			CaseID: "c1", CVEID: "CVE-2024-0001",
			AdvisoryExcerpt: "rce", ComponentName: "foo", Ecosystem: "go",
			CodeReachability: CodeReachability{Reachable: false, Evidence: []string{"unused"}},
			ExpectedState:    "not_affected",
		},
		{
			CaseID: "c2", CVEID: "CVE-2024-0002",
			AdvisoryExcerpt: "rce", ComponentName: "bar", Ecosystem: "npm",
			CodeReachability: CodeReachability{Reachable: true, Evidence: []string{"called from index.js"}},
			ExpectedState:    "affected",
		},
	}
	notAffectedJSON := `{"state":"not_affected","justification":"code_not_reachable","confidence":0.9,"evidence":[{"kind":"llm_rationale","description":"unreachable","source":"llm"}]}`
	affectedJSON := `{"state":"affected","confidence":0.85,"evidence":[{"kind":"llm_rationale","description":"reachable","source":"llm"}]}`

	providers := []namedProvider{
		{
			name: "openai", model: "gpt-4o-mini",
			provider: &fakeProvider{
				name: "openai", model: "gpt-4o-mini",
				inputTokens: 500, outputTokens: 50,
				responses: map[string]string{
					"CVE-2024-0001": notAffectedJSON,
					"CVE-2024-0002": affectedJSON,
				},
			},
		},
		{
			name: "anthropic", model: "claude-3-5-haiku-20241022",
			provider: &fakeProvider{
				name: "anthropic", model: "claude-3-5-haiku-20241022",
				inputTokens: 500, outputTokens: 50,
				responses: map[string]string{
					// Anthropic gets c1 right, c2 wrong (says not_affected
					// when ground truth is affected). Bench should record
					// precision=0.5 for this provider.
					"CVE-2024-0001": notAffectedJSON,
					"CVE-2024-0002": notAffectedJSON,
				},
			},
		},
	}

	var jsonl bytes.Buffer
	results, err := runBench(context.Background(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		providers, cases,
		runOptions{
			Timeout:        5 * time.Second,
			MaxConcurrency: 2,
			JSONLWriter:    &jsonl,
			Clock:          func() time.Time { return time.Unix(0, 0) }, // deterministic latency=0
		},
	)
	if err != nil {
		t.Fatalf("runBench: %v", err)
	}
	if want := len(providers) * len(cases); len(results) != want {
		t.Fatalf("expected %d results, got %d", want, len(results))
	}

	// Verify JSONL stream contains one line per (provider, case).
	lines := strings.Split(strings.TrimSpace(jsonl.String()), "\n")
	if len(lines) != len(providers)*len(cases) {
		t.Errorf("expected %d JSONL lines, got %d", len(providers)*len(cases), len(lines))
	}
	for i, line := range lines {
		var row CaseResult
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Errorf("line %d: invalid JSON: %v\n%s", i, err, line)
		}
	}

	// Aggregation should report precision=1.0 for openai (both correct)
	// and precision=0.5 for anthropic (one correct out of two).
	summary := aggregate(results)
	if len(summary) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(summary))
	}
	// Alphabetical ordering: anthropic, openai.
	if summary[0].Provider != "anthropic" || summary[1].Provider != "openai" {
		t.Errorf("provider ordering not alphabetical: %+v / %+v", summary[0], summary[1])
	}
	if summary[1].Precision != 1.0 {
		t.Errorf("openai precision = %v, want 1.0", summary[1].Precision)
	}
	if summary[0].Precision != 0.5 {
		t.Errorf("anthropic precision = %v, want 0.5", summary[0].Precision)
	}
}

// TestRunBenchErrorFold covers F13 redact + error-isolation: a
// provider that returns an error should produce a JSONL row with
// error populated, not abort the whole bench.
func TestRunBenchErrorFold(t *testing.T) {
	cases := []EvalCase{
		{
			CaseID: "c1", CVEID: "CVE-2024-0001",
			AdvisoryExcerpt: "x", ComponentName: "foo", Ecosystem: "go",
			CodeReachability: CodeReachability{Reachable: false, Evidence: []string{}},
			ExpectedState:    "not_affected",
		},
	}
	providers := []namedProvider{
		{name: "openai", model: "gpt-4o-mini",
			provider: &fakeProvider{name: "openai", model: "gpt-4o-mini",
				err: errors.New("dial tcp 127.0.0.1:443: connect: connection refused")}},
		{name: "gemini", model: "gemini-2.0-flash",
			provider: &fakeProvider{name: "gemini", model: "gemini-2.0-flash",
				responses: map[string]string{
					"CVE-2024-0001": `{"state":"not_affected","confidence":0.9,"evidence":[{"kind":"llm_rationale","description":"ok","source":"llm"}]}`,
				}}},
	}
	var jsonl bytes.Buffer
	results, err := runBench(context.Background(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		providers, cases,
		runOptions{
			Timeout:        1 * time.Second,
			MaxConcurrency: 2,
			JSONLWriter:    &jsonl,
			Clock:          func() time.Time { return time.Unix(0, 0) },
		},
	)
	if err != nil {
		t.Fatalf("runBench: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	summary := aggregate(results)
	// Find the openai row — error-folded, denom = 0 so precision should
	// stay at the zero-value (0.0) without dividing by zero.
	for _, s := range summary {
		if s.Provider == "openai" {
			if s.Errors != 1 {
				t.Errorf("openai errors = %d, want 1", s.Errors)
			}
			if s.Precision != 0.0 {
				t.Errorf("openai precision should be 0 when only call errored, got %v", s.Precision)
			}
		}
		if s.Provider == "gemini" {
			if s.Errors != 0 {
				t.Errorf("gemini errors = %d, want 0", s.Errors)
			}
			if s.Precision != 1.0 {
				t.Errorf("gemini precision = %v, want 1.0", s.Precision)
			}
		}
	}
}

// TestRenderMarkdownDeterministic pins the exact markdown shape so a
// drift in column order / number precision is caught at test time.
func TestRenderMarkdownDeterministic(t *testing.T) {
	summary := []ProviderSummary{
		{
			Provider: "anthropic", Model: "claude-3-5-haiku-20241022",
			CaseCount: 2, Matches: 1, Precision: 0.5,
			AvgConfidence: 0.875, AvgLatencyMs: 1234.5,
			Errors: 0, TotalCostUSD: 0.001234,
		},
		{
			Provider: "openai", Model: "gpt-4o-mini",
			CaseCount: 2, Matches: 2, Precision: 1.0,
			AvgConfidence: 0.9, AvgLatencyMs: 567.8,
			Errors: 0, TotalCostUSD: 0.000456,
		},
	}
	got := renderMarkdown(summary, 2)

	// Two passes against the same input must produce byte-equal output.
	got2 := renderMarkdown(summary, 2)
	if got != got2 {
		t.Fatalf("renderMarkdown is non-deterministic")
	}

	// Spot-check structural markers + precision formatting.
	wantSubs := []string{
		"## llm-bench summary (eval-set cases: 2)",
		"| Provider | Model | Cases | Matches | Precision | AvgConf | AvgLatency(ms) | Errors | TotalCost(USD) |",
		"| anthropic | claude-3-5-haiku-20241022 | 2 | 1 | 0.500 | 0.875 |",
		"| openai | gpt-4o-mini | 2 | 2 | 1.000 | 0.900 |",
		"0.001234",
		"0.000456",
	}
	for _, sub := range wantSubs {
		if !strings.Contains(got, sub) {
			t.Errorf("markdown missing substring %q\n--- got ---\n%s", sub, got)
		}
	}
}

// TestComputeCost checks the per-model price lookup and the
// unknown-model honest-zero fallback.
func TestComputeCost(t *testing.T) {
	// Known model: 1K input + 1K output for gpt-4o-mini at 0.000150 /
	// 0.000600 per 1K = 0.000750 USD total. Tolerance accounts for
	// IEEE-754 float64 round-trip (the product chain through
	// `inputTok/1000.0 * inputPer1K` is not bit-exact).
	got := computeCost("openai", "gpt-4o-mini", 1000, 1000)
	want := 0.000150 + 0.000600
	if diff := got - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("computeCost(gpt-4o-mini, 1K,1K) = %v, want %v (tol 1e-9)", got, want)
	}
	// Unknown model: 0, not a fabricated number from a stale tier.
	if c := computeCost("openai", "imaginary-model", 1000, 1000); c != 0 {
		t.Errorf("unknown model should cost 0, got %v", c)
	}
	// Ollama is always free at the API surface.
	if c := computeCost("ollama", "qwen2.5-coder:7b", 1000, 1000); c != 0 {
		t.Errorf("ollama should cost 0, got %v", c)
	}
}

// TestResolveProviderSpec covers env-driven skip behaviour: every
// provider that fails its env check must surface a non-empty
// skipReason so realMain logs + skips rather than calling the factory
// with garbage.
func TestResolveProviderSpec(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	t.Setenv("SBOMHUB_LLM_API_KEY", "")
	t.Setenv("SBOMHUB_LLM_AZURE_ENDPOINT", "")
	t.Setenv("SBOMHUB_LLM_AZURE_DEPLOYMENT", "")
	t.Setenv("SBOMHUB_LLM_BENCH_OLLAMA_MODEL", "")

	for _, name := range []string{"openai", "anthropic", "gemini", "azure_openai", "ollama"} {
		spec := resolveProviderSpec(name)
		if spec.skipReason == "" {
			t.Errorf("provider %s: expected non-empty skipReason when env is empty", name)
		}
	}

	t.Setenv("OPENAI_API_KEY", "sk-test")
	spec := resolveProviderSpec("openai")
	if spec.skipReason != "" {
		t.Errorf("openai with key set: skipReason=%q, want empty", spec.skipReason)
	}
	if spec.apiKey != "sk-test" {
		t.Errorf("openai apiKey = %q, want sk-test", spec.apiKey)
	}
}

// TestOllamaBaseURLPropagatedToFactory_F41 verifies the F41 fix:
// the bench must propagate the operator's Ollama base URL to the
// factory via the canonical SBOMHUB_LLM_OLLAMA_URL env, not OLLAMA_HOST
// (which the factory's ollamaBaseURLFromEnv never reads).
//
// Three sub-tests cover the documented precedence:
//   - SBOMHUB_LLM_OLLAMA_URL set → spec uses it (canonical wins).
//   - only OLLAMA_HOST set       → spec falls back to it (alias kept).
//   - both set                   → SBOMHUB_LLM_OLLAMA_URL wins.
//
// After buildProvider, llm.EnvOllamaURL must hold the resolved URL so
// the factory's ollamaBaseURLFromEnv (which only reads that env) sees
// the right value when constructing the Ollama provider.
func TestOllamaBaseURLPropagatedToFactory_F41(t *testing.T) {
	// SBOMHUB_LLM_BENCH_OLLAMA_MODEL is required for the spec not to
	// short-circuit on skipReason. Set once for all sub-tests; t.Setenv
	// is per-test so each sub-test restores the previous value.
	t.Setenv("SBOMHUB_LLM_BENCH_OLLAMA_MODEL", "qwen2.5-coder:7b")

	t.Run("SBOMHUB_LLM_OLLAMA_URL is canonical", func(t *testing.T) {
		t.Setenv(llm.EnvOllamaURL, "http://canonical:11434")
		t.Setenv("OLLAMA_HOST", "")
		spec := resolveProviderSpec("ollama")
		if spec.ollamaURL != "http://canonical:11434" {
			t.Errorf("ollamaURL = %q, want http://canonical:11434", spec.ollamaURL)
		}
		if spec.skipReason != "" {
			t.Fatalf("unexpected skipReason: %q", spec.skipReason)
		}
		if _, err := buildProvider(spec); err != nil {
			t.Fatalf("buildProvider: %v", err)
		}
		if got := os.Getenv(llm.EnvOllamaURL); got != "http://canonical:11434" {
			t.Errorf("after buildProvider, %s = %q, want http://canonical:11434 (factory wouldn't see the operator's URL)", llm.EnvOllamaURL, got)
		}
	})

	t.Run("OLLAMA_HOST alias fallback when canonical unset", func(t *testing.T) {
		t.Setenv(llm.EnvOllamaURL, "")
		t.Setenv("OLLAMA_HOST", "http://alias:11434")
		spec := resolveProviderSpec("ollama")
		if spec.ollamaURL != "http://alias:11434" {
			t.Errorf("ollamaURL = %q, want http://alias:11434 (OLLAMA_HOST alias not honoured)", spec.ollamaURL)
		}
		if _, err := buildProvider(spec); err != nil {
			t.Fatalf("buildProvider: %v", err)
		}
		// After buildProvider the alias must have been promoted into the
		// canonical env so the factory picks it up.
		if got := os.Getenv(llm.EnvOllamaURL); got != "http://alias:11434" {
			t.Errorf("after buildProvider, %s = %q, want http://alias:11434 (alias should be promoted to canonical for factory)", llm.EnvOllamaURL, got)
		}
	})

	t.Run("canonical wins over alias when both set", func(t *testing.T) {
		t.Setenv(llm.EnvOllamaURL, "http://canonical:11434")
		t.Setenv("OLLAMA_HOST", "http://alias:11434")
		spec := resolveProviderSpec("ollama")
		if spec.ollamaURL != "http://canonical:11434" {
			t.Errorf("ollamaURL = %q, want http://canonical:11434 (canonical did not win precedence)", spec.ollamaURL)
		}
	})

	t.Run("factory default when neither set", func(t *testing.T) {
		t.Setenv(llm.EnvOllamaURL, "")
		t.Setenv("OLLAMA_HOST", "")
		spec := resolveProviderSpec("ollama")
		if spec.ollamaURL != "http://localhost:11434" {
			t.Errorf("ollamaURL = %q, want http://localhost:11434 (factory default mismatch)", spec.ollamaURL)
		}
	})
}

// TestRealMainNoProviders exercises the top-level guard that aborts
// when zero providers resolve — the operator gets a clear error rather
// than an empty JSONL stream that looks like a silent success.
func TestRealMainNoProviders(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "ok.json", `{
		"version":1,
		"cases":[{
			"case_id":"c","cve_id":"CVE-X","advisory_excerpt":"x",
			"component_name":"n","ecosystem":"go",
			"code_reachability":{"reachable":false,"evidence":[]},
			"expected_state":"not_affected"
		}]
	}`)
	// Wipe every BYOK env so all providers skip.
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	t.Setenv("SBOMHUB_LLM_API_KEY", "")
	t.Setenv("SBOMHUB_LLM_AZURE_ENDPOINT", "")
	t.Setenv("SBOMHUB_LLM_AZURE_DEPLOYMENT", "")
	t.Setenv("SBOMHUB_LLM_BENCH_OLLAMA_MODEL", "")

	var stdout, stderr bytes.Buffer
	ee := realMain([]string{"--eval-set", path}, &stdout, &stderr)
	if ee == nil {
		t.Fatal("expected exitError when no providers are configured")
	}
	if !strings.Contains(ee.Error(), "no providers available") {
		t.Errorf("expected 'no providers available' message, got %v", ee)
	}
	if ee.Code != exitNoProviders {
		t.Errorf("exit code = %d, want %d (exitNoProviders)", ee.Code, exitNoProviders)
	}
}

// TestRealMain_ExitCodes_F42 pins the F42 exit-code contract. Each
// sub-test triggers a distinct failure mode and asserts the typed
// exit code so CI / orchestrators can dispatch on the classification.
//
// Contract:
//
//	2 (exitUsageError)      — flag parse, missing required flag, unknown provider
//	3 (exitConfigError)     — fixture load / schema validation failure
//	4 (exitNoProviders)     — every requested provider skipped (no BYOK env)
//	5 (exitExecutionFailed) — output-creation / run failure
func TestRealMain_ExitCodes_F42(t *testing.T) {
	// Clean BYOK env so the no-providers branch is deterministic in
	// every sub-test that reaches provider resolution.
	clearBYOK := func(t *testing.T) {
		t.Helper()
		t.Setenv("OPENAI_API_KEY", "")
		t.Setenv("ANTHROPIC_API_KEY", "")
		t.Setenv("GOOGLE_API_KEY", "")
		t.Setenv("SBOMHUB_LLM_API_KEY", "")
		t.Setenv("SBOMHUB_LLM_AZURE_ENDPOINT", "")
		t.Setenv("SBOMHUB_LLM_AZURE_DEPLOYMENT", "")
		t.Setenv("SBOMHUB_LLM_BENCH_OLLAMA_MODEL", "")
	}

	dir := t.TempDir()
	goodFixture := writeFixture(t, dir, "ok.json", `{
		"version":1,
		"cases":[{
			"case_id":"c","cve_id":"CVE-X","advisory_excerpt":"x",
			"component_name":"n","ecosystem":"go",
			"code_reachability":{"reachable":false,"evidence":[]},
			"expected_state":"not_affected"
		}]
	}`)

	t.Run("exit 2 on missing --eval-set", func(t *testing.T) {
		clearBYOK(t)
		var out, errb bytes.Buffer
		ee := realMain([]string{}, &out, &errb)
		if ee == nil || ee.Code != exitUsageError {
			t.Fatalf("got %+v, want exitUsageError (%d)", ee, exitUsageError)
		}
	})

	t.Run("exit 2 on unknown flag", func(t *testing.T) {
		clearBYOK(t)
		var out, errb bytes.Buffer
		ee := realMain([]string{"--not-a-flag"}, &out, &errb)
		if ee == nil || ee.Code != exitUsageError {
			t.Fatalf("got %+v, want exitUsageError (%d)", ee, exitUsageError)
		}
	})

	t.Run("exit 2 on unknown provider", func(t *testing.T) {
		clearBYOK(t)
		var out, errb bytes.Buffer
		ee := realMain([]string{"--eval-set", goodFixture, "--providers", "acme"}, &out, &errb)
		if ee == nil || ee.Code != exitUsageError {
			t.Fatalf("got %+v, want exitUsageError (%d)", ee, exitUsageError)
		}
	})

	t.Run("exit 3 on missing fixture file", func(t *testing.T) {
		clearBYOK(t)
		var out, errb bytes.Buffer
		ee := realMain([]string{"--eval-set", filepath.Join(dir, "does-not-exist.json")}, &out, &errb)
		if ee == nil || ee.Code != exitConfigError {
			t.Fatalf("got %+v, want exitConfigError (%d)", ee, exitConfigError)
		}
	})

	t.Run("exit 3 on invalid fixture schema", func(t *testing.T) {
		clearBYOK(t)
		bad := writeFixture(t, dir, "bad.json", `{"version":1,"cases":[]}`)
		var out, errb bytes.Buffer
		ee := realMain([]string{"--eval-set", bad}, &out, &errb)
		if ee == nil || ee.Code != exitConfigError {
			t.Fatalf("got %+v, want exitConfigError (%d)", ee, exitConfigError)
		}
	})

	t.Run("exit 4 when no providers configured", func(t *testing.T) {
		clearBYOK(t)
		var out, errb bytes.Buffer
		ee := realMain([]string{"--eval-set", goodFixture}, &out, &errb)
		if ee == nil || ee.Code != exitNoProviders {
			t.Fatalf("got %+v, want exitNoProviders (%d)", ee, exitNoProviders)
		}
	})

	t.Run("exit 5 when --out points to unwritable directory", func(t *testing.T) {
		clearBYOK(t)
		t.Setenv("OPENAI_API_KEY", "sk-test") // unblock no-providers path so we reach --out
		var out, errb bytes.Buffer
		// Parent dir does not exist → os.Create fails with ENOENT. This
		// is the same class of failure as disk-full / EACCES (output
		// surface broken before any provider call), so it maps to
		// exitExecutionFailed.
		badOut := filepath.Join(dir, "no-such-dir", "out.jsonl")
		ee := realMain([]string{"--eval-set", goodFixture, "--out", badOut, "--providers", "openai"}, &out, &errb)
		if ee == nil || ee.Code != exitExecutionFailed {
			t.Fatalf("got %+v, want exitExecutionFailed (%d)", ee, exitExecutionFailed)
		}
	})
}
