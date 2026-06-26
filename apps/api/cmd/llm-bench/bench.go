package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/service/llm"
	"github.com/sbomhub/sbomhub/internal/service/triage"
)

// EvalCase is one fixture row. The JSON shape is documented in
// test/fixtures/llm-bench/cve-20-50.json and intentionally kept narrow
// — anything more elaborate would force the harness to mimic the full
// advisory / reachability schemas.
//
// SECURITY NOTE: AdvisoryExcerpt SHOULD only carry text that is already
// public in NVD / GHSA / JVN advisory bodies; do not paste proprietary
// vendor advisories that the operator's BYOK provider would otherwise
// not see.
type EvalCase struct {
	CaseID                   string             `json:"case_id"`
	CVEID                    string             `json:"cve_id"`
	AdvisoryTitle            string             `json:"advisory_title,omitempty"`
	AdvisoryExcerpt          string             `json:"advisory_excerpt"`
	ComponentName            string             `json:"component_name"`
	ComponentVersion         string             `json:"component_version,omitempty"`
	Ecosystem                string             `json:"ecosystem"`
	CodeReachability         CodeReachability   `json:"code_reachability"`
	ExpectedState            string             `json:"expected_state"`
	ExpectedReasoningKeywords []string          `json:"expected_reasoning_keywords,omitempty"`
	Comment                  string             `json:"comment,omitempty"`
}

// CodeReachability is the per-case reachability evidence the bench
// renders into the synthesized triage.ReachabilityRow. We keep it
// loose so a fixture author does not have to fabricate file paths /
// line numbers that the analyser would produce in real life.
type CodeReachability struct {
	Reachable bool     `json:"reachable"`
	Evidence  []string `json:"evidence"`
}

// EvalSet is the on-disk fixture envelope.
type EvalSet struct {
	Version     int        `json:"version"`
	Description string     `json:"description,omitempty"`
	Cases       []EvalCase `json:"cases"`
}

// loadEvalSet reads + validates the fixture.
//
// Validation deliberately rejects an empty case list early so the
// per-provider fan-out loop does not silently no-op.
func loadEvalSet(path string) ([]EvalCase, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var set EvalSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("parse fixture JSON: %w", err)
	}
	if len(set.Cases) == 0 {
		return nil, errors.New("fixture contains zero cases")
	}
	for i, c := range set.Cases {
		if err := validateCase(c); err != nil {
			return nil, fmt.Errorf("case[%d] (id=%q): %w", i, c.CaseID, err)
		}
	}
	return set.Cases, nil
}

// validateCase enforces the minimum schema. Strict-ish: every case
// MUST carry a case_id / cve_id / advisory_excerpt / expected_state.
// Unknown expected_state is rejected so a typo doesn't silently make
// every result count as a mismatch.
func validateCase(c EvalCase) error {
	if c.CaseID == "" {
		return errors.New("case_id is required")
	}
	if c.CVEID == "" {
		return errors.New("cve_id is required")
	}
	if c.AdvisoryExcerpt == "" {
		return errors.New("advisory_excerpt is required")
	}
	if c.ExpectedState == "" {
		return errors.New("expected_state is required")
	}
	if !triage.IsValidState(c.ExpectedState) {
		return fmt.Errorf("expected_state %q is not in the triage allowlist", c.ExpectedState)
	}
	return nil
}

// capCases applies the F25 fan-out cap. We truncate rather than
// random-sample so back-to-back runs of the same fixture produce
// identical case sequences (determinism is required by the issue
// completion criterion).
func capCases(cases []EvalCase, maxCases int) []EvalCase {
	if maxCases <= 0 || len(cases) <= maxCases {
		return cases
	}
	return cases[:maxCases]
}

// namedProvider pairs a Provider with the bench-facing display name so
// the JSONL / markdown rows reference the same label regardless of
// what the Provider implementation reports via Name() (which is
// already the same value in practice, but keeping the bench's name
// explicit lets a future "openai-v2" alias coexist).
type namedProvider struct {
	name     string
	provider llm.Provider
	model    string // env-supplied override, "" = provider default
}

// CaseResult is one JSONL row. Fields are stable — adding new fields
// is fine, renaming is a downstream-tooling break.
type CaseResult struct {
	Provider      string  `json:"provider"`
	Model         string  `json:"model"`
	CaseID        string  `json:"case_id"`
	CVEID         string  `json:"cve_id"`
	ExpectedState string  `json:"expected_state"`
	GotState      string  `json:"got_state"`
	Confidence    float64 `json:"confidence"`
	Clamped       bool    `json:"clamped"`
	InputTokens   int     `json:"input_tokens"`
	OutputTokens  int     `json:"output_tokens"`
	LatencyMs     int64   `json:"latency_ms"`
	CostUSD       float64 `json:"cost_usd"`
	Error         string  `json:"error,omitempty"`
}

// runOptions wires the F19 bounded-ctx + concurrency cap into runBench.
type runOptions struct {
	Timeout        time.Duration
	MaxConcurrency int
	JSONLWriter    io.Writer
	// Clock is overrideable for tests so latency numbers are deterministic.
	Clock func() time.Time
}

// runBench fans out one Provider.Complete per (provider, case) pair,
// serialising each result as a JSONL row immediately so a long run can
// be interrupted with partial output preserved.
//
// F19 (bench variant): each call runs under context.WithTimeout(opts.Timeout)
// and the global semaphore caps total concurrency at opts.MaxConcurrency
// — DB connection-pool hygiene is moot here (no DB), but rate-limit
// hygiene for live providers is the same shape.
//
// F25 is enforced upstream via capCases; runBench trusts the caller to
// have applied the cap before this entry point.
//
// F43: the FIRST JSONL write error is captured, the run context is
// cancelled to stop further provider calls, and the error is returned
// from runBench so realMain can surface exitExecutionFailed. Previously
// the error was only logged, so a disk-full or read-only --out file
// produced a corrupt-but-success bench (CI pipelines treated it as
// valid evidence). Per-call provider errors are NOT promoted — those
// are still folded into CaseResult.Error so a single 429 does not abort
// the whole bench.
func runBench(
	ctx context.Context,
	logger *slog.Logger,
	providers []namedProvider,
	cases []EvalCase,
	opts runOptions,
) ([]CaseResult, error) {
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.MaxConcurrency <= 0 {
		return nil, errors.New("runBench: MaxConcurrency must be > 0")
	}

	type job struct {
		providerIdx int
		caseIdx     int
	}
	jobs := []job{}
	for pi := range providers {
		for ci := range cases {
			jobs = append(jobs, job{providerIdx: pi, caseIdx: ci})
		}
	}

	results := make([]CaseResult, len(jobs))

	// jsonlMu guards opts.JSONLWriter — Encoder.Encode is not goroutine
	// safe and concurrent writes would interleave bytes. F43: the same
	// mutex also guards firstWriteErr so the first failure is captured
	// even when multiple goroutines write concurrently. We deliberately
	// reuse jsonlMu rather than a second mutex so the (encode +
	// firstWriteErr update + cancel) sequence is atomic per goroutine.
	var jsonlMu sync.Mutex
	enc := json.NewEncoder(opts.JSONLWriter)
	var firstWriteErr error

	// F43: derive a cancellable child context so the first JSONL write
	// failure can short-circuit the remaining provider calls. We don't
	// rely on the caller passing a cancellable ctx because the bench's
	// own output failure is its own concern, not the caller's.
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	sem := make(chan struct{}, opts.MaxConcurrency)
	var wg sync.WaitGroup
	for i, j := range jobs {
		j := j
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-runCtx.Done():
				return
			}
			defer func() { <-sem }()

			p := providers[j.providerIdx]
			c := cases[j.caseIdx]

			res := runOne(runCtx, p, c, opts.Timeout, opts.Clock)
			results[i] = res

			jsonlMu.Lock()
			defer jsonlMu.Unlock()
			// Skip the write if a previous goroutine already detected a
			// broken writer — repeated writes to /dev/full / a closed
			// file just spam stderr with the same error.
			if firstWriteErr != nil {
				return
			}
			if err := enc.Encode(res); err != nil {
				firstWriteErr = err
				logger.Warn("jsonl write failed (F43: aborting run)",
					"provider", res.Provider, "case_id", res.CaseID, "error", err)
				// Cancel the run ctx so in-flight provider calls stop
				// burning quota — output is already broken, no point
				// finishing the remaining 50 cases.
				cancelRun()
			}
		}()
	}
	wg.Wait()

	if firstWriteErr != nil {
		return results, fmt.Errorf("bench: failed to write JSONL: %w", firstWriteErr)
	}
	return results, nil
}

// runOne handles a single (provider, case) pair. Errors are folded
// into CaseResult.Error rather than returned so the harness keeps
// going — a single 429 should not abort the whole bench.
func runOne(
	parentCtx context.Context,
	p namedProvider,
	c EvalCase,
	timeout time.Duration,
	clock func() time.Time,
) CaseResult {
	res := CaseResult{
		Provider:      p.name,
		Model:         p.provider.Model(),
		CaseID:        c.CaseID,
		CVEID:         c.CVEID,
		ExpectedState: c.ExpectedState,
	}

	advisories, reach := caseToTriageRows(c)
	prompt := triage.BuildPrompt(c.CVEID, advisories, reach)

	req := llm.CompleteRequest{
		System:      triage.VEXTriageSystemPrompt,
		Messages:    []llm.Message{{Role: llm.RoleUser, Content: prompt}},
		Temperature: 0.0,
		JSONMode:    true,
		Purpose:     "vex_triage_bench",
	}

	// F19: bounded ctx per call.
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	start := clock()
	resp, err := p.provider.Complete(ctx, req)
	res.LatencyMs = clock().Sub(start).Milliseconds()

	if err != nil {
		// F13: scrub provider transport errors before persisting /
		// echoing in the JSONL row.
		err = llm.RedactProviderError(err)
		res.Error = err.Error()
		res.GotState = "" // not "under_investigation" — we want the precision metric to clearly distinguish error from low-confidence verdict.
		return res
	}
	if resp == nil {
		res.Error = "nil response from provider"
		return res
	}
	res.InputTokens = resp.InputTokens
	res.OutputTokens = resp.OutputTokens
	res.CostUSD = computeCost(p.name, p.provider.Model(), resp.InputTokens, resp.OutputTokens)

	parsed, _ := triage.ParseLLMResponse(resp.Content)
	if parsed == nil {
		res.Error = "parsed decision was nil"
		return res
	}
	finalState, clamped := triage.ApplyConfidenceThreshold(
		string(parsed.State), parsed.Confidence, triage.DefaultConfidenceThreshold)
	res.GotState = finalState
	res.Confidence = parsed.Confidence
	res.Clamped = clamped
	return res
}

// caseToTriageRows synthesises the (advisory, reachability) input that
// triage.BuildPrompt expects from one fixture case. We fabricate a
// single advisory row and a single reachability row per case so the
// prompt structure matches the production runner's worst-case fan-in
// (one CVE × one component).
//
// uuid.New is used for the row ids so the rendered prompt looks like a
// real run (BuildPrompt prints `id=<uuid>` per row). The bench treats
// these ids as ephemeral; nothing downstream of triage.ParseLLMResponse
// cares about them.
func caseToTriageRows(c EvalCase) ([]triage.AdvisoryExcerptRow, []triage.ReachabilityRow) {
	// Collapse evidence list into the JSON envelope BuildPrompt prints.
	// We use json.Marshal rather than fmt.Sprintf so a future evidence
	// schema change (nested objects, arrays of arrays) is encoded
	// safely.
	evidenceJSON, _ := json.Marshal(map[string]interface{}{
		"reachable": c.CodeReachability.Reachable,
		"evidence":  c.CodeReachability.Evidence,
	})

	excerpt := c.AdvisoryExcerpt
	if c.AdvisoryTitle != "" {
		excerpt = c.AdvisoryTitle + "\n" + excerpt
	}

	advisories := []triage.AdvisoryExcerptRow{{
		ID:         uuid.New(),
		CVEID:      c.CVEID,
		Source:     sourceForCVE(c.CVEID),
		RawExcerpt: excerpt,
	}}
	status := "not_reachable"
	if c.CodeReachability.Reachable {
		status = "reachable"
	}
	reach := []triage.ReachabilityRow{{
		ID:          uuid.New(),
		ComponentID: uuid.New(),
		CVEID:       c.CVEID,
		Ecosystem:   c.Ecosystem,
		Status:      status,
		Evidence:    evidenceJSON,
	}}
	return advisories, reach
}

// sourceForCVE makes a best-effort guess at the upstream so the
// prompt row's `source=` label is human-meaningful. Bench fixtures
// rarely care about source attribution, but the prompt does print it.
func sourceForCVE(cveID string) string {
	switch {
	case strings.HasPrefix(cveID, "GHSA-"):
		return "ghsa"
	case strings.HasPrefix(cveID, "JVN"):
		return "jvn"
	default:
		return "nvd"
	}
}

// ProviderSummary is the per-provider aggregation row.
type ProviderSummary struct {
	Provider      string
	Model         string
	CaseCount     int
	Matches       int     // expected_state == got_state
	Precision     float64 // Matches / (CaseCount - Errors)
	AvgConfidence float64
	AvgLatencyMs  float64
	TotalCostUSD  float64
	Errors        int
}

// aggregate computes per-provider summary stats. Provider order is
// alphabetical so the markdown table is byte-equal across runs.
func aggregate(results []CaseResult) []ProviderSummary {
	byProvider := map[string][]CaseResult{}
	modelByProvider := map[string]string{}
	for _, r := range results {
		byProvider[r.Provider] = append(byProvider[r.Provider], r)
		if _, ok := modelByProvider[r.Provider]; !ok {
			modelByProvider[r.Provider] = r.Model
		}
	}
	names := make([]string, 0, len(byProvider))
	for n := range byProvider {
		names = append(names, n)
	}
	sort.Strings(names)

	summaries := make([]ProviderSummary, 0, len(names))
	for _, n := range names {
		rows := byProvider[n]
		s := ProviderSummary{
			Provider:  n,
			Model:     modelByProvider[n],
			CaseCount: len(rows),
		}
		var confSum, latSum float64
		var confN int
		for _, r := range rows {
			if r.Error != "" {
				s.Errors++
				latSum += float64(r.LatencyMs)
				continue
			}
			if r.GotState == r.ExpectedState {
				s.Matches++
			}
			confSum += r.Confidence
			confN++
			latSum += float64(r.LatencyMs)
			s.TotalCostUSD += r.CostUSD
		}
		denom := s.CaseCount - s.Errors
		if denom > 0 {
			s.Precision = float64(s.Matches) / float64(denom)
		}
		if confN > 0 {
			s.AvgConfidence = confSum / float64(confN)
		}
		if s.CaseCount > 0 {
			s.AvgLatencyMs = latSum / float64(s.CaseCount)
		}
		summaries = append(summaries, s)
	}
	return summaries
}

// renderMarkdown formats the per-provider summary as a stable markdown
// table. Column order, alignment, and number precision are fixed so a
// byte-equal comparison against a recorded baseline is meaningful.
func renderMarkdown(summaries []ProviderSummary, totalCases int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## llm-bench summary (eval-set cases: %d)\n\n", totalCases)
	b.WriteString("| Provider | Model | Cases | Matches | Precision | AvgConf | AvgLatency(ms) | Errors | TotalCost(USD) |\n")
	b.WriteString("|---|---|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, s := range summaries {
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %.3f | %.3f | %.1f | %d | %.6f |\n",
			s.Provider,
			displayModel(s.Model),
			s.CaseCount,
			s.Matches,
			s.Precision,
			s.AvgConfidence,
			s.AvgLatencyMs,
			s.Errors,
			s.TotalCostUSD,
		)
	}
	return b.String()
}

// displayModel keeps the markdown cell tidy when the provider did not
// advertise a model (Disabled / fake). "n/a" is preferred over an
// empty cell so a column-alignment-sensitive copy/paste does not
// silently collapse a row.
func displayModel(m string) string {
	if m == "" {
		return "n/a"
	}
	return m
}

// computeCost returns an approximate USD cost for one call.
//
// ※要確認: prices below are 2026-06 list rates per 1K tokens (input /
// output). The bench uses them as a sanity-check signal, not an
// invoiced number — production cost rollup belongs in the audit layer
// (llm_calls.cost_usd, currently 0 from every provider). When a
// provider rotates its price card (or adds a new model), update this
// table. Unknown model → returns 0 so the cost column stays honest
// rather than silently fabricating a number from a stale tier.
func computeCost(provider, model string, inputTok, outputTok int) float64 {
	type priceRow struct {
		inputPer1K  float64
		outputPer1K float64
	}
	priceTable := map[string]map[string]priceRow{
		"openai": {
			// gpt-4o-mini list rate (2024-07 launch, still GA 2026-06).
			"gpt-4o-mini": {inputPer1K: 0.000150, outputPer1K: 0.000600},
			"gpt-4o":      {inputPer1K: 0.005000, outputPer1K: 0.015000},
			// gpt-5-mini placeholder — ※要確認 once OpenAI publishes.
			"gpt-5-mini": {inputPer1K: 0.000150, outputPer1K: 0.000600},
		},
		"anthropic": {
			"claude-3-5-haiku-20241022":  {inputPer1K: 0.000800, outputPer1K: 0.004000},
			"claude-3-5-sonnet-20241022": {inputPer1K: 0.003000, outputPer1K: 0.015000},
			"claude-opus-4-7":            {inputPer1K: 0.015000, outputPer1K: 0.075000},
		},
		"gemini": {
			"gemini-2.0-flash":     {inputPer1K: 0.000075, outputPer1K: 0.000300},
			"gemini-1.5-flash":     {inputPer1K: 0.000075, outputPer1K: 0.000300},
			"gemini-1.5-pro":       {inputPer1K: 0.001250, outputPer1K: 0.005000},
		},
		"azure_openai": {
			// Mirrors openai pricing; Azure tier add-on varies per
			// region / commitment (※要確認: production rollup belongs
			// in azure_openai.go cost computation, see the existing
			// CostUSD = 0 comment).
			"gpt-4o-mini": {inputPer1K: 0.000150, outputPer1K: 0.000600},
			"gpt-4o":      {inputPer1K: 0.005000, outputPer1K: 0.015000},
		},
		"ollama": {
			// Local LLM is free at the API surface (operator pays for
			// hardware separately). Cost is the wedge of the M4 bench;
			// "0" is the honest answer.
		},
	}
	rows, ok := priceTable[provider]
	if !ok {
		return 0
	}
	row, ok := rows[model]
	if !ok {
		return 0
	}
	return float64(inputTok)/1000.0*row.inputPer1K + float64(outputTok)/1000.0*row.outputPer1K
}
