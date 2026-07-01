// Package diff_summary provides an AI-assisted natural-language summary
// of the supply-chain churn diff computed by internal/service/diff for
// M11-4 (issue #79).
//
// Design notes (mirror the M1 / M2 patterns):
//
//   - Takes an already-computed diff.Response so this service does not
//     re-do the deterministic comparison the diff endpoint already
//     produced. The caller (handler) compute()s the diff first, then
//     passes the response in. This keeps the LLM stage purely a
//     summarisation step over deterministic inputs the audit trail
//     already references.
//   - Provider abstraction goes through internal/service/llm — BYOK only,
//     no bundled keys. The DisabledProvider path produces a deterministic
//     "AI summary unavailable" placeholder so the UI can still render
//     the audit-required Confidence / Evidence / Approve controls.
//   - Persists an llm_calls row (provider + model + prompt hash + response
//     hash + cost) AND an audit_logs row (action=diff_summary_ai_generated
//     or diff_summary_ai_disabled, resource_type=sbom_diff, details with
//     from/to ids + confidence + bucket counts). This is the audit-or-
//     nothing contract from M1 F5 — if either write fails, the whole
//     request fails closed.
//   - Provider.Complete is bounded by triage.LLMTimeoutFromEnv() so a
//     hanging upstream cannot pin a goroutine.
//   - The summary is a structured envelope (Summary + Evidence pointers +
//     Confidence) per the CLAUDE.md "AI drafts only. Humans approve."
//     contract. Approve/Edit/Reject controls live in the frontend; this
//     service deliberately does NOT persist the summary text in a
//     domain table — the only persistence is the llm_calls + audit_logs
//     audit pair. M12 may introduce a diff_summaries table if the
//     product needs to render historical summaries; M11-4 ships
//     stateless (the summary is regenerated per click).
package diff_summary

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/diff"
	"github.com/sbomhub/sbomhub/internal/service/llm"
	"github.com/sbomhub/sbomhub/internal/service/triage"
)

// Audit + LLM purpose constants.
const (
	// LLMCallPurposeDiffSummary tags llm_calls rows produced by this
	// service. Mirrors the LLM provider policy purpose list in
	// CLAUDE.md (vex_triage / cra_draft / meti_prefill / embed /
	// diff_summary).
	LLMCallPurposeDiffSummary = "diff_summary"

	// ResourceTypeSbomDiff is the audit_logs.resource_type for any
	// sbom-diff-related row.
	ResourceTypeSbomDiff = "sbom_diff"

	// AuditActionAIGenerated is emitted on a successful LLM run.
	AuditActionAIGenerated = "diff_summary_ai_generated"

	// AuditActionAIDisabled is emitted when AI features are not
	// configured for this tenant (no BYOK, no env default) and the
	// service falls back to a deterministic placeholder.
	AuditActionAIDisabled = "diff_summary_ai_disabled"

	// AuditActionAIFailed is emitted when the LLM call itself errors
	// (timeout / upstream 5xx / parse failure). The audit row records
	// the redacted error so operators can investigate.
	AuditActionAIFailed = "diff_summary_ai_failed"
)

// SupportedLangs enumerates the languages the prompt supports.
var SupportedLangs = []string{"en", "ja"}

// ProviderResolver mirrors the runner/resolver shape used by triage / cra
// (M1 #F2). Production wiring passes the same closure built by
// cmd/server/llm_resolver.go; unit tests substitute a fake.
type ProviderResolver func(ctx context.Context, tenantID uuid.UUID) (llm.Provider, error)

// LLMCallWriter is satisfied by *repository.LLMCallsRepository.
type LLMCallWriter interface {
	Insert(ctx context.Context, call *repository.LLMCall) error
}

// AuditLogWriter is satisfied by *repository.AuditRepository.Log.
type AuditLogWriter interface {
	Log(ctx context.Context, input *model.CreateAuditLogInput) error
}

// Service wires the AI summary generator over the diff service +
// LLM provider + audit + llm_calls repository.
type Service struct {
	diffSvc          *diff.Service
	defaultProvider  llm.Provider
	providerResolver ProviderResolver
	llmCalls         LLMCallWriter
	audit            AuditLogWriter

	llmTimeout time.Duration
	clock      func() time.Time
}

// Config bundles construction inputs.
type Config struct {
	Diff             *diff.Service
	Provider         llm.Provider     // default (env) provider
	ProviderResolver ProviderResolver // per-tenant BYOK resolver (may be nil)
	LLMCalls         LLMCallWriter
	Audit            AuditLogWriter
	LLMTimeout       time.Duration // zero -> triage.LLMTimeoutFromEnv()
	Clock            func() time.Time
}

// NewService constructs the service. Required fields (Diff, Provider,
// LLMCalls, Audit) panic at construction if missing — misconfiguration
// surfaces immediately, not at first call.
func NewService(cfg Config) *Service {
	if cfg.Diff == nil {
		panic("diff_summary.NewService: Diff is required")
	}
	if cfg.Provider == nil {
		panic("diff_summary.NewService: Provider is required")
	}
	if cfg.LLMCalls == nil {
		panic("diff_summary.NewService: LLMCalls is required")
	}
	if cfg.Audit == nil {
		panic("diff_summary.NewService: Audit is required")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	timeout := cfg.LLMTimeout
	if timeout <= 0 {
		timeout = triage.LLMTimeoutFromEnv()
	}
	return &Service{
		diffSvc:          cfg.Diff,
		defaultProvider:  cfg.Provider,
		providerResolver: cfg.ProviderResolver,
		llmCalls:         cfg.LLMCalls,
		audit:            cfg.Audit,
		llmTimeout:       timeout,
		clock:            clock,
	}
}

// Request is the input to Generate.
type Request struct {
	TenantID   uuid.UUID
	ProjectID  uuid.UUID
	UserID     *uuid.UUID
	FromSbomID uuid.UUID // optional; passed through to diff.Service
	ToSbomID   uuid.UUID // optional; passed through to diff.Service
	Lang       string    // "en" | "ja" (default "en")
}

// Response is the structured envelope returned to the handler.
//
// Summary is the natural-language 3-5 sentence summary. Highlights is the
// AI-extracted bullet list (CVE resolution, license violations, high-impact
// component changes). Confidence is the model's self-rated confidence
// (0.0 - 1.0). Evidence points back to deterministic diff facts so the
// audit reviewer can verify the summary against the underlying data.
//
// The frontend renders Summary + Highlights + Confidence + Evidence and
// shows Approve / Edit / Reject controls per the CLAUDE.md AI policy.
type Response struct {
	ProjectID   uuid.UUID     `json:"project_id"`
	From        *diff.SbomRef `json:"from"`
	To          *diff.SbomRef `json:"to"`
	Summary     string        `json:"summary"`
	Highlights  []string      `json:"highlights"`
	Confidence  float64       `json:"confidence"`
	Evidence    []Evidence    `json:"evidence"`
	Provider    string        `json:"provider"`
	Model       string        `json:"model"`
	Lang        string        `json:"lang"`
	GeneratedAt time.Time     `json:"generated_at"`
	// AIDisabled is true when no provider was available and the
	// summary is the deterministic placeholder. The UI uses this to
	// render a "Configure BYOK to enable AI summary" banner instead
	// of hiding the audit controls.
	AIDisabled bool `json:"ai_disabled"`
}

// Evidence is a pointer back to a deterministic diff fact. Kind is one
// of: "vulnerability_added", "vulnerability_resolved",
// "vulnerability_severity_changed", "component_added", "component_removed",
// "component_version_changed", "license_policy_violation_added",
// "license_policy_violation_removed". Ref is a free-form short label
// (CVE id, component name, etc.) the UI can echo back so reviewers can
// jump to the underlying bucket.
type Evidence struct {
	Kind string `json:"kind"`
	Ref  string `json:"ref"`
}

// llmFields is the JSON envelope the model is asked to return.
type llmFields struct {
	Summary    string   `json:"summary"`
	Highlights []string `json:"highlights"`
	Confidence float64  `json:"confidence"`
}

// Generate runs the LLM summarisation pipeline end-to-end.
//
// Flow:
//
//  1. Compute the diff via diff.Service (RLS-scoped via ambient TenantTx).
//  2. Resolve the per-tenant provider; fall back to default env provider.
//  3. If provider is disabled → write llm_calls row (error_message=disabled)
//     + audit_logs row (action=diff_summary_ai_disabled) + return the
//     deterministic placeholder envelope with AIDisabled=true.
//  4. Otherwise call Provider.Complete bounded by llmTimeout.
//  5. Parse the JSON response; if parse fails → write llm_calls row
//     (error_message=parse fail) + audit_logs row (action=diff_summary_ai_failed)
//     and return the error.
//  6. Persist llm_calls row + audit_logs row (action=diff_summary_ai_generated)
//     and return the response.
//
// The audit_logs / llm_calls writes share the request's ambient TenantTx
// so RLS GUC is honoured.
func (s *Service) Generate(ctx context.Context, req Request) (*Response, error) {
	lang := strings.ToLower(strings.TrimSpace(req.Lang))
	if lang != "ja" {
		lang = "en"
	}

	// 1. compute the diff. Errors surface as-is so the handler maps them
	//    to the same status codes the GET /diff endpoint does.
	diffResp, err := s.diffSvc.Compute(ctx, diff.Request{
		TenantID:   req.TenantID,
		ProjectID:  req.ProjectID,
		FromSbomID: req.FromSbomID,
		ToSbomID:   req.ToSbomID,
	})
	if err != nil {
		return nil, err
	}

	// 2. resolve provider.
	provider := s.defaultProvider
	if s.providerResolver != nil {
		p, perr := s.providerResolver(ctx, req.TenantID)
		if perr != nil {
			return nil, fmt.Errorf("resolve provider: %w", perr)
		}
		if p != nil {
			provider = p
		}
	}

	now := s.clock()
	systemPrompt, userPrompt := buildPrompt(diffResp, lang)
	promptForHash := systemPrompt + "\n---\n" + userPrompt
	promptHash := sha256hex(promptForHash)
	promptPreview := truncate(userPrompt, 512)

	// Evidence is derived from the deterministic diff regardless of
	// the LLM path so reviewers always get the underlying bucket
	// pointers (M1 F5 audit-or-nothing requires evidence to be
	// audit-attached, not LLM-attached).
	evidence := buildEvidence(diffResp)

	// 3. disabled path.
	if provider == nil || provider.Name() == "disabled" {
		placeholder := disabledPlaceholder(lang, diffResp)
		callID, llmErr := s.writeDisabledLLMCall(ctx, req, provider, promptHash, promptPreview, now)
		if llmErr != nil {
			return nil, llmErr
		}
		if auditErr := s.writeAudit(ctx, req, AuditActionAIDisabled, callID, diffResp, placeholder, 0.0); auditErr != nil {
			return nil, auditErr
		}
		return &Response{
			ProjectID:   diffResp.ProjectID,
			From:        diffResp.From,
			To:          diffResp.To,
			Summary:     placeholder.Summary,
			Highlights:  placeholder.Highlights,
			Confidence:  0.0,
			Evidence:    evidence,
			Provider:    providerName(provider),
			Model:       providerModel(provider),
			Lang:        lang,
			GeneratedAt: now,
			AIDisabled:  true,
		}, nil
	}

	// 4. bounded LLM call.
	llmCtx, cancel := context.WithTimeout(ctx, s.llmTimeout)
	defer cancel()

	start := s.clock()
	cresp, cerr := provider.Complete(llmCtx, llm.CompleteRequest{
		System: systemPrompt,
		Messages: []llm.Message{
			{Role: llm.RoleUser, Content: userPrompt},
		},
		Temperature: 0.1,
		MaxTokens:   1024,
		JSONMode:    true,
		TenantID:    req.TenantID.String(),
		UserID:      uuidStringOrEmpty(req.UserID),
		Purpose:     LLMCallPurposeDiffSummary,
	})
	duration := s.clock().Sub(start)

	if cerr != nil {
		redacted := llm.RedactProviderError(cerr).Error()
		callID, llmErr := s.writeFailedLLMCall(ctx, req, provider, promptHash, promptPreview, redacted, duration, now)
		if llmErr != nil {
			return nil, llmErr
		}
		if auditErr := s.writeFailedAudit(ctx, req, callID, diffResp, redacted); auditErr != nil {
			return nil, auditErr
		}
		return nil, fmt.Errorf("llm complete: %s", redacted)
	}

	// 5. parse JSON response.
	parsed, parseErr := parseLLMResponse(cresp.Content)
	if parseErr != nil {
		// Persist the audit pair even on parse failure so the operator
		// has a trail to debug from. The returned error carries the
		// parse reason but no upstream secrets.
		redacted := fmt.Sprintf("parse: %s", parseErr.Error())
		callID, llmErr := s.writeLLMCallFailedParse(ctx, req, provider, promptHash, promptPreview, cresp, redacted, duration, now)
		if llmErr != nil {
			return nil, llmErr
		}
		if auditErr := s.writeFailedAudit(ctx, req, callID, diffResp, redacted); auditErr != nil {
			return nil, auditErr
		}
		return nil, fmt.Errorf("llm response parse: %w", parseErr)
	}

	// Clamp confidence to [0,1].
	if parsed.Confidence < 0 {
		parsed.Confidence = 0
	}
	if parsed.Confidence > 1 {
		parsed.Confidence = 1
	}

	// 6. persist llm_calls + audit_logs (audit-or-nothing: if either
	//    write fails the request returns 500 and the caller's TenantTx
	//    rolls back).
	callID, llmErr := s.writeSuccessLLMCall(ctx, req, provider, promptHash, promptPreview, cresp, duration, now)
	if llmErr != nil {
		return nil, llmErr
	}
	if auditErr := s.writeAudit(ctx, req, AuditActionAIGenerated, callID, diffResp, parsed, parsed.Confidence); auditErr != nil {
		return nil, auditErr
	}

	return &Response{
		ProjectID:   diffResp.ProjectID,
		From:        diffResp.From,
		To:          diffResp.To,
		Summary:     parsed.Summary,
		Highlights:  parsed.Highlights,
		Confidence:  parsed.Confidence,
		Evidence:    evidence,
		Provider:    provider.Name(),
		Model:       provider.Model(),
		Lang:        lang,
		GeneratedAt: now,
		AIDisabled:  false,
	}, nil
}

// ---------- prompt building ----------

const promptSystemEN = `You are SBOMHub's diff summariser. ` +
	`Given a structured SBOM diff between two ingests of the same project, ` +
	`produce a JSON object with exactly these keys: "summary" (3-5 sentence English summary), ` +
	`"highlights" (3-7 short bullets, each <80 chars), "confidence" (0.0 to 1.0). ` +
	`Focus on: CVE resolutions and introductions (CRA compliance load-bearing), ` +
	`license-policy violations introduced or removed, high-impact component changes ` +
	`(major version bumps, removed dependencies). ` +
	`Do not invent CVE ids, severities, or licenses. Only reference items present in the diff JSON. ` +
	`Confidence: 0.9+ if every claim is directly grounded in the diff data; 0.5-0.7 if some items are ` +
	`under-specified; below 0.5 if the diff is too sparse to summarise meaningfully. ` +
	`Return only the JSON object, no markdown, no commentary.`

const promptSystemJA = `あなたは SBOMHub の差分要約担当です。` +
	`同一プロジェクトの 2 つの SBOM 取り込み間の構造化差分を入力に、` +
	`次のキーを持つ JSON オブジェクトを生成してください: "summary" (3〜5 文の日本語要約)、` +
	`"highlights" (各 80 文字未満の箇条書き 3〜7 件)、"confidence" (0.0〜1.0)。` +
	`重点項目: CVE の解消と新規検出 (CRA 報告義務に直結)、ライセンスポリシー違反の追加/解消、` +
	`重大なコンポーネント変更 (メジャーバージョン更新、依存削除)。` +
	`差分 JSON に存在しない CVE / 重大度 / ライセンスを創作しないこと。` +
	`confidence: 全主張が差分データに直接根拠を持つ場合 0.9 以上、一部不明瞭な場合 0.5〜0.7、` +
	`差分が薄く要約困難な場合は 0.5 未満。` +
	`JSON オブジェクトのみを返す。 markdown / 注釈は不要。`

// buildPrompt renders the (system, user) prompt pair from the diff
// response. The user prompt is a serialised JSON-shaped slice of facts
// (not the raw diff envelope) so the prompt stays compact even on
// large diffs.
func buildPrompt(d *diff.Response, lang string) (string, string) {
	system := promptSystemEN
	if lang == "ja" {
		system = promptSystemJA
	}

	user := struct {
		ProjectID                 string                             `json:"project_id"`
		From                      *diff.SbomRef                      `json:"from"`
		To                        *diff.SbomRef                      `json:"to"`
		ComponentsAdded           []diff.ComponentChange             `json:"components_added"`
		ComponentsRemoved         []diff.ComponentChange             `json:"components_removed"`
		ComponentsVersionChanged  []diff.ComponentVersionChange      `json:"components_version_changed"`
		VulnsAdded                []diff.VulnerabilityAdded          `json:"vulnerabilities_added"`
		VulnsResolved             []diff.VulnerabilityResolved       `json:"vulnerabilities_resolved"`
		VulnsSeverityChanged      []diff.VulnerabilitySeverityChange `json:"vulnerabilities_severity_changed"`
		LicensesAddedViolations   []diff.LicensePolicyViolation      `json:"licenses_added_violations"`
		LicensesRemovedViolations []diff.LicensePolicyViolation      `json:"licenses_removed_violations"`
	}{
		ProjectID:                 d.ProjectID.String(),
		From:                      d.From,
		To:                        d.To,
		ComponentsAdded:           cap50(d.Components.Added),
		ComponentsRemoved:         cap50(d.Components.Removed),
		ComponentsVersionChanged:  cap50vc(d.Components.VersionChanged),
		VulnsAdded:                capVulnAdded(d.Vulnerabilities.Added),
		VulnsResolved:             capVulnResolved(d.Vulnerabilities.Resolved),
		VulnsSeverityChanged:      capVulnSev(d.Vulnerabilities.SeverityChanged),
		LicensesAddedViolations:   capLic(d.Licenses.AddedPolicyViolations),
		LicensesRemovedViolations: capLic(d.Licenses.RemovedPolicyViolations),
	}
	buf, _ := json.Marshal(user)
	return system, string(buf)
}

// cap50 truncates a slice to 50 entries. The model only needs a
// representative sample — without the cap, a project with thousands of
// added components would blow past the context window AND the per-call
// token cost on the operator's BYOK key.
func cap50(in []diff.ComponentChange) []diff.ComponentChange {
	if len(in) <= 50 {
		return in
	}
	return in[:50]
}

func cap50vc(in []diff.ComponentVersionChange) []diff.ComponentVersionChange {
	if len(in) <= 50 {
		return in
	}
	return in[:50]
}

func capVulnAdded(in []diff.VulnerabilityAdded) []diff.VulnerabilityAdded {
	if len(in) <= 50 {
		return in
	}
	return in[:50]
}

func capVulnResolved(in []diff.VulnerabilityResolved) []diff.VulnerabilityResolved {
	if len(in) <= 50 {
		return in
	}
	return in[:50]
}

func capVulnSev(in []diff.VulnerabilitySeverityChange) []diff.VulnerabilitySeverityChange {
	if len(in) <= 50 {
		return in
	}
	return in[:50]
}

func capLic(in []diff.LicensePolicyViolation) []diff.LicensePolicyViolation {
	if len(in) <= 50 {
		return in
	}
	return in[:50]
}

// ---------- response parsing ----------

func parseLLMResponse(content string) (*llmFields, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, errors.New("empty content")
	}
	// Strip markdown code fences some providers wrap JSON in.
	if strings.HasPrefix(content, "```") {
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimPrefix(content, "```")
		content = strings.TrimSuffix(content, "```")
		content = strings.TrimSpace(content)
	}
	var f llmFields
	if err := json.Unmarshal([]byte(content), &f); err != nil {
		return nil, err
	}
	if strings.TrimSpace(f.Summary) == "" {
		return nil, errors.New("summary field is empty")
	}
	return &f, nil
}

// ---------- evidence pointers ----------

func buildEvidence(d *diff.Response) []Evidence {
	out := make([]Evidence, 0)
	for _, v := range d.Vulnerabilities.Added {
		out = append(out, Evidence{Kind: "vulnerability_added", Ref: v.CVEID})
	}
	for _, v := range d.Vulnerabilities.Resolved {
		out = append(out, Evidence{Kind: "vulnerability_resolved", Ref: v.CVEID})
	}
	for _, v := range d.Vulnerabilities.SeverityChanged {
		out = append(out, Evidence{Kind: "vulnerability_severity_changed", Ref: v.CVEID})
	}
	for _, v := range d.Components.VersionChanged {
		out = append(out, Evidence{Kind: "component_version_changed", Ref: v.Name + " " + v.FromVersion + " → " + v.ToVersion})
	}
	for _, v := range d.Licenses.AddedPolicyViolations {
		out = append(out, Evidence{Kind: "license_policy_violation_added", Ref: v.ComponentName + " (" + v.License + ")"})
	}
	for _, v := range d.Licenses.RemovedPolicyViolations {
		out = append(out, Evidence{Kind: "license_policy_violation_removed", Ref: v.ComponentName + " (" + v.License + ")"})
	}
	// Cap at 50 to keep the audit row + response payload bounded.
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

// ---------- disabled placeholder ----------

// disabledPlaceholder returns a deterministic summary built from the diff
// counts. M1 F4 analogue — the UI can still render Confidence / Evidence /
// Approve controls and the operator knows AI was deliberately disabled
// (not a silent failure).
func disabledPlaceholder(lang string, d *diff.Response) *llmFields {
	cAdd := len(d.Components.Added)
	cRem := len(d.Components.Removed)
	cChg := len(d.Components.VersionChanged)
	vAdd := len(d.Vulnerabilities.Added)
	vRes := len(d.Vulnerabilities.Resolved)
	lAdd := len(d.Licenses.AddedPolicyViolations)

	if lang == "ja" {
		return &llmFields{
			Summary: fmt.Sprintf(
				"AI 要約は無効化されています (BYOK 未設定)。差分の機械的サマリ: コンポーネント追加 %d / 削除 %d / バージョン変更 %d、新規脆弱性 %d / 解消 %d、新規ライセンス違反 %d。",
				cAdd, cRem, cChg, vAdd, vRes, lAdd,
			),
			Highlights: []string{
				fmt.Sprintf("コンポーネント変更: 追加 %d / 削除 %d / バージョン更新 %d", cAdd, cRem, cChg),
				fmt.Sprintf("脆弱性: 新規 %d / 解消 %d", vAdd, vRes),
				fmt.Sprintf("ライセンスポリシー違反: 新規 %d", lAdd),
				"AI 要約を有効化するには /settings/llm で BYOK を設定してください。",
			},
			Confidence: 0.0,
		}
	}
	return &llmFields{
		Summary: fmt.Sprintf(
			"AI summary is disabled (BYOK not configured). Mechanical diff summary: components +%d / -%d / version-changed %d, vulnerabilities +%d / resolved %d, new licence-policy violations %d.",
			cAdd, cRem, cChg, vAdd, vRes, lAdd,
		),
		Highlights: []string{
			fmt.Sprintf("Components: %d added, %d removed, %d version-changed", cAdd, cRem, cChg),
			fmt.Sprintf("Vulnerabilities: %d added, %d resolved", vAdd, vRes),
			fmt.Sprintf("License-policy violations: %d new", lAdd),
			"Configure BYOK at /settings/llm to enable AI summaries.",
		},
		Confidence: 0.0,
	}
}

// ---------- persistence helpers ----------

func (s *Service) writeSuccessLLMCall(
	ctx context.Context, req Request, provider llm.Provider,
	promptHash, promptPreview string, cresp *llm.CompleteResponse,
	duration time.Duration, now time.Time,
) (uuid.UUID, error) {
	respHash := sha256hexBytes(cresp.RawResponse)
	respPreview := truncate(cresp.Content, 512)
	call := &repository.LLMCall{
		ID:              uuid.New(),
		TenantID:        req.TenantID,
		UserID:          req.UserID,
		Purpose:         LLMCallPurposeDiffSummary,
		Provider:        provider.Name(),
		Model:           provider.Model(),
		PromptHash:      promptHash,
		PromptPreview:   promptPreview,
		ResponseHash:    respHash,
		ResponsePreview: respPreview,
		InputTokens:     cresp.InputTokens,
		OutputTokens:    cresp.OutputTokens,
		CostUSD:         cresp.CostUSD,
		DurationMs:      int(duration / time.Millisecond),
		FinishReason:    cresp.FinishReason,
		CreatedAt:       now,
	}
	if err := s.llmCalls.Insert(ctx, call); err != nil {
		return uuid.Nil, fmt.Errorf("insert llm_calls: %w", err)
	}
	return call.ID, nil
}

func (s *Service) writeFailedLLMCall(
	ctx context.Context, req Request, provider llm.Provider,
	promptHash, promptPreview, errorMsg string,
	duration time.Duration, now time.Time,
) (uuid.UUID, error) {
	call := &repository.LLMCall{
		ID:            uuid.New(),
		TenantID:      req.TenantID,
		UserID:        req.UserID,
		Purpose:       LLMCallPurposeDiffSummary,
		Provider:      provider.Name(),
		Model:         provider.Model(),
		PromptHash:    promptHash,
		PromptPreview: promptPreview,
		DurationMs:    int(duration / time.Millisecond),
		ErrorMessage:  errorMsg,
		CreatedAt:     now,
	}
	if err := s.llmCalls.Insert(ctx, call); err != nil {
		return uuid.Nil, fmt.Errorf("insert llm_calls (failed): %w", err)
	}
	return call.ID, nil
}

func (s *Service) writeLLMCallFailedParse(
	ctx context.Context, req Request, provider llm.Provider,
	promptHash, promptPreview string, cresp *llm.CompleteResponse,
	errorMsg string, duration time.Duration, now time.Time,
) (uuid.UUID, error) {
	respHash := sha256hexBytes(cresp.RawResponse)
	respPreview := truncate(cresp.Content, 512)
	call := &repository.LLMCall{
		ID:              uuid.New(),
		TenantID:        req.TenantID,
		UserID:          req.UserID,
		Purpose:         LLMCallPurposeDiffSummary,
		Provider:        provider.Name(),
		Model:           provider.Model(),
		PromptHash:      promptHash,
		PromptPreview:   promptPreview,
		ResponseHash:    respHash,
		ResponsePreview: respPreview,
		InputTokens:     cresp.InputTokens,
		OutputTokens:    cresp.OutputTokens,
		CostUSD:         cresp.CostUSD,
		DurationMs:      int(duration / time.Millisecond),
		FinishReason:    cresp.FinishReason,
		ErrorMessage:    errorMsg,
		CreatedAt:       now,
	}
	if err := s.llmCalls.Insert(ctx, call); err != nil {
		return uuid.Nil, fmt.Errorf("insert llm_calls (parse-fail): %w", err)
	}
	return call.ID, nil
}

func (s *Service) writeDisabledLLMCall(
	ctx context.Context, req Request, provider llm.Provider,
	promptHash, promptPreview string, now time.Time,
) (uuid.UUID, error) {
	providerName := "disabled"
	if provider != nil {
		providerName = provider.Name()
	}
	call := &repository.LLMCall{
		ID:            uuid.New(),
		TenantID:      req.TenantID,
		UserID:        req.UserID,
		Purpose:       LLMCallPurposeDiffSummary,
		Provider:      providerName,
		Model:         "",
		PromptHash:    promptHash,
		PromptPreview: promptPreview,
		ErrorMessage:  "ai_disabled",
		CreatedAt:     now,
	}
	if err := s.llmCalls.Insert(ctx, call); err != nil {
		return uuid.Nil, fmt.Errorf("insert llm_calls (disabled): %w", err)
	}
	return call.ID, nil
}

func (s *Service) writeAudit(
	ctx context.Context, req Request, action string,
	llmCallID uuid.UUID, d *diff.Response,
	parsed *llmFields, confidence float64,
) error {
	details := map[string]interface{}{
		"llm_call_id":                llmCallID.String(),
		"confidence":                 confidence,
		"components_added":           len(d.Components.Added),
		"components_removed":         len(d.Components.Removed),
		"components_changed":         len(d.Components.VersionChanged),
		"vulns_added":                len(d.Vulnerabilities.Added),
		"vulns_resolved":             len(d.Vulnerabilities.Resolved),
		"vulns_sev_changed":          len(d.Vulnerabilities.SeverityChanged),
		"license_violations_added":   len(d.Licenses.AddedPolicyViolations),
		"license_violations_removed": len(d.Licenses.RemovedPolicyViolations),
		"summary_preview":            truncate(parsed.Summary, 200),
	}
	if d.From != nil {
		details["from_sbom_id"] = d.From.SbomID.String()
	}
	if d.To != nil {
		details["to_sbom_id"] = d.To.SbomID.String()
	}
	tenantID := req.TenantID
	input := &model.CreateAuditLogInput{
		TenantID:     &tenantID,
		UserID:       req.UserID,
		Action:       action,
		ResourceType: ResourceTypeSbomDiff,
		ResourceID:   &req.ProjectID,
		Details:      details,
	}
	if err := s.audit.Log(ctx, input); err != nil {
		return fmt.Errorf("write audit: %w", err)
	}
	return nil
}

func (s *Service) writeFailedAudit(
	ctx context.Context, req Request, llmCallID uuid.UUID,
	d *diff.Response, errMsg string,
) error {
	details := map[string]interface{}{
		"llm_call_id":        llmCallID.String(),
		"error":              errMsg,
		"components_added":   len(d.Components.Added),
		"components_removed": len(d.Components.Removed),
		"vulns_added":        len(d.Vulnerabilities.Added),
		"vulns_resolved":     len(d.Vulnerabilities.Resolved),
	}
	if d.From != nil {
		details["from_sbom_id"] = d.From.SbomID.String()
	}
	if d.To != nil {
		details["to_sbom_id"] = d.To.SbomID.String()
	}
	tenantID := req.TenantID
	input := &model.CreateAuditLogInput{
		TenantID:     &tenantID,
		UserID:       req.UserID,
		Action:       AuditActionAIFailed,
		ResourceType: ResourceTypeSbomDiff,
		ResourceID:   &req.ProjectID,
		Details:      details,
	}
	if err := s.audit.Log(ctx, input); err != nil {
		return fmt.Errorf("write failed-audit: %w", err)
	}
	return nil
}

// ---------- small helpers ----------

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func sha256hexBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func uuidStringOrEmpty(p *uuid.UUID) string {
	if p == nil {
		return ""
	}
	return p.String()
}

func providerName(p llm.Provider) string {
	if p == nil {
		return "disabled"
	}
	return p.Name()
}

func providerModel(p llm.Provider) string {
	if p == nil {
		return ""
	}
	return p.Model()
}

// silence unused-import linter when middleware constants are referenced
// elsewhere; the package is imported for documentation cross-reference.
var _ = middleware.ContextKeyTenantID
