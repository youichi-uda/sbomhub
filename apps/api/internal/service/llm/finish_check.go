package llm

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// FinishKind classifies a CompleteResponse.FinishReason (M75).
type FinishKind int

const (
	// FinishNormal: the provider ended the answer itself (or did not say).
	FinishNormal FinishKind = iota
	// FinishTruncated: the provider cut the answer at a token / context
	// limit.
	FinishTruncated
	// FinishFiltered: the provider stopped or withheld the answer for a
	// content-filter, safety, recitation or refusal reason.
	FinishFiltered
	// FinishUnfinished: any other value — SBOMHub's own "incomplete",
	// "unrecognized", or a provider value not known to be a normal end.
	FinishUnfinished
)

func (k FinishKind) String() string {
	switch k {
	case FinishNormal:
		return "normal"
	case FinishTruncated:
		return "truncated"
	case FinishFiltered:
		return "filtered"
	default:
		return "unfinished"
	}
}

// ErrTruncatedResponse is returned (wrapped) when the provider reports that
// it cut the answer at a token or context limit (OpenAI / Azure / Ollama
// "length", Anthropic "max_tokens" / "model_context_window_exceeded" /
// "pause_turn", Gemini "MAX_TOKENS"). It wraps ErrIncompleteResponse, so a
// caller checking for an incomplete answer also catches a truncated one.
var ErrTruncatedResponse = fmt.Errorf("%w: cut by the provider's token limit", ErrIncompleteResponse)

// ErrFilteredResponse is returned (wrapped) when the provider reports that a
// content filter, safety rule, recitation check or model refusal stopped the
// answer (OpenAI / Azure "content_filter", Anthropic "refusal", Gemini
// "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", …).
// Whatever text came back is not the model's full answer to the prompt.
var ErrFilteredResponse = errors.New("llm: response stopped by the provider's content filter")

// Finish reasons, lower-cased. Providers spell them differently (Gemini
// upper-case), so matching is case-insensitive.
var (
	normalFinishReasons = map[string]struct{}{
		"stop":          {}, // OpenAI / Azure / Ollama / Gemini "STOP"
		"end_turn":      {}, // Anthropic
		"stop_sequence": {}, // Anthropic
		// Not here: tool_calls / function_call / tool_use. They ask the
		// caller to run a tool and continue; no SBOMHub caller offers
		// tools, so such an answer is not a final one (FinishUnfinished).
	}
	truncatedFinishReasons = map[string]struct{}{
		"length":                        {}, // OpenAI / Azure / Ollama
		"max_tokens":                    {}, // Anthropic, Gemini "MAX_TOKENS"
		"model_context_window_exceeded": {}, // Anthropic
		"pause_turn":                    {}, // Anthropic: turn paused before the answer ended
	}
	filteredFinishReasons = map[string]struct{}{
		"content_filter":           {}, // OpenAI / Azure
		"refusal":                  {}, // Anthropic
		"safety":                   {}, // Gemini
		"recitation":               {}, // Gemini
		"blocklist":                {}, // Gemini
		"prohibited_content":       {}, // Gemini
		"spii":                     {}, // Gemini
		"image_safety":             {}, // Gemini
		"image_prohibited_content": {}, // Gemini
		"image_recitation":         {}, // Gemini
	}
)

// ClassifyFinishReason says whether a finish reason is a normal end of the
// answer. Only the values listed above as normal (and the empty string: the
// provider did not say, accepted as before M75) are FinishNormal; every
// unknown value is FinishUnfinished, so a reason a provider adds later fails
// closed rather than letting a cut answer through.
func ClassifyFinishReason(reason string) FinishKind {
	r := strings.ToLower(strings.TrimSpace(reason))
	if r == "" {
		return FinishNormal
	}
	if _, ok := normalFinishReasons[r]; ok {
		return FinishNormal
	}
	if _, ok := truncatedFinishReasons[r]; ok {
		return FinishTruncated
	}
	if _, ok := filteredFinishReasons[r]; ok {
		return FinishFiltered
	}
	return FinishUnfinished
}

// IsTruncated reports whether the provider says it cut the answer at a token
// or context limit.
func IsTruncated(reason string) bool { return ClassifyFinishReason(reason) == FinishTruncated }

// CheckFinish returns an error when resp's finish reason is not a normal end
// of the answer: ErrTruncatedResponse, ErrFilteredResponse, or (any other
// value) ErrIncompleteResponse, each naming the reason. It returns nil for a
// nil response or a normal end.
func CheckFinish(resp *CompleteResponse) error {
	if resp == nil {
		return nil
	}
	if strings.TrimSpace(resp.Refusal) != "" {
		return fmt.Errorf("%w (model refusal, finish_reason %q)", ErrFilteredResponse, resp.FinishReason)
	}
	switch ClassifyFinishReason(resp.FinishReason) {
	case FinishNormal:
		return nil
	case FinishTruncated:
		return fmt.Errorf("%w (finish_reason %q)", ErrTruncatedResponse, resp.FinishReason)
	case FinishFiltered:
		return fmt.Errorf("%w (finish_reason %q)", ErrFilteredResponse, resp.FinishReason)
	default:
		return fmt.Errorf("%w: finish_reason %q is not a normal end of the answer", ErrIncompleteResponse, resp.FinishReason)
	}
}

// Complete calls p.Complete and then CheckFinish. Every caller that keeps an
// answer as a draft, suggestion or summary goes through it (M75): a
// truncated, filtered or unfinished answer comes back as an error together
// with the response, which the caller records in llm_calls (partial
// content, finish reason, error message) and does not use. A provider error
// is returned unchanged.
func Complete(ctx context.Context, p Provider, req CompleteRequest) (*CompleteResponse, error) {
	resp, err := p.Complete(ctx, req)
	if err != nil {
		return resp, err
	}
	if resp == nil {
		return nil, fmt.Errorf("%w: provider %s returned no response and no error", ErrIncompleteResponse, p.Name())
	}
	if ferr := CheckFinish(resp); ferr != nil {
		return resp, ferr
	}
	return resp, nil
}
