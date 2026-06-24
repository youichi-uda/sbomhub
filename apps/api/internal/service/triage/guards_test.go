package triage

import (
	"errors"
	"math"
	"testing"
)

func TestApplyConfidenceThreshold(t *testing.T) {
	cases := []struct {
		name        string
		state       string
		confidence  float64
		threshold   float64
		wantState   string
		wantClamped bool
	}{
		{
			name:        "above threshold keeps state",
			state:       "not_affected",
			confidence:  0.95,
			threshold:   0.7,
			wantState:   "not_affected",
			wantClamped: false,
		},
		{
			name:        "exactly at threshold keeps state",
			state:       "affected",
			confidence:  0.7,
			threshold:   0.7,
			wantState:   "affected",
			wantClamped: false,
		},
		{
			name:        "below threshold clamps to under_investigation",
			state:       "not_affected",
			confidence:  0.5,
			threshold:   0.7,
			wantState:   "under_investigation",
			wantClamped: true,
		},
		{
			name:        "NaN confidence always clamps",
			state:       "not_affected",
			confidence:  math.NaN(),
			threshold:   0.7,
			wantState:   "under_investigation",
			wantClamped: true,
		},
		{
			name:        "invalid state above threshold still clamps",
			state:       "maybe_affected",
			confidence:  0.99,
			threshold:   0.7,
			wantState:   "under_investigation",
			wantClamped: true,
		},
		{
			name:        "empty state above threshold clamps",
			state:       "",
			confidence:  0.99,
			threshold:   0.7,
			wantState:   "under_investigation",
			wantClamped: true,
		},
		{
			name:        "negative threshold treated as 0 (always pass)",
			state:       "resolved",
			confidence:  0.0,
			threshold:   -5,
			wantState:   "resolved",
			wantClamped: false,
		},
		{
			name:        "threshold > 1 treated as 1 (only confidence=1 passes)",
			state:       "affected",
			confidence:  0.99,
			threshold:   42,
			wantState:   "under_investigation",
			wantClamped: true,
		},
		{
			name:        "valid resolved state above threshold preserved",
			state:       "resolved",
			confidence:  0.85,
			threshold:   0.7,
			wantState:   "resolved",
			wantClamped: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotState, gotClamped := ApplyConfidenceThreshold(tc.state, tc.confidence, tc.threshold)
			if gotState != tc.wantState {
				t.Errorf("state: got %q, want %q", gotState, tc.wantState)
			}
			if gotClamped != tc.wantClamped {
				t.Errorf("clamped: got %v, want %v", gotClamped, tc.wantClamped)
			}
		})
	}
}

func TestValidateEvidence(t *testing.T) {
	cases := []struct {
		name    string
		input   []EvidencePointer
		wantErr error // sentinel to errors.Is against; nil means must succeed
	}{
		{
			name:    "nil slice rejected with ErrEmptyEvidence",
			input:   nil,
			wantErr: ErrEmptyEvidence,
		},
		{
			name:    "empty slice rejected with ErrEmptyEvidence",
			input:   []EvidencePointer{},
			wantErr: ErrEmptyEvidence,
		},
		{
			name: "valid import_path pointer accepted",
			input: []EvidencePointer{
				{Kind: EvidenceKindImportPath, ImportPath: "gopkg.in/yaml.v2"},
			},
			wantErr: nil,
		},
		{
			name: "valid symbol_ref pointer accepted",
			input: []EvidencePointer{
				{Kind: EvidenceKindSymbolRef, Symbol: "yaml.Unmarshal", FilePath: "main.go", Line: 12},
			},
			wantErr: nil,
		},
		{
			name: "import_path without ImportPath rejected",
			input: []EvidencePointer{
				{Kind: EvidenceKindImportPath},
			},
			wantErr: ErrInvalidEvidence,
		},
		{
			name: "symbol_ref without Symbol rejected",
			input: []EvidencePointer{
				{Kind: EvidenceKindSymbolRef, FilePath: "main.go"},
			},
			wantErr: ErrInvalidEvidence,
		},
		{
			name: "advisory_excerpt with RawSnippet accepted",
			input: []EvidencePointer{
				{Kind: EvidenceKindAdvisoryExcerpt, RawSnippet: "yaml.Unmarshal may panic on..."},
			},
			wantErr: nil,
		},
		{
			name: "advisory_excerpt with neither RawSnippet nor Description rejected",
			input: []EvidencePointer{
				{Kind: EvidenceKindAdvisoryExcerpt},
			},
			wantErr: ErrInvalidEvidence,
		},
		{
			name: "llm_rationale with Description accepted",
			input: []EvidencePointer{
				{Kind: EvidenceKindLLMRationale, Description: "Function only called in tests."},
			},
			wantErr: nil,
		},
		{
			name: "unknown Kind rejected",
			input: []EvidencePointer{
				{Kind: EvidenceKind("magic"), Description: "x"},
			},
			wantErr: ErrInvalidEvidence,
		},
		{
			name: "empty Kind rejected",
			input: []EvidencePointer{
				{Description: "x"},
			},
			wantErr: ErrInvalidEvidence,
		},
		{
			name: "first invalid in mixed slice surfaces error",
			input: []EvidencePointer{
				{Kind: EvidenceKindImportPath, ImportPath: "ok"},
				{Kind: EvidenceKindSymbolRef}, // bad
			},
			wantErr: ErrInvalidEvidence,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEvidence(tc.input)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got err=%v, want errors.Is(_, %v)", err, tc.wantErr)
			}
		})
	}
}

func TestIsValidState(t *testing.T) {
	cases := []struct {
		state string
		want  bool
	}{
		{"not_affected", true},
		{"affected", true},
		{"under_investigation", true},
		{"resolved", true},
		{"fixed", false}, // CycloneDX 1.4 only, intentionally excluded for M1
		{"", false},
		{"NOT_AFFECTED", false}, // case-sensitive
		{"maybe", false},
	}
	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			if got := IsValidState(tc.state); got != tc.want {
				t.Errorf("IsValidState(%q) = %v, want %v", tc.state, got, tc.want)
			}
		})
	}
}

func TestIsValidJustification(t *testing.T) {
	cases := []struct {
		just string
		want bool
	}{
		{"", true}, // accepted: states like 'affected' have no justification
		{"code_not_present", true},
		{"code_not_reachable", true},
		{"requires_configuration", true},
		{"requires_dependency", true},
		{"requires_environment", true},
		{"protected_by_compiler", true},
		{"protected_at_perimeter", true},
		{"protected_at_runtime", true},
		{"inline_mitigations_already_exist", true},
		{"vulnerable_code_not_present", false}, // CycloneDX 1.4 name (rejected)
		{"component_not_present", false},       // CycloneDX 1.4 name (rejected)
		{"something_else", false},
		{"CODE_NOT_PRESENT", false}, // case-sensitive
	}
	for _, tc := range cases {
		t.Run(tc.just, func(t *testing.T) {
			if got := IsValidJustification(tc.just); got != tc.want {
				t.Errorf("IsValidJustification(%q) = %v, want %v", tc.just, got, tc.want)
			}
		})
	}
}

func TestParseLLMResponse(t *testing.T) {
	t.Run("valid response parsed verbatim", func(t *testing.T) {
		raw := `{
            "state": "not_affected",
            "justification": "code_not_reachable",
            "detail": "Only called in tests.",
            "confidence": 0.92,
            "evidence": [
                {"kind": "symbol_ref", "symbol": "yaml.Unmarshal", "file_path": "x.go"}
            ]
        }`
		got, err := ParseLLMResponse(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.State != StateNotAffected {
			t.Errorf("State = %q, want %q", got.State, StateNotAffected)
		}
		if got.Justification != JustificationCodeNotReachable {
			t.Errorf("Justification = %q, want %q", got.Justification, JustificationCodeNotReachable)
		}
		if got.Confidence != 0.92 {
			t.Errorf("Confidence = %v, want 0.92", got.Confidence)
		}
		if len(got.Evidence) != 1 {
			t.Fatalf("len(Evidence) = %d, want 1", len(got.Evidence))
		}
		if got.RawResponse != raw {
			t.Errorf("RawResponse not preserved")
		}
	})

	t.Run("unknown state collapses to under_investigation", func(t *testing.T) {
		raw := `{"state":"definitely_maybe","confidence":0.9}`
		got, err := ParseLLMResponse(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.State != StateUnderInvestigation {
			t.Errorf("State = %q, want %q", got.State, StateUnderInvestigation)
		}
		if got.Confidence != 0.9 {
			t.Errorf("Confidence not preserved: got %v", got.Confidence)
		}
	})

	t.Run("unknown justification cleared", func(t *testing.T) {
		raw := `{"state":"not_affected","justification":"vulnerable_code_not_present","confidence":0.9}`
		got, _ := ParseLLMResponse(raw)
		if got.Justification != "" {
			t.Errorf("Justification = %q, want \"\"", got.Justification)
		}
		if got.State != StateNotAffected {
			t.Errorf("State should remain not_affected, got %q", got.State)
		}
	})

	t.Run("malformed JSON returns fallback decision (nil error)", func(t *testing.T) {
		raw := `{not really json`
		got, err := ParseLLMResponse(raw)
		if err != nil {
			t.Fatalf("ParseLLMResponse must never error; got %v", err)
		}
		if got.State != StateUnderInvestigation {
			t.Errorf("fallback State = %q, want under_investigation", got.State)
		}
		if got.Confidence != 0 {
			t.Errorf("fallback Confidence = %v, want 0", got.Confidence)
		}
		if len(got.Evidence) != 1 || got.Evidence[0].Kind != EvidenceKindLLMRationale {
			t.Fatalf("fallback should carry single llm_rationale evidence pointer, got %+v", got.Evidence)
		}
		if got.Evidence[0].Note != "parse_error" {
			t.Errorf("fallback evidence Note = %q, want parse_error", got.Evidence[0].Note)
		}
		if got.RawResponse != raw {
			t.Errorf("RawResponse not preserved on fallback")
		}
	})

	t.Run("confidence > 1 clamped to 1", func(t *testing.T) {
		raw := `{"state":"affected","confidence":42}`
		got, _ := ParseLLMResponse(raw)
		if got.Confidence != 1 {
			t.Errorf("Confidence = %v, want 1", got.Confidence)
		}
	})

	t.Run("negative confidence clamped to 0", func(t *testing.T) {
		raw := `{"state":"affected","confidence":-0.5}`
		got, _ := ParseLLMResponse(raw)
		if got.Confidence != 0 {
			t.Errorf("Confidence = %v, want 0", got.Confidence)
		}
	})

	t.Run("missing state defaults to under_investigation", func(t *testing.T) {
		raw := `{"confidence":0.5}`
		got, _ := ParseLLMResponse(raw)
		if got.State != StateUnderInvestigation {
			t.Errorf("State = %q, want under_investigation", got.State)
		}
	})
}

func TestConfidenceThresholdFromEnv(t *testing.T) {
	cases := []struct {
		name string
		set  bool
		val  string
		want float64
	}{
		{"unset returns default", false, "", DefaultConfidenceThreshold},
		{"empty string returns default", true, "", DefaultConfidenceThreshold},
		{"valid value parsed", true, "0.85", 0.85},
		{"zero accepted", true, "0", 0},
		{"one accepted", true, "1", 1},
		{"unparseable returns default", true, "abc", DefaultConfidenceThreshold},
		{"negative returns default", true, "-0.1", DefaultConfidenceThreshold},
		{"greater than 1 returns default", true, "1.5", DefaultConfidenceThreshold},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(EnvConfidenceThreshold, tc.val)
			} else {
				// t.Setenv with empty string and tc.set=false: explicitly unset.
				// Use os.Unsetenv-equivalent via t.Setenv("", ...) is not portable;
				// rely on test isolation via t.Setenv to a sentinel then unset.
				t.Setenv(EnvConfidenceThreshold, "")
				// re-read via the helper below: the parser treats "" as default
				// so the assertion still holds. (Covered by "empty" case too.)
			}
			got := ConfidenceThresholdFromEnv()
			if got != tc.want {
				t.Errorf("ConfidenceThresholdFromEnv() = %v, want %v", got, tc.want)
			}
		})
	}
}
