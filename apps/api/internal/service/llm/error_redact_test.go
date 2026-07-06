package llm

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// TestRedactProviderError_NilInput verifies the helper is nil-safe so
// callers can wrap unconditionally (`RedactProviderError(err)` without a
// guard before persistence).
func TestRedactProviderError_NilInput(t *testing.T) {
	if got := RedactProviderError(nil); got != nil {
		t.Errorf("RedactProviderError(nil) = %v, want nil", got)
	}
}

// TestRedactProviderError_URLErrorWithKeyQueryParam covers the M1 #F13
// primary leak path: net/http returns *url.Error whose Error() method
// echoes the full URL including the BYOK key in the query string.
func TestRedactProviderError_URLErrorWithKeyQueryParam(t *testing.T) {
	const apiKey = "AIzaSyTEST_SECRET_KEY_DO_NOT_LEAK"
	urlErr := &url.Error{
		Op:  "Post",
		URL: "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" + apiKey,
		Err: errors.New("dial tcp: lookup ...: no such host"),
	}
	// Wrap the way the gemini provider does (`fmt.Errorf("gemini: http call: %w", err)`)
	// so we exercise the chain-walk path of errors.As.
	wrapped := fmt.Errorf("gemini: http call: %w", urlErr)
	redacted := RedactProviderError(wrapped)
	if redacted == nil {
		t.Fatal("RedactProviderError returned nil for non-nil input")
	}
	msg := redacted.Error()
	if strings.Contains(msg, apiKey) {
		t.Errorf("redacted error still contains API key: %q", msg)
	}
	if strings.Contains(msg, "key=AIza") {
		t.Errorf("redacted error still contains key= prefix: %q", msg)
	}
	// The url.Error leaf must also have been mutated so any downstream
	// `errors.As(err, &urlErr); log.Print(urlErr.URL)` is safe too.
	var leaf *url.Error
	if !errors.As(redacted, &leaf) {
		t.Fatal("expected *url.Error to remain reachable via errors.As after redaction")
	}
	if strings.Contains(leaf.URL, apiKey) {
		t.Errorf("url.Error.URL field still contains API key: %q", leaf.URL)
	}
	if strings.Contains(leaf.URL, "?key=") {
		t.Errorf("url.Error.URL field still contains ?key= query: %q", leaf.URL)
	}
	// And the underlying error chain must remain intact so callers that
	// check sentinels (e.g. context.Canceled) keep working.
	if !errors.Is(redacted, urlErr.Err) {
		t.Errorf("errors.Is should still match the original cause through the redacted wrapper")
	}
}

// TestRedactProviderError_AlternateAuthParamNames covers the alternate
// auth-shaped query parameter names the regex catches.
func TestRedactProviderError_AlternateAuthParamNames(t *testing.T) {
	cases := []struct {
		name    string
		rawURL  string
		secret  string
		wantHit string // substring that must be removed
	}{
		{"api_key", "https://example.com/v1/x?api_key=AKIA_SECRET", "AKIA_SECRET", "api_key=AKIA_SECRET"},
		{"api-key", "https://example.com/v1/x?api-key=AKIA_SECRET", "AKIA_SECRET", "api-key=AKIA_SECRET"},
		{"apikey", "https://example.com/v1/x?apikey=AKIA_SECRET", "AKIA_SECRET", "apikey=AKIA_SECRET"},
		{"access_token", "https://example.com/v1/x?access_token=ya29.SECRET", "ya29.SECRET", "access_token=ya29.SECRET"},
		{"key_with_amp", "https://example.com/v1/x?model=foo&key=AIza_SECRET", "AIza_SECRET", "key=AIza_SECRET"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			urlErr := &url.Error{Op: "Get", URL: tc.rawURL, Err: errors.New("connection refused")}
			redacted := RedactProviderError(urlErr)
			if redacted == nil {
				t.Fatal("redacted is nil")
			}
			if strings.Contains(redacted.Error(), tc.secret) {
				t.Errorf("[%s] redacted error contains secret: %q", tc.name, redacted.Error())
			}
			if strings.Contains(redacted.Error(), tc.wantHit) {
				t.Errorf("[%s] redacted error still contains auth substring %q: %q", tc.name, tc.wantHit, redacted.Error())
			}
		})
	}
}

// TestRedactProviderError_NonURLErrorPassthrough verifies the helper does
// not touch errors that contain no auth-shaped material — preserving
// stack-trace fidelity for unrelated failures.
func TestRedactProviderError_NonURLErrorPassthrough(t *testing.T) {
	original := errors.New("upstream LLM 503 (transient)")
	got := RedactProviderError(original)
	if got != original {
		t.Errorf("expected pass-through of original error, got %v (different instance)", got)
	}
}

// TestRedactProviderError_NonURLErrorWithKeySubstring covers the
// defense-in-depth layer: even if the chain has no *url.Error, an error
// whose rendered text contains a `?key=...` substring (e.g. from a
// hand-rolled HTTP wrapper that printed the request URL) is still
// scrubbed.
func TestRedactProviderError_NonURLErrorWithKeySubstring(t *testing.T) {
	const apiKey = "AIzaSyTEST_SECRET"
	original := fmt.Errorf("custom transport: GET %s failed", "https://example.com/x?key="+apiKey)
	got := RedactProviderError(original)
	if got == nil {
		t.Fatal("got nil")
	}
	if strings.Contains(got.Error(), apiKey) {
		t.Errorf("string-only scrubber missed the key: %q", got.Error())
	}
	if !strings.Contains(got.Error(), "[REDACTED]") {
		t.Errorf("expected [REDACTED] marker, got: %q", got.Error())
	}
}

// NOTE (M42 Wave 2): TestRedactURLString_MalformedFallback moved to
// internal/redact/redact_test.go alongside the redactURLString
// implementation, which now lives in the internal/redact leaf package.
// RedactProviderError above is a thin re-export of redact.Error, so the
// TestRedactProviderError_* cases in this file continue to exercise the
// exported contract unchanged.
