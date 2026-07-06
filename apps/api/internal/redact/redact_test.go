package redact

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// TestString_RedactsSecrets asserts that each unambiguous secret shape has
// its VALUE replaced with the placeholder while the surrounding structure
// (param name, scheme/user/host, header name) is preserved.
func TestString_RedactsSecrets(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		secret  string // must NOT survive
		wantSub string // must appear in the output
	}{
		{"query key", "https://api.example.com/v1?key=abcSECRET123", "abcSECRET123", "?key=[REDACTED]"},
		{"query api_key", "GET https://x/y?api_key=AKIA_SECRET failed", "AKIA_SECRET", "api_key=[REDACTED]"},
		{"query api-key", "https://x/y?api-key=AKIA_SECRET", "AKIA_SECRET", "api-key=[REDACTED]"},
		{"query apikey", "https://x/y?apikey=AKIA_SECRET", "AKIA_SECRET", "apikey=[REDACTED]"},
		{"query access_token", "https://x/y?access_token=ya29.SECRET", "ya29.SECRET", "access_token=[REDACTED]"},
		{"query token", "callback?token=deadbeefdeadbeef", "deadbeefdeadbeef", "token=[REDACTED]"},
		{"query secret", "https://x/y?secret=hunter2value", "hunter2value", "secret=[REDACTED]"},
		{"query password", "https://x/y?password=hunter2value", "hunter2value", "password=[REDACTED]"},
		{"amp key", "https://x/y?model=foo&key=AIza_SECRET", "AIza_SECRET", "&key=[REDACTED]"},
		{"bearer", "Bearer eyJhbGciOiJIUzI1Ni.payload-sig", "eyJhbGciOiJIUzI1Ni.payload-sig", "Bearer [REDACTED]"},
		{"authorization bearer", "Authorization: Bearer eyJ0okenSECRET", "eyJ0okenSECRET", "Authorization: [REDACTED]"},
		{"authorization bare", "Authorization: sk-liveSECRETkey", "sk-liveSECRETkey", "Authorization: [REDACTED]"},
		// M42 Phase D: a Basic base64 credential must be removed IN FULL, not
		// just the scheme word (the value is all-letters mixed-case base64, so it
		// is caught by the mixed-case credential shape, not a digit/special).
		{"authorization basic base64", "Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz", "Authorization: [REDACTED]"},
		// M42 Phase D r2: a Digest header spreads the credential across
		// comma-separated params (response=<hash> is the real secret); with a
		// recognised scheme the WHOLE value is redacted, not just the first param.
		{"authorization digest", `Authorization: Digest username="u", realm="r", nonce="abc", response="deadbeef1234567890abcdef"`, "deadbeef1234567890abcdef", "Authorization: [REDACTED]"},
		{"dsn password", "dial postgres://appuser:S3cr3tPw@db.internal:5432/app", "S3cr3tPw", "postgres://appuser:[REDACTED]@db.internal:5432/app"},
		{"dsn empty user", "redis://:R3disPw@cache:6379", "R3disPw", "redis://:[REDACTED]@cache:6379"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := String(tc.in)
			if strings.Contains(got, tc.secret) {
				t.Errorf("secret survived redaction: in=%q out=%q (leaked %q)", tc.in, got, tc.secret)
			}
			if !strings.Contains(got, tc.wantSub) {
				t.Errorf("expected %q in output, got %q", tc.wantSub, got)
			}
		})
	}
}

// TestString_PreservesNonSecrets is the over-redaction guard: the compliance
// evidence classes named in the M42 spec (§8.5 audit trail) MUST pass through
// String byte-for-byte because none of them match a secret shape.
func TestString_PreservesNonSecrets(t *testing.T) {
	preserved := []string{
		"CVE-2021-44228",
		"CVE-2024-3094",
		"550e8400-e29b-41d4-a716-446655440000",   // resource UUID
		"provider=openai model=gemini-3.5-flash", // provider/model NAMES
		"claude-opus-4-7",                        // model name
		"Not affected: the vulnerable code path is guarded by an allow-list " +
			"and the tainted parameter is never reached; reviewed 2026-07-01 " +
			"against advisory GHSA-jfh8-c2jp-5v3q.", // justification prose
		"draft_justification: input is validated at the edge",
		"edited_detail: see remediation ticket PROJ-123",
		"count=42 approved=true action=vex_draft.created",
		"2026-07-06T12:34:56Z",
		"https://github.com/apache/logging-log4j2/releases", // plain URL, no auth
		"postgres://db.internal:5432/app",                   // host:port, no userinfo -> no password
		// M42 Phase D over-redaction guard: "Bearer"/"Authorization:" are common
		// English words in auth-CVE justifications and MUST survive — only
		// credential-SHAPED values are redacted, and these dictionary words are
		// not credential shaped.
		"validates the Bearer token signature before use",
		"attackers can bypass Bearer authentication entirely",
		"Authorization: role-based access control is enforced",
		"The flag bearer approach was rejected",
		"Authorization: Basic authentication is required by the endpoint",
		// snake_case OAuth terms are prose, not credentials (underscore alone no
		// longer qualifies as a credential shape).
		"Bearer access_token and refresh_token are rotated via PKCE",
		"the client_secret is stored in Vault, never in a Bearer access_token",
	}
	for _, s := range preserved {
		if got := String(s); got != s {
			t.Errorf("non-secret was corrupted by redaction:\n in:  %q\n out: %q", s, got)
		}
	}
}

// TestString_EmptyIsNoop guards the fast path.
func TestString_EmptyIsNoop(t *testing.T) {
	if got := String(""); got != "" {
		t.Errorf("String(\"\") = %q, want empty", got)
	}
}

// --- Error() contract (moved from llm.error_redact_test, generalised) ---

// TestError_NilInput verifies nil-safety so callers can wrap
// unconditionally.
func TestError_NilInput(t *testing.T) {
	if got := Error(nil); got != nil {
		t.Errorf("Error(nil) = %v, want nil", got)
	}
}

// TestError_URLErrorScrubsAndPreservesChain covers the primary M1 #F13 leak
// path AND asserts errors.Is / errors.As survive redaction.
func TestError_URLErrorScrubsAndPreservesChain(t *testing.T) {
	const apiKey = "AIzaSyTEST_SECRET_KEY_DO_NOT_LEAK"
	cause := errors.New("dial tcp: lookup ...: no such host")
	urlErr := &url.Error{
		Op:  "Post",
		URL: "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" + apiKey,
		Err: cause,
	}
	wrapped := fmt.Errorf("gemini: http call: %w", urlErr)

	redacted := Error(wrapped)
	if redacted == nil {
		t.Fatal("Error returned nil for non-nil input")
	}
	if strings.Contains(redacted.Error(), apiKey) {
		t.Errorf("redacted error still contains API key: %q", redacted.Error())
	}

	// The *url.Error leaf must remain reachable AND scrubbed.
	var leaf *url.Error
	if !errors.As(redacted, &leaf) {
		t.Fatal("expected *url.Error reachable via errors.As after redaction")
	}
	if strings.Contains(leaf.URL, apiKey) || strings.Contains(leaf.URL, "?key=") {
		t.Errorf("url.Error.URL still leaks: %q", leaf.URL)
	}

	// The original cause must still match through the wrapper.
	if !errors.Is(redacted, cause) {
		t.Error("errors.Is should still match the original cause through the redacted wrapper")
	}
}

// TestError_NonURLPassthrough verifies a secret-free error is returned as
// the SAME instance so sentinel identity is preserved.
func TestError_NonURLPassthrough(t *testing.T) {
	original := errors.New("upstream LLM 503 (transient)")
	if got := Error(original); got != original {
		t.Errorf("expected pass-through of original instance, got a different value: %v", got)
	}
}

// TestError_StringLayerCatchesGeneralisedShapes covers the defense-in-depth
// layer for secrets echoed into a non-*url.Error message: a Bearer token and
// a DSN password (shapes the old URL-query-only scrubber missed).
func TestError_StringLayerCatchesGeneralisedShapes(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		secret string
	}{
		{"key substring", fmt.Errorf("custom transport: GET %s failed", "https://x/y?key=AIzaSyTEST_SECRET"), "AIzaSyTEST_SECRET"},
		{"bearer", errors.New("auth failed: Authorization: Bearer eyJsecretTOKEN"), "eyJsecretTOKEN"},
		{"dsn", errors.New("db connect: postgres://admin:S3cr3tPw@db:5432 refused"), "S3cr3tPw"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Error(tc.err)
			if got == nil {
				t.Fatal("got nil")
			}
			if strings.Contains(got.Error(), tc.secret) {
				t.Errorf("string layer missed the secret: %q", got.Error())
			}
			if !strings.Contains(got.Error(), placeholder) {
				t.Errorf("expected %s marker, got: %q", placeholder, got.Error())
			}
			// Chain preserved for errors.Is.
			if !errors.Is(got, tc.err) {
				t.Error("errors.Is should match the wrapped original error")
			}
		})
	}
}

// TestRedactURLString_MalformedFallback (moved from llm.error_redact_test)
// verifies a parse failure falls back to the static placeholder so the raw
// URL cannot leak through a parse-error shortcut.
func TestRedactURLString_MalformedFallback(t *testing.T) {
	got := redactURLString("ht\x7ftp://oops?key=secret")
	if strings.Contains(got, "secret") {
		t.Errorf("malformed URL fallback leaked the secret: %q", got)
	}
	if got != urlPlaceholder {
		t.Errorf("got %q, want %q", got, urlPlaceholder)
	}
}

// --- Details() deep-scrub: the audit choke-point behaviour ---

// TestDetails_ScrubsNestedSecretsPreservesEvidence pins the exact M42 §8.5
// invariant: a detail map carrying BOTH secrets and compliance evidence has
// the secrets redacted while every evidence field survives verbatim.
// url.Values (the audit middleware's query map) is scrubbed leaf-by-leaf.
func TestDetails_ScrubsNestedSecretsPreservesEvidence(t *testing.T) {
	uuidVal := "550e8400-e29b-41d4-a716-446655440000"
	justification := "Not affected: sink unreachable; reviewed 2026-07-01 (GHSA-jfh8-c2jp-5v3q)."

	in := map[string]interface{}{
		"cve_id":        "CVE-2021-44228",
		"resource_uuid": uuidVal,
		"provider":      "openai",
		"model":         "gemini-3.5-flash",
		"justification": justification,
		"approved":      true,
		"count":         42,
		"dsn":           "postgres://appuser:S3cr3tPw@db.internal:5432/sbomhub",
		"error":         "call failed with Authorization: Bearer eyJhbGciSECRETtoken",
		"query": url.Values{
			"q":        []string{"log4j"},
			"redirect": []string{"https://svc/cb?key=LEAKEDKEY123"},
		},
		"nested": map[string]interface{}{
			"note": "human decision text, no secret",
			"list": []interface{}{"CVE-2024-3094", "Bearer eyJnestedSECRET"},
		},
	}
	// Snapshot the input so we can assert non-mutation.
	origDSN := in["dsn"].(string)

	out := Details(in)

	// Re-marshal-free string assertions on individual fields.
	mustEq := func(key, want string) {
		if got, _ := out[key].(string); got != want {
			t.Errorf("out[%q] = %q, want %q", key, got, want)
		}
	}
	// Evidence preserved verbatim.
	mustEq("cve_id", "CVE-2021-44228")
	mustEq("resource_uuid", uuidVal)
	mustEq("provider", "openai")
	mustEq("model", "gemini-3.5-flash")
	mustEq("justification", justification)
	if out["approved"] != true {
		t.Errorf("approved bool corrupted: %v", out["approved"])
	}
	if out["count"] != 42 {
		t.Errorf("count int corrupted: %v", out["count"])
	}

	// Secrets redacted.
	mustEq("dsn", "postgres://appuser:[REDACTED]@db.internal:5432/sbomhub")
	if got, _ := out["error"].(string); strings.Contains(got, "eyJhbGciSECRETtoken") {
		t.Errorf("Authorization bearer token leaked: %q", got)
	}

	// url.Values leaf scrubbing: q preserved, redirect key= redacted.
	q, ok := out["query"].(url.Values)
	if !ok {
		t.Fatalf("query type changed: %T", out["query"])
	}
	if q.Get("q") != "log4j" {
		t.Errorf("query q corrupted: %q", q.Get("q"))
	}
	if got := q.Get("redirect"); strings.Contains(got, "LEAKEDKEY123") || !strings.Contains(got, "key=[REDACTED]") {
		t.Errorf("query redirect not scrubbed: %q", got)
	}

	// Nested map + []interface{} recursion.
	nested, ok := out["nested"].(map[string]interface{})
	if !ok {
		t.Fatalf("nested type changed: %T", out["nested"])
	}
	if nested["note"] != "human decision text, no secret" {
		t.Errorf("nested note corrupted: %v", nested["note"])
	}
	list, ok := nested["list"].([]interface{})
	if !ok || len(list) != 2 {
		t.Fatalf("nested list shape changed: %#v", nested["list"])
	}
	if list[0] != "CVE-2024-3094" {
		t.Errorf("nested list CVE corrupted: %v", list[0])
	}
	if s, _ := list[1].(string); strings.Contains(s, "eyJnestedSECRET") {
		t.Errorf("nested bearer token leaked: %q", s)
	}

	// Non-mutation of the caller's map.
	if in["dsn"].(string) != origDSN {
		t.Errorf("input map was mutated: in[dsn]=%q", in["dsn"])
	}
	if in["cve_id"].(string) != "CVE-2021-44228" {
		t.Errorf("input map cve_id mutated: %q", in["cve_id"])
	}
}

// TestDetails_NilReturnsNil keeps json.Marshal producing the same `null`.
func TestDetails_NilReturnsNil(t *testing.T) {
	if got := Details(nil); got != nil {
		t.Errorf("Details(nil) = %v, want nil", got)
	}
}
