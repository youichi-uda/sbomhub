package llm

import (
	"github.com/sbomhub/sbomhub/internal/redact"
)

// RedactProviderError scrubs API-key-shaped (and other secret-shaped)
// material from a provider transport error before it is wrapped,
// persisted, or returned to a client.
//
// M42 Wave 2: the implementation moved to the dependency-free leaf
// package internal/redact so the SAME scrubber is applied both here (LLM
// provider errors) and at the audit-log repository choke point
// (internal/repository/audit.go). This function is now a thin re-export
// preserving the original signature and semantics:
//
//   - nil in -> nil out (callers can wrap unconditionally);
//   - a chain containing *url.Error has its URL query/fragment stripped
//     in place, so downstream errors.As(_, &urlErr) sees the scrubbed URL;
//   - the rendered message is scrubbed for auth-shaped query params,
//     Bearer tokens, Authorization headers, and DSN passwords;
//   - errors.Is / errors.As against the original chain still resolve
//     because a non-trivial redaction wraps the cause with Unwrap;
//   - an error with no secret-shaped material is returned unchanged (same
//     instance) so sentinel checks keep matching.
//
// The M1 #F13 rationale (a Gemini transport error echoing the BYOK
// `?key=` into the rewrapped error, llm_calls.error_message, and the HTTP
// 500 body) still applies — see redact.Error for the full pattern set.
func RedactProviderError(err error) error {
	return redact.Error(err)
}

// redactedError carries a scrubbed message plus the original cause so
// errors.Is / errors.As against sentinels in the original chain still
// resolve. It is retained in this package (rather than moved wholesale to
// internal/redact) because RedactAzureTransportError in azure_openai.go
// constructs it directly to wrap its Azure-endpoint-scrubbed message
// before delegating to RedactProviderError for the generic pass.
type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.cause }
