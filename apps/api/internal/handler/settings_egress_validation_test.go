package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/egress"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
)

// The two Update handlers reject a destination before writing the row. Driving
// the full echo.Context + repository stack for that would need a database, so
// these tests assert on the guard each handler holds — the same object, built
// the same way, that the handler calls ValidateURL on.
//
// What this pins is the wiring decision, not the classification (that is
// covered exhaustively in internal/egress): a nil guard must resolve to the
// strict policy rather than to no policy, and the two handlers must not have
// been given policies that disagree with the services that deliver under them.

func TestSettingsDiffWebhookHandler_NilGuardIsStrict(t *testing.T) {
	h := NewSettingsDiffWebhookHandler(nil, nil, nil, nil)
	if h.egress == nil {
		t.Fatal("expected a guard for a nil argument")
	}
	for _, bad := range []string{
		"http://127.0.0.1:9000/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]:9000/hook",
		"file:///etc/passwd",
	} {
		if err := h.egress.ValidateURL(bad); err == nil {
			t.Errorf("ValidateURL(%q) = nil, want a refusal", bad)
		}
	}
	if err := h.egress.ValidateURL("https://hooks.slack.com/services/T/B/X"); err != nil {
		t.Errorf("a public webhook URL must still be accepted: %v", err)
	}
	// The handler's policy has to match the deliverer's: diff_webhook does not
	// follow redirects.
	if h.egress.Policy().MaxRedirects != 0 {
		t.Error("handler policy disagrees with diff_webhook.Service (which refuses redirects)")
	}
}

func TestSettingsLLMHandler_NilGuardIsStrict(t *testing.T) {
	h := NewSettingsLLMHandler(nil, nil, nil, nil)
	if h.egress == nil {
		t.Fatal("expected a guard for a nil argument")
	}
	for _, bad := range []string{
		"http://10.0.0.5/openai",
		"http://169.254.169.254/",
		"gopher://acme.openai.azure.com/",
	} {
		if err := h.egress.ValidateURL(bad); err == nil {
			t.Errorf("ValidateURL(%q) = nil, want a refusal", bad)
		}
	}
	if err := h.egress.ValidateURL("https://acme.openai.azure.com"); err != nil {
		t.Errorf("a public Azure endpoint must still be accepted: %v", err)
	}
}

// TestSettingsHandlers_RefusalMessagesDoNotReflectTheRequest backs the claim at
// each echo site that these messages are safe to return at 400.
//
// The precise property (Codex round 3, Low corrected the earlier, stronger
// wording): the REASON text is written by internal/egress, and the only parts of
// the admin's input that appear are the hostname and the resolved address, both
// normalised by url.Hostname / netip parsing. The path, query and fragment —
// where an attacker would put anything worth reflecting — never appear.
func TestSettingsHandlers_RefusalMessagesDoNotReflectTheRequest(t *testing.T) {
	g := egress.NewSet(egress.Settings{}).DiffWebhook
	err := g.ValidateURL("http://169.254.169.254/latest/meta-data/iam/security-credentials/?x=<script>#frag")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := err.Error()
	for _, leak := range []string{"security-credentials", "latest", "meta-data", "<script>", "frag", "x="} {
		if strings.Contains(msg, leak) {
			t.Errorf("refusal message reflects request content %q: %q", leak, msg)
		}
	}
	if !strings.Contains(msg, "metadata") {
		t.Errorf("refusal message should name the reason, got %q", msg)
	}
	// The host does appear, by design — the admin needs to know which value was
	// refused — and it is the normalised hostname, not the raw string.
	if !strings.Contains(msg, "169.254.169.254") {
		t.Errorf("refusal message should name the destination, got %q", msg)
	}
}

// TestSettingsDiffWebhookHandler_UpdateRejectsInternalURL drives the handler
// itself.
//
// Codex round 3 (Low): the nil-guard tests above are causal only for the
// constructor fallback — they would still pass if Update stopped calling
// ValidateURL. This one would not: the repository is nil, and Update
// dereferences it immediately after the URL checks, so a 400 here can ONLY mean
// the egress check fired first.
func TestSettingsDiffWebhookHandler_UpdateRejectsInternalURL(t *testing.T) {
	h := NewSettingsDiffWebhookHandler(nil, nil, nil, nil)

	body := `{"enabled":true,"webhook_url":"http://169.254.169.254/hook","format":"json"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenant/settings/diff-webhook", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	c.Set(middleware.ContextKeyTenantID, uuid.New())
	c.Set(middleware.ContextKeyUserID, uuid.New())
	c.Set(middleware.ContextKeyRole, string(model.RoleOwner))

	if err := h.Update(c); err != nil {
		t.Fatalf("Update returned an error rather than a response: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not an allowed destination") {
		t.Errorf("body = %s, want the egress refusal", rec.Body.String())
	}
}

// TestSettingsLLMHandler_UpdateRejectsInternalAzureEndpoint is the same causal
// shape for the LLM settings screen.
func TestSettingsLLMHandler_UpdateRejectsInternalAzureEndpoint(t *testing.T) {
	h := NewSettingsLLMHandler(nil, nil, nil, nil)

	body := `{"mode":"byok","provider":"azure_openai","api_key":"k","azure_endpoint":"http://169.254.169.254/","azure_deployment":"d"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/llm", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	c.Set(middleware.ContextKeyTenantID, uuid.New())
	c.Set(middleware.ContextKeyUserID, uuid.New())
	c.Set(middleware.ContextKeyRole, string(model.RoleOwner))

	if err := h.Update(c); err != nil {
		t.Fatalf("Update returned an error rather than a response: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not an allowed destination") {
		t.Errorf("body = %s, want the egress refusal", rec.Body.String())
	}
}

// TestNotificationHandler_TestEndpointDoesNotLeakTheWebhookURL is the Codex
// round-5 (Low) regression, and the most consequential of that round.
//
// The refusal reaches this handler from http.Client.Do, wrapped in a
// *url.Error whose message contains the ENTIRE request URL. For a Slack or
// Discord webhook that URL is the credential, so echoing err.Error() at 400 put
// the tenant's webhook secret in an HTTP response body. The handler now extracts
// the *egress.DestinationError with errors.As and echoes only that.
func TestNotificationHandler_TestEndpointDoesNotLeakTheWebhookURL(t *testing.T) {
	const secretPath = "/services/T00000000/B00000000/SUPERSECRETTOKEN"
	inner := &egress.DestinationError{
		Purpose: egress.PurposeNotificationWebhook,
		Host:    "hooks.slack.example",
		Addr:    "10.1.2.3",
		Reason:  "RFC 1918 private range",
	}
	// Exactly the shape http.Client.Do produces.
	wrapped := &neturl.Error{
		Op:  "Post",
		URL: "https://hooks.slack.example" + secretPath,
		Err: inner,
	}
	if !strings.Contains(wrapped.Error(), secretPath) {
		t.Fatalf("premise failed: *url.Error should quote the full URL, got %q", wrapped.Error())
	}

	// The handler's branch condition and its response body, exercised on that
	// error value.
	var dest *egress.DestinationError
	if !errors.As(wrapped, &dest) {
		t.Fatal("errors.As must recover the DestinationError from the *url.Error chain")
	}
	body := dest.Error()
	if strings.Contains(body, secretPath) || strings.Contains(body, "SUPERSECRETTOKEN") {
		t.Errorf("the echoed message leaks the webhook URL: %q", body)
	}
	for _, want := range []string{"notification_webhook", "hooks.slack.example", "RFC 1918"} {
		if !strings.Contains(body, want) {
			t.Errorf("the echoed message should still be actionable; missing %q in %q", want, body)
		}
	}
}
