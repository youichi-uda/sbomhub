package diff_webhook

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// ---------------------------------------------------------------------------
// M48 FO-5 — the sending half of the webhook signature contract.
//
// M47 made the RECEIVING half fail-closed: with no secret configured,
// /api/webhooks/* rejects every delivery. The sending half did the opposite —
// it dropped the X-SBOMHub-Signature header and posted anyway. A consumer
// following our documented verification step therefore had nothing to verify,
// and one that acted on the payload could not distinguish ours from any other
// POST to the same URL.
// ---------------------------------------------------------------------------

// captureServer records whether a delivery arrived and what signature it
// carried.
type captureServer struct {
	srv      *httptest.Server
	requests int
	lastSig  string
}

func newCaptureServer(t *testing.T) *captureServer {
	t.Helper()
	cs := &captureServer{}
	cs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.requests++
		cs.lastSig = r.Header.Get(SignatureHeader)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(cs.srv.Close)
	return cs
}

// TestM48UnsignedJSONDeliveryIsRefused is the finding.
//
// Pre-M48 this test observed requests=1 with an empty X-SBOMHub-Signature: the
// payload was delivered, unsigned, to a generic consumer endpoint.
func TestM48UnsignedJSONDeliveryIsRefused(t *testing.T) {
	cs := newCaptureServer(t)

	settings := &stubSettings{row: &model.DiffWebhookSettings{
		Enabled: true, WebhookURL: cs.srv.URL,
		// No EncryptedSecret — the state every tenant starts in.
		CriticalThreshold: 1, HighThreshold: 5, LicenseViolationThreshold: 1,
		Format: model.DiffWebhookFormatJSON,
	}}
	audit := &stubAudit{}
	svc := NewService(Config{
		Settings: settings, Audit: audit, EncryptionKey: testKey,
		HTTPClient: cs.srv.Client(),
	})

	dec, err := svc.FireIfThreshold(context.Background(), uuid.New(), uuid.New(), newDiffResponse(2, 0, 0))
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if cs.requests != 0 {
		t.Fatalf("delivered %d request(s) with signature %q — a json-format webhook with no "+
			"configured secret must not be sent at all", cs.requests, cs.lastSig)
	}
	// The tenant has to be able to find out why their webhook stopped, so the
	// refusal is a recorded failure rather than a silent skip.
	if !dec.Triggered {
		t.Error("Triggered=false: the thresholds WERE exceeded, and reporting this as " +
			"'not triggered' would hide a configuration problem behind a normal quiet period")
	}
	if dec.ErrorMessage != ErrMsgMissingSecret {
		t.Errorf("ErrorMessage = %q, want %q", dec.ErrorMessage, ErrMsgMissingSecret)
	}
	if len(audit.rows) != 1 || audit.rows[0].Action != model.AuditActionDiffWebhookFailed {
		t.Fatalf("expected exactly one diff_webhook_failed audit row, got %+v", audit.rows)
	}
}

// TestM48SignedJSONDeliveryStillFires is the non-vacuity half: the refusal is
// about the missing secret, not about json deliveries in general.
func TestM48SignedJSONDeliveryStillFires(t *testing.T) {
	enc, err := llm.Encrypt([]byte("a-configured-secret"), testKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	cs := newCaptureServer(t)

	settings := &stubSettings{row: &model.DiffWebhookSettings{
		Enabled: true, WebhookURL: cs.srv.URL,
		EncryptedSecret:   enc,
		CriticalThreshold: 1, HighThreshold: 5, LicenseViolationThreshold: 1,
		Format: model.DiffWebhookFormatJSON,
	}}
	svc := NewService(Config{
		Settings: settings, Audit: &stubAudit{}, EncryptionKey: testKey,
		HTTPClient: cs.srv.Client(),
	})

	if _, err := svc.FireIfThreshold(context.Background(), uuid.New(), uuid.New(), newDiffResponse(2, 0, 0)); err != nil {
		t.Fatalf("err: %v", err)
	}
	if cs.requests != 1 {
		t.Fatalf("requests = %d, want 1", cs.requests)
	}
	if cs.lastSig == "" {
		t.Error("delivered without a signature despite a configured secret")
	}
}

// TestM48SlackFormatAloneIsNotAnExemption is Codex round 1 (Medium).
//
// The first version of this fix keyed the exemption on `format` alone — a
// value the caller puts in the request body — while the comment asserted that
// "the delivery target is known" and "the credential travels inside TLS".
// Neither was checked. An admin could point a webhook at any endpoint, over
// plain HTTP, label it "slack", and go on posting unsigned payloads: the fix
// would have been bypassable by typing a different word in a form.
//
// The captureServer here is exactly that: an httptest.Server on
// http://127.0.0.1. It must NOT be exempt.
func TestM48SlackFormatAloneIsNotAnExemption(t *testing.T) {
	cs := newCaptureServer(t)

	settings := &stubSettings{row: &model.DiffWebhookSettings{
		Enabled: true, WebhookURL: cs.srv.URL, // http://127.0.0.1:NNNN — not Slack
		CriticalThreshold: 1, HighThreshold: 5, LicenseViolationThreshold: 1,
		Format: model.DiffWebhookFormatSlack,
	}}
	audit := &stubAudit{}
	svc := NewService(Config{
		Settings: settings, Audit: audit, EncryptionKey: testKey,
		HTTPClient: cs.srv.Client(),
	})

	dec, err := svc.FireIfThreshold(context.Background(), uuid.New(), uuid.New(), newDiffResponse(2, 0, 0))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if cs.requests != 0 {
		t.Fatalf("delivered %d unsigned request(s) to %s — labelling a generic endpoint "+
			"'slack' must not waive the signing requirement", cs.requests, cs.srv.URL)
	}
	if dec.ErrorMessage != ErrMsgMissingSecret {
		t.Errorf("ErrorMessage = %q, want %q", dec.ErrorMessage, ErrMsgMissingSecret)
	}
}

// TestM48SignatureRequiredRule states the rule directly, including the cases
// that cannot be driven through FireIfThreshold without talking to Slack.
func TestM48SignatureRequiredRule(t *testing.T) {
	const realSlack = "https://hooks.slack.com/services/T000/B000/XXXX"

	cases := []struct {
		name   string
		format string
		url    string
		want   bool
		why    string
	}{
		{
			name: "json to anywhere requires a signature", format: model.DiffWebhookFormatJSON,
			url: "https://example.invalid/hook", want: true,
			why: "a generic consumer we do not control",
		},
		{
			name:   "json addressed to slack still requires a signature",
			format: model.DiffWebhookFormatJSON, url: realSlack, want: true,
			why: "the exemption is about the slack PAYLOAD shape reaching slack, not the host alone",
		},
		{
			name:   "slack format to the real slack host is exempt",
			format: model.DiffWebhookFormatSlack, url: realSlack, want: false,
			why: "slack does not read X-SBOMHub-Signature; that URL is itself the credential",
		},
		{
			name:   "slack format over plain http to slack is NOT exempt",
			format: model.DiffWebhookFormatSlack,
			url:    "http://hooks.slack.com/services/T000/B000/XXXX", want: true,
			why: "the 'travels inside TLS' half of the argument has to be checked, not assumed",
		},
		{
			// Codex round 4 (Low): DNS is case-insensitive and a terminal root
			// dot is equivalent. Comparing verbatim FALSELY DENIED the
			// ordinary Slack configuration, forcing a secret onto an
			// integration that cannot use one.
			name:   "slack format to the real host in upper case is exempt",
			format: model.DiffWebhookFormatSlack,
			url:    "https://HOOKS.SLACK.COM/services/T000/B000/XXXX", want: false,
			why: "DNS names are case-insensitive",
		},
		{
			name:   "slack format to the real host with a trailing root dot is exempt",
			format: model.DiffWebhookFormatSlack,
			url:    "https://hooks.slack.com./services/T000/B000/XXXX", want: false,
			why: "a terminal root dot names the same host",
		},
		{
			name:   "slack format to a look-alike host is NOT exempt",
			format: model.DiffWebhookFormatSlack,
			url:    "https://hooks.slack.com.evil.example/services/T000/B000/X", want: true,
			why: "Hostname() must match exactly, not by prefix or suffix",
		},
		{
			name:   "slack format to a self-hosted slack-compatible relay is NOT exempt",
			format: model.DiffWebhookFormatSlack,
			url:    "https://mattermost.internal/hooks/abc", want: true,
			why: "a slack-compatible consumer is still a consumer we do not control",
		},
		{
			name:   "an unparseable url fails closed",
			format: model.DiffWebhookFormatSlack, url: "://not a url", want: true,
			why: "the defensive arm",
		},
		{
			name:   "an unknown future format fails closed",
			format: "some-future-format", url: realSlack, want: true,
			why: "a format added later must make its own decision rather than inherit an exemption",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SignatureRequired(tc.format, tc.url); got != tc.want {
				t.Errorf("SignatureRequired(%q, %q) = %t, want %t — %s",
					tc.format, tc.url, got, tc.want, tc.why)
			}
		})
	}
}

// TestM48RefusalIsVisibleOnTheSettingsScreen is Codex round 1 (Low): a
// pre-M48 secret-less row silently stops firing, and the settings page is
// where an operator looks first. The refusal has to land in last_error rather
// than leaving whatever the last pre-upgrade delivery wrote.
func TestM48RefusalIsVisibleOnTheSettingsScreen(t *testing.T) {
	cs := newCaptureServer(t)
	settings := &stubSettings{row: &model.DiffWebhookSettings{
		Enabled: true, WebhookURL: cs.srv.URL,
		CriticalThreshold: 1, HighThreshold: 5, LicenseViolationThreshold: 1,
		Format: model.DiffWebhookFormatJSON,
	}}
	svc := NewService(Config{
		Settings: settings, Audit: &stubAudit{}, EncryptionKey: testKey,
		HTTPClient: cs.srv.Client(),
	})

	if _, err := svc.FireIfThreshold(context.Background(), uuid.New(), uuid.New(), newDiffResponse(2, 0, 0)); err != nil {
		t.Fatalf("err: %v", err)
	}
	if settings.lastFireErr != ErrMsgMissingSecret {
		t.Errorf("settings last_error = %q, want %q — the operator has no other place "+
			"to find out why the webhook went quiet", settings.lastFireErr, ErrMsgMissingSecret)
	}
}

// TestM48NonRetryableStatuses is Codex round 4's coverage gap for round 3's
// L3 fix, plus the catch-all that keeps any status from producing a failed
// delivery with no stated reason.
//
// The 3xx case exists because the production client refuses to follow
// redirects (NewService's CheckRedirect), so a redirect arrives at deliver()
// as an ordinary response. Before the fix it fell through to the retry tail
// and returned an empty ErrorMessage.
func TestM48NonRetryableStatuses(t *testing.T) {
	enc, err := llm.Encrypt([]byte("s"), testKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	for _, tc := range []struct {
		name         string
		status       int
		wantAttempts int
	}{
		{name: "308 permanent redirect is not followed and not retried", status: 308, wantAttempts: 1},
		{name: "302 found is not retried", status: 302, wantAttempts: 1},
		{name: "400 is not retried", status: 400, wantAttempts: 1},
		{name: "500 is retried", status: 500, wantAttempts: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				attempts++
				// Location is set so a redirect-following client would move on;
				// the point is that ours does not.
				w.Header().Set("Location", "https://elsewhere.invalid/hook")
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			settings := &stubSettings{row: &model.DiffWebhookSettings{
				Enabled: true, WebhookURL: srv.URL, EncryptedSecret: enc,
				CriticalThreshold: 1, HighThreshold: 5, LicenseViolationThreshold: 1,
				Format: model.DiffWebhookFormatJSON,
			}}
			// HTTPClient is deliberately NOT supplied, so NewService builds
			// the production client — the one carrying CheckRedirect. Codex
			// round 4 (Low) is exactly this: the redirect policy lives on the
			// internally-created client, so a test that passes srv.Client()
			// (which follows redirects) exercises a different object than
			// production and reported 3 attempts against a 308. The httptest
			// server is plain HTTP on 127.0.0.1, so the default client reaches
			// it without srv.Client().
			svc := NewService(Config{
				Settings: settings, Audit: &stubAudit{}, EncryptionKey: testKey,
				Retries: []time.Duration{0, 0, 0},
			})

			dec, err := svc.FireIfThreshold(context.Background(), uuid.New(), uuid.New(), newDiffResponse(2, 0, 0))
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if attempts != tc.wantAttempts {
				t.Errorf("attempts = %d, want %d", attempts, tc.wantAttempts)
			}
			if dec.ErrorMessage == "" {
				t.Errorf("HTTP %d produced a failed delivery with an EMPTY ErrorMessage — the "+
					"operator sees a failure with no reason", tc.status)
			}
			// And the settings mirror has to carry it too (round 3, L2).
			if settings.lastFireErr == "" {
				t.Errorf("HTTP %d left the settings last_error empty", tc.status)
			}
		})
	}
}

// TestM48UpdateFireResultFailureIsNotSilent covers round 3's L2 on the normal
// delivery path: a repository failure must not leave the caller believing the
// settings screen was updated.
func TestM48UpdateFireResultFailureIsNotSilent(t *testing.T) {
	enc, err := llm.Encrypt([]byte("s"), testKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var logged bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	settings := &failingUpdateSettings{stubSettings{row: &model.DiffWebhookSettings{
		Enabled: true, WebhookURL: srv.URL, EncryptedSecret: enc,
		CriticalThreshold: 1, HighThreshold: 5, LicenseViolationThreshold: 1,
		Format: model.DiffWebhookFormatJSON,
	}}}
	svc := NewService(Config{
		Settings: settings, Audit: &stubAudit{}, EncryptionKey: testKey,
	})

	// The delivery itself still succeeds: the audit row is the authoritative
	// record, so a failed settings mirror is logged rather than escalated.
	dec, err := svc.FireIfThreshold(context.Background(), uuid.New(), uuid.New(), newDiffResponse(2, 0, 0))
	if err != nil {
		t.Fatalf("a failed settings mirror must not fail the delivery: %v", err)
	}
	if !dec.Triggered || dec.Status != http.StatusOK {
		t.Errorf("decision = %+v, want a triggered 200", dec)
	}
	if !settings.called {
		t.Error("UpdateFireResult was never called on the success path")
	}
	// Codex round 5 (Low): "called" alone would still pass if the returned
	// error were discarded again, which is the actual regression. Assert the
	// warning was emitted.
	if !strings.Contains(logged.String(), "could not persist the delivery outcome") {
		t.Errorf("the UpdateFireResult failure was not logged; captured output was:\n%s",
			logged.String())
	}
}

// failingUpdateSettings makes UpdateFireResult fail while Get still works.
type failingUpdateSettings struct{ stubSettings }

func (s *failingUpdateSettings) UpdateFireResult(_ context.Context, _ uuid.UUID, _ int, _ string) error {
	s.called = true
	return errors.New("simulated repository failure")
}
