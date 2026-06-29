package diff_webhook

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/diff"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// 32-byte test key (NEVER reuse in prod) — used by Encrypt/Decrypt
// round-trip in the secret-validation test.
var testKey = []byte("0123456789abcdef0123456789abcdef")

type stubSettings struct {
	row *model.DiffWebhookSettings
	err error

	lastFireStatus int
	lastFireErr    string
}

func (s *stubSettings) Get(_ context.Context, _ uuid.UUID) (*model.DiffWebhookSettings, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.row, nil
}
func (s *stubSettings) UpdateFireResult(_ context.Context, _ uuid.UUID, status int, errMsg string) error {
	s.lastFireStatus = status
	s.lastFireErr = errMsg
	return nil
}

type stubAudit struct {
	rows []model.CreateAuditLogInput
}

func (a *stubAudit) Log(_ context.Context, in *model.CreateAuditLogInput) error {
	a.rows = append(a.rows, *in)
	return nil
}

func newDiffResponse(critical, high, licenseViolations int) *diff.Response {
	d := &diff.Response{
		ProjectID:       uuid.New(),
		Components:      diff.ComponentsDiff{Added: []diff.ComponentChange{}, Removed: []diff.ComponentChange{}, VersionChanged: []diff.ComponentVersionChange{}},
		Vulnerabilities: diff.VulnerabilitiesDiff{Added: []diff.VulnerabilityAdded{}, Resolved: []diff.VulnerabilityResolved{}, SeverityChanged: []diff.VulnerabilitySeverityChange{}},
		Licenses:        diff.LicensesDiff{AddedPolicyViolations: []diff.LicensePolicyViolation{}, RemovedPolicyViolations: []diff.LicensePolicyViolation{}},
	}
	for i := 0; i < critical; i++ {
		d.Vulnerabilities.Added = append(d.Vulnerabilities.Added, diff.VulnerabilityAdded{CVEID: "CVE", Severity: "CRITICAL"})
	}
	for i := 0; i < high; i++ {
		d.Vulnerabilities.Added = append(d.Vulnerabilities.Added, diff.VulnerabilityAdded{CVEID: "CVE", Severity: "HIGH"})
	}
	for i := 0; i < licenseViolations; i++ {
		d.Licenses.AddedPolicyViolations = append(d.Licenses.AddedPolicyViolations, diff.LicensePolicyViolation{ComponentName: "x", License: "GPL-3.0", PolicyName: "denied"})
	}
	return d
}

func TestFireIfThreshold_NoConfig_ReturnsNoConfig(t *testing.T) {
	settings := &stubSettings{err: repository.ErrDiffWebhookNotFound}
	audit := &stubAudit{}
	svc := NewService(Config{Settings: settings, Audit: audit, EncryptionKey: testKey})
	dec, err := svc.FireIfThreshold(context.Background(), uuid.New(), uuid.New(), newDiffResponse(0, 0, 0))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if dec.Triggered {
		t.Errorf("triggered without config")
	}
	if dec.Reason != "no_config" {
		t.Errorf("reason mismatch: %q", dec.Reason)
	}
}

func TestFireIfThreshold_Disabled_SkipsWithoutFiring(t *testing.T) {
	settings := &stubSettings{row: &model.DiffWebhookSettings{Enabled: false, WebhookURL: "https://example.com/hook"}}
	audit := &stubAudit{}
	svc := NewService(Config{Settings: settings, Audit: audit, EncryptionKey: testKey})
	dec, err := svc.FireIfThreshold(context.Background(), uuid.New(), uuid.New(), newDiffResponse(10, 10, 10))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Triggered {
		t.Errorf("triggered when disabled")
	}
}

func TestFireIfThreshold_BelowThresholds_SkipsWithoutFiring(t *testing.T) {
	settings := &stubSettings{row: &model.DiffWebhookSettings{
		Enabled: true, WebhookURL: "https://example.com/hook",
		CriticalThreshold: 5, HighThreshold: 5, LicenseViolationThreshold: 5,
	}}
	audit := &stubAudit{}
	svc := NewService(Config{Settings: settings, Audit: audit, EncryptionKey: testKey})
	dec, err := svc.FireIfThreshold(context.Background(), uuid.New(), uuid.New(), newDiffResponse(1, 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	if dec.Triggered {
		t.Errorf("triggered below thresholds")
	}
}

func TestFireIfThreshold_CriticalAboveThreshold_PostsWithSignature(t *testing.T) {
	// Prepare a real encrypted secret so the signature path is exercised end-to-end.
	plaintext := []byte("shhh-this-is-the-shared-secret")
	enc, err := llm.Encrypt(plaintext, testKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	var (
		gotSig   string
		gotEvent string
		gotBody  []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get(SignatureHeader)
		gotEvent = r.Header.Get(EventHeader)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	settings := &stubSettings{row: &model.DiffWebhookSettings{
		Enabled: true, WebhookURL: srv.URL,
		EncryptedSecret:   enc,
		CriticalThreshold: 1, HighThreshold: 5, LicenseViolationThreshold: 1,
		Format: model.DiffWebhookFormatJSON,
	}}
	audit := &stubAudit{}
	svc := NewService(Config{
		Settings: settings, Audit: audit, EncryptionKey: testKey,
		HTTPClient: srv.Client(),
	})

	dec, err := svc.FireIfThreshold(context.Background(), uuid.New(), uuid.New(), newDiffResponse(2, 0, 0))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !dec.Triggered {
		t.Fatalf("expected triggered=true; got %+v", dec)
	}
	if dec.Status != http.StatusOK {
		t.Errorf("status: got %d, want 200", dec.Status)
	}
	if gotEvent != EventTypeDiff {
		t.Errorf("event header: got %q, want %q", gotEvent, EventTypeDiff)
	}
	if !strings.HasPrefix(gotSig, "sha256=") {
		t.Errorf("signature header missing sha256 prefix: %q", gotSig)
	}
	// Verify the signature is HMAC-SHA256(body, plaintext).
	expected := "sha256=" + computeSignature(gotBody, plaintext)
	if gotSig != expected {
		t.Errorf("signature mismatch: got %q, want %q", gotSig, expected)
	}
	if !strings.Contains(string(gotBody), `"new_critical_vulns":2`) {
		t.Errorf("payload missing critical count; body=%s", string(gotBody))
	}
	if len(audit.rows) != 1 || audit.rows[0].Action != model.AuditActionDiffWebhookFired {
		t.Errorf("audit row mismatch: %+v", audit.rows)
	}
}

func TestFireIfThreshold_5xxRetried_4xxNotRetried(t *testing.T) {
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	settings := &stubSettings{row: &model.DiffWebhookSettings{
		Enabled: true, WebhookURL: srv.URL,
		CriticalThreshold: 1, HighThreshold: 5, LicenseViolationThreshold: 1,
		Format: model.DiffWebhookFormatJSON,
	}}
	audit := &stubAudit{}
	svc := NewService(Config{
		Settings: settings, Audit: audit, EncryptionKey: testKey,
		HTTPClient: srv.Client(),
		Retries:    []time.Duration{0, 0, 0}, // zero-delay so the test is fast
	})

	_, err := svc.FireIfThreshold(context.Background(), uuid.New(), uuid.New(), newDiffResponse(2, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 retry attempts on 500; got %d", attempts)
	}
	if len(audit.rows) != 1 || audit.rows[0].Action != model.AuditActionDiffWebhookFailed {
		t.Errorf("audit row mismatch: %+v", audit.rows)
	}

	// 4xx case
	attempts = 0
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv2.Close()
	settings.row.WebhookURL = srv2.URL
	svc2 := NewService(Config{
		Settings: settings, Audit: &stubAudit{}, EncryptionKey: testKey,
		HTTPClient: srv2.Client(),
		Retries:    []time.Duration{0, 0, 0},
	})
	_, err = svc2.FireIfThreshold(context.Background(), uuid.New(), uuid.New(), newDiffResponse(2, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Errorf("4xx must not retry; got %d attempts", attempts)
	}
}

func TestExceededThreshold_ZeroLicenseTriggers(t *testing.T) {
	s := &model.DiffWebhookSettings{LicenseViolationThreshold: 0, CriticalThreshold: 1, HighThreshold: 5}
	c := severityCounts{Licenses: 1}
	if !exceededThreshold(c, s) {
		t.Errorf("zero license threshold should trigger on any violation")
	}
}

func TestPayloadShape_SlackContainsCanonical(t *testing.T) {
	d := newDiffResponse(2, 1, 1)
	c := countSeverities(d)
	s := &model.DiffWebhookSettings{
		CriticalThreshold: 1, HighThreshold: 1, LicenseViolationThreshold: 0,
	}
	payload := buildPayload(model.DiffWebhookFormatSlack, uuid.New(), uuid.New(), d, c, s)
	m, ok := payload.(map[string]interface{})
	if !ok {
		t.Fatal("slack payload should be a map")
	}
	if _, ok := m["sbomhub"]; !ok {
		t.Errorf("slack payload missing sbomhub canonical envelope")
	}
	if _, ok := m["text"]; !ok {
		t.Errorf("slack payload missing text field")
	}
}

func TestSignature_Deterministic(t *testing.T) {
	body := []byte(`{"hello":"world"}`)
	secret := []byte("abc")
	got := computeSignature(body, secret)
	if _, err := hex.DecodeString(got); err != nil {
		t.Errorf("signature not hex: %v", err)
	}
	if got != computeSignature(body, secret) {
		t.Errorf("signature not deterministic")
	}
	if got == computeSignature(body, []byte("different")) {
		t.Errorf("different secret should produce different signature")
	}
}

func TestService_PanicsOnBadKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic on bad key")
		}
	}()
	NewService(Config{
		Settings:      &stubSettings{},
		Audit:         &stubAudit{},
		EncryptionKey: []byte("too short"),
	})
}

// guard against a sentinel-error rewiring drift.
var _ = errors.Is // keep import alive
