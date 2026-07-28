package service

// M46 Track A wave 4 — Codex round B-1 Medium 3: the notification path must
// never render an un-scored CVE as "CVSS 0.0". vulnerabilities.cvss_score is
// NULL for NVD "Awaiting Analysis" rows, CVSS 0.0 is a real "None" score, and
// the old bare-float64 VulnerabilityNotification turned nil into a 0.0
// sentinel right before the Slack / Discord / email renderers — presenting an
// un-triaged CRITICAL as harmless in the alert that exists to say the
// opposite. After wave 4 CVSSScore is *float64 end to end and every renderer
// prints 未採点 for nil (the notification bodies are Japanese-fixed:
// 新規%s脆弱性検出 / 詳細を見る; the wording matches the web UI's un-scored
// rendering in create-ticket-button).
//
// The payload builders are pure (no I/O) so these tests pin the exact
// delivered text without a webhook endpoint.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/model"
)

func wave4Notif(score *float64) model.VulnerabilityNotification {
	return model.VulnerabilityNotification{
		CVEID:            "CVE-2026-4444",
		CVSSScore:        score,
		EPSSScore:        f64p(0.42),
		Severity:         "CRITICAL",
		ProjectID:        "11111111-1111-1111-1111-111111111111",
		ProjectName:      "app-a",
		ComponentName:    "libz",
		ComponentVersion: "1.2.3",
		DetailsURL:       "https://sbomhub.test/projects/x/vulnerabilities",
	}
}

// marshalPayload flattens a payload to its JSON text so the assertions cover
// exactly the bytes a webhook would receive.
func marshalPayload(t *testing.T, payload map[string]interface{}) string {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return string(b)
}

func TestNotifCVSSText_NilIsUnscoredNotZero(t *testing.T) {
	if got := notifCVSSText(nil); got != "未採点" {
		t.Errorf("notifCVSSText(nil) = %q, want 未採点", got)
	}
	// A REAL 0.0 ("None") score still renders numerically — nil and 0.0 must
	// stay distinguishable.
	if got := notifCVSSText(f64p(0)); got != "0.0" {
		t.Errorf("notifCVSSText(0.0) = %q, want \"0.0\" (real 'None' score)", got)
	}
	if got := notifCVSSText(f64p(9.8)); got != "9.8" {
		t.Errorf("notifCVSSText(9.8) = %q, want \"9.8\"", got)
	}
}

func TestSlackPayload_UnscoredCVSSRendersAsUnscored(t *testing.T) {
	payload := marshalPayload(t, buildSlackVulnerabilityPayload(wave4Notif(nil)))

	if !strings.Contains(payload, `*CVSS:*\n未採点 (CRITICAL)`) {
		t.Errorf("Slack payload does not carry the un-scored CVSS field, got: %s", payload)
	}
	if strings.Contains(payload, "0.0") {
		t.Errorf("Slack payload for an un-scored CVE contains a 0.0 sentinel: %s", payload)
	}

	// A scored notification still renders the number.
	scored := marshalPayload(t, buildSlackVulnerabilityPayload(wave4Notif(f64p(9.8))))
	if !strings.Contains(scored, `*CVSS:*\n9.8 (CRITICAL)`) {
		t.Errorf("Slack payload lost the real score, got: %s", scored)
	}
}

func TestDiscordPayload_UnscoredCVSSRendersAsUnscored(t *testing.T) {
	payload := marshalPayload(t, buildDiscordVulnerabilityPayload(wave4Notif(nil)))

	if !strings.Contains(payload, `{"inline":true,"name":"CVSS","value":"未採点"}`) {
		t.Errorf("Discord payload does not carry the un-scored CVSS field, got: %s", payload)
	}
	if strings.Contains(payload, "0.0") {
		t.Errorf("Discord payload for an un-scored CVE contains a 0.0 sentinel: %s", payload)
	}

	scored := marshalPayload(t, buildDiscordVulnerabilityPayload(wave4Notif(f64p(0))))
	if !strings.Contains(scored, `{"inline":true,"name":"CVSS","value":"0.0"}`) {
		t.Errorf("Discord payload lost the real 0.0 ('None') score, got: %s", scored)
	}
}

func TestEmailBodies_UnscoredCVSSRendersAsUnscored(t *testing.T) {
	svc := &NotificationService{cfg: &config.Config{}}

	text := svc.generateEmailText(wave4Notif(nil))
	if !strings.Contains(text, "CVSS Score: 未採点 (CRITICAL)") {
		t.Errorf("email text does not carry the un-scored CVSS line, got:\n%s", text)
	}
	if strings.Contains(text, "0.0") {
		t.Errorf("email text for an un-scored CVE contains a 0.0 sentinel:\n%s", text)
	}

	html := svc.generateEmailHTML(wave4Notif(nil))
	if !strings.Contains(html, "未採点 (CRITICAL)") {
		t.Errorf("email HTML does not carry the un-scored CVSS cell, got:\n%s", html)
	}
	if strings.Contains(html, "0.0 (CRITICAL)") {
		t.Errorf("email HTML for an un-scored CVE renders a 0.0 sentinel:\n%s", html)
	}

	// Scored bodies keep the numeric rendering.
	scoredText := svc.generateEmailText(wave4Notif(f64p(9.8)))
	if !strings.Contains(scoredText, "CVSS Score: 9.8 (CRITICAL)") {
		t.Errorf("email text lost the real score, got:\n%s", scoredText)
	}
}
