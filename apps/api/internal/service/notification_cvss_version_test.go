package service

// M74 — every outgoing vulnerability notification that shows a CVSS score
// says which CVSS version it is from (vulnerabilities.cvss_version, M67 /
// migration 069), because a v2.0 9.3 and a v3.1 9.3 are different
// statements. The version rides in the label ("CVSS v3.1"), so the value
// text keeps its M46 contract (score, or 未採点 for nil). An unknown or
// unrecognised version renders the bare "CVSS" label exactly as before —
// never a guessed version.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/model"
)

func strPtr(s string) *string { return &s }

func versionedNotif(score *float64, version *string) model.VulnerabilityNotification {
	n := wave4Notif(score)
	n.CVSSVersion = version
	return n
}

func TestNotifCVSSLabel(t *testing.T) {
	cases := []struct {
		name    string
		version *string
		want    string
	}{
		{"nil", nil, "CVSS"},
		{"3.1", strPtr("3.1"), "CVSS v3.1"},
		{"3.0", strPtr("3.0"), "CVSS v3.0"},
		{"2.0", strPtr("2.0"), "CVSS v2.0"},
		{"4.0", strPtr("4.0"), "CVSS v4.0"},
		{"padded", strPtr(" 3.1 "), "CVSS v3.1"},
		// A value the feed layer would never store is not echoed into a
		// Slack mrkdwn / HTML body; the label falls back to bare CVSS.
		{"garbage", strPtr("*bold* <b>"), "CVSS"},
		{"empty", strPtr(""), "CVSS"},
	}
	for _, tc := range cases {
		if got := notifCVSSLabel(tc.version); got != tc.want {
			t.Errorf("%s: notifCVSSLabel = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestSlackPayload_CVSSVersion(t *testing.T) {
	payload := marshalPayload(t, buildSlackVulnerabilityPayload(versionedNotif(f64p(9.8), strPtr("3.1"))))
	if !strings.Contains(payload, `*CVSS v3.1:*\n9.8 (CRITICAL)`) {
		t.Errorf("Slack payload does not name the CVSS version, got: %s", payload)
	}
	// Unknown version: unchanged pre-M74 text, no guessed version.
	plain := marshalPayload(t, buildSlackVulnerabilityPayload(versionedNotif(f64p(9.8), nil)))
	if !strings.Contains(plain, `*CVSS:*\n9.8 (CRITICAL)`) || strings.Contains(plain, "CVSS v") {
		t.Errorf("Slack payload with unknown version changed shape, got: %s", plain)
	}
	// Version without a score: the label still names the assessment the
	// severity came from, and the value stays 未採点.
	unscored := marshalPayload(t, buildSlackVulnerabilityPayload(versionedNotif(nil, strPtr("4.0"))))
	if !strings.Contains(unscored, `*CVSS v4.0:*\n未採点 (CRITICAL)`) {
		t.Errorf("Slack payload for versioned un-scored CVE, got: %s", unscored)
	}
}

func TestDiscordPayload_CVSSVersion(t *testing.T) {
	payload := marshalPayload(t, buildDiscordVulnerabilityPayload(versionedNotif(f64p(7.5), strPtr("2.0"))))
	if !strings.Contains(payload, `{"inline":true,"name":"CVSS v2.0","value":"7.5"}`) {
		t.Errorf("Discord payload does not name the CVSS version, got: %s", payload)
	}
	plain := marshalPayload(t, buildDiscordVulnerabilityPayload(versionedNotif(f64p(7.5), strPtr("9.9"))))
	if !strings.Contains(plain, `{"inline":true,"name":"CVSS","value":"7.5"}`) {
		t.Errorf("Discord payload with unrecognised version must use the bare label, got: %s", plain)
	}
}

func TestEmailBodies_CVSSVersion(t *testing.T) {
	svc := &NotificationService{cfg: &config.Config{}}
	n := versionedNotif(f64p(9.8), strPtr("3.0"))

	text := svc.generateEmailText(n)
	if !strings.Contains(text, "CVSS v3.0 Score: 9.8 (CRITICAL)") {
		t.Errorf("email text does not name the CVSS version, got:\n%s", text)
	}
	html := svc.generateEmailHTML(n)
	if !strings.Contains(html, "<strong>CVSS v3.0 Score</strong>") {
		t.Errorf("email HTML does not name the CVSS version, got:\n%s", html)
	}

	plainText := svc.generateEmailText(versionedNotif(f64p(9.8), nil))
	if !strings.Contains(plainText, "CVSS Score: 9.8 (CRITICAL)") {
		t.Errorf("email text with unknown version changed shape, got:\n%s", plainText)
	}
}

// The notification model is additive: cvss_version is omitted when unknown,
// so anything that serialises it keeps its old shape.
func TestVulnerabilityNotification_CVSSVersionJSONIsAdditive(t *testing.T) {
	b, err := json.Marshal(versionedNotif(f64p(9.8), nil))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "cvss_version") {
		t.Errorf("nil version must be omitted, got %s", b)
	}
	b, err = json.Marshal(versionedNotif(f64p(9.8), strPtr("3.1")))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"cvss_version":"3.1"`) {
		t.Errorf("version missing from JSON, got %s", b)
	}
}
