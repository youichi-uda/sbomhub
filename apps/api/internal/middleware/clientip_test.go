package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func realIPWith(t *testing.T, spec, remoteAddr string, headers map[string]string) string {
	t.Helper()
	ext, err := ClientIPExtractor(spec)
	if err != nil {
		t.Fatalf("ClientIPExtractor(%q): %v", spec, err)
	}
	e := echo.New()
	e.IPExtractor = ext
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return e.NewContext(req, httptest.NewRecorder()).RealIP()
}

func TestClientIPExtractor_DefaultIgnoresForwardingHeaders(t *testing.T) {
	spoof := map[string]string{
		echo.HeaderXForwardedFor: "1.2.3.4",
		echo.HeaderXRealIP:       "5.6.7.8",
	}
	for _, spec := range []string{"", "  ", "\t\n"} {
		if got := realIPWith(t, spec, "203.0.113.9:4444", spoof); got != "203.0.113.9" {
			t.Errorf("spec %q: RealIP = %q, want peer 203.0.113.9 (forwarding headers must be ignored)", spec, got)
		}
	}
}

func TestClientIPExtractor_TrustedProxyHonoursXFF(t *testing.T) {
	got := realIPWith(t, "10.0.0.10/32", "10.0.0.10:4444",
		map[string]string{echo.HeaderXForwardedFor: "198.51.100.7"})
	if got != "198.51.100.7" {
		t.Errorf("RealIP = %q, want client 198.51.100.7 forwarded by trusted proxy", got)
	}
	// Bare IP form is equivalent to a /32.
	got = realIPWith(t, "10.0.0.10", "10.0.0.10:4444",
		map[string]string{echo.HeaderXForwardedFor: "198.51.100.7"})
	if got != "198.51.100.7" {
		t.Errorf("bare-IP spec: RealIP = %q, want 198.51.100.7", got)
	}
}

func TestClientIPExtractor_UntrustedPeerCannotSpoof(t *testing.T) {
	// Peer is outside the trusted range: its XFF claim is not believed.
	got := realIPWith(t, "10.0.0.10/32", "203.0.113.9:4444",
		map[string]string{echo.HeaderXForwardedFor: "1.2.3.4"})
	if got != "203.0.113.9" {
		t.Errorf("RealIP = %q, want untrusted peer 203.0.113.9", got)
	}
	// echo's implicit private-network trust is switched off: a different
	// RFC1918 host on the same network is not a trusted proxy.
	got = realIPWith(t, "10.0.0.10/32", "10.0.0.99:4444",
		map[string]string{echo.HeaderXForwardedFor: "1.2.3.4"})
	if got != "10.0.0.99" {
		t.Errorf("RealIP = %q, want 10.0.0.99 (implicit RFC1918 trust must be off)", got)
	}
	// X-Real-IP is never consulted, even from a trusted proxy.
	got = realIPWith(t, "10.0.0.10/32", "10.0.0.10:4444",
		map[string]string{echo.HeaderXRealIP: "1.2.3.4"})
	if got != "10.0.0.10" {
		t.Errorf("RealIP = %q, want 10.0.0.10 (X-Real-IP must be ignored)", got)
	}
}

func TestClientIPExtractor_ClientPrependedHopIsSkipped(t *testing.T) {
	// The client sends its own XFF; the trusted proxy appends the real peer.
	// The nearest untrusted hop (the real client) wins, not the forged one.
	got := realIPWith(t, "10.0.0.10/32", "10.0.0.10:4444",
		map[string]string{echo.HeaderXForwardedFor: "1.2.3.4, 198.51.100.7"})
	if got != "198.51.100.7" {
		t.Errorf("RealIP = %q, want 198.51.100.7 (forged leftmost hop must not win)", got)
	}
}

func TestClientIPExtractor_InvalidEntryRefused(t *testing.T) {
	for _, spec := range []string{"10.0.0.0/33", "not-an-ip", "10.0.0.10, bogus"} {
		if _, err := ClientIPExtractor(spec); err == nil {
			t.Errorf("spec %q: want error, got nil", spec)
		}
	}
	if _, err := ClientIPExtractor("10.0.0.0/8, 2001:db8::1 192.0.2.1"); err != nil {
		t.Errorf("valid mixed spec refused: %v", err)
	}
}

// Codex review 2026-11-08 (R2 Low): a value that is non-blank but names no
// proxy (e.g. "," or " , ") used to select the direct extractor silently while
// main.go, seeing a non-empty string, logged that X-Forwarded-For was being
// honoured. An operator could believe proxy attribution was active when it was
// not. Such a value is malformed and must refuse startup like any other typo.
func TestClientIPExtractor_SeparatorOnlyIsRejected(t *testing.T) {
	for _, spec := range []string{",", " , ", ",,\t,"} {
		if _, err := ClientIPExtractor(spec); err == nil {
			t.Errorf("spec %q: want error (names no proxy), got nil", spec)
		}
	}
}
