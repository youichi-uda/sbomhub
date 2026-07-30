package main

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/egress"
)

// The tests in internal/egress build a Policy directly. That leaves the path
// from environment variable to live guard untested, so reverting Config.Load,
// parseNAT64Prefixes or buildEgressGuards would disable the production defence
// with every other test still green — Codex round 5 (Low). These cover that
// path end to end.

func TestBuildEgressGuards_DefaultsAreFailClosed(t *testing.T) {
	t.Setenv("SBOMHUB_EGRESS_ALLOW_PRIVATE", "")
	t.Setenv("SBOMHUB_EGRESS_ALLOWED_INTERNAL", "")
	t.Setenv("SBOMHUB_EGRESS_ALLOW_PROXY", "")
	t.Setenv("SBOMHUB_EGRESS_NAT64_PREFIXES", "")

	set, err := buildEgressGuards(loadEgressConfig(t))
	if err != nil {
		t.Fatalf("buildEgressGuards: %v", err)
	}
	for name, g := range map[string]*egress.Guard{
		"issue_tracker": set.IssueTracker,
		"notification":  set.NotificationWebhook,
		"diff_webhook":  set.DiffWebhook,
		"tenant_llm":    set.TenantLLM,
	} {
		if g.Policy().AllowPrivate {
			t.Errorf("%s: AllowPrivate must default to false", name)
		}
		if g.Transport().Proxy != nil {
			t.Errorf("%s: a proxy must not be consulted by default", name)
		}
		if err := g.ValidateURL("https://169.254.169.254/"); err == nil {
			t.Errorf("%s: the metadata address must be refused", name)
		}
		if err := g.ValidateURL("https://10.0.0.5/x"); err == nil {
			t.Errorf("%s: an internal literal must be refused by default", name)
		}
	}
}

func TestBuildEgressGuards_EnvOptInsReachTheGuards(t *testing.T) {
	t.Setenv("SBOMHUB_EGRESS_ALLOW_PRIVATE", "false")
	t.Setenv("SBOMHUB_EGRESS_ALLOWED_INTERNAL", "jira.corp.example, 10.20.0.0/24")
	t.Setenv("SBOMHUB_EGRESS_ALLOW_PROXY", "true")
	t.Setenv("SBOMHUB_EGRESS_NAT64_PREFIXES", "fd00:1234::/32")

	set, err := buildEgressGuards(loadEgressConfig(t))
	if err != nil {
		t.Fatalf("buildEgressGuards: %v", err)
	}
	p := set.NotificationWebhook.Policy()

	if len(p.PrivateHostExemptions) != 1 || p.PrivateHostExemptions[0] != "jira.corp.example" {
		t.Errorf("PrivateHostExemptions = %v", p.PrivateHostExemptions)
	}
	if len(p.PrivateCIDRExemptions) != 1 || p.PrivateCIDRExemptions[0].String() != "10.20.0.0/24" {
		t.Errorf("PrivateCIDRExemptions = %v", p.PrivateCIDRExemptions)
	}
	if len(p.NAT64Prefixes) != 1 || p.NAT64Prefixes[0].String() != "fd00:1234::/32" {
		t.Errorf("NAT64Prefixes = %v", p.NAT64Prefixes)
	}
	if set.NotificationWebhook.Transport().Proxy == nil {
		t.Error("SBOMHUB_EGRESS_ALLOW_PROXY=true must restore proxy support")
	}

	// The declared prefix has to be live at the enforcement point, not merely
	// stored: 192.168.1.1 behind it must be refused as a private destination.
	if err := set.NotificationWebhook.ValidateURL("http://[fd00:1234:c0a8:101::]/"); !errors.Is(err, egress.ErrBlockedDestination) {
		t.Errorf("translated RFC1918 behind the declared prefix = %v, want ErrBlockedDestination", err)
	}
	// And the metadata address behind it, which no opt-in re-enables.
	if err := set.NotificationWebhook.ValidateURL("http://[fd00:1234:a9fe:a9fe::]/"); !errors.Is(err, egress.ErrBlockedDestination) {
		t.Errorf("translated metadata behind the declared prefix = %v, want ErrBlockedDestination", err)
	}
	// The exempted IPv4 network is reachable through the declared prefix.
	if err := set.NotificationWebhook.ValidateURL("http://[fd00:1234:a14:1::]/"); err != nil {
		t.Errorf("10.20.0.1 behind the declared prefix is exempted, got %v", err)
	}
}

func TestBuildEgressGuards_MalformedEnvRefusesStartup(t *testing.T) {
	cases := map[string]map[string]string{
		"exemption is a URL":            {"SBOMHUB_EGRESS_ALLOWED_INTERNAL": "http://jira.corp.example"},
		"exemption is a bad CIDR":       {"SBOMHUB_EGRESS_ALLOWED_INTERNAL": "10.0.0.0/99"},
		"exemption is a bad host":       {"SBOMHUB_EGRESS_ALLOWED_INTERNAL": "*.corp.example"},
		"nat64 is not a CIDR":           {"SBOMHUB_EGRESS_NAT64_PREFIXES": "fd00:1234::"},
		"nat64 has a bad length":        {"SBOMHUB_EGRESS_NAT64_PREFIXES": "fd00:1234::/44"},
		"nat64 is blocked-class":        {"SBOMHUB_EGRESS_NAT64_PREFIXES": "fe80::/64"},
		"nat64 overlaps the well-known": {"SBOMHUB_EGRESS_NAT64_PREFIXES": "64:ff9b::/96"},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("SBOMHUB_EGRESS_ALLOWED_INTERNAL", "")
			t.Setenv("SBOMHUB_EGRESS_NAT64_PREFIXES", "")
			for k, v := range env {
				t.Setenv(k, v)
			}
			if _, err := buildEgressGuards(loadEgressConfig(t)); err == nil {
				t.Error("expected a startup refusal; a silently-dropped setting leaves the operator believing a path is open when it is closed")
			}
		})
	}
}

func TestParseNAT64Prefixes(t *testing.T) {
	got, err := parseNAT64Prefixes(" fd00:1234::/32 , 2a01:4f8:aabb::/48 ")
	if err != nil {
		t.Fatalf("parseNAT64Prefixes: %v", err)
	}
	want := []string{"fd00:1234::/32", "2a01:4f8:aabb::/48"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("got[%d] = %s, want %s", i, got[i], want[i])
		}
	}
	if _, err := parseNAT64Prefixes("not-a-prefix"); err == nil || !strings.Contains(err.Error(), "not a CIDR prefix") {
		t.Errorf("err = %v, want a CIDR-shape complaint", err)
	}
	// Masking: a prefix with host bits set is normalised.
	masked, err := parseNAT64Prefixes("fd00:1234:5678::/32")
	if err != nil {
		t.Fatalf("parseNAT64Prefixes: %v", err)
	}
	if masked[0] != netip.MustParsePrefix("fd00:1234::/32") {
		t.Errorf("masked = %s, want fd00:1234::/32", masked[0])
	}
}

// loadEgressConfig loads config in a shape that satisfies Config.Load's
// non-egress requirements, so these tests exercise only the egress path.
func loadEgressConfig(t *testing.T) *config.Config {
	t.Helper()
	t.Setenv("APP_ENV", "development")
	t.Setenv("SBOMHUB_AUTH_MODE", "anonymous")
	cfg := config.Load()
	if cfg == nil {
		t.Fatal("config.Load returned nil")
	}
	return cfg
}

// TestParseNAT64Prefixes_RefusesOverlap — Codex round 7 (Medium): two
// declarations of different lengths covering the same address decode different
// embedded IPv4 addresses, so an overlapping pair is ambiguous. The classifier
// resolves that fail-closed by taking the most restrictive reading, but the
// operator has made a mistake and is told about it.
func TestParseNAT64Prefixes_RefusesOverlap(t *testing.T) {
	if _, err := parseNAT64Prefixes("fd00:1234::/32, fd00:1234:800::/40"); err == nil {
		t.Error("expected overlapping declarations to be refused")
	}
	if _, err := parseNAT64Prefixes("fd00:1234:800::/40, fd00:1234::/32"); err == nil {
		t.Error("expected overlapping declarations to be refused in either order")
	}
	// Non-overlapping declarations are fine.
	if _, err := parseNAT64Prefixes("fd00:1234::/32, fd00:5678::/32"); err != nil {
		t.Errorf("non-overlapping declarations must be accepted: %v", err)
	}
}
