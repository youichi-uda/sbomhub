package egress

import (
	"net/netip"
	"testing"
)

// TestClassify pins the classification of every address family the M50 SSRF
// review called out, plus the ones the predecessor implementation
// (service.isPrivateIP) missed.
//
// The "current implementation misses this" cases were measured against that
// predecessor on 2026-07-30 with go1.26.4: 100.64.1.1, 192.0.0.1, 198.18.0.1,
// 224.0.0.1, 239.1.2.3, 240.0.0.1, 255.255.255.255, :: , 64:ff9b::a9fe:a9fe
// and 2002:a9fe:a9fe::1 all classified as "not private", i.e. permitted.
//
// The 4-in-6 cases went the other way: net.IPNet.Contains normalises
// ::ffff:a.b.c.d before comparing, so ::ffff:169.254.169.254 WAS already
// caught. That is measured, not assumed, and the cases stay here so a future
// rewrite cannot lose it.
func TestClassify(t *testing.T) {
	cases := []struct {
		addr  string
		class Class
	}{
		// Blocked: cloud metadata and the rest of link-local.
		{"169.254.169.254", ClassBlocked},
		{"169.254.0.1", ClassBlocked},
		{"::ffff:169.254.169.254", ClassBlocked},
		{"::ffff:a9fe:a9fe", ClassBlocked},
		{"fe80::1", ClassBlocked},
		{"168.63.129.16", ClassBlocked},

		// Blocked: special-purpose ranges the predecessor let through.
		{"0.0.0.0", ClassBlocked},
		{"0.1.2.3", ClassBlocked},
		{"192.0.0.1", ClassBlocked},
		{"192.0.2.1", ClassBlocked},
		{"198.18.0.1", ClassBlocked},
		{"198.51.100.1", ClassBlocked},
		{"203.0.113.1", ClassBlocked},
		{"224.0.0.1", ClassBlocked},
		{"239.1.2.3", ClassBlocked},
		{"240.0.0.1", ClassBlocked},
		{"255.255.255.255", ClassBlocked},
		{"::", ClassBlocked},
		{"100::1", ClassBlocked},
		{"2001:db8::1", ClassBlocked},
		{"2001::1", ClassBlocked},
		{"ff02::1", ClassBlocked},

		// Blocked: IPv6 forms that embed a blocked IPv4 address.
		{"64:ff9b::a9fe:a9fe", ClassBlocked}, // NAT64 -> 169.254.169.254
		{"2002:a9fe:a9fe::1", ClassBlocked},  // 6to4  -> 169.254.169.254
		{"::169.254.169.254", ClassBlocked},  // IPv4-compatible
		{"64:ff9b::ffff:ffff", ClassBlocked}, // NAT64 -> 255.255.255.255
		{"2002:a83f:8110::1", ClassBlocked},  // 6to4  -> 168.63.129.16
		{"64:ff9b::7f00:1", ClassPrivate},    // NAT64 -> 127.0.0.1
		{"2002:c0a8:0101::1", ClassPrivate},  // 6to4  -> 192.168.1.1
		{"64:ff9b::808:808", ClassPublic},    // NAT64 -> 8.8.8.8, still fine
		{"2002:0808:0808::1", ClassPublic},   // 6to4  -> 8.8.8.8, still fine

		// Private: policy decides.
		{"10.1.2.3", ClassPrivate},
		{"172.16.0.1", ClassPrivate},
		{"172.31.255.255", ClassPrivate},
		{"192.168.1.1", ClassPrivate},
		{"127.0.0.1", ClassPrivate},
		{"::ffff:127.0.0.1", ClassPrivate},
		{"::1", ClassPrivate},
		{"fc00::1", ClassPrivate},
		{"fd12:3456::1", ClassPrivate},
		{"100.64.1.1", ClassPrivate},

		// Public.
		{"8.8.8.8", ClassPublic},
		{"1.1.1.1", ClassPublic},
		{"172.32.0.1", ClassPublic},
		{"172.15.255.255", ClassPublic},
		{"99.255.255.255", ClassPublic},
		{"100.128.0.1", ClassPublic},
		{"2606:4700::1111", ClassPublic},
	}

	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			addr, err := netip.ParseAddr(tc.addr)
			if err != nil {
				t.Fatalf("ParseAddr(%q): %v", tc.addr, err)
			}
			got, reason := Classify(addr)
			if got != tc.class {
				t.Errorf("Classify(%s) = %v (%q), want %v", tc.addr, got, reason, tc.class)
			}
			if got != ClassPublic && reason == "" {
				t.Errorf("Classify(%s) returned %v with no reason", tc.addr, got)
			}
		})
	}
}

// TestClassify_ZonedLinkLocalIsBlocked guards the netip.Prefix.Contains trap:
// Contains reports false for ANY address carrying a zone, so fe80::1%eth0 would
// classify as public if the zone were not stripped first.
func TestClassify_ZonedLinkLocalIsBlocked(t *testing.T) {
	addr, err := netip.ParseAddr("fe80::1%eth0")
	if err != nil {
		t.Fatalf("ParseAddr: %v", err)
	}
	if addr.Zone() == "" {
		t.Fatalf("expected the parsed address to carry a zone, got %q", addr.String())
	}
	if got, _ := Classify(addr); got != ClassBlocked {
		t.Errorf("Classify(fe80::1%%eth0) = %v, want ClassBlocked", got)
	}
}

func TestClassify_InvalidAddrIsBlocked(t *testing.T) {
	if got, _ := Classify(netip.Addr{}); got != ClassBlocked {
		t.Errorf("Classify(zero Addr) = %v, want ClassBlocked", got)
	}
}

func TestHostMatches(t *testing.T) {
	entries := []string{"github.com", "atlassian.net"}
	cases := []struct {
		host string
		want bool
	}{
		{"github.com", true},
		{"GitHub.com", true},
		{"github.com.", true},
		{"api.github.com", true},
		{"notgithub.com", false},
		{"github.com.evil.example", false},
		{"evilgithub.com", false},
		{"acme.atlassian.net", true},
		{"", false},
	}
	for _, tc := range cases {
		if got := hostMatches(tc.host, entries); got != tc.want {
			t.Errorf("hostMatches(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestParseExemptions(t *testing.T) {
	hosts, cidrs, err := ParseExemptions("jira.corp.example, 10.1.2.0/24 192.168.5.7\nOllama.internal")
	if err != nil {
		t.Fatalf("ParseExemptions: %v", err)
	}
	wantHosts := []string{"jira.corp.example", "ollama.internal"}
	if len(hosts) != len(wantHosts) {
		t.Fatalf("hosts = %v, want %v", hosts, wantHosts)
	}
	for i := range wantHosts {
		if hosts[i] != wantHosts[i] {
			t.Errorf("hosts[%d] = %q, want %q", i, hosts[i], wantHosts[i])
		}
	}
	if len(cidrs) != 2 {
		t.Fatalf("cidrs = %v, want 2 entries", cidrs)
	}
	if cidrs[0].String() != "10.1.2.0/24" {
		t.Errorf("cidrs[0] = %s, want 10.1.2.0/24", cidrs[0])
	}
	if cidrs[1].String() != "192.168.5.7/32" {
		t.Errorf("cidrs[1] = %s, want 192.168.5.7/32", cidrs[1])
	}
}

func TestParseExemptions_RejectsGarbage(t *testing.T) {
	if _, _, err := ParseExemptions("http://jira.corp.example"); err == nil {
		t.Error("expected an error for a URL-shaped exemption, got nil")
	}
	if _, _, err := ParseExemptions("10.0.0.0/99"); err == nil {
		t.Error("expected an error for an out-of-range prefix, got nil")
	}
}

func TestParseExemptions_Empty(t *testing.T) {
	hosts, cidrs, err := ParseExemptions("  , \n ")
	if err != nil {
		t.Fatalf("ParseExemptions: %v", err)
	}
	if len(hosts) != 0 || len(cidrs) != 0 {
		t.Errorf("expected no entries, got hosts=%v cidrs=%v", hosts, cidrs)
	}
}
