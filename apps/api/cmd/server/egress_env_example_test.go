package main

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/config"
)

// envExampleRelPath is the shipped .env.example, relative to this package's
// directory (apps/api/cmd/server → four levels up is the repository root).
const envExampleRelPath = "../../../../.env.example"

// TestShippedEnvExampleEgressConfigIsAccepted reads the ACTUAL .env.example the
// product ships and asserts buildEgressGuards accepts it.
//
// Why this exists
// ===============
//
// M50 made an invalid SBOMHUB_EGRESS_* value a STARTUP REFUSAL — a deliberate
// fail-closed choice (a typo in an exemption list must not silently widen or
// narrow egress). The cost of that choice is that `.env.example` is now load
// bearing: install.sh copies it to .env, so a malformed value shipped here does
// not produce a warning, it produces an api that will not boot, on a fresh
// self-hosted install, for a user who changed nothing.
//
// The values are shipped UNCOMMENTED and two of them are EMPTY
// (SBOMHUB_EGRESS_ALLOWED_INTERNAL=, SBOMHUB_EGRESS_NAT64_PREFIXES=), which is
// precisely the shape most likely to be mis-parsed by a future edit to the
// exemption or prefix parsers — "" is not a host, and it is not a CIDR.
// Measured 2026-07-30: both parse to empty sets and the guard builds with
// strict defaults.
//
// This is the repository's anti-pattern #90 ("what ships the default is the
// installer, not the doc") turned into a gate. The M48 postmortem records the
// same shape costing three red CI jobs: a contract was made mandatory and the
// files that supply it were left out of the change. Nothing else in the suite
// reads this file — the docker-compose and install.sh smoke jobs would catch it
// eventually, but only by failing a container health check, and only after
// pulling images (which is exactly the step that was flaky when this test was
// written, so that signal is not dependable).
//
// What this test does NOT do: it does not validate any non-egress variable in
// .env.example, and it does not assert the values are a good POLICY (that
// ALLOW_PRIVATE ships false is asserted below, but whether that is the right
// default is a product decision, not a parse question).
func TestShippedEnvExampleEgressConfigIsAccepted(t *testing.T) {
	shipped := readShippedEgressEnv(t)

	if len(shipped) == 0 {
		t.Fatalf("no uncommented SBOMHUB_EGRESS_* assignment found in %s — either the "+
			"variables were removed (in which case delete this test and say why in the "+
			"commit) or they were commented out (in which case a fresh install no longer "+
			"gets an explicit egress posture, which was the point of shipping them)",
			envExampleRelPath)
	}

	cfg := &config.Config{
		EgressAllowedInternal: shipped["SBOMHUB_EGRESS_ALLOWED_INTERNAL"],
		EgressNAT64Prefixes:   shipped["SBOMHUB_EGRESS_NAT64_PREFIXES"],
		EgressAllowPrivate:    shipped["SBOMHUB_EGRESS_ALLOW_PRIVATE"] == "true",
		EgressAllowProxy:      shipped["SBOMHUB_EGRESS_ALLOW_PROXY"] == "true",
	}

	set, err := buildEgressGuards(cfg)
	if err != nil {
		t.Fatalf("buildEgressGuards REFUSED the shipped .env.example (%v): %v\n"+
			"A fresh `install.sh` copies this file to .env, so this is an api that "+
			"will not boot for a user who changed nothing.", shipped, err)
	}
	if set == nil {
		t.Fatalf("buildEgressGuards returned a nil set for the shipped .env.example (%v) — "+
			"a nil guard is treated as the strictest policy downstream, but reaching that "+
			"state without an error means the constructor silently produced no policy",
			shipped)
	}

	// The shipped posture must be the closed one. If a future edit flips either
	// of these to true in .env.example, every fresh self-hosted install would
	// start with internal addresses reachable (ALLOW_PRIVATE) or with the
	// destination check delegated to a proxy (ALLOW_PROXY, which defeats the
	// dialer-level enforcement entirely — see docs/security/egress.md).
	if cfg.EgressAllowPrivate {
		t.Errorf("SBOMHUB_EGRESS_ALLOW_PRIVATE ships as true — every fresh install would "+
			"permit tenant-configured webhooks and issue trackers to reach internal "+
			"addresses. Ship false and let operators opt in; %s is the file install.sh "+
			"copies.", envExampleRelPath)
	}
	if cfg.EgressAllowProxy {
		t.Errorf("SBOMHUB_EGRESS_ALLOW_PROXY ships as true — a proxy chooses the " +
			"destination, so the dialer only ever sees the proxy's address and the " +
			"policy stops being enforceable. This must be an explicit operator opt-in.")
	}
}

// readShippedEgressEnv returns the uncommented SBOMHUB_EGRESS_* assignments in
// .env.example. Values are returned verbatim (not trimmed) so that a stray
// trailing space, which the parser would see, is not hidden by the test.
func readShippedEgressEnv(t *testing.T) map[string]string {
	t.Helper()

	f, err := os.Open(envExampleRelPath)
	if err != nil {
		t.Fatalf("open %s: %v", envExampleRelPath, err)
	}
	defer func() { _ = f.Close() }()

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || !strings.HasPrefix(key, "SBOMHUB_EGRESS_") {
			continue
		}
		out[key] = value
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", envExampleRelPath, err)
	}
	return out
}
