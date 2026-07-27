package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// M47 W1 — the four "sync a global catalog now" endpoints must be Admin-only.
//
// These routes are the one item in the M47 W1 set with NO caller-supplied
// resource id, so there is nothing to scope. What makes them belong in a
// tenant-boundary wave anyway is the blast radius: each one writes GLOBAL,
// RLS-free tables that EVERY tenant in the installation reads
// (`vulnerabilities` epss columns, `kev_*`, `eol_*`, `ipa_*`), and each one
// drives an unbounded outbound fetch (FIRST / CISA / endoflife.date / IPA).
// On the bare `auth` group any authenticated member — including a Viewer,
// who by definition may not write anything — could therefore mutate or stall
// shared data for every other tenant, repeatedly. That is a cross-tenant
// integrity and availability primitive handed out to the lowest role in the
// system.
//
// Why this test reads the source instead of driving a request: the gate is a
// middleware argument at the registration site in main.go, and Echo exposes
// no way to enumerate a route's middleware after the fact (e.Routes() returns
// method/path/handler-name only). The behaviour of the middleware itself is
// already pinned by middleware.TestRequireAdmin_RoleMatrix and
// handler.TestAPIKeyRoutesAreAdminOnly; what is NOT otherwise pinned — and
// what actually regressed here — is that the registration site passes it. A
// source assertion is the honest instrument for that: it cannot prove the
// middleware works, only that it is wired, which is exactly the claim.
func TestM47W1GlobalSyncRoutesAreAdminGated(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	body := string(src)

	// Every route whose handler kicks off a global-catalog sync. Keep this
	// list in step with the handlers: a new global sync endpoint that is not
	// listed here is invisible to this guard.
	globalSyncRoutes := []string{
		"/vulnerabilities/sync-epss",
		"/kev/sync",
		"/eol/sync",
		"/ipa/sync",
	}

	for _, route := range globalSyncRoutes {
		t.Run(route, func(t *testing.T) {
			// The POST registration line for this exact path. `"` around the
			// path prevents /kev/sync from matching /kev/sync/latest.
			re := regexp.MustCompile(`(?m)^.*\.POST\("` + regexp.QuoteMeta(route) + `",.*$`)
			matches := re.FindAllString(body, -1)
			if len(matches) == 0 {
				t.Fatalf("no POST registration found for %s — either the route was removed "+
					"(then remove it from this list) or renamed (then this guard is now blind)", route)
			}
			for _, line := range matches {
				if !strings.Contains(line, "adminOnly") && !strings.Contains(line, "RequireAdmin()") {
					t.Errorf("POST %s is registered without an admin gate:\n\t%s\n"+
						"This endpoint writes a GLOBAL, RLS-free catalog that every tenant reads. "+
						"Add `adminOnly` to the registration.", route, strings.TrimSpace(line))
				}
			}
		})
	}
}

// TestM47W1ManualScanRequiresWrite pins the Codex round-1 High finding.
//
// POST /projects/:id/scan sat on the bare `auth` group with no role gate.
// That was survivable only because the endpoint did nothing: its goroutine
// ran on context.Background(), so RLS filtered every component and no scan
// ever happened. M47 W1 bound the goroutine to the tenant, which made the
// route work — and therefore made the missing gate live: a read-scoped
// Viewer could kick off unbounded outbound NVD/JVN fetches that write the
// GLOBAL, RLS-free vulnerabilities tables every tenant reads.
//
// RequireWrite, not RequireAdmin: this is a project mutation of the same
// class as SBOM upload and triage/run, both of which use RequireWrite.
func TestM47W1ManualScanRequiresWrite(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	re := regexp.MustCompile(`(?m)^.*\.POST\("/projects/:id/scan",.*$`)
	matches := re.FindAllString(string(src), -1)
	if len(matches) == 0 {
		t.Fatal("no POST registration found for /projects/:id/scan — this guard is now blind")
	}
	for _, line := range matches {
		if !strings.Contains(line, "RequireWrite()") {
			t.Errorf("POST /projects/:id/scan is registered without a write gate:\n\t%s\n"+
				"A read-scoped Viewer must not be able to drive outbound scans that write "+
				"the global vulnerability tables.", strings.TrimSpace(line))
		}
	}
}

// TestM47W1AdminOnlyIsDeclaredBeforeItsFirstUse guards the mechanical hazard
// the fix introduced: `adminOnly` is a local variable, and Go would simply
// fail to compile if it were used before declaration — but a future edit
// could "fix" that by declaring a SECOND adminOnly further down, silently
// leaving the earlier routes ungated while everything still builds. One
// declaration is the invariant.
func TestM47W1AdminOnlyIsDeclaredBeforeItsFirstUse(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	decls := regexp.MustCompile(`(?m)^\s*adminOnly\s*:=`).FindAllString(string(src), -1)
	if len(decls) != 1 {
		t.Errorf("main.go declares `adminOnly` %d time(s), want exactly 1 — "+
			"a second declaration would shadow the first and can leave earlier routes ungated", len(decls))
	}
}
