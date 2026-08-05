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
// Why this test reads the source instead of driving a request: the gate is
// middleware at the registration site in main.go, and Echo exposes no way to
// enumerate a route's middleware after the fact (e.Routes() returns
// method/path/handler-name only). The behaviour of the middleware itself is
// already pinned by middleware.TestRequireAdmin_RoleMatrix and
// handler.TestAPIKeyRoutesAreAdminOnly; what is NOT otherwise pinned — and
// what actually regressed here — is that the registration site applies it. A
// source assertion is the honest instrument for that: it cannot prove the
// middleware works, only that it is wired, which is exactly the claim.
//
// M47R: the gate moved from a per-route ARGUMENT to the `authAdmin` GROUP, so
// that it runs before TenantTx rather than inside it (see the group
// declarations in main.go). This test therefore accepts either form. The
// group's own declaration is pinned by
// TestM47RGatedGroupsAreDeclaredCorrectly, and
// TestM47RMutatingRoutesCarryARoleGate now sweeps EVERY mutating route rather
// than the four named here — this test survives as the targeted guard for the
// highest-blast-radius ones.
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
				if !strings.Contains(line, "adminOnly") &&
					!strings.Contains(line, "RequireAdmin()") &&
					!strings.HasPrefix(strings.TrimSpace(line), "authAdmin.") {
					t.Errorf("POST %s is registered without an admin gate:\n\t%s\n"+
						"This endpoint writes a GLOBAL, RLS-free catalog that every tenant reads. "+
						"Register it on the `authAdmin` group.", route, strings.TrimSpace(line))
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
//
// M47R: accepts the `authWrite` group as well as the per-route argument, for
// the same reason as the admin guard above.
//
// M53 W1: rewritten from a LINE regex to the AST-derived chain. The route moved
// off `authWrite` onto an explicit MultiAuth chain whose middleware arguments
// sit on their own lines, and the old
// `(?m)^.*\.POST\("/projects/:id/scan",.*$` matched neither the new registered
// path (which is the full "/api/v1/..." on the Echo instance) nor a single line
// carrying the guard. Both failure modes were silent-ish in opposite
// directions — a stale path anchor t.Fatal'd "this guard is now blind", and a
// multi-line registration would have reported a MISSING gate that is in fact
// present. parseRoutes resolves the group's inherited middleware and the
// per-route arguments into one chain, so it is indifferent to both.
func TestM47W1ManualScanRequiresWrite(t *testing.T) {
	routes, _ := parseRoutes(t)
	found := 0
	for _, r := range routes {
		if r.method != "POST" || !strings.HasSuffix(r.fullPath, "/projects/:id/scan") {
			continue
		}
		found++
		if indexOf(r.chain, func(m string) bool { return strings.Contains(m, "RequireWrite") }) < 0 {
			t.Errorf("main.go:%d %s %s is registered without a write gate; chain = %v\n"+
				"A read-scoped Viewer must not be able to drive outbound scans that write "+
				"the global vulnerability tables.", r.line, r.method, r.fullPath, r.chain)
		}
	}
	if found == 0 {
		t.Fatal("no POST registration found for /projects/:id/scan — this guard is now blind")
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
