package main

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// M53 W1 — POST /api/v1/projects/:id/scan must be reachable with an API key.
//
// # The defect this closes
//
// .github/workflows/sbom-upload.yml is the workflow this repository ships and
// runs against its own code. It is `workflow_dispatch`-only — NOT a reusable
// action and not a called workflow (Codex round 4, Low: an earlier draft said
// "reusable GitHub Action"; it declares no `workflow_call` trigger, there is no
// action manifest anywhere in the tree, and docs/ci-inventory.md classifies it
// as manual dogfooding. Codex round 5, Low: the replacement wording
// "copy-me-into-your-repo reference" was also unsupported by anything in the
// repository and is gone too).
// It is three steps: upload the SBOM, read it back to learn its id,
// then POST that id to /scan. The first two ran on the MultiAuth-fronted
// chain and worked with `Authorization: Bearer sbh_...`; the third was
// registered on the Clerk-only `authWrite` group, so no API key was ever
// consulted for it.
//
// Measured on a throwaway stack, 2026-08-05, one tenant-level `sbh_` key:
//
//	                                          anonymous mode   clerk mode
//	POST /api/v1/projects/:id/sbom                       201          201
//	GET  /api/v1/projects/:id/sbom                       200          200
//	POST /api/v1/projects/:id/scan?sbom_id=…             404          401
//
// The 404 is the worse half: with SBOMHUB_AUTH_MODE=anonymous the Bearer header
// is ignored and the request resolves as the DEFAULT tenant, which does not own
// the SBOM — the same 404, byte for byte, that the route answers with NO
// credential at all. And neither status ever turned a run red for two
// independent reasons: the step carried `continue-on-error: true`, and — the
// half that is easy to miss — its curl had no --fail flag, so an HTTP refusal
// exited 0 and the `echo "Vulnerability scan triggered!"` after it ran anyway
// (Codex rounds 4 and 5, Low).
//
// # What was NOT broken (corrected after Codex round 1, Medium)
//
// The first draft of this comment said users "have been uploading SBOMs that
// were never scanned". That is FALSE, and the correction matters because it
// changes what this route is for. POST /api/v1/projects/:id/sbom starts its own
// TRACKED NVD/JVN scan on ingest (SbomHandler.startBackgroundScan) and always
// has: measured on the same throwaway stack, uploading the fixture and making
// no /scan call at all produced a component_vulnerabilities row and left
// GET /sboms/:sbom_id/scan-status reporting `"status":"completed"` with
// `"critical":1`.
//
// So the workflow's SBOMs were scanned. What never worked is the explicit
// RE-scan trigger — the route that lets a client sweep an existing SBOM again
// (against refreshed advisory data, or with a narrower `sources` list) without
// re-uploading it. That is a smaller defect than "nothing was scanned", and it
// is still a defect: an endpoint the product documents, and calls from its own
// shipped workflow, that answers 404 to every API key in existence.
//
// # What this change is NOT: purely additive (Codex round 5, Low)
//
// In SBOMHUB_AUTH_MODE=anonymous the pre-M53 Auth() ignored the Authorization
// header outright and served every request as the DEFAULT tenant's Owner. So a
// request that happened to carry an `sbh_` key was not refused — the key was
// simply not read, and the request succeeded on the default identity whenever
// the target belonged to the default tenant. Measured on a throwaway stack
// 2026-08-05 against a default-tenant SBOM, pre-fix binary → post-fix binary:
//
//	read-scoped (Viewer) key   202 -> 403
//	unknown `sbh_` value       202 -> 401
//	no Authorization header    202 -> 202   (the self-hosted identity, unchanged)
//
// That tightening is the whole point — the credential is finally read — but it
// is a behaviour change for self-hosted deployments, not a pure gain, and
// docs/UPGRADE.md says so. A CI job passing a read-scoped or stale key to this
// route was succeeding by accident and now fails.
//
// # What this file pins
//
// TestM50W2APIKeyReachableRoutesAreAllClassified already sweeps every
// API-key-fronted route, but it is symmetric: it is equally happy if this route
// leaves the MultiAuth chain again, as long as the scope table follows it out.
// That is exactly the regression that would silently re-break the shipped
// workflow's re-scan step, so the route is named here explicitly.
// ---------------------------------------------------------------------------

const m53ScanRoute = "POST /api/v1/projects/:id/scan"

// TestM53ScanRouteIsAPIKeyReachable is the direct statement of the fix: the
// route the shipped workflow calls must accept a Bearer API key.
func TestM53ScanRouteIsAPIKeyReachable(t *testing.T) {
	reachable := apiKeyReachableRoutes(t)
	if _, ok := reachable[m53ScanRoute]; !ok {
		t.Errorf("%s is not on an API-key-fronted chain. "+
			".github/workflows/sbom-upload.yml's third step calls it with "+
			"`Authorization: Bearer sbh_...`, which means it is answered 401 (clerk) or "+
			"404-as-the-default-tenant (anonymous), so the shipped workflow's re-scan step "+
			"does nothing at all. (The SBOM is still scanned on ingest by the upload — see "+
			"the file comment — but the explicit re-scan trigger is unreachable.)", m53ScanRoute)
	}
}

// TestM53ScanRouteChainMatchesItsNeighbours pins the SHAPE of the chain, not
// only its reachability.
//
// The three properties, and why each one is not negotiable for this route:
//
//   - RequireWrite runs BEFORE RateLimitByAPIKey and TenantTx. M47 W1 made the
//     gate load-bearing (a read-scoped Viewer must not drive unbounded outbound
//     NVD/JVN fetches that write the GLOBAL, RLS-free vulnerability tables), and
//     putting it first means a refused request spends no rate-limit token and
//     opens no transaction. TestM47RRoleGateRunsBeforeTheTransaction enforces
//     the gate-before-TenantTx half generically; the rate-limit half is only
//     here.
//   - RateLimitByAPIKey on BudgetStandard (60/min), not BudgetPoll (300/min).
//     This is a trigger, not a polling surface, and it starts the most expensive
//     side effect an API key can — the tighter of the two budgets is the right
//     one, and it is the same one POST /sbom uses. Measured on a throwaway stack
//     2026-08-05: 65 POSTs with a fresh key gave 60 admitted then 5 × 429.
//     The claim is only that the tighter budget is WIRED. It is not a capacity
//     bound (Codex R1 Low): nothing limits concurrent in-flight sweeps, and the
//     window is fixed rather than sliding, so straddling the boundary admits
//     120 in seconds. Both are properties of RateLimitByAPIKey itself.
//   - TenantTx is present. VulnerabilityHandler.Scan refuses with 401 when
//     GetTenantID is nil, and the scope check it performs (SbomInProject) is
//     RLS-filtered, so without the request transaction the route cannot work at
//     all.
func TestM53ScanRouteChainMatchesItsNeighbours(t *testing.T) {
	routes, _ := parseRoutes(t)
	var chain []string
	var handler string
	var lines []int
	for _, r := range routes {
		if r.method+" "+r.fullPath == m53ScanRoute {
			if chain == nil {
				chain = r.chain
				handler = r.handler
			}
			lines = append(lines, r.line)
		}
	}
	if len(lines) == 0 {
		t.Fatalf("main.go no longer registers %s at all — this guard is blind", m53ScanRoute)
	}

	// EXACTLY ONE registration (Codex round 5, Low). Echo lets the same
	// method+path be registered twice and serves the LAST one, while every
	// assertion below — and TestM50W2APIKeyReachableRoutesAreAllClassified's
	// set membership, and TestM47W1ManualScanRequiresWrite's per-match loop —
	// is satisfied by the FIRST. So re-adding the historical
	// `authWrite.POST("/projects/:id/scan", vulnHandler.Scan)` further down
	// main.go would restore the Clerk-only behaviour at run time with the whole
	// suite green. Counting is the only thing that sees it.
	if len(lines) != 1 {
		t.Errorf("main.go registers %s %d times (lines %v). Echo serves the LAST "+
			"registration for a duplicate method+path, so the effective chain is not "+
			"necessarily the one asserted below — and every other guard in this package "+
			"is satisfied by the first match.", m53ScanRoute, len(lines), lines)
	}

	idx := func(needle string) int {
		return indexOf(chain, func(m string) bool { return strings.Contains(m, needle) })
	}
	auth := idx("MultiAuth(")
	gate, limit, tx := idx("RequireWrite"), idx("RateLimitByAPIKey"), idx("TenantTx(")
	audit := idx("auditMiddleware")

	// The HANDLER, not just the chain (Codex round 6, Low). Every assertion in
	// this file is about the middleware in front of the route; none of them
	// notices if the handler behind it is replaced by something that answers
	// 202 and scans nothing — which would satisfy the workflow's status check
	// too. Naming it is what makes "the scan trigger works" a claim about the
	// scan rather than about the status code.
	if handler != "vulnHandler.Scan" {
		t.Errorf("%s is handled by %q, want vulnHandler.Scan. Everything else here "+
			"asserts the middleware in front of the route; a handler that answers 202 "+
			"without starting a sweep would pass all of it, and the workflow's 202 check "+
			"with it.", m53ScanRoute, handler)
	}

	// auditMiddleware (Codex round 6, Low). It was inherited from the
	// authWrite group before this wave and is now a per-route argument, so
	// deleting that one line is a plausible edit — and it would silently drop
	// the audit_logs row for every scan trigger. In a compliance product the
	// record of who started a scan is part of the product.
	if audit < 0 {
		t.Errorf("%s has no auditMiddleware in its chain %v — the scan.started audit row "+
			"is what records who triggered the sweep (observed on a throwaway stack: one "+
			"`scan.started` row per accepted request)", m53ScanRoute, chain)
	}

	// MultiAuth must be OUTERMOST (Codex round 3, Low). Asserting only the
	// relative order of the three below leaves a mutation undetected that
	// breaks the route completely: swap the registration to
	// `RequireWrite(), MultiAuth(...), RateLimit..., TenantTx...` and every
	// other assertion in this test still holds — RequireWrite is still before
	// the limiter, the limiter still before TenantTx, MultiAuth is still
	// present — while at run time RequireWrite executes before any credential
	// has been read, so ContextKeyRole is unset and every API key is answered
	// 401. Echo composes route middleware outermost-first, so position 0 is
	// the claim.
	if auth != 0 {
		t.Errorf("%s does not run MultiAuth first (position %d in %v). Every guard after "+
			"it reads context MultiAuth populates — RequireWrite reads the role, "+
			"RateLimitByAPIKey keys off the API key, TenantTx off the tenant — so anything "+
			"ahead of it judges a request whose credential has not been read yet.",
			m53ScanRoute, auth, chain)
	}

	if gate < 0 {
		t.Errorf("%s has no RequireWrite in its chain %v — a read-scoped API key could "+
			"drive outbound NVD/JVN fetches that write the global vulnerability tables",
			m53ScanRoute, chain)
	}
	if limit < 0 {
		t.Errorf("%s has no RateLimitByAPIKey in its chain %v — a leaked `sbh_` key could "+
			"start unbounded scans", m53ScanRoute, chain)
	}
	if tx < 0 {
		t.Errorf("%s has no TenantTx in its chain %v — VulnerabilityHandler.Scan answers "+
			"401 without a tenant context and its SbomInProject check is RLS-filtered",
			m53ScanRoute, chain)
	}
	if gate >= 0 && limit >= 0 && gate > limit {
		t.Errorf("%s runs RequireWrite (position %d) after RateLimitByAPIKey (position %d) "+
			"in %v — a refused request would spend a rate-limit token", m53ScanRoute, gate, limit, chain)
	}
	if gate >= 0 && tx >= 0 && gate > tx {
		t.Errorf("%s runs RequireWrite (position %d) after TenantTx (position %d) in %v — "+
			"a refused request would open the request transaction", m53ScanRoute, gate, tx, chain)
	}
	if limit >= 0 && tx >= 0 && limit > tx {
		t.Errorf("%s runs RateLimitByAPIKey (position %d) after TenantTx (position %d) in "+
			"%v — a throttled request would hold a pooled connection", m53ScanRoute, limit, tx, chain)
	}
	if limit >= 0 && !strings.Contains(chain[limit], "BudgetStandard") {
		t.Errorf("%s is rate-limited with %q, want appmw.BudgetStandard (60/min). "+
			"BudgetPoll's 300/min exists for the scan-STATUS polling loop; this is the "+
			"trigger, called once per upload, and it starts the most expensive side effect "+
			"an API key has.", m53ScanRoute, chain[limit])
	}
}
