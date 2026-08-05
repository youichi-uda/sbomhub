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
// .github/workflows/sbom-upload.yml is the reusable GitHub Action SBOMHub ships
// to its users. It is three steps: upload the SBOM, read it back to learn its
// id, then POST that id to /scan. The first two ran on the MultiAuth-fronted
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
// credential at all. And because the workflow step carries
// `continue-on-error: true`, neither status ever turned a run red: users have
// been uploading SBOMs that were never scanned, with a green check next to them.
//
// # What this file pins
//
// TestM50W2APIKeyReachableRoutesAreAllClassified already sweeps every
// API-key-fronted route, but it is symmetric: it is equally happy if this route
// leaves the MultiAuth chain again, as long as the scope table follows it out.
// That is exactly the regression that would silently re-break the shipped
// Action, so the route is named here explicitly.
// ---------------------------------------------------------------------------

const m53ScanRoute = "POST /api/v1/projects/:id/scan"

// TestM53ScanRouteIsAPIKeyReachable is the direct statement of the fix: the
// route the shipped GitHub Action calls must accept a Bearer API key.
func TestM53ScanRouteIsAPIKeyReachable(t *testing.T) {
	reachable := apiKeyReachableRoutes(t)
	if _, ok := reachable[m53ScanRoute]; !ok {
		t.Errorf("%s is not on an API-key-fronted chain. "+
			".github/workflows/sbom-upload.yml's third step calls it with "+
			"`Authorization: Bearer sbh_...`, which means it is answered 401 (clerk) or "+
			"404-as-the-default-tenant (anonymous) and the shipped Action silently uploads "+
			"SBOMs that are never scanned.", m53ScanRoute)
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
//     This is a trigger the Action calls once per upload, and it is the most
//     expensive side effect an API key can start — the tighter of the two
//     budgets is the right one, and it is the same one POST /sbom uses.
//   - TenantTx is present. VulnerabilityHandler.Scan refuses with 401 when
//     GetTenantID is nil, and the scope check it performs (SbomInProject) is
//     RLS-filtered, so without the request transaction the route cannot work at
//     all.
func TestM53ScanRouteChainMatchesItsNeighbours(t *testing.T) {
	routes, _ := parseRoutes(t)
	var chain []string
	found := false
	for _, r := range routes {
		if r.method+" "+r.fullPath == m53ScanRoute {
			chain = r.chain
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("main.go no longer registers %s at all — this guard is blind", m53ScanRoute)
	}

	idx := func(needle string) int {
		return indexOf(chain, func(m string) bool { return strings.Contains(m, needle) })
	}
	gate, limit, tx := idx("RequireWrite"), idx("RateLimitByAPIKey"), idx("TenantTx(")

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
