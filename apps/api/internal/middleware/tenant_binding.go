package middleware

import (
	"sort"
)

// M52 — every route registered WITHOUT appmw.TenantTx must say how it binds
// `app.current_tenant_id`.
//
// # The defect this closes
//
// POST /api/v1/projects/:id/cra-reports/:report_id/reanalyse answered 500 for
// EVERY input from the day it shipped — including a report the caller owns.
// The cause was not the endpoint's own logic:
//
//   - /reanalyse is one of the F19 routes deliberately registered without
//     appmw.TenantTx, because the drafting cycle must not hold a Postgres
//     transaction across the LLM call;
//   - `cra_reports` is FORCE ROW LEVEL SECURITY (migration 038) with the
//     policy predicate
//     `tenant_id = current_setting('app.current_tenant_id', true)::UUID`;
//   - the handler's gatekeeper read went straight to the repository, i.e. onto
//     a pooled connection with no GUC bound.
//
// An unbound connection behaves in two different ways, neither of them the
// intended one (measured against the live schema as sbomhub_app, 2026-08-04):
//
//	GUC never set on that backend  → current_setting(...) is NULL
//	                               → the predicate is NULL
//	                               → ZERO rows: a report you own reads as a
//	                                 FALSE 404.
//	GUC set once by an earlier
//	`SET LOCAL` on the same pooled → the placeholder reverts to the EMPTY
//	backend                          STRING, so ''::UUID raises 22P02
//	                               → the read ERRORS: 500 for every input.
//
// A running server is permanently in the second state, because every
// TenantTx route borrows from the same pool. Hence "works on a freshly
// started server, 500 in production".
//
// The same shape had already been found and fixed on
// /vex-drafts/:draft_id/reanalyse, and cmd/server/main.go carried a comment
// saying so twelve lines above the CRA registration. Nothing carried the fix
// across. That is the failure this file mechanises against.
//
// # What this file is
//
// A classification table, keyed by route, covering exactly the routes that
// main.go registers with NO TenantTx in their effective middleware chain.
// Every such route must state HOW it binds the tenant, or state that it
// touches no RLS-protected table. A route with no entry fails
// TestM52NoTenantTxRoutesAreAllClassified — default-deny, the same posture
// apiKeyRouteScope takes in project_scope.go.
//
// The reason (`Why`) is a FIELD rather than a comment above the line, so a
// route cannot be added by copying its neighbour without writing down why.
//
// # What it deliberately is NOT
//
// It is not a call-graph analysis. Nothing here parses handler → service →
// repository → table, and nothing should: a hand-written resolver for a
// language whose scoping rules are not ours produces false positives
// indefinitely, and a gate that reddens CI on correct code gets disabled. The
// division of labour is instead:
//
//	the ROUTE SET is derived mechanically   — from main.go's AST
//	                                          (tenant_binding_routes_test.go);
//	the CLASSIFICATION is written by a human — once, with a reason;
//	the CLASSIFICATION's CLAIM is measured  — against a live database on a
//	                                          deliberately poisoned pooled
//	                                          connection
//	                                          (handler/m52_no_tenanttx_route_
//	                                          binding_integration_test.go for
//	                                          BindsItself; the pg_class check
//	                                          in tenant_binding_schema_
//	                                          integration_test.go for
//	                                          TouchesNoRLSTable).
//
// # Threat model
//
// This catches an HONEST author's oversight: a new no-TenantTx route whose
// handler forgets to bind, or a precedent that was not carried across to a
// sibling. It is not a boundary against an author who wants to evade it —
// anyone who can add a route to main.go can also add a line here. Its value
// is that adding the line is a deliberate, reviewed act that has to carry a
// written reason and (for BindsItself) a test that actually drives the claim.
//
// Nothing in the request path reads this table. It is data for tests.
//
// # What it does not cover
//
//   - Routes that DO carry TenantTx. Those are bound by the middleware; the
//     M47R gate in cmd/server/m47r_route_role_gate_test.go covers their
//     ordering.
//   - WHICH tenant gets bound. This file only asks whether a tenant is bound
//     at all. Binding the wrong tenant is an authorisation defect and is the
//     job of the M47 W1 scope checks and the RLS policy itself.
//   - Background jobs, the scheduler, and anything not reachable through an
//     Echo route registration in cmd/server/main.go.
//   - Statements issued by middleware that runs BEFORE TenantTx on a route
//     that does have it. `authMiddleware` sits outside TenantTx on every
//     `auth*` group (main.go declares `authBase := api.Group("",
//     authMiddleware)` and hangs the TenantTx groups off it), so its own
//     database work is as unbound as anything here — this table simply does
//     not enumerate those routes, because the question it asks is per-route
//     and they answer "yes, TenantTx". What that middleware does is covered
//     by the note below rather than by a rule.
//
// # What runs before every classified handler
//
// Six of the nine routes sit behind `triageMultiAuth` / `authMiddleware`, and
// that middleware does two things worth knowing when reading a rule:
//
//  1. It CAN provision a tenant. `Auth`'s self-hosted branch calls
//     TenantRepository.GetOrCreateDefault and its Clerk branch calls
//     GetOrCreateByClerkOrgID; both fall through to TenantRepository.Create on
//     a first visit, and Create writes the RLS-protected `scan_settings` row.
//     That access is bound — Create opens its own transaction and issues the
//     set_config between the two INSERTs (F187) — so it is listed in the
//     affected rules' BindsVia even though it happens before the handler.
//  2. Its own `SetCurrentTenant` does NOT bind anything for the handler.
//     handleAPIKeyAuth calls `tenantRepo.SetCurrentTenant`, which issues
//     `SELECT set_config('app.current_tenant_id', $1, true)` through the
//     request-scoped query helper. On a route with no TenantTx there is no
//     ambient transaction, so the statement runs in its own implicit one and
//     `is_local = true` discards the value the moment it commits. Measured on
//     the migrated schema, 2026-08-05: the very next statement on the same
//     connection reads the placeholder as the EMPTY STRING, not the tenant and
//     not NULL. So on these routes the auth step is not a binding — it is one
//     of the things that leaves the pooled connection in exactly the state
//     that turned /reanalyse's unbound read into a 500 rather than a false
//     404.

// TenantBindingKind is how a route that carries no TenantTx keeps its
// database access inside a tenant.
type TenantBindingKind string

const (
	// TenantBindingBindsItself: the route ISSUES at least one statement
	// against an RLS-protected table, and every such statement is preceded on
	// its branch by a transaction of the route's own carrying
	// `SELECT set_config('app.current_tenant_id', $1, true)`.
	//
	// "Issues" is load-bearing. It excludes the work PostgreSQL performs on
	// the route's behalf to maintain referential integrity: an `ON DELETE
	// CASCADE` or `ON DELETE SET NULL` reaching an RLS-protected child table.
	// Those actions run in RI triggers, which bypass row security by design,
	// so they need no binding and a rule is not expected to name one for them.
	// Measured on the migrated schema as the NOBYPASSRLS `sbomhub_app` role
	// with no GUC set, 2026-08-05: `DELETE FROM tenants` removed the tenant's
	// `projects` row (FORCE RLS) and raised nothing, and `DELETE FROM users`
	// nulled `llm_calls.user_id` (FORCE RLS) and raised nothing. The Clerk
	// webhook's two delete branches are the routes that depend on this.
	//
	// This classification is a PROMISE ABOUT CODE ELSEWHERE, so it is not
	// accepted on its word: every rule carrying it must name, in ProvedBy, a
	// test that drives the route against a live database on a pooled
	// connection left in the empty-string state a running server produces —
	// with a negative control that removes the binding and observes the
	// failure. TestM52EveryBindsItselfRuleNamesAnExistingTest checks the name
	// resolves; TestM52EveryBindsItselfRouteIsDriven (in the handler package)
	// checks the test set actually covers the table.
	TenantBindingBindsItself TenantBindingKind = "binds-itself"

	// TenantBindingTouchesNoRLSTable: the route's code path reads and writes
	// only tables that have Row-Level Security DISABLED, so no GUC is needed.
	//
	// RLSExemptTables must name them. Every named table is checked against
	// live `pg_class.relrowsecurity` by
	// TestM52TouchesNoRLSTableRulesNameOnlyRLSExemptTables, so a migration
	// that turns RLS on for one of them reddens this gate instead of turning
	// the route into the next /reanalyse. An empty list means the route
	// touches no table at all.
	TenantBindingTouchesNoRLSTable TenantBindingKind = "touches-no-rls-table"
)

// TenantBindingRule is one classification plus the evidence for it.
type TenantBindingRule struct {
	// Kind is the classification.
	Kind TenantBindingKind

	// Handler is the registration's handler argument as main.go writes it,
	// with runs of whitespace collapsed to single spaces.
	//
	// It is part of the key material, not decoration: without it, swapping
	// `GET /api/v1/health`'s inline "return 200 ok" closure for a handler
	// that pings the database would inherit a classification made about
	// different code. Comparing it costs one string per route and fails
	// loudly with the new text in the message, so the fix is to re-read the
	// new handler and update this field.
	Handler string

	// Why is the reason for the classification, in the table rather than in a
	// comment so a new route cannot be classified by copying its neighbour.
	Why string

	// BindsVia names the function(s) that issue the set_config. Required for
	// TenantBindingBindsItself; it is what a reviewer reads first and what
	// ProvedBy's test drives.
	BindsVia []string

	// ProvedBy is the name of the test that drives this route's binding
	// against a live database. Required for TenantBindingBindsItself.
	ProvedBy string

	// RLSExemptTables lists the tables the route's code path touches, for
	// TenantBindingTouchesNoRLSTable only. Each is asserted to have RLS
	// disabled in the live schema.
	RLSExemptTables []string
}

// noTenantTxRouteBinding classifies every route cmd/server/main.go registers
// whose EFFECTIVE middleware chain (global `e.Use` + inherited group
// middleware + per-route arguments) contains no appmw.TenantTx.
//
// The key is "<METHOD> <full registered path>" — the group prefix plus the
// route's own path, with `:param` placeholders intact.
//
// TestM52NoTenantTxRoutesAreAllClassified re-derives that set from main.go's
// AST and compares it against these keys in both directions, which is what
// makes this an ENUMERATION rather than a claim: a new unbound route, a
// removed one, and a route that gained or lost TenantTx all fail it.
var noTenantTxRouteBinding = map[string]TenantBindingRule{
	// -----------------------------------------------------------------
	// Provider callbacks. Both are unauthenticated and carry no tenant
	// context, so there is nothing for TenantTx to bind even in principle:
	// the tenant is discovered from the payload.
	// -----------------------------------------------------------------
	"POST /api/webhooks/clerk": {
		Kind:     TenantBindingBindsItself,
		Handler:  "clerkWebhookHandler.Handle",
		BindsVia: []string{"repository.TenantRepository.Create"},
		ProvedBy: "TestM52ClerkTenantCreateBindsOnAPoisonedConnection",
		Why: "The handler itself issues no set_config, and every table it names in a " +
			"statement of its own is RLS-exempt except one — `users`, `tenants` and " +
			"`tenant_users` never had RLS and migration 029 removed it from `audit_logs`. " +
			"The exception is why this is not TouchesNoRLSTable: TenantRepository.Create " +
			"writes a default `scan_settings` row for every new tenant, and migration 048 " +
			"gave that table the full ENABLE+FORCE+policy triple. Create opens its own tx " +
			"and binds the NEW tenant's id between the `tenants` INSERT and the " +
			"`scan_settings` INSERT (F187) — organization.created and the create branch of " +
			"organizationMembership.created both reach it. " +
			"The two DELETE branches (organization.deleted → `DELETE FROM tenants`, " +
			"user.deleted → `DELETE FROM users`) do reach RLS-protected tables, but only " +
			"through referential integrity: CASCADE into `projects` and the rest of the " +
			"tenant's tree, SET NULL into `llm_calls.user_id` and " +
			"`generated_reports.generated_by`. Those are RI-trigger actions, which bypass " +
			"row security — see TenantBindingBindsItself's doc comment for the " +
			"measurement — so they need no binding and none is named for them.",
	},
	"POST /api/webhooks/lemonsqueezy": {
		Kind:    TenantBindingTouchesNoRLSTable,
		Handler: "lsWebhookHandler.Handle",
		RLSExemptTables: []string{
			"audit_logs",
			"subscription_checkout_claims",
			"subscription_events",
			"subscriptions",
			"tenants",
		},
		Why: "Every table the delivery touches is RLS-exempt, and four of the five are " +
			"exempt BECAUSE of this route: migration 031 removed RLS from " +
			"`subscriptions` / `subscription_events`, 029 from `audit_logs`, and 060 " +
			"created `subscription_checkout_claims` without it, all so a callback that " +
			"runs outside TenantTx can find the tenant it belongs to at all. " +
			"applyDelivery nevertheless calls bindWebhookTenant once the owning tenant " +
			"is known — defence in depth against one of these tables regaining a policy, " +
			"not a load-bearing binding, and explicitly NOT covering the two discovery " +
			"lookups that necessarily precede it (see bindWebhookTenant's doc comment). " +
			"That is why this is classified by the table set rather than as BindsItself: " +
			"the table set is what the schema check can actually verify.",
	},

	// -----------------------------------------------------------------
	// No database access at all.
	// -----------------------------------------------------------------
	"GET /api/v1/health": {
		Kind: TenantBindingTouchesNoRLSTable,
		Handler: `func(c echo.Context) error { return c.JSON(200, map[string]string{ ` +
			`"status": "ok", "mode": string(cfg.Mode()), }) }`,
		RLSExemptTables: nil,
		Why: "An inline closure that serialises two in-memory values (a literal and " +
			"cfg.Mode()). It holds no repository and no *sql.DB, so it cannot reach a " +
			"table. Deliberately shallow: a health check that queried the database would " +
			"need a tenant binding like anything else, which is exactly what the Handler " +
			"pin above is here to notice.",
	},

	// -----------------------------------------------------------------
	// Anonymous share links. There is no authenticated tenant on these
	// routes at all — the tenant comes from the row the token resolves to,
	// so the binding cannot be middleware-level by construction.
	// -----------------------------------------------------------------
	"GET /api/v1/public/:token": {
		Kind:     TenantBindingBindsItself,
		Handler:  "publicLinkHandler.PublicGet",
		BindsVia: []string{"service.PublicLinkService.runWithTenantTx"},
		ProvedBy: "TestM52PublicGetBindsOnAPoisonedConnection",
		Why: "GetPublicView resolves the token against `public_links` (RLS removed in " +
			"030 precisely so an anonymous request can reach it), then opens its own tx " +
			"bound to link.TenantID for the reads that DO hit RLS-protected tables — " +
			"`projects`, `sboms`, `components`. The counter/log calls the handler makes " +
			"afterwards (TryRegisterView, LogAccess) run outside that tx but only touch " +
			"`public_links` / `public_link_access_logs`, both RLS-free since 030.",
	},
	"GET /api/v1/public/:token/download": {
		Kind:     TenantBindingBindsItself,
		Handler:  "publicLinkHandler.PublicDownload",
		BindsVia: []string{"service.PublicLinkService.runWithTenantTx"},
		ProvedBy: "TestM52PublicDownloadBindsOnAPoisonedConnection",
		Why: "GetPublicSbomRaw mirrors GetPublicView: token lookup outside the tx, the " +
			"`sboms` read (FORCE RLS) inside one bound to link.TenantID. This is the " +
			"path that hands over the raw SBOM bytes, so it is driven separately rather " +
			"than assumed to behave like its twin.",
	},

	// -----------------------------------------------------------------
	// The F19 routes: no ambient TenantTx BY DESIGN, because the runner
	// must not hold a Postgres connection across the LLM call. The runner
	// owns the transaction boundary instead.
	// -----------------------------------------------------------------
	"POST /api/v1/projects/:id/triage/run": {
		Kind:    TenantBindingBindsItself,
		Handler: "vexDraftsHandler.RunTriage",
		BindsVia: []string{
			"triage.DBTxManager.RunRead",
			"triage.DBTxManager.RunWrite",
			"repository.TenantRepository.Create (reached from the auth middleware on a first visit)",
		},
		ProvedBy: "TestM52TriageRunBindsOnAPoisonedConnection",
		Why: "triage.Runner.Run is a 3-stage cycle (short read tx → LLM call with no tx " +
			"→ short write tx) and every DB stage goes through the TxManager, which " +
			"issues the set_config and reuses an ambient tx when one exists. Stage 1's " +
			"first RLS-protected read is resolveProvider → tenant_llm_config (production " +
			"wires newTenantLLMProviderResolver, and migration 037 gave that table the " +
			"ENABLE+FORCE+policy triple); resolveComponentIDs over `components`/`sboms` " +
			"and the Stage 3 `vex_drafts` INSERT follow, all inside the same manager. " +
			"Production wires *triage.DBTxManager (main.go); the nil default is " +
			"PassthroughTxManager, which binds nothing — the negative control in the " +
			"ProvedBy test swaps it in and observes the 500. The third BindsVia entry is " +
			"route-wide rather than runner-level: see the file header's note on what runs " +
			"before every classified handler.",
	},
	"POST /api/v1/projects/:id/vex-drafts/:draft_id/reanalyse": {
		Kind:    TenantBindingBindsItself,
		Handler: "vexDraftsHandler.Reanalyse",
		BindsVia: []string{
			"triage.Runner.GetDraft",
			"triage.DBTxManager.RunRead",
			"triage.DBTxManager.RunWrite",
			"repository.TenantRepository.Create (reached from the auth middleware on a first visit)",
		},
		ProvedBy: "TestM52VexDraftReanalyseBindsOnAPoisonedConnection",
		Why: "Same 3-stage runner as /triage/run, plus a gatekeeper read that runs " +
			"BEFORE it: loadDraftScoped reads `vex_drafts` (FORCE RLS) through " +
			"triage.Runner.GetDraft, which wraps the read in TxManager.RunRead rather " +
			"than going to the repository directly. That indirection is the whole fix — " +
			"the CRA twin below did go to the repository directly and was 500 for every " +
			"input.",
	},
	"POST /api/v1/projects/:id/cra-reports/run": {
		Kind:    TenantBindingBindsItself,
		Handler: "craReportsHandler.RunReport",
		BindsVia: []string{
			"triage.DBTxManager.RunRead",
			"triage.DBTxManager.RunWrite",
			"repository.TenantRepository.Create (reached from the auth middleware on a first visit)",
		},
		ProvedBy: "TestM52CRAReportRunBindsOnAPoisonedConnection",
		Why: "cra.Runner.Run is the CRA counterpart of triage.Runner.Run and shares the " +
			"very same *triage.DBTxManager instance (main.go passes triageTxManager to " +
			"both). Stage 1 opens with resolveProvider → tenant_llm_config (FORCE RLS, " +
			"migration 037), then resolveAuthoritativeCVEID whose EXISTS subquery joins " +
			"`components` and `sboms`, then the source vex_draft lookup; Stage 3 writes " +
			"`cra_reports`. Same route-wide third entry as /triage/run.",
	},
	"POST /api/v1/projects/:id/cra-reports/:report_id/reanalyse": {
		Kind:    TenantBindingBindsItself,
		Handler: "craReportsHandler.Reanalyse",
		BindsVia: []string{
			"cra.Runner.GetReport",
			"triage.DBTxManager.RunRead",
			"triage.DBTxManager.RunWrite",
			"repository.TenantRepository.Create (reached from the auth middleware on a first visit)",
		},
		ProvedBy: "TestM52CRAReanalyseBindsOnAPoisonedConnection",
		Why: "The route this whole file exists because of. loadReportScoped read " +
			"`cra_reports` (FORCE RLS) straight from the repository on the request's " +
			"pooled connection, so the endpoint answered 500 for every input including " +
			"the caller's own report; commit 1cb5920 routed it through " +
			"cra.Runner.GetReport (TxManager.RunRead) and deleted Get from CRAReportStore " +
			"so the unbound read cannot be reintroduced through the handler's own " +
			"interface. The original reproduction lives in " +
			"handler/m51_cra_reanalyse_tenant_binding_integration_test.go; ProvedBy " +
			"points at the M52 drive instead because that one also carries the negative " +
			"control.",
	},
}

// NoTenantTxRouteBindings returns a copy of the classification table.
//
// It exists so other packages can check the table against something real:
// cmd/server has the AST (see tenant_binding_routes_test.go, which lives here
// and reads main.go by path), and internal/handler has the live database (see
// TestM52EveryBindsItselfRouteIsDriven, which fails when a BindsItself route
// has no drive). Nothing in the request path calls it.
//
// The returned map is a shallow copy: the slice fields are shared, so callers
// must not mutate them.
func NoTenantTxRouteBindings() map[string]TenantBindingRule {
	out := make(map[string]TenantBindingRule, len(noTenantTxRouteBinding))
	for k, v := range noTenantTxRouteBinding {
		out[k] = v
	}
	return out
}

// NoTenantTxRouteKeys returns the classified "<METHOD> <path>" keys, sorted.
func NoTenantTxRouteKeys() []string {
	out := make([]string, 0, len(noTenantTxRouteBinding))
	for k := range noTenantTxRouteBinding {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
