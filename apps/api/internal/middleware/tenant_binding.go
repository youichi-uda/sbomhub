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
//     and they answer "yes, TenantTx".
//     That remainder is NOT unexamined: preTenantTxMiddleware, further down
//     this file, classifies it per MIDDLEWARE instead of per route, over
//     every chain in main.go rather than only these nine.
//
// # What runs before four of the classified handlers
//
// Four of the nine routes — the F19 runner four — sit behind
// `triageMultiAuth`, and that middleware does two things worth knowing when
// reading their rules. (The other five carry no authentication at all: the two
// provider webhooks verify their own signature, /health is anonymous, and the
// two share-link routes are authorised by the token itself.)
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

	// TenantBindingTouchesNoRLSTable: the route's code path names only tables
	// that the runtime role can reach with no tenant bound, so no GUC is
	// needed. In practice today that means Row-Level Security is DISABLED on
	// all of them.
	//
	// RLSExemptTables must name them, and
	// TestM52TouchesNoRLSTableRulesNameOnlyRLSExemptTables checks each against
	// the live database:
	//
	//	relrowsecurity false  → accepted. PostgreSQL ignores every stored
	//	                        policy, so nothing about the tenant GUC can
	//	                        break the route.
	//	a materialised view   → accepted and LOGGED. Reads return stored rows
	//	                        and carry no row security.
	//	relrowsecurity true   → the runtime role is made to read the table on a
	//	                        connection in the poisoned state. If that
	//	                        statement RAISES, the rule fails. If it does
	//	                        not, the rule passes and the run logs what was
	//	                        and was not established.
	//
	// That last branch is why the wording above is "can reach" rather than
	// "has RLS disabled": a permissive policy can admit the unbound read, and
	// deciding otherwise from the policy TEXT produced a false failure on a
	// correct schema (see m52UnboundReadVerdict's doc comment for the exact
	// policy that broke the text model). An empty list means the route touches
	// no table at all.
	TenantBindingTouchesNoRLSTable TenantBindingKind = "touches-no-rls-table"
)

// TenantBindingRule is one classification plus the evidence for it.
type TenantBindingRule struct {
	// Kind is the classification.
	Kind TenantBindingKind

	// Handler identifies the code the classification is about, as
	// m52HandlerIdentity renders it from main.go's registration:
	//
	//	<constructor>#<method>   for the usual `xHandler.Method` shape, where
	//	                         the receiver is bound exactly once — so a
	//	                         RENAME of the variable does not trip this,
	//	                         but pointing the route at a different handler
	//	                         does;
	//	<expression>             for anything else, whitespace-normalised.
	//	                         /health's inline closure lands here, and that
	//	                         is right: for an inline handler the body IS
	//	                         the code being classified.
	//
	// It is key material, not decoration. Without it, swapping /health's
	// "return 200 ok" closure for a handler that pings the database would
	// inherit a classification written about different code, with the route
	// set and the middleware chain both unchanged.
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

	// RLSExemptTables lists every table the route's code path names in a
	// statement of its own, for TenantBindingTouchesNoRLSTable only. Each is
	// checked against the live schema — see the Kind's doc comment for the
	// outcomes, only one of which is "row security is disabled".
	//
	// "of its own" matches TenantBindingBindsItself's use of the word: tables
	// reached only by a CASCADE or SET NULL are not listed, because RI
	// triggers bypass row security and their RLS flag therefore says nothing
	// about whether the route is safe. No rule needs that carve-out today —
	// the Lemon Squeezy delivery issues no DELETE — but the field means the
	// same thing in both places.
	RLSExemptTables []string

	// RLSEnabledButReachable is the escape hatch for a relation in
	// RLSExemptTables that has GAINED row security and is nonetheless still
	// fine for this route, keyed by relation name and carrying the reason.
	//
	// It exists because row security is per-COMMAND and per-ROLE, and because
	// an ordinary view evaluates policies as its OWNER unless it is
	// security_invoker. The schema check reads with a plain SELECT as the
	// runtime role; three shapes make that SELECT fail while the route is
	// correct:
	//
	//	the route only INSERTs into the relation, and the new policy set pairs
	//	`FOR INSERT ... WITH CHECK (true)` with a tenant-gated FOR SELECT;
	//	the route reads through a view whose owner sees rows the runtime role
	//	cannot;
	//	the relation is a foreign table, which carries no local RLS at all.
	//
	// Rather than let any of those redden a required check, the check names
	// them in its failure message and passes when the relation is listed here
	// with a reason. Empty today — no rule names a relation with row security.
	RLSEnabledButReachable map[string]string
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
		Handler:  "handler.NewClerkWebhookHandler#Handle",
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
		Handler: "handler.NewLemonSqueezyWebhookHandler#Handle",
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
		Handler:  "handler.NewPublicLinkHandler#PublicGet",
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
		Handler:  "handler.NewPublicLinkHandler#PublicDownload",
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
		Handler: "handler.NewVexDraftsHandler#RunTriage",
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
			"before the four authenticated handlers.",
	},
	"POST /api/v1/projects/:id/vex-drafts/:draft_id/reanalyse": {
		Kind:    TenantBindingBindsItself,
		Handler: "handler.NewVexDraftsHandler#Reanalyse",
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
		Handler: "handler.NewCRAReportsHandler#RunReport",
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
		Handler: "handler.NewCRAReportsHandler#Reanalyse",
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

// ---------------------------------------------------------------------------
// M52P — the OTHER half of the same question: what runs while nothing has
// bound `app.current_tenant_id`, on EVERY route rather than only on the nine.
// ---------------------------------------------------------------------------

// PreTenantTxKind is how a middleware that runs with no tenant bound keeps its
// own database access safe.
//
// # The gap this closes
//
// The table above asks a question PER ROUTE — "does this route carry
// TenantTx?" — and its own header says what that leaves out:
//
//	Statements issued by middleware that runs BEFORE TenantTx on a route
//	that does have it.
//
// That is not a small remainder. Measured from cmd/server/main.go's AST
// (2026-08-05): 181 route registrations, 172 of them carrying TenantTx — and
// on all 181 there is a prefix of the chain that runs before anything has
// bound the GUC. Nine of the 181 have no TenantTx at all, so for them the
// prefix is the WHOLE chain. `authMiddleware` is in that prefix on 137 routes,
// and it names four tables: three it reads and one it writes.
//
// A statement issued there lands on exactly the connection state that made
// /reanalyse answer 500 for every input, for exactly the same reason. Whether
// that is a defect depends on which TABLES those middlewares name, and that is
// the question this table answers — once, per middleware, with a reason.
//
// # Scan unit
//
// Every middleware entry in every route's effective chain that is NOT preceded
// by appmw.TenantTx in that same chain. One sentence, and it covers both
// shapes: the prefix on a TenantTx route, and the entirety of a route without
// one. Derived from main.go's AST by tenant_binding_premw_test.go, reusing the
// same parser the route sweep uses; the key is the middleware's CONSTRUCTOR
// expression with its arguments dropped, so `appmw.RateLimitByAPIKey(rdb,
// appmw.BudgetPoll)` and `appmw.RateLimitByAPIKey(rdb, appmw.BudgetStandard)`
// are one entry — the question is about the function, not about a call site.
//
// # The measured answer, and why it is not "no problem, then"
//
// As of 2026-08-05 nothing here reads or writes an RLS-protected table
// unbound. Five tables are named in that region — `api_keys`, `tenant_users`,
// `tenants`, `users` and `scan_settings` — and the first four have
// relrowsecurity FALSE on the migrated schema, while the fifth is reached only
// through TenantRepository.Create, which opens its own transaction and binds
// between its two INSERTs (F187).
//
// That is a fact about today's code, and three of the four exemptions are
// deliberate but REVERSIBLE: migration 028 removed RLS from `api_keys`
// precisely so an API-key lookup could run before any tenant is known, and
// nothing stops a later migration putting it back. So the answer is written
// down as a table a change has to edit, rather than as a paragraph a change
// can leave standing.
//
// # What this does NOT cover, stated because each one is a real gap
//
//   - WHICH tenant. Same limit as the route table: this asks only whether a
//     tenant is bound, never whether it is the right one.
//   - The handler. That is the route table's job above.
//   - Statements a middleware issues through code it does not name — a
//     repository method that grows a new join is invisible here. The
//     classification is a human's reading of the middleware, kept honest by
//     the live-schema check on the tables it DOES name, not by call-graph
//     analysis. See the route table's "What it deliberately is NOT".
//   - Ordering WITHIN the pre-TenantTx prefix. Two middlewares there both run
//     unbound; which runs first changes nothing this table asks.
//   - Ordering among the GLOBAL middlewares. `e.Pre` runs before `e.Use` at
//     request time whatever order they are written in, and the parser this
//     derivation borrows collects both order-insensitively. That is harmless
//     while no global entry is TenantTx — everything global is then in the
//     unbound prefix regardless of order, which is the answer this table wants
//     — and it cannot silently become harmful, because a global TenantTx would
//     leave the route sweep above with an EMPTY set of unbound routes and
//     TestM52NoTenantTxRoutesAreAllClassified fails outright on that.
//
// # One thing that is emphatically not a binding
//
// Three of these middlewares call TenantRepository.SetCurrentTenant, and it
// does NOT bind anything for what follows. It issues
// `SELECT set_config('app.current_tenant_id', $1, true)` through the
// request-scoped query helper; with no ambient transaction the statement runs
// in its own implicit one and `is_local = true` discards the value the moment
// that commits. Measured on the migrated schema, 2026-08-05: the next
// statement on the same connection reads the placeholder as the EMPTY STRING.
// So those calls do not protect the middleware's own reads, and they are one
// of the things that leave a pooled connection in the state that turns an
// unbound read into a 500 rather than a false 404. No rule below may name
// SetCurrentTenant in BindsVia; TestM52PSetCurrentTenantIsNotAcceptedAsABinding
// refuses it.
type PreTenantTxKind string

const (
	// PreTenantTxNamesNoTable: the middleware issues no statement that names a
	// table. It may still issue a statement — SetCurrentTenant names none —
	// and it may hold a *sql.DB it does not use; Why must say which.
	//
	// Nothing about row security can reach a middleware in this class, so it
	// carries no table list and nothing about it is checked against the live
	// schema. That is why Why has to be specific: it is the whole of the
	// evidence.
	PreTenantTxNamesNoTable PreTenantTxKind = "names-no-table"

	// PreTenantTxRLSExemptTablesOnly: the middleware names tables, and the
	// runtime role can reach every one of them with no tenant bound.
	//
	// RLSExemptTables must name them, and they are checked against the live
	// database by TestM52PPreTenantTxRulesNameOnlyReachableTables with exactly
	// the outcomes TenantBindingTouchesNoRLSTable's doc comment describes —
	// relrowsecurity false is decisive, a foreign table is exempt by
	// construction, and anything else is settled by making the runtime role
	// perform the read on a poisoned connection.
	PreTenantTxRLSExemptTablesOnly PreTenantTxKind = "rls-exempt-tables-only"

	// PreTenantTxBindsWhatItReaches: the middleware names at least one
	// RLS-protected table, and every statement against one is preceded on its
	// branch by a transaction of its own carrying
	// `SELECT set_config('app.current_tenant_id', $1, true)`.
	//
	// BoundRLSTables names those tables; RLSExemptTables names the rest, and
	// is checked exactly as it is for the class above — a middleware does not
	// stop having to account for its other reads because one of them is bound.
	//
	// Like TenantBindingBindsItself this is a promise about code elsewhere, so
	// ProvedBy must name a test that drives the binding against a live
	// database on a poisoned pooled connection, with a negative control.
	PreTenantTxBindsWhatItReaches PreTenantTxKind = "binds-what-it-reaches"
)

// PreTenantTxRule is one middleware's classification plus the evidence.
type PreTenantTxRule struct {
	// Kind is the classification.
	Kind PreTenantTxKind

	// Why is the reason, in the table rather than in a comment so a new
	// middleware cannot be classified by copying its neighbour.
	Why string

	// RLSExemptTables lists every table the middleware names in a statement of
	// its own that is NOT covered by a binding. Each is checked against the
	// live schema. Required non-empty for PreTenantTxRLSExemptTablesOnly;
	// allowed, and still checked, for PreTenantTxBindsWhatItReaches.
	//
	// "of its own" means the same thing it does in the route table: a table
	// reached only by an ON DELETE CASCADE / SET NULL is not listed, because
	// RI triggers bypass row security.
	RLSExemptTables []string

	// BoundRLSTables lists the RLS-protected tables the middleware reaches
	// through a binding. For PreTenantTxBindsWhatItReaches only.
	//
	// Each name must RESOLVE against the live schema — a name that resolves to
	// nothing is a stale rule. Whether it still has row security is only
	// LOGGED, not asserted: if a migration removes RLS from one of these the
	// rule becomes over-cautious rather than wrong, and failing there would
	// redden correct code.
	BoundRLSTables []string

	// BindsVia names the function(s) that issue the set_config. Required for
	// PreTenantTxBindsWhatItReaches. SetCurrentTenant is refused here — see
	// the kind's doc comment.
	BindsVia []string

	// ProvedBy is the name of the test that drives the binding against a live
	// database. Required for PreTenantTxBindsWhatItReaches.
	ProvedBy string

	// RLSEnabledButReachable is the escape hatch for a relation in
	// RLSExemptTables that has gained row security and is nonetheless fine for
	// this middleware, keyed by relation name and carrying the reason. Same
	// three shapes as the route table's field of the same name. Empty today.
	RLSEnabledButReachable map[string]string
}

// preTenantTxMiddleware classifies every middleware that cmd/server/main.go
// puts in front of appmw.TenantTx on some route — or on a route that has no
// TenantTx at all.
//
// The key is the constructor expression with its arguments dropped, exactly as
// main.go spells it: `appmw.Auth`, `middleware.BodyLimit`,
// `appmw.NewTriageConcurrencyLimiterFromEnv().Middleware`. Renaming the
// package qualifier changes the key and demands a one-line edit here; that is
// the price of a key stable against everything else.
//
// TestM52PPreTenantTxMiddlewareIsClassified re-derives the set from main.go's
// AST and compares in both directions, which is what makes this an enumeration
// rather than a claim.
var preTenantTxMiddleware = map[string]PreTenantTxRule{
	// -----------------------------------------------------------------
	// Echo's own global middleware. `e.Use` applies these to every route
	// however it was registered, so they are the first four entries of all
	// 181 chains and are unbound on every one of them.
	// -----------------------------------------------------------------
	"middleware.Logger": {
		Kind: PreTenantTxNamesNoTable,
		Why: "echo's request logger (labstack/echo/v4/middleware). It writes a line to the " +
			"configured io.Writer after the handler returns and holds no database handle " +
			"of any kind — the whole of its state is a template and an output stream.",
	},
	"middleware.Recover": {
		Kind: PreTenantTxNamesNoTable,
		Why: "echo's panic recovery. It calls next(c) inside a defer/recover and, on a " +
			"panic, logs a stack trace and answers 500. No handle, no statement.",
	},
	"middleware.BodyLimit": {
		Kind: PreTenantTxNamesNoTable,
		Why: "echo's request-size cap. It compares Content-Length and wraps the body reader " +
			"with a counting limiter, answering 413 when the limit is passed. Entirely " +
			"in-process.",
	},
	"middleware.CORSWithConfig": {
		Kind: PreTenantTxNamesNoTable,
		Why: "echo's CORS. It matches the Origin header against a configured allowlist and " +
			"sets response headers; the preflight branch answers 204 without calling the " +
			"handler. The allowlist is a []string literal in main.go, not a lookup.",
	},

	// -----------------------------------------------------------------
	// This package's non-database middleware.
	// -----------------------------------------------------------------
	"appmw.RequireWrite": {
		Kind: PreTenantTxNamesNoTable,
		Why: "role_guard.go. It reads ContextKeyTenantID and ContextKeyRole through " +
			"NewTenantContext, which is a wrapper over echo.Context.Get and nothing else, " +
			"and answers 401 or 403 from those two values. It holds no repository. This is " +
			"why it can sit ahead of TenantTx at all: a denial never opens the request " +
			"transaction (TestM47RRoleGuardRefusesWithoutTheRequestTransaction).",
	},
	"appmw.RequireAdmin": {
		Kind: PreTenantTxNamesNoTable,
		Why: "role_guard.go, the CanAdmin twin of RequireWrite and the same shape: " +
			"TenantContext over echo.Context.Get, no repository, no statement. Reached " +
			"through main.go's `adminOnly` alias, which this gate expands.",
	},
	"appmw.RateLimitByAPIKey": {
		Kind: PreTenantTxNamesNoTable,
		Why: "ratelimit.go. Its only I/O is Redis — INCR on " +
			"`ratelimit:apikey:v2:<key id>:<budget>:<window>` and, on the first request of " +
			"a bucket, EXPIRE. The API key it counts against is read from the echo context " +
			"(ContextKeyAPI), already validated by the auth middleware ahead of it, so it " +
			"issues no lookup of its own. ratelimit.go does not import database/sql at all.",
	},
	"appmw.RateLimitPublicLink": {
		Kind: PreTenantTxNamesNoTable,
		Why: "ratelimit.go, the anonymous share-link limiter. Same file, same absence of a " +
			"database handle: a cumulative failure counter and a sorted-set lease, both in " +
			"Redis, keyed by the token from the URL and the caller's IP. It runs on the two " +
			"routes that have no TenantTx at all, so `unbound` there is the whole request, " +
			"not a prefix — and it still names no table.",
	},
	"appmw.NewTriageConcurrencyLimiterFromEnv().Middleware": {
		Kind: PreTenantTxNamesNoTable,
		Why: "triage_concurrency.go. Two buffered channels used as semaphores — one per " +
			"tenant, one global — sized from the environment at construction. The tenant id " +
			"comes from the echo context. No handle, no statement; the file imports neither " +
			"database/sql nor redis.",
	},
	"appmw.NewCRAConcurrencyLimiterFromEnv().Middleware": {
		Kind: PreTenantTxNamesNoTable,
		Why: "cra_concurrency.go, the CRA counterpart of the triage limiter and the same " +
			"in-process semaphore pair. Listed separately because it is a different type " +
			"with its own env vars, and because a shared classification would hide the day " +
			"one of them starts persisting its queue.",
	},
	"appmw.APIKeyTenant": {
		Kind: PreTenantTxNamesNoTable,
		Why: "apikey.go. It issues exactly ONE statement — TenantRepository.SetCurrentTenant's " +
			"`SELECT set_config('app.current_tenant_id', $1, true)` — which names no table, " +
			"and then sets two context values from the *model.APIKey that APIKeyAuth already " +
			"put on the context. It takes a *ProjectRepository it no longer uses (M50 W2 " +
			"moved the project-scope check into APIKeyAuth). So it TOUCHES the pool without " +
			"reading anything from it: it is on the harmless side of this table and on the " +
			"harmful side of the connection-state note above, because that set_config is " +
			"precisely what leaves the placeholder at the empty string for whatever borrows " +
			"the connection next.",
	},

	// -----------------------------------------------------------------
	// The authenticators. These are the middlewares that actually read.
	// -----------------------------------------------------------------
	"appmw.APIKeyAuth": {
		Kind:            PreTenantTxRLSExemptTablesOnly,
		RLSExemptTables: []string{"api_keys"},
		Why: "apikey.go, the legacy /api/v1/{cli,mcp}/* authenticator. It hashes the " +
			"presented credential and calls APIKeyService.ValidateKey, which is two " +
			"statements against ONE table: APIKeyRepository.GetByKeyHash (SELECT ... FROM " +
			"api_keys WHERE key_hash = $1) and the best-effort " +
			"UpdateLastUsed (UPDATE api_keys SET last_used_at ... WHERE id = $2 AND " +
			"tenant_id = $3). `api_keys` is RLS-free BECAUSE of this middleware: migration " +
			"028 removed it so a key lookup, which by definition happens before any tenant " +
			"is known, can reach the row that names the tenant. That is also why the " +
			"tenant_id predicate is written into UpdateLastUsed by hand — with RLS gone it " +
			"is the whole of the isolation. apiKeyProjectScopeAllowed, which runs " +
			"immediately after, reads only c.Path() and the key struct.",
	},
	"appmw.Auth": {
		Kind:            PreTenantTxBindsWhatItReaches,
		RLSExemptTables: []string{"tenant_users", "tenants", "users"},
		BoundRLSTables:  []string{"scan_settings"},
		BindsVia:        []string{"repository.TenantRepository.Create"},
		ProvedBy:        "TestM52ClerkTenantCreateBindsOnAPoisonedConnection",
		Why: "auth.go, and the widest surface in this table: main.go's `authMiddleware` is " +
			"the first thing on every route of the authBase group, which is where the " +
			"authAdmin / authWrite / auth TenantTx groups hang off, so it runs unbound on " +
			"most of the API. Both branches read. Self-hosted: TenantRepository." +
			"GetOrCreateDefault (SELECT ... FROM tenants WHERE slug = 'default') then " +
			"UserRepository.GetOrCreateDefault (SELECT ... FROM users WHERE email = $1, " +
			"then INSERT INTO users and INSERT INTO tenant_users on a first visit). Clerk: " +
			"GetOrCreateByClerkOrgID (tenants by clerk_org_id), GetByClerkUserID / Create " +
			"(users), GetUserRole / AddToTenant (tenant_users). All three tables have " +
			"relrowsecurity FALSE — `tenants` and `tenant_users` never had it (migration " +
			"007 protected the per-tenant RESOURCE tables only), and `users` is global by " +
			"design because one Clerk user can belong to several tenants. " +
			"The exception, and the reason this is not RLSExemptTablesOnly: on a first " +
			"visit both branches fall through to TenantRepository.Create, which writes a " +
			"default `scan_settings` row, and migration 048 gave that table the " +
			"ENABLE+FORCE+policy triple. Create opens its OWN transaction and issues the " +
			"set_config between the `tenants` INSERT and the `scan_settings` INSERT (F187), " +
			"so that write is bound even though everything around it is not. The named " +
			"drive is the one the Clerk-webhook rule above already uses: it replays those " +
			"two INSERTs on a poisoned connection and, as its negative control, replays " +
			"them without the set_config and observes the refusal. " +
			"Auth also calls SetCurrentTenant at the end of both branches. That is NOT what " +
			"makes any of the above safe — see the header note; it binds nothing for the " +
			"middleware's own reads, which have already happened, and nothing for the " +
			"handler either.",
	},
	"appmw.MultiAuth": {
		Kind:            PreTenantTxBindsWhatItReaches,
		RLSExemptTables: []string{"api_keys", "tenant_users", "tenants", "users"},
		BoundRLSTables:  []string{"scan_settings"},
		BindsVia:        []string{"repository.TenantRepository.Create"},
		ProvedBy:        "TestM52ClerkTenantCreateBindsOnAPoisonedConnection",
		Why: "multiauth.go, the canonical authenticator, and the union of the two above. " +
			"Its Clerk / self-hosted fall-through IS appmw.Auth — MultiAuth constructs one " +
			"and calls it — so everything in that rule applies here unchanged, including " +
			"the TenantRepository.Create binding. Its API-key branch adds `api_keys` " +
			"(APIKeyService.ValidateKey, the same two statements APIKeyAuth issues) and " +
			"reaches `users` + `tenant_users` a second way, through " +
			"UserRepository.GetOrCreateAPIKeyUser: GetByClerkUserID on " +
			"`api-key:<tenant uuid>`, then INSERT INTO users and INSERT INTO tenant_users " +
			"for the synthetic per-tenant user that audit_logs.user_id points at. " +
			"handleAPIKeyAuth's SetCurrentTenant is subject to the header note like the " +
			"rest. Reached under two names in main.go — the inline " +
			"`appmw.MultiAuth(...)` on the canonical routes and the `triageMultiAuth` alias " +
			"on the four F19 routes, which have no TenantTx at all — and this gate expands " +
			"the alias, so both spellings land on this one rule.",
	},
}

// PreTenantTxMiddlewareRules returns a copy of the pre-TenantTx table.
//
// It exists for the same reason NoTenantTxRouteBindings does: a package with a
// live database may need to check the table against what it can measure. The
// returned map is a shallow copy, so callers must not mutate the slice fields.
func PreTenantTxMiddlewareRules() map[string]PreTenantTxRule {
	out := make(map[string]PreTenantTxRule, len(preTenantTxMiddleware))
	for k, v := range preTenantTxMiddleware {
		out[k] = v
	}
	return out
}

// PreTenantTxMiddlewareKeys returns the classified middleware keys, sorted.
func PreTenantTxMiddlewareKeys() []string {
	out := make([]string, 0, len(preTenantTxMiddleware))
	for k := range preTenantTxMiddleware {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// NoTenantTxRouteBindings returns a copy of the classification table.
//
// It exists so internal/handler — the package with the live database — can
// check the table against the drives it actually runs (see
// TestM52EveryBindsItselfRouteIsDriven, which fails when a BindsItself route
// has none). The AST half needs no accessor: it lives in this package and
// reads main.go by path. Nothing in the request path calls either.
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
