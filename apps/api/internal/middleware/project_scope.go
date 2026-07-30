package middleware

import (
	"log/slog"
	"net/http"
	"sort"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
)

// M50 W2 — enforcement of api_keys.project_id.
//
// # The defect this closes
//
// `api_keys.project_id` was fully wired on the WRITE side (POST
// /api/v1/projects/:id/apikeys → APIKeyService.CreateProjectKey → an INSERT
// that fills the column, with M47 W1's ProjectInTenant check on top) and read
// by NOTHING. Every authentication path derived the request's authority from
// `key.TenantID` alone: APIKeyAuth/APIKeyTenant on the /api/v1/{mcp,cli}/*
// groups, and MultiAuth's handleAPIKeyAuth on the canonical routes. The web UI
// offers the key under a project's "API Keys" tab and the i18n string calls it
// "Project-scoped", so an administrator handing one to a contractor or a
// per-repository CI job was handing over the whole tenant.
//
// The risk is confused deputy, not privilege escalation by the issuer: the
// issuer is already an Admin (RequireAdmin gates the mint route), so nothing
// they could not already do becomes possible. What was false is the LABEL, and
// the label is what decides who the key gets given to.
//
// # The shape of the fix
//
// A project-scoped key must not reach a project other than its own. That is not
// the same as "must name its own project on every request": a route that touches
// no project-scoped resource at all (POST /api/v1/cli/check) is allowed through
// without naming anything. Rather than
// bolt a guard onto each of the 38 API-key-reachable route registrations — where
// the cost of forgetting one is a silently unscoped route, and the count alone
// says how easy that is — the check lives at the three places where a raw
// `sbh_...` string becomes an authenticated request context, i.e. every caller of
// APIKeyService.ValidateKey:
//
//	APIKeyAuth          (internal/middleware/apikey.go)   — /mcp/*, /cli/*
//	OptionalAPIKeyAuth  (internal/middleware/apikey.go)   — currently unwired
//	handleAPIKeyAuth    (internal/middleware/multiauth.go) — canonical routes
//
// TestM50W2ScopeCheckCoversEveryValidateKeyCallSite pins that this list is the
// complete set of ValidateKey call sites in the non-test source, so a fourth
// authentication path cannot be added without failing a test.
//
// # Default-deny
//
// apiKeyRouteScope classifies routes by their registered Echo path. A path with
// NO entry is DENIED for a project-scoped key. That is the property worth
// having: a route added to an API-key-fronted chain next month is refused until
// somebody classifies it, instead of silently inheriting tenant-wide authority.
// Tenant-level keys (`project_id IS NULL`) are unaffected by the table
// entirely — they never reach the switch.
//
// # What this file does NOT do
//
// It compares two UUIDs the request already carries. It performs no database
// access and therefore verifies nothing about the project's existence, its
// tenant, or the caller's rights over it. Tenant isolation remains the job of
// the tenant GUC + RLS, and resource ownership remains the job of the
// handler/service scope checks added in M47 W1. This is strictly a third,
// narrower filter placed in front of both.
//
// For the two routes marked scopeHandlerChecked the comparison is NOT performed
// here at all — see that constant's doc comment.

// projectScopeKind classifies how a route relates to a project, and therefore
// what a project-scoped API key may do with it.
type projectScopeKind int

const (
	// scopeProjectPathParam: the route's `:id` path parameter IS the project
	// UUID. The middleware compares it against the key's project_id and
	// refuses on mismatch. The comparison itself issues no SQL — but
	// ValidateKey has already read `api_keys` by the time it runs, so the
	// refusal is not "before any database access", only before any TENANT or
	// RESOURCE access (Codex R1 Low).
	scopeProjectPathParam projectScopeKind = iota

	// scopeTenantWide: the route does not name a project. Its answer spans
	// the tenant (a list, a cross-project search, an aggregate). A
	// project-scoped key is refused.
	//
	// Why refuse rather than silently narrow the result to the key's own
	// project: the narrowing would change what every field of the response
	// MEANS without the consumer being able to tell. `/mcp/dashboard/summary`
	// would report the tenant's posture while describing one project;
	// `/mcp/search/cve` would answer "this CVE is not present" when it is
	// present elsewhere in the tenant. Both are read by an LLM through the
	// MCP server, which will restate them as tenant-level facts. In a
	// compliance product a silently-narrowed answer is a worse failure than
	// a refusal, and it would recreate — in the response body — exactly the
	// confused deputy this wave is closing.
	//
	// M50 W3 carved out the one family of tenant-wide route where that
	// argument does not apply — see scopeProjectListNarrowed.
	scopeTenantWide

	// scopeProjectListNarrowed (M50 W3): the route's entire response is an
	// ENUMERATION OF PROJECTS. The middleware admits the request; the handler
	// then answers with the key's own project instead of the tenant's list —
	// one element, or zero when that project is not visible under the
	// request's tenant.
	//
	// # Why this is an exception to scopeTenantWide and not a hole in it
	//
	// scopeTenantWide refuses because narrowing changes what a field MEANS
	// without the consumer being able to tell. That is a property of DERIVED
	// answers: `/mcp/dashboard/summary`'s counters and `/mcp/search/cve`'s
	// "not present" are computed over a population, and the body does not
	// carry the population, so a narrowed answer is byte-shaped exactly like a
	// tenant-wide one and reads as a tenant-level fact.
	//
	// A project list has no such field. The population IS the body: the caller
	// receives the set element by element, every element is a project the
	// credential can in fact address, and nothing in the response is computed
	// over a wider set than the one shown. `total` on the CLI shape is the
	// length of the array beside it, not a tenant-wide count
	// (TestM50W3ScopedKeySeesOnlyItsOwnProject's decoder asserts that).
	//
	// The line is "the WHOLE body is the enumeration", not "the body mentions
	// projects". Three of the four routes still classified scopeTenantWide
	// below also enumerate projects — `/mcp/dashboard/summary` carries a
	// `project_scores` array, `/mcp/search/cve` carries `affected_projects`
	// AND `unaffected_projects` (which is every remaining project of the
	// tenant), `/mcp/search/component` carries a `matches` row per project —
	// and none of them qualifies, because in each case the enumeration is one
	// FIELD of an answer whose other fields are computed over the tenant.
	// Narrowing those would leave `total_vulnerabilities`, `risk_score` and
	// "this CVE is not present" saying something they no longer measure.
	// (Route-by-route sweep of all 181 registrations in cmd/server/main.go,
	// 2026-07-30: those three plus the two below are the only routes an API
	// key can reach whose body carries more than one project.)
	//
	// It also discloses nothing new. The same key may already read that
	// project through GET /api/v1/cli/projects/:id (scopeProjectPathParam),
	// so the narrowed list adds no field the credential could not fetch
	// already — and it is read with the same PROJECTION as the tenant-wide
	// list (a different statement, same five columns, neither selecting
	// tenant_id), so it cannot add one by accident
	// (TestM50W3NarrowedRowIsTheSameRowAsTheTenantWideOne compares the
	// serialised rows against a live database).
	//
	// What refusing cost, measured on a live server on 2026-07-30: `sbomhub
	// doctor` reported `[FAIL] 認証失敗 (403)` and exited 1, because
	// GET /api/v1/cli/projects is its auth probe; `sbomhub projects list`
	// exited 1. A project-scoped key also had no way to learn its own project
	// id, which every scopeProjectPathParam route requires it to supply.
	//
	// # What this classification does NOT do
	//
	// Like scopeHandlerChecked it is a promise about code elsewhere — here
	// handler.CLIHandler.ListProjects and handler.ProjectHandler.List, both of
	// which branch on APIKeyProjectID. The middleware performs no comparison
	// for these routes, so a handler that forgot to branch would serve the
	// whole tenant. That is why the set is pinned by name
	// (TestM50W3NarrowedListRoutesAreExactlyTheKnownTwo) and the handler
	// behaviour against a live database
	// (internal/handler/m50w3_project_list_scope_integration_test.go).
	scopeProjectListNarrowed

	// scopeHandlerChecked: the route resolves its project from the request
	// BODY, so `:id` does not exist and this middleware has nothing to
	// compare. The handler MUST resolve the project first and then call
	// RespondProjectScopeDenied when the resolved project is not the key's.
	//
	// Cost of deferring: the handler runs after TenantTx / RateLimitByAPIKey /
	// MCPAudit, so unlike a middleware-level refusal this one opens the request
	// transaction, spends a rate-limit token, and reaches handler-side project
	// resolution before refusing. See apiKeyProjectScopeAllowed's doc comment.
	//
	// This is one of the two classifications the middleware cannot enforce —
	// scopeProjectListNarrowed above is the other, and defers the NARROWING
	// rather than the refusal. It is
	// deliberately limited to the two routes listed in apiKeyRouteScope, and
	// their handler-side refusal is pinned by the integration tests in
	// internal/handler/m50w2_cli_project_scope_integration_test.go (which
	// assert against a live database that no project row and no sbom row is
	// created). TestM50W2HandlerCheckedRoutesAreExactlyTheKnownTwo fails if a
	// third route is given this classification.
	scopeHandlerChecked

	// scopeNoProjectResource: the route touches no project-scoped resource at
	// all, so a project-scoped key is allowed through unchanged.
	scopeNoProjectResource
)

// projectScopeRule is one classification plus the reason it was chosen. The
// reason is part of the table rather than a comment above it so that a route
// cannot be added by copying a neighbouring line without stating why.
type projectScopeRule struct {
	kind projectScopeKind
	why  string
}

// apiKeyRouteScope classifies every route an API key can reach, keyed by
// "<METHOD> <echo route path>" — c.Path() returns the REGISTERED path with
// `:param` placeholders intact (pinned by
// TestM50W2EchoPathIsTheRegisteredRouteInMiddleware), so the key is stable
// against the concrete request URL.
//
// The set of keys here is checked against cmd/server/main.go by
// TestM50W2APIKeyReachableRoutesAreAllClassified, which re-derives the
// API-key-reachable route set from main.go's AST. That test is what makes this
// table a complete enumeration rather than a claim: a missing entry, a stale
// entry, or a newly API-key-fronted route all fail it.
//
// A route absent from this map is DENIED (see apiKeyProjectScopeAllowed's
// default branch).
var apiKeyRouteScope = map[string]projectScopeRule{
	// -----------------------------------------------------------------
	// `:id` is the project UUID — the middleware compares it directly.
	// -----------------------------------------------------------------
	"GET /api/v1/cli/projects/:id":                                       {scopeProjectPathParam, ":id is the project"},
	"GET /api/v1/mcp/projects/:id/compliance":                            {scopeProjectPathParam, ":id is the project"},
	"GET /api/v1/mcp/projects/:id/sboms":                                 {scopeProjectPathParam, ":id is the project"},
	"GET /api/v1/mcp/projects/:id/vulnerabilities":                       {scopeProjectPathParam, ":id is the project"},
	"GET /api/v1/projects/:id/cra-reports":                               {scopeProjectPathParam, ":id is the project"},
	"GET /api/v1/projects/:id/cra-reports/:report_id":                    {scopeProjectPathParam, ":id is the project"},
	"PATCH /api/v1/projects/:id/cra-reports/:report_id/awareness":        {scopeProjectPathParam, ":id is the project"},
	"PUT /api/v1/projects/:id/cra-reports/:report_id/decision":           {scopeProjectPathParam, ":id is the project"},
	"POST /api/v1/projects/:id/cra-reports/:report_id/reanalyse":         {scopeProjectPathParam, ":id is the project"},
	"GET /api/v1/projects/:id/cra-reports/:report_id/submissions":        {scopeProjectPathParam, ":id is the project"},
	"POST /api/v1/projects/:id/cra-reports/:report_id/submissions":       {scopeProjectPathParam, ":id is the project"},
	"POST /api/v1/projects/:id/cra-reports/run":                          {scopeProjectPathParam, ":id is the project"},
	"POST /api/v1/projects/:id/evidence-pack/build":                      {scopeProjectPathParam, ":id is the project"},
	"GET /api/v1/projects/:id/meti/assessment":                           {scopeProjectPathParam, ":id is the project"},
	"DELETE /api/v1/projects/:id/meti/assessment/:criterion_id/override": {scopeProjectPathParam, ":id is the project"},
	"PUT /api/v1/projects/:id/meti/assessment/:criterion_id/override":    {scopeProjectPathParam, ":id is the project"},
	"POST /api/v1/projects/:id/meti/assessment/refresh":                  {scopeProjectPathParam, ":id is the project"},
	"GET /api/v1/projects/:id/meti/improvement-actions":                  {scopeProjectPathParam, ":id is the project"},
	"POST /api/v1/projects/:id/reachability":                             {scopeProjectPathParam, ":id is the project"},
	"GET /api/v1/projects/:id/reachability/targets":                      {scopeProjectPathParam, ":id is the project"},
	"GET /api/v1/projects/:id/sbom":                                      {scopeProjectPathParam, ":id is the project"},
	"POST /api/v1/projects/:id/sbom":                                     {scopeProjectPathParam, ":id is the project"},
	"GET /api/v1/projects/:id/sboms/:sbom_id/scan-status":                {scopeProjectPathParam, ":id is the project"},
	"POST /api/v1/projects/:id/triage/run":                               {scopeProjectPathParam, ":id is the project"},
	"GET /api/v1/projects/:id/vex-drafts":                                {scopeProjectPathParam, ":id is the project"},
	"GET /api/v1/projects/:id/vex-drafts/:draft_id":                      {scopeProjectPathParam, ":id is the project"},
	"PUT /api/v1/projects/:id/vex-drafts/:draft_id/decision":             {scopeProjectPathParam, ":id is the project"},
	"POST /api/v1/projects/:id/vex-drafts/:draft_id/reanalyse":           {scopeProjectPathParam, ":id is the project"},
	"GET /api/v1/projects/:id/vulnerabilities":                           {scopeProjectPathParam, ":id is the project"},

	// -----------------------------------------------------------------
	// The response IS the project enumeration — the HANDLER narrows it.
	// -----------------------------------------------------------------
	"GET /api/v1/cli/projects": {scopeProjectListNarrowed,
		"the body is the enumeration itself, so returning the key's own project " +
			"narrows the SET without redefining any field — unlike the aggregates " +
			"and searches below. Served by CLIHandler.ListProjects as " +
			"`{\"projects\":[<the key's project>],\"total\":1}`, or an empty array " +
			"when that project is not visible under the key's own tenant. M50 W2 " +
			"refused it, which made `sbomhub doctor` report FAIL (it probes this " +
			"route) and `sbomhub projects list` fail outright"},
	"GET /api/v1/mcp/projects": {scopeProjectListNarrowed,
		"the same enumeration mounted for the MCP server, served by " +
			"ProjectHandler.List as a bare array. Narrowed identically to the /cli " +
			"twin so the two cannot disagree about what a project-scoped key sees " +
			"(TestM50W3TheTwoProjectListRoutesAgree). ProjectHandler.List ALSO " +
			"serves the Clerk-fronted auth.GET(\"/api/v1/projects\"), which no API " +
			"key can reach and which must keep listing the whole tenant — hence the " +
			"narrowing keys off the credential, not the route"},

	// -----------------------------------------------------------------
	// Tenant-wide: no project in the request, so nothing to scope to.
	// -----------------------------------------------------------------
	"GET /api/v1/mcp/dashboard/summary": {scopeTenantWide,
		"tenant aggregate; narrowing it would silently redefine every counter"},
	"GET /api/v1/mcp/search/cve": {scopeTenantWide,
		"cross-project search; a narrowed miss reads as 'not present in the tenant'"},
	"GET /api/v1/mcp/search/component": {scopeTenantWide,
		"cross-project search; same misreading as /search/cve"},
	"POST /api/v1/mcp/sbom/diff": {scopeTenantWide,
		"selects two SBOMs by UUID in the body, so the project is only known " +
			"after both rows are loaded. SbomDiffService already refuses a " +
			"cross-project pair, but nothing compares the resulting project " +
			"against the key's. Refused rather than half-checked; a project-scoped " +
			"key cannot diff even its own SBOMs through this route (recorded as a " +
			"residual in docs/UPGRADE.md)"},

	// -----------------------------------------------------------------
	// Project resolved from the request body — the HANDLER must compare.
	// -----------------------------------------------------------------
	"POST /api/v1/cli/upload": {scopeHandlerChecked,
		"resolves the project from form field project_name; CLIHandler.Upload " +
			"compares the resolved project against the key's and never creates"},
	"POST /api/v1/cli/projects": {scopeHandlerChecked,
		"resolves the project from JSON field name; CLIHandler.CreateProject " +
			"compares the resolved project against the key's and never creates"},

	// -----------------------------------------------------------------
	// No project-scoped resource involved.
	// -----------------------------------------------------------------
	"POST /api/v1/cli/check": {scopeNoProjectResource,
		"stateless OSV lookup over components supplied in the request body. " +
			"CLIService.CheckVulnerabilities touches no repository — proved by " +
			"TestM50W2CheckVulnerabilitiesTouchesNoRepository, which drives it with " +
			"all three repositories nil so any access would panic"},
}

// APIKeyRouteScopeKeys returns the "<METHOD> <echo route path>" keys
// apiKeyRouteScope classifies, sorted.
//
// It exists so cmd/server can check the table against the routes main.go
// actually registers — see TestM50W2APIKeyReachableRoutesAreAllClassified, which
// is what turns this table from a claim into an enumeration. Nothing in the
// request path calls it.
func APIKeyRouteScopeKeys() []string {
	out := make([]string, 0, len(apiKeyRouteScope))
	for k := range apiKeyRouteScope {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// APIKeyProjectListNarrowedRoutes returns the "<METHOD> <echo route path>" keys
// classified scopeProjectListNarrowed, sorted.
//
// It exists so the handler package can check that it actually narrows every
// route this table promises will be narrowed — see
// TestM50W3EveryNarrowedRouteHasAHandlerUnderTest in
// internal/handler/m50w3_project_list_scope_integration_test.go. Without that
// cross-check the classification would be fail-open with only a procedural
// guard: adding a route here and adding the same string to the middleware test's
// expected set would satisfy every test in this package while the route's
// handler still served the whole tenant (Codex R2, Medium). With it, the new
// route has to be driven through a real handler against a live database before
// the suite is green. Nothing in the request path calls this.
func APIKeyProjectListNarrowedRoutes() []string {
	out := []string{}
	for k, rule := range apiKeyRouteScope {
		if rule.kind == scopeProjectListNarrowed {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// APIKeyProjectID returns the project a project-scoped API key is limited to.
//
// The second return value is false when the request is not authenticated by a
// project-scoped API key — i.e. for a Clerk session, a self-hosted default
// request, or a tenant-level API key (`project_id IS NULL`). Handlers must treat
// false as "no project restriction", which is the pre-M50 W2 behaviour for every
// key. docs/UPGRADE.md §2d has the dated measurement of how many keys that was
// in the development database; a count does not belong in a source comment,
// where it goes stale silently.
func APIKeyProjectID(c echo.Context) (uuid.UUID, bool) {
	key, ok := c.Get(ContextKeyAPI).(*model.APIKey)
	if !ok || key == nil || key.ProjectID == nil {
		return uuid.Nil, false
	}
	return *key.ProjectID, true
}

// RespondProjectScopeDenied writes the single refusal a project-scope violation
// produces, for handlers that have to perform the comparison themselves (the
// scopeHandlerChecked routes).
//
// `reason` goes to the log only; it is never part of the response, so the body is
// byte-identical for every rejected outcome no matter what the caller passes. The
// caller-facing indistinguishability the scopeHandlerChecked routes need is
// therefore a property of THIS function, not something a handler can get wrong by
// choosing a different reason string — what a handler CAN get wrong is returning
// a different status or body instead of calling this at all. That is what
// service.ErrCLIProjectOutOfScope being one sentinel for both "no such name" and
// "a different project" is for: it leaves the handler nothing to branch on.
//
// Vary `reason` freely to make the log useful.
func RespondProjectScopeDenied(c echo.Context, reason string) error {
	logProjectScopeDenial(c, reason)
	return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
}

func logProjectScopeDenial(c echo.Context, reason string) {
	key, _ := c.Get(ContextKeyAPI).(*model.APIKey)
	attrs := []any{
		"path", c.Path(),
		"method", c.Request().Method,
		"reason", reason,
		"ip", c.RealIP(),
	}
	if key != nil {
		attrs = append(attrs, "api_key_id", key.ID, "tenant_id", key.TenantID)
		if key.ProjectID != nil {
			attrs = append(attrs, "key_project_id", *key.ProjectID)
		}
	}
	slog.Warn("apikey: project scope violation", attrs...)
}

// apiKeyProjectScopeAllowed decides whether a validated API key may be used on
// the route the request has already been matched to.
//
// Returns (true, nil) to continue. Returns (false, err) with the 403 already
// written to the response, so callers must propagate err without touching the
// response themselves.
//
// Placement: every caller invokes this immediately after ValidateKey and BEFORE
// SetCurrentTenant / GetOrCreateAPIKeyUser. The four chains in
// cmd/server/main.go that reach an API key all put those callers first:
//
//	mcp group        APIKeyAuth -> APIKeyTenant -> TenantTx -> RateLimit -> MCPAudit
//	cliWrite group   APIKeyAuth -> APIKeyTenant -> RequireWrite -> TenantTx -> RateLimit -> MCPAudit
//	cli group        APIKeyAuth -> APIKeyTenant -> TenantTx -> RateLimit -> MCPAudit
//	canonical routes MultiAuth -> [RequireWrite] -> RateLimit -> TenantTx -> Audit
//
// The properties below hold for a MIDDLEWARE-LEVEL denial, i.e. one this
// function returns itself. They do NOT hold for the two scopeHandlerChecked
// routes, which this function ADMITS and whose handler refuses later — see
// below (Codex R1 Low, refined in R4).
//
// A middleware-level denial:
//   - issues no SQL of its own (the comparison is two in-memory UUIDs);
//   - never enters TenantTx, so no BEGIN and no tenant-GUC statement
//     (TenantRepository.SetCurrentTenant's
//     `SELECT set_config('app.current_tenant_id', $1, true)`) is issued for it;
//   - never pins a rate-limit token;
//   - produces no audit_logs row, because the audit middleware is never entered.
//     This function emits a slog.Warn (logProjectScopeDenial) carrying the path,
//     method, key id, tenant and the key's project. What else observes the
//     request — Echo's request logger, any reverse proxy, any metrics exporter —
//     is outside this file's knowledge; the claim here is only that no
//     audit_logs row is produced.
//
// It is NOT independent of the database: ValidateKey ahead of it already read
// api_keys, so an outage during authentication is answered 401 before this is
// reached.
//
// A HANDLER-LEVEL denial (POST /api/v1/cli/upload, POST /api/v1/cli/projects)
// is the opposite on the first three points. Both routes sit on the `cliWrite`
// group above, so by the time CLIHandler.resolveCLIProject refuses, the request
// has opened the transaction, consumed a rate-limit token, and performed the one
// `projects` lookup in CLIService.ResolveProjectForScopedKey. On the fourth point
// the OUTCOME is the same but the reason is not: MCPAudit runs after the handler
// and ATTEMPTS an `apikey.used` insert carrying `status: 403` (it swallows insert
// errors, so the row is attempted rather than guaranteed), and TenantTx then
// rolls back because the status is >= 400 (tx.go). Either way no audit row
// survives a scope denial — never attempted at the middleware level, rolled back
// at the handler level. What is OBSERVED, by
// TestM50W2CLIUpload_HandlerLevelDenialLeavesNoAuditRow against a live database,
// is the persisted outcome only: exactly one apikey.used row after a successful
// /cli/upload, and none after a scope-refused one. The attempt-then-rollback
// mechanism above is read off MCPAudit and TenantTx, not measured.
//
// This is the same shape, and the same residual, as RequireWrite/RequireAdmin
// in role_guard.go.
//
// # Response: 403, not the M47 W1 404 sentinel
//
// M47 W1 folded "unknown resource" and "resource you do not own" into one 404
// so that a caller could not use the status to probe for existence. This
// refusal deliberately answers 403 instead, and does not weaken that property:
//
//   - the comparison is credential-local. Both UUIDs are already in hand and no
//     row is read, so the answer for a sibling project that exists, a foreign
//     tenant's project, and a UUID that was never allocated is the SAME 403
//     with the SAME body. There is nothing to probe.
//     (TestM50W2PathParamDenialIsIndistinguishable asserts byte equality.)
//   - what a 404 WOULD add is a false claim: the key is valid, authenticated,
//     and the project may well exist. Reporting "not found" makes a mis-scoped
//     CI job indistinguishable from a deleted project, which in a compliance
//     product means silently missing evidence.
//
// The split it establishes: 403 = something about the CREDENTIAL is
// insufficient (role — RequireWrite/RequireAdmin — or scope, here); 404 =
// something about the RESOURCE is not addressable by this tenant. The body is
// the same generic `{"error":"forbidden"}` RequireWrite already returns.
func apiKeyProjectScopeAllowed(c echo.Context, key *model.APIKey) (bool, error) {
	// Tenant-level key: unchanged, tenant-wide authority. This is checked before
	// anything else so the route table cannot affect an existing tenant-level key
	// in any way — no lookup, no classification, no possibility of a new route
	// entry changing what such a key can do.
	if key == nil || key.ProjectID == nil {
		return true, nil
	}
	scoped := *key.ProjectID

	rule, classified := apiKeyRouteScope[routeScopeKey(c)]
	if !classified {
		// Default-deny. Reached by (a) a route newly mounted on an
		// API-key-fronted chain and not yet classified — the case this
		// branch exists for — and (b) Echo's per-prefix RouteNotFound
		// catch-all, which runs the group middleware for unmatched paths
		// under /api/v1/mcp and /api/v1/cli with c.Path() = ".../*". So a
		// project-scoped key sees 403 rather than 404 on a mistyped URL
		// under those two prefixes. That is deliberate: detecting the
		// catch-all in order to exempt it would also exempt any future
		// wildcard route, and no wildcard route exists today
		// (TestM50W2NoWildcardRouteIsAPIKeyReachable).
		return false, RespondProjectScopeDenied(c, "route is not classified for project-scoped keys")
	}

	switch rule.kind {
	case scopeProjectPathParam:
		requested, err := uuid.Parse(c.Param("id"))
		if err != nil {
			// A malformed :id cannot be shown to be the key's project, so
			// it is refused here rather than passed down to the handler's
			// own 400. Fail-closed on an unparseable identifier.
			return false, RespondProjectScopeDenied(c, "project id in path is not a uuid")
		}
		if requested != scoped {
			return false, RespondProjectScopeDenied(c, "path names a project outside the key's scope")
		}
		return true, nil

	case scopeTenantWide:
		return false, RespondProjectScopeDenied(c, "route is tenant-wide: "+rule.why)

	case scopeHandlerChecked, scopeProjectListNarrowed, scopeNoProjectResource:
		// Admitted here, and for three different reasons — see each
		// constant's doc comment. scopeHandlerChecked and
		// scopeProjectListNarrowed are promises about a handler (refuse the
		// request / narrow the answer, respectively); only
		// scopeNoProjectResource is a route where admitting is the whole
		// answer.
		return true, nil

	default:
		// Unreachable while projectScopeKind has exactly the five values
		// above; kept fail-closed so adding a sixth without a case here
		// denies rather than admits.
		return false, RespondProjectScopeDenied(c, "unhandled project scope classification")
	}
}

// routeScopeKey builds the apiKeyRouteScope lookup key for the current request.
// c.Path() is the REGISTERED route path (":id" not "abc-123"), which is what
// makes the table stable.
//
// The match is EXACT — no trailing-slash or case normalisation. Normalisation
// here would only ever turn a non-matching path into a matching one, i.e. turn
// a default-deny into an admit, which is the wrong direction for a fail-closed
// filter. Any path the table does not contain verbatim is denied.
func routeScopeKey(c echo.Context) string {
	return c.Request().Method + " " + c.Path()
}
