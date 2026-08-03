// The backend's own answer to "what may a project-scoped API key do with this
// route", read out of apps/api/internal/middleware/project_scope.go.
//
// WHY THIS FILE READS GO SOURCE
//
// bad1b8c fixed five tool descriptions that disagreed with the M50 W2/W3 scope
// rules. A test that pinned the corrected wording would only be a second copy
// of it. What makes a description TRUE or FALSE is:
//
//   (a) which route the tool actually calls  — observed in tool-contract.test.mjs
//       from the stub API's request log, and
//   (b) how the backend classifies that route — the table in project_scope.go,
//       which is itself pinned to cmd/server/main.go's registrations by
//       TestM50W2APIKeyReachableRoutesAreAllClassified.
//
// Reading (b) here joins the two, so a description can be checked against the
// authority instead of against itself. A hermetic test cannot run the Go
// server; this is the closest available ground truth, and it is the one that
// changes when the policy changes.
//
// If the table moves or is renamed, every load below throws with the path it
// looked for. That is deliberate: silently parsing zero entries would turn the
// strongest assertion in this suite green.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const SCOPE_SOURCE = fileURLToPath(
  new URL("../../../../apps/api/internal/middleware/project_scope.go", import.meta.url)
);

// `"GET /api/v1/mcp/projects": {scopeProjectListNarrowed,` — the key is always
// at the start of a line and the classification always follows the brace, both
// for one-line entries and for the ones whose `why` string wraps.
const ENTRY_RE =
  /^\s*"((?:GET|POST|PUT|PATCH|DELETE) \/api\/v1\/[^"]+)":\s*\{(scope[A-Za-z]+)/gm;

const STATUS_BY_GO_NAME = {
  BadRequest: 400,
  Unauthorized: 401,
  Forbidden: 403,
  NotFound: 404,
  InternalServerError: 500,
};

// The MCP server can only reach these eight. Asserting they are all present
// makes a regex that stopped matching fail loudly instead of vacuously.
export const MCP_ROUTES = [
  "GET /api/v1/mcp/projects",
  "GET /api/v1/mcp/dashboard/summary",
  "GET /api/v1/mcp/search/cve",
  "GET /api/v1/mcp/search/component",
  "POST /api/v1/mcp/sbom/diff",
  "GET /api/v1/mcp/projects/:id/vulnerabilities",
  "GET /api/v1/mcp/projects/:id/compliance",
  "GET /api/v1/mcp/projects/:id/sboms",
];

function load() {
  let src;
  try {
    src = readFileSync(SCOPE_SOURCE, "utf8");
  } catch (err) {
    throw new Error(
      `cannot read the API-key scope table at ${SCOPE_SOURCE} (${err.code}). ` +
        "The MCP tool descriptions make claims about what a project-scoped key " +
        "reaches; that file is where those claims are decided. If it moved, " +
        "point this helper at the new location — do not delete the check."
    );
  }

  const routeScope = new Map();
  for (const m of src.matchAll(ENTRY_RE)) {
    routeScope.set(m[1], m[2]);
  }

  if (routeScope.size < 20) {
    throw new Error(
      `parsed only ${routeScope.size} entries out of apiKeyRouteScope in ${SCOPE_SOURCE}; ` +
        "the table's shape changed and this parser needs updating (a partial parse " +
        "would silently weaken every scope assertion in this suite)"
    );
  }
  const missing = MCP_ROUTES.filter((r) => !routeScope.has(r));
  if (missing.length > 0) {
    throw new Error(
      `apiKeyRouteScope no longer classifies: ${missing.join(", ")}. ` +
        "Either the MCP routes moved, or the parse is broken."
    );
  }
  const kinds = new Set(routeScope.values());
  for (const required of [
    "scopeProjectPathParam",
    "scopeTenantWide",
    "scopeProjectListNarrowed",
  ]) {
    if (!kinds.has(required)) {
      throw new Error(
        `no route is classified ${required} — the classification names changed, ` +
          "so the description rules below are checking against nothing"
      );
    }
  }

  // The single status a project-scope violation produces. The descriptions
  // quote it ("403で拒否される"), so it is read rather than hardcoded: if the
  // backend ever changed it, the descriptions would become false and this
  // suite has to notice.
  const denial = /func RespondProjectScopeDenied[\s\S]{0,400}?c\.JSON\(http\.Status(\w+),/.exec(
    src
  );
  if (!denial || !STATUS_BY_GO_NAME[denial[1]]) {
    throw new Error(
      "could not read the status RespondProjectScopeDenied answers with from " +
        SCOPE_SOURCE
    );
  }

  return { routeScope, denialStatus: STATUS_BY_GO_NAME[denial[1]] };
}

const loaded = load();

export const ROUTE_SCOPE = loaded.routeScope;
export const DENIAL_STATUS = loaded.denialStatus;

/**
 * Classification for one "<METHOD> <registered path>" key.
 * Throws for an unclassified route: the backend default-denies those for a
 * project-scoped key, so a tool calling one is a defect, not a gap in the test.
 */
export function scopeKindOf(routeKey) {
  const kind = ROUTE_SCOPE.get(routeKey);
  if (!kind) {
    throw new Error(
      `the MCP server issued a request to ${routeKey}, which apiKeyRouteScope ` +
        `(${SCOPE_SOURCE}) does not classify. Unclassified API-key-reachable routes ` +
        "are DENIED for a project-scoped key, so this tool is either calling a " +
        "route that does not exist or one nobody has classified yet."
    );
  }
  return kind;
}

export function scopeKindsOf(routeKeys) {
  return new Set([...routeKeys].map(scopeKindOf));
}
