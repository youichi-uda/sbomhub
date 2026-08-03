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

// Every route the MCP server can reach. Asserting they are all present makes a
// regex that stopped matching fail loudly instead of vacuously.
//
// The last two are NOT under /api/v1/mcp/. They sit on the canonical route
// group (MultiAuth), which the MCP client reaches with the same X-API-Key it
// uses everywhere else — that header only started authenticating there in
// e84142c. They are what makes the asynchronous scan state observable to this
// server; see SCAN_LIFECYCLE below.
export const MCP_ROUTES = [
  "GET /api/v1/mcp/projects",
  "GET /api/v1/mcp/dashboard/summary",
  "GET /api/v1/mcp/search/cve",
  "GET /api/v1/mcp/search/component",
  "POST /api/v1/mcp/sbom/diff",
  "GET /api/v1/mcp/projects/:id/vulnerabilities",
  "GET /api/v1/mcp/projects/:id/compliance",
  "GET /api/v1/mcp/projects/:id/sboms",
  "GET /api/v1/projects/:id/sbom",
  "GET /api/v1/projects/:id/sboms/:sbom_id/scan-status",
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
  //
  // Full-line comments are stripped first. A commented-out `c.JSON(
  // http.StatusForbidden, ...)` left above a changed return would otherwise
  // keep yielding the OLD status, and every assertion downstream would go on
  // agreeing with a value the server no longer answers (Codex R7).
  const executable = src
    .split("\n")
    .filter((line) => !/^\s*\/\//.test(line))
    .join("\n");
  const denial = /func RespondProjectScopeDenied[\s\S]{0,400}?c\.JSON\(http\.Status(\w+),/.exec(
    executable
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

// ---------------------------------------------------------------------------
// Folding a concrete request path back to the REGISTERED echo path.
//
// project_scope.go is keyed by the registered path, `:param` names and all, so
// an observed URL has to be folded before it can be looked up. Doing that by
// SHAPE alone — "a UUID segment is `:id`" — was enough while every route had
// exactly one parameter. It is not any more: the scan-status route registers
// `:id` AND `:sbom_id`, and a shape fold produces
// `/api/v1/projects/:id/sboms/:id/scan-status`, which matches no table entry
// and would make a classified route look unclassified.
//
// So the fold uses the table's own keys as its vocabulary. A concrete path
// matches a key when the segment counts agree, every literal segment is equal,
// and every `:param` position holds a UUID. The UUID requirement is what keeps
// the fold from inventing matches: `/api/v1/mcp/projects/not-a-uuid/sboms`
// stays unfolded rather than being reported as a route that was called.
// ---------------------------------------------------------------------------
const UUID_SEGMENT_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const REGISTERED_ROUTES = [...ROUTE_SCOPE.keys()].map((key) => {
  const sep = key.indexOf(" ");
  return {
    key,
    method: key.slice(0, sep),
    segments: key.slice(sep + 1).split("/"),
  };
});

/**
 * The registered path for a concrete request, or null when the table knows no
 * route of that shape.
 */
export function registeredPathFor(method, pathname) {
  const observed = pathname.split("/");
  for (const route of REGISTERED_ROUTES) {
    if (route.method !== method) continue;
    if (route.segments.length !== observed.length) continue;
    const matches = route.segments.every((seg, i) =>
      seg.startsWith(":") ? UUID_SEGMENT_RE.test(observed[i]) : seg === observed[i]
    );
    if (matches) return route.segments.join("/");
  }
  return null;
}

// ---------------------------------------------------------------------------
// The vulnerability scan is asynchronous.
//
// apps/api tracks a per-SBOM scan state (running / completed / failed /
// unknown) and says so explicitly: the counts behind
// GET /projects/:id/vulnerabilities reflect whatever the background scan has
// matched SO FAR, and are only authoritative once the scan reports completed.
//
// That state used to be UNREACHABLE from this server, so a project whose scan
// was still running answered "0 vulnerabilities" in exactly the shape a
// finished scan would, and the only honest place to put it was the tool
// description. It is reachable now:
// `GET /api/v1/projects/:id/sboms/:sbom_id/scan-status` sits on the canonical
// (MultiAuth) group, is classified scopeProjectPathParam, and — since e84142c —
// authenticates with the X-API-Key header this client sends. The tools that
// report scan counts therefore REPORT the state instead of merely warning about
// it, and the description explains what the reported states mean.
//
// Read from the Go source rather than assumed, so the day the lifecycle changes
// this check is revisited instead of pinning a vocabulary the server no longer
// speaks.
// ---------------------------------------------------------------------------
const SCAN_SOURCE = fileURLToPath(
  new URL("../../../../apps/api/internal/service/scan_tracker.go", import.meta.url)
);

export function loadScanLifecycle() {
  let src;
  try {
    src = readFileSync(SCAN_SOURCE, "utf8");
  } catch (err) {
    throw new Error(
      `cannot read the scan lifecycle at ${SCAN_SOURCE} (${err.code}); the MCP ` +
        "vulnerability tools' caveat about partial scans is derived from it"
    );
  }
  const states = [...src.matchAll(/ScanState\w+\s+ScanState = "(\w+)"/g)].map(
    (m) => m[1]
  );
  return {
    states,
    // True when a caller can be served counts from a scan that has not finished.
    canBePartial: states.includes("running"),
    // The ONE state under which the counts are final. The client maps exactly
    // this string to counts_final=true; every other state, known or not, is
    // reported as non-final. Pinned here so a rename in Go is caught as a
    // vocabulary change rather than silently turning counts_final into a
    // constant false.
    finalState: states.includes("completed") ? "completed" : null,
  };
}

export const SCAN_LIFECYCLE = loadScanLifecycle();
