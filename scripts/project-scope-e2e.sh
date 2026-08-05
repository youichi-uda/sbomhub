#!/usr/bin/env bash
# SBOMHub — project-scoped API key enforcement E2E (M50 W2/W3)
#
# WHAT THIS IS FOR
#
# apps/api/internal/middleware/project_scope.go makes a set of very specific
# promises about what an `api_keys.project_id`-scoped `sbh_...` key can reach.
# Those promises were pinned by unit tests, by integration tests that build a
# *model.APIKey in memory (internal/handler/m50w2_*, m50w3_*), by one
# integration test that mounts a SINGLE middleware on a hand-registered echo
# route (internal/middleware/m50w3_apikey_auth_integration_test.go), and by an
# AST sweep of cmd/server/main.go. None of that observes the shipped product:
# a real `sbh_...` string, over HTTP, against the route table and middleware
# chains that cmd/server/main.go actually assembles.
#
# This script is that observation. Every assertion below is a status code or a
# response body read off the wire, or a row count read out of postgres.
#
# WHAT IT ADDS OVER THE GO TESTS (deliberately does not re-prove them)
#
#   - the full production chain and route registration from cmd/server/main.go
#     (groups, RequireWrite, RateLimitByAPIKey, TenantTx, MCPAudit, the global
#     HTTP error handler) rather than one middleware on a synthetic route;
#   - the on-wire 403 envelope, and its BYTE identity across every refusal —
#     sibling project, a REAL project in another tenant, unallocated UUID,
#     malformed :id, unclassified route, unknown project name — which is the
#     property that makes the refusal useless as an existence oracle. The Go
#     tests cover part of this: TestM50W2PathParamDenialIsIndistinguishable
#     compares status AND body across the four :id cases (M53 W1 added the
#     malformed one), and one handler-level test compares echo.HTTPError message
#     strings for POST /cli/projects. What is only observed here is the identity
#     ACROSS those families and over the real HTTP envelope — a path-param
#     refusal, an unclassified-route refusal and a name-resolved refusal all
#     being the same bytes, after the global error handler has run;
#   - Echo's real RouteNotFound catch-all under /api/v1/{mcp,cli}/* (the Go
#     test registers `/api/v1/mcp/not-a-real-route` as a concrete route, so it
#     never reaches the wildcard);
#   - a NEGATIVE CONTROL: the same matrix driven with a tenant-level key
#     (project_id IS NULL). Without it a wall of 403s cannot be told apart from
#     a broken stack;
#   - a staleness check: every route in the table must be REGISTERED. Echo's
#     router 404 is `{"message":"Not Found"}` while a handler 404 is
#     `{"error":"..."}`, so a table entry whose path drifted away from
#     main.go is caught over HTTP, not only by the AST test.
#
# THE ROUTE MATRIX IS DERIVED, NOT TRANSCRIBED
#
# The route list and each route's classification are parsed out of
# project_scope.go itself. Copying the table into this script would mean a route
# added there is silently untested here — exactly the failure mode the table's
# own doc comment says default-deny exists to prevent.
#
# Seven structural guards make that derivation trustworthy. Six are cheap source
# checks that fail with a precise message — the parse finding nothing (1), two
# independent occurrence counts disagreeing with it (2), an unknown class (3), a
# path parameter with no substitution (4), a route joining one of the three
# classes the middleware merely ADMITS without getting its own route-specific
# assertion (5), the map ceasing to be a closed literal of literal pairs (6).
#
# The seventh is the actual PROOF of completeness: the parsed route set is
# compared against the RUNTIME map, read out of the initialised
# apiKeyRouteScope through APIKeyRouteScopeKeys() /
# APIKeyProjectListNarrowedRoutes() by a throwaway program that `go run
# -overlay` mounts inside apps/api without writing a repo file. Source-shape
# inference alone is an arms race — an expression key, a mutation through an
# alias, a whole-map reassignment each hide a route from every regex while
# leaving the counts in agreement — so the run REQUIRES the Go toolchain rather
# than skipping the check when it is missing.
#
# ---------------------------------------------------------------------------
# CONTRACT
#
#   SBOMHUB_URL          api base URL                 (default http://localhost:8080)
#   SBOMHUB_REPO_ROOT    repo root                    (default: parent of this script)
#   SBOMHUB_SBOM_FIXTURE CycloneDX JSON to upload     (default test/fixtures/minimal-cyclonedx.json)
#   COMPOSE_PSQL_SVC     compose service name         (default postgres)
#   SBOMHUB_PSQL_CMD     full psql command reading SQL on stdin. Overrides
#                        COMPOSE_PSQL_SVC. Default:
#                          docker compose exec -T <svc> psql -v ON_ERROR_STOP=1 -U sbomhub -d sbomhub -X -q
#                        Local example (standalone container on port 15433):
#                          SBOMHUB_PSQL_CMD='docker exec -i my-pg psql -v ON_ERROR_STOP=1 -U sbomhub -d sbomhub -X -q'
#
# The fixtures are SEEDED BY THIS SCRIPT via psql, because the mandatory
# row-count assertions need psql anyway and seeding here keeps CI and local
# runs byte-identical. To drive a pre-seeded environment instead, set ALL of:
#
#   SBOMHUB_TENANT_ID          tenant UUID
#   SBOMHUB_SCOPED_KEY         raw sbh_... key with project_id = SBOMHUB_PROJECT_OWN
#   SBOMHUB_TENANT_KEY         raw sbh_... key with project_id IS NULL, same tenant
#   SBOMHUB_PROJECT_OWN        project UUID the scoped key is limited to
#   SBOMHUB_PROJECT_SIBLING    a DIFFERENT project UUID in the same tenant
#   SBOMHUB_PROJECT_OWN_NAME   name of SBOMHUB_PROJECT_OWN
#   SBOMHUB_PROJECT_SIBLING_NAME name of SBOMHUB_PROJECT_SIBLING
#
# The second tenant and its project (the foreign-tenant refusal column) are
# always seeded through psql, in both modes: nothing authenticates as that
# tenant, so only a real project id whose tenant is not the key's is needed.
#
# Exit codes: 0 — every cell matched. non-zero — first failed assertion.
# ---------------------------------------------------------------------------

set -euo pipefail

SBOMHUB_URL="${SBOMHUB_URL:-http://localhost:8080}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SBOMHUB_REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
SCOPE_TABLE_SRC="${REPO_ROOT}/apps/api/internal/middleware/project_scope.go"
SBOM_FIXTURE="${SBOMHUB_SBOM_FIXTURE:-${REPO_ROOT}/test/fixtures/minimal-cyclonedx.json}"
COMPOSE_PSQL_SVC="${COMPOSE_PSQL_SVC:-postgres}"
PSQL_CMD="${SBOMHUB_PSQL_CMD:-docker compose exec -T ${COMPOSE_PSQL_SVC} psql -v ON_ERROR_STOP=1 -U sbomhub -d sbomhub -X -q}"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

# An :id that parses as a UUID but was never allocated, and one that does not
# parse at all. The middleware must answer both exactly as it answers a real
# sibling project — that is the whole "nothing to probe" claim.
UNALLOCATED_PROJECT="9f8e7d6c-5b4a-4392-8180-7f6e5d4c3b2a"
MALFORMED_PROJECT="not-a-uuid"
# Sub-resource path params (:report_id, :draft_id, :sbom_id, :criterion_id) are
# never the project, so any well-formed UUID does. The request is expected to
# die in the handler with 404/400/500 — what matters is that it was ADMITTED.
DUMMY_SUBRESOURCE="00000000-0000-4000-8000-000000000000"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Both write to stderr: `die` can be reached from inside a command substitution
# (request()), where stdout is being captured as the status code and the message
# would be swallowed. `set -e` then propagates the subshell's exit 1 to the
# assignment that invoked it.
fail() { echo "::error::$*" >&2; FAILURES=$((FAILURES + 1)); }
die()  { echo "::error::$*" >&2; exit 1; }
note() { echo "  $*"; }

# RateLimitByAPIKey sits behind the scope check, so a healthy run never spends a
# token on a refused request and stays far under the per-minute caps. A 429
# means the matrix outran the limiter and the run cannot judge anything — say so
# rather than letting it surface as "want 200, got 429" three steps later.
assert_not_ratelimited() {
  [ "$1" != "429" ] || fail "RATE LIMITED (429) on $2 — RateLimitByAPIKey interfered, so this cell says nothing about project scope. Re-run against a fresh stack."
}

# Split the configured psql command into an argv ARRAY once, and always invoke
# it quoted. An unquoted `${PSQL_CMD}` would also glob-expand any `*`/`?` in the
# command (Codex R2 Low). Splitting is on whitespace only, which is the
# documented contract for SBOMHUB_PSQL_CMD — it takes a command line, not a
# shell expression.
IFS=' ' read -r -a PSQL_ARGV <<< "${PSQL_CMD}"
psql_exec()  { "${PSQL_ARGV[@]}"; }              # SQL on stdin
psql_query() { "${PSQL_ARGV[@]}" -At -c "$1"; }  # scalar out

# assert_uuid VALUE LABEL — every identifier that reaches SQL goes through here
# first. PROJECT_OWN / PROJECT_SIBLING come out of an HTTP response and
# UP_SBOM_ID out of another, i.e. from the very code under test, and they are
# then interpolated into statements run as the bootstrap superuser. A canonical
# UUID contains no quote, semicolon or backslash, so validating the shape closes
# that path (Codex R2 Medium). Pre-seeded values from the environment go through
# the same check.
assert_uuid() {
  case "$1" in
    [0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]-[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]-[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]-[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]-[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]) ;;
    *) die "$2 is not a canonical UUID: '$1' — refusing to interpolate it into SQL" ;;
  esac
}

# http METHOD URL BODYFILE [curl args...] -> prints status, writes body to BODYFILE
http() {
  local method="$1" url="$2" out="$3"; shift 3
  curl -sS --max-time 60 -o "${out}" -w '%{http_code}' -X "${method}" "$@" "${url}"
}

# request KEY "METHOD /route/with/:params" PROJECT_ID BODYFILE -> prints status
#
# Turns one apiKeyRouteScope key into a concrete request. Anything that needs a
# body or a query string beyond the generic `{}` is special-cased BY ROUTE, so
# a route added to the table without a recipe still gets driven (generic `{}`)
# and still has its scope decision observed — the scope decision happens in
# middleware, before the handler ever looks at the body.
request() {
  local key="$1" route="$2" project="$3" out="$4"
  local method="${route%% *}" path="${route#* }"
  path="${path//:id/${project}}"
  path="${path//:report_id/${DUMMY_SUBRESOURCE}}"
  path="${path//:draft_id/${DUMMY_SUBRESOURCE}}"
  path="${path//:sbom_id/${DUMMY_SUBRESOURCE}}"
  path="${path//:criterion_id/${DUMMY_SUBRESOURCE}}"

  # Structural guard: an unsubstituted :param means the table grew a parameter
  # this script does not know, so the recipe would be guessing. Fail loudly
  # rather than send a literal ":foo" and record a meaningless status.
  case "${path}" in
    */:*) die "route '${route}' has a path parameter this script has no substitution for (add it to request())" ;;
  esac

  local auth="Authorization: Bearer ${key}"
  local json="Content-Type: application/json"

  case "${route}" in
    "GET /api/v1/mcp/search/cve")       path="${path}?cve=CVE-2021-44228" ;;
    "GET /api/v1/mcp/search/component") path="${path}?name=log4j-core" ;;
  esac

  case "${route}" in
    "POST /api/v1/cli/upload")
      http POST "${SBOMHUB_URL}${path}" "${out}" -H "${auth}" \
        -F "project_name=${PROJECT_OWN_NAME}" -F "sbom=@${SBOM_FIXTURE}" ;;
    "POST /api/v1/cli/projects")
      http POST "${SBOMHUB_URL}${path}" "${out}" -H "${auth}" -H "${json}" \
        -d "{\"name\":\"${PROJECT_OWN_NAME}\"}" ;;
    "POST /api/v1/cli/check")
      http POST "${SBOMHUB_URL}${path}" "${out}" -H "${auth}" -H "${json}" \
        -d '{"components":[{"name":"log4j-core","version":"2.14.0","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"}]}' ;;
    "POST /api/v1/projects/:id/sbom")
      http POST "${SBOMHUB_URL}${path}" "${out}" -H "${auth}" -H "${json}" \
        --data-binary "@${SBOM_FIXTURE}" ;;
    # POST /api/v1/projects/:id/scan (M53 W1) deliberately has NO recipe and
    # falls through to the generic `{}` below, which omits the required
    # `sbom_id` query parameter and is therefore answered 400 by
    # VulnerabilityHandler.Scan. That is the intended cell: the scope decision
    # is made in middleware, before the handler reads anything, so 400-vs-400
    # between the two credentials is exactly as strong a "the key's own project
    # was ADMITTED" as 202-vs-202 would be — and supplying a real sbom_id would
    # start a real NVD/JVN sweep, i.e. outbound network traffic and writes to
    # the global vulnerability tables, on every CI run of this script. That the
    # route works end to end with an API key is observed elsewhere (the M53
    # negative-control run recorded in docs/UPGRADE.md §2d, and
    # cmd/server/m53_scan_route_apikey_test.go for the wiring).
    GET*)
      http GET "${SBOMHUB_URL}${path}" "${out}" -H "${auth}" ;;
    *)
      http "${method}" "${SBOMHUB_URL}${path}" "${out}" -H "${auth}" -H "${json}" -d '{}' ;;
  esac
}

# assert_refusal_body FILE LABEL
#
# Every project-scope refusal must be the SAME bytes. The first one observed
# becomes the reference; everything after is compared to it with cmp. The shape
# is checked once, on the reference, so a change in the envelope is reported as
# a shape failure rather than 40 identical diff failures.
REFUSAL_REF="${WORK}/refusal.reference"
REFUSAL_REF_TAKEN=0
assert_refusal_body() {
  local file="$1" label="$2"
  # A flag, not `[ -s "${REFUSAL_REF}" ]`: a 403 whose body happened to be EMPTY
  # would leave a zero-byte reference, and every later call would re-take it
  # instead of comparing — i.e. the byte-identity check would quietly stop
  # checking anything.
  if [ "${REFUSAL_REF_TAKEN}" -eq 0 ]; then
    REFUSAL_REF_TAKEN=1
    cp "${file}" "${REFUSAL_REF}"
    local keys err
    keys="$(jq -r 'keys | join(",")' <"${file}" 2>/dev/null || echo "<not json>")"
    err="$(jq -r '.error // "<missing>"' <"${file}" 2>/dev/null || echo "<not json>")"
    if [ "${keys}" != "error" ] || [ "${err}" != "forbidden" ]; then
      fail "refusal envelope changed: keys='${keys}' error='${err}' (want keys='error', error='forbidden'); reference taken from ${label}"
    else
      note "refusal reference (from ${label}): $(tr -d '\n' <"${file}") [$(wc -c <"${file}") bytes]"
    fi
    return
  fi
  if ! cmp -s "${REFUSAL_REF}" "${file}"; then
    fail "refusal body for ${label} is NOT byte-identical to the reference refusal — this is an existence oracle. got: $(tr -d '\n' <"${file}")"
  fi
}

# assert_registered FILE ROUTE — Echo's router 404 means the table names a path
# cmd/server/main.go does not register.
assert_registered() {
  local file="$1" route="$2"
  if [ "$(jq -r '.message // empty' <"${file}" 2>/dev/null)" = "Not Found" ]; then
    fail "route '${route}' is in apiKeyRouteScope but NOT REGISTERED by cmd/server/main.go (Echo router 404)"
  fi
}

# ---------------------------------------------------------------------------
# Step 0: derive the route table from project_scope.go
# ---------------------------------------------------------------------------
echo "=== Step 0: derive apiKeyRouteScope from ${SCOPE_TABLE_SRC#"${REPO_ROOT}"/} ==="

[ -f "${SCOPE_TABLE_SRC}" ] || die "scope table source not found: ${SCOPE_TABLE_SRC}"
[ -f "${SBOM_FIXTURE}" ]    || die "SBOM fixture not found: ${SBOM_FIXTURE}"

# Everything below works on the map BODY only (between the `var apiKeyRouteScope
# = ...{` line and its closing brace at column 0), so an unanchored regex cannot
# stray into a doc comment that happens to quote a route.
awk '
  /^var apiKeyRouteScope = map\[string\]projectScopeRule\{/ { inmap=1; next }
  inmap && /^\}/ { inmap=0 }
  inmap
' "${SCOPE_TABLE_SRC}" > "${WORK}/scope-map-body.go"

# `grep -o` prints one line per OCCURRENCE, and the patterns are unanchored, so
# two entries sharing a physical line are two matches rather than one. (Codex R2
# High: the earlier `^`-anchored extraction and its line-counting guards all
# agreed on 37 when two entries were coalesced onto one line, hiding a route.)
# `|| true` so a pattern that matches NOTHING reaches structural guard 1 with its
# explanation instead of aborting the pipeline under `set -o pipefail`.
match_in_map() { { grep -oE "$1" "${WORK}/scope-map-body.go" || true; }; }

match_in_map '"[A-Z]+ /api/v1/[^"]*":[[:space:]]*\{scope[A-Za-z]+' \
  | sed -E 's/"([^"]*)":[[:space:]]*\{(scope[A-Za-z]+)/\2|\1/' \
  | sort > "${WORK}/routes.txt"
ROUTE_COUNT=$(wc -l < "${WORK}/routes.txt")

# Structural guard 1: the parse must find something.
[ "${ROUTE_COUNT}" -ge 1 ] || die "derived 0 routes from ${SCOPE_TABLE_SRC} — the map literal format changed and this script's regex is stale"

# Structural guard 2: the parse must find EVERY entry. The extraction requires
# the key and the `{scope...` to be adjacent; two INDEPENDENT occurrence counts
# over the same body catch an entry written any other way:
#
#   MAP_KEY_COUNT   counts KEY literals   — independent of how the VALUE is laid
#                                           out, so it still sees
#                                             "GET /x": {
#                                                 scopeTenantWide, "why",
#                                             },
#   MAP_RULE_COUNT  counts `{scope` opens — independent of how the KEY is laid
#                                           out, so it still sees a key split
#                                           across lines.
#
# A route that either count sees and the extraction does not is an UNTESTED
# route, which is the whole failure mode this guard exists for.
MAP_KEY_COUNT=$(match_in_map '"[A-Z]+ /api/v1/[^"]*":' | wc -l)
MAP_RULE_COUNT=$(match_in_map '\{scope[A-Za-z]+' | wc -l)
if [ "${ROUTE_COUNT}" -ne "${MAP_KEY_COUNT}" ] || [ "${ROUTE_COUNT}" -ne "${MAP_RULE_COUNT}" ]; then
  die "derived ${ROUTE_COUNT} routes, but the apiKeyRouteScope literal has ${MAP_KEY_COUNT} key literal(s) and ${MAP_RULE_COUNT} rule literal(s) — an entry is written in a shape this script does not parse and would go UNTESTED"
fi

# Structural guard 6: the map must be a CLOSED LITERAL of literal key/value
# pairs, so that "what the source text says" and "what the runtime map holds"
# cannot diverge (Codex R3 High). Guard 2 already catches a non-literal on one
# side of a pair — `"GET /x": ruleVar` makes keys > rules, `routeConst: {scope…}`
# makes rules > keys. The two cases left are:
#
#   (a) BOTH sides non-literal (`routeConst: ruleVar`) — invisible to every
#       count, so all three still agree. Caught by 6a: inside the map body a key
#       must be a string literal, never a bare identifier followed by `:`.
#   (b) entries added after the literal (init(), an index assignment, a copy
#       from another map). Caught by 6b.
#
# Without these two, a route could exist at runtime, never be driven here, and
# the run would still report full coverage.
#
# 6a — no identifier-shaped key inside the map body. Continuation lines of a
# `why` string start with `"`, and a kind on its own line (`scopeTenantWide,`)
# is followed by a comma, not a colon, so neither matches.
BAD_KEY=$( { grep -nE '^[[:space:]]*[A-Za-z_][A-Za-z0-9_.]*[[:space:]]*:' "${WORK}/scope-map-body.go" || true; } | head -3)
[ -z "${BAD_KEY}" ] || die "apiKeyRouteScope contains a non-literal (identifier) key, which this script cannot see and would therefore leave UNTESTED: ${BAD_KEY}"

# 6b — the map is declared exactly once and never mutated afterwards. Anything
# that adds entries at run time puts routes in the table that no amount of
# source parsing can find.
SCOPE_PKG_DIR="$(dirname "${SCOPE_TABLE_SRC}")"
DECL_COUNT=$( { grep -rhcE '^var apiKeyRouteScope = map\[string\]projectScopeRule\{' "${SCOPE_TABLE_SRC}" || true; } )
[ "${DECL_COUNT}" = "1" ] || die "expected exactly one 'var apiKeyRouteScope = map[string]projectScopeRule{' declaration, found ${DECL_COUNT}"
MUTATIONS=$( { grep -rnE 'apiKeyRouteScope[[:space:]]*\[[^]]*\][[:space:]]*=|maps\.Copy\([[:space:]]*apiKeyRouteScope|delete\([[:space:]]*apiKeyRouteScope' "${SCOPE_PKG_DIR}" --include='*.go' 2>/dev/null || true; } | grep -v '_test\.go:' || true)
[ -z "${MUTATIONS}" ] || die "apiKeyRouteScope is mutated outside its literal, so the runtime table cannot be derived from the source text: ${MUTATIONS}"

# Structural guard 3: every class must be one this script knows how to judge.
# Structural guard 4: every path parameter must be one request() substitutes.
# An unknown `:param` would be sent literally and the recorded status would be
# about a garbage URL, not about project scope. Checked here, at top level, so
# the failure is not swallowed by the command substitution around request().
while IFS='|' read -r kind route; do
  case "${kind}" in
    scopeProjectPathParam|scopeTenantWide|scopeProjectListNarrowed|scopeHandlerChecked|scopeNoProjectResource) ;;
    *) die "route '${route}' has classification '${kind}', which this script has no expected outcome for (projectScopeKind gained a value — add a case)" ;;
  esac
  for param in $(printf '%s\n' "${route#* }" | tr '/' '\n' | grep '^:' || true); do
    case "${param}" in
      :id|:report_id|:draft_id|:sbom_id|:criterion_id) ;;
      *) die "route '${route}' uses path parameter '${param}', which request() has no substitution for — the request recipe would be guessing. Add it to request() and to this list." ;;
    esac
  done
done < "${WORK}/routes.txt"

# Structural guard 5: the three classes the MIDDLEWARE ADMITS are promises about
# code somewhere else — a handler that narrows (scopeProjectListNarrowed), a
# handler that refuses (scopeHandlerChecked), or a route that genuinely touches
# no project (scopeNoProjectResource). The matrix can only check "was admitted";
# what the promise is actually worth is checked route by route in Steps 3-4,
# against the CONCRETE response shapes of the routes below.
#
# So a route joining one of these classes must not be able to inherit that
# vacuous "was admitted" pass (Codex R2 High). Pin the sets: adding a route here
# fails the run until somebody writes its route-specific assertion. This is the
# HTTP-level twin of TestM50W3NarrowedListRoutesAreExactlyTheKnownTwo and
# TestM50W2HandlerCheckedRoutesAreExactlyTheKnownTwo.
assert_deferred_class_set() {
  local kind="$1" want="$2" got
  got=$(awk -v k="${kind}" 'index($0, k "|") == 1 { sub(/^[^|]*\|/, ""); print }' "${WORK}/routes.txt" | sort | paste -sd';' -)
  [ "${got}" = "${want}" ] || die "${kind} is now {${got}}, expected {${want}}. This class is ADMITTED by the middleware, so the matrix alone proves nothing about it — its enforcement is asserted route-by-route in Steps 3-4. Add the new route's own deterministic assertion there, then update this expected set."
}
assert_deferred_class_set scopeProjectListNarrowed "GET /api/v1/cli/projects;GET /api/v1/mcp/projects"
assert_deferred_class_set scopeHandlerChecked      "POST /api/v1/cli/projects;POST /api/v1/cli/upload"
assert_deferred_class_set scopeNoProjectResource   "POST /api/v1/cli/check"

# ---------------------------------------------------------------------------
# Structural guard 7: the RUNTIME map must contain exactly the routes parsed out
# of the source text.
#
# Guards 1-6 are all inferences about source SHAPE, and Codex R4 was right that
# shape inference is an arms race it eventually loses: an expression key
# (`prefix + "/x": rule`), a mutation through an alias (`m := apiKeyRouteScope;
# m[k] = r`), `clear()`, a whole-map reassignment — each one hides a route from
# every regex while leaving all the counts in agreement, and the gate would then
# report full coverage over an incomplete set.
#
# So ask the initialised map itself. middleware exports APIKeyRouteScopeKeys()
# and APIKeyProjectListNarrowedRoutes() for exactly this kind of cross-check;
# this runs a throwaway `package main` that prints both.
#
# `go run -overlay` mounts that program at a path INSIDE apps/api that does not
# exist on disk, so:
#   - the import of the module's own internal/ package is legal (the overlaid
#     path is under github.com/sbomhub/sbomhub/, which is what Go's internal
#     rule keys off);
#   - it resolves through apps/api's real go.mod / go.sum — no second module, no
#     go.sum juggling;
#   - NOTHING is written into the repository, so this is safe to run against a
#     working tree somebody else is editing.
#
# Go is a HARD requirement, not a skip: a silently skipped completeness proof is
# the same as not having one.
#
# What this does NOT settle: the dump is a HOST process. It is built with the
# image's flags (CGO_ENABLED=0 GOOS=linux, see below) so build-constraint file
# selection matches, but a map mutation conditioned on the container's runtime
# ENVIRONMENT would still be invisible here. That case is covered by
# TestM50W2APIKeyReachableRoutesAreAllClassified, which compares the runtime map
# against cmd/server/main.go's registrations; the workflow runs it in the same
# job, before this script, so the gate does not depend on go-test.yml having run.
#
# Nor does it settle: the per-route KIND still comes from the text for
# the four classes with no runtime accessor. A text/runtime disagreement there
# is caught behaviourally instead — swap scopeTenantWide and
# scopeProjectPathParam either way and the matrix's own-project or refusal
# assertion fails — and the narrowed set, the one deferred promise that would be
# silent, is compared against the runtime accessor below.
# ---------------------------------------------------------------------------
GO_BIN="${SBOMHUB_GO:-go}"
command -v "${GO_BIN}" >/dev/null 2>&1 || die "the route-table completeness proof needs the Go toolchain (set SBOMHUB_GO if it is not on PATH). It reads the RUNTIME apiKeyRouteScope; skipping it would leave route coverage resting on source-text regexes alone."

API_MODULE_DIR="${REPO_ROOT}/apps/api"
cat > "${WORK}/scopedump.go" <<'GOPROG'
// Throwaway: prints the runtime apiKeyRouteScope as "<narrowed>|<route>".
// Mounted into the module by `go run -overlay`; never written to disk in-repo.
package main

import (
	"fmt"

	mw "github.com/sbomhub/sbomhub/internal/middleware"
)

func main() {
	narrowed := map[string]bool{}
	for _, r := range mw.APIKeyProjectListNarrowedRoutes() {
		narrowed[r] = true
	}
	for _, k := range mw.APIKeyRouteScopeKeys() {
		fmt.Printf("%v|%s\n", narrowed[k], k)
	}
}
GOPROG
VIRTUAL_PKG="zz_project_scope_e2e_scopedump"
printf '{"Replace":{"%s/%s/main.go":"%s"}}\n' "${API_MODULE_DIR}" "${VIRTUAL_PKG}" "${WORK}/scopedump.go" > "${WORK}/overlay.json"
# CGO_ENABLED=0 GOOS=linux matches apps/api/Dockerfile's build of ./cmd/server
# exactly (Codex R6 Medium). Without it the dump is compiled under the host's
# defaults, so a file selected by a different build constraint — `//go:build
# !cgo`, `//go:build linux` — could contribute routes to the SERVER's map that
# the dump never sees. Built then executed rather than `go run`, because `go
# run` refuses to execute a binary whose GOOS is not the host's; the runner is
# linux, same as the image.
( cd "${API_MODULE_DIR}" && GOWORK=off CGO_ENABLED=0 GOOS=linux \
    "${GO_BIN}" build -overlay "${WORK}/overlay.json" -o "${WORK}/scopedump" "./${VIRTUAL_PKG}" ) \
  || die "could not build the runtime apiKeyRouteScope dump (go build -overlay failed in ${API_MODULE_DIR})"
"${WORK}/scopedump" > "${WORK}/runtime.txt" \
  || die "could not read the runtime apiKeyRouteScope (the dump binary failed to run)"

# `-f2-` / a single leading-field strip, not `-f2`: a route key containing `|`
# would otherwise be truncated on both sides and two different keys could
# compare equal (Codex R6 Low).
cut -d'|' -f2- "${WORK}/runtime.txt" | sort > "${WORK}/runtime-keys.txt"
cut -d'|' -f2- "${WORK}/routes.txt"  | sort > "${WORK}/derived-keys.txt"
if ! diff -u "${WORK}/derived-keys.txt" "${WORK}/runtime-keys.txt" > "${WORK}/keys.diff"; then
  die "the routes parsed from project_scope.go do NOT match the runtime apiKeyRouteScope — routes marked '+' exist at run time and would go UNTESTED, routes marked '-' are parsed but not in the map:
$(cat "${WORK}/keys.diff")"
fi

awk '/^true\|/  { sub(/^[^|]*\|/, ""); print }' "${WORK}/runtime.txt" | sort > "${WORK}/runtime-narrowed.txt"
awk '/^scopeProjectListNarrowed\|/ { sub(/^[^|]*\|/, ""); print }' "${WORK}/routes.txt" | sort > "${WORK}/derived-narrowed.txt"
if ! diff -u "${WORK}/derived-narrowed.txt" "${WORK}/runtime-narrowed.txt" > "${WORK}/narrowed.diff"; then
  die "scopeProjectListNarrowed disagrees between the source text and APIKeyProjectListNarrowedRoutes() at run time:
$(cat "${WORK}/narrowed.diff")"
fi
note "runtime apiKeyRouteScope agrees with the parsed table ($(wc -l < "${WORK}/runtime-keys.txt") routes, $(wc -l < "${WORK}/runtime-narrowed.txt") narrowed) — CGO_ENABLED=0 GOOS=linux via -overlay, no repo file created"

note "derived ${ROUTE_COUNT} routes:"
cut -d'|' -f1 "${WORK}/routes.txt" | sort | uniq -c | sed 's/^/    /'

# ---------------------------------------------------------------------------
# Step 1: seed (tenant T1, projects P_own + P_sibling, K_scoped, K_tenant, SBOM)
# ---------------------------------------------------------------------------
echo "=== Step 1: seed ==="

if [ -n "${SBOMHUB_SCOPED_KEY:-}" ] && [ -n "${SBOMHUB_TENANT_KEY:-}" ] \
   && [ -n "${SBOMHUB_PROJECT_OWN:-}" ] && [ -n "${SBOMHUB_PROJECT_SIBLING:-}" ] \
   && [ -n "${SBOMHUB_TENANT_ID:-}" ]; then
  TENANT_ID="${SBOMHUB_TENANT_ID}"
  K_SCOPED="${SBOMHUB_SCOPED_KEY}"
  K_TENANT="${SBOMHUB_TENANT_KEY}"
  PROJECT_OWN="${SBOMHUB_PROJECT_OWN}"
  PROJECT_SIBLING="${SBOMHUB_PROJECT_SIBLING}"
  PROJECT_OWN_NAME="${SBOMHUB_PROJECT_OWN_NAME:?SBOMHUB_PROJECT_OWN_NAME is required when pre-seeding}"
  PROJECT_SIBLING_NAME="${SBOMHUB_PROJECT_SIBLING_NAME:?SBOMHUB_PROJECT_SIBLING_NAME is required when pre-seeding}"
  assert_uuid "${TENANT_ID}"      "SBOMHUB_TENANT_ID"
  assert_uuid "${PROJECT_OWN}"    "SBOMHUB_PROJECT_OWN"
  assert_uuid "${PROJECT_SIBLING}" "SBOMHUB_PROJECT_SIBLING"
  note "using pre-seeded fixtures (SBOMHUB_SCOPED_KEY et al. supplied)"
else
  RUN_TAG="$(openssl rand -hex 4)"
  TENANT_ID="$(uuidgen)"
  assert_uuid "${TENANT_ID}" "seeded tenant id"
  PROJECT_OWN_NAME="a3-scope-own-${RUN_TAG}"
  PROJECT_SIBLING_NAME="a3-scope-sibling-${RUN_TAG}"
  K_TENANT="sbh_$(openssl rand -hex 16)"
  K_SCOPED="sbh_$(openssl rand -hex 16)"
  echo "::add-mask::${K_TENANT}"
  echo "::add-mask::${K_SCOPED}"

  # api_keys stores sha256(raw) hex and the first 12 chars as key_prefix — same
  # shape POST /apikeys persists, and the same seed pattern golden-path-e2e.yml
  # uses. api_keys has no RLS (migration 028) so the superuser insert is the
  # canonical path.
  psql_exec <<SQL
INSERT INTO tenants (id, clerk_org_id, name, slug, plan)
VALUES ('${TENANT_ID}', 'ci_${TENANT_ID}', 'project-scope-e2e',
        'project-scope-e2e-${TENANT_ID:0:8}', 'free');

INSERT INTO api_keys (id, tenant_id, project_id, name, key_hash, key_prefix, permissions, created_at)
VALUES ('$(uuidgen)', '${TENANT_ID}', NULL, 'project-scope-e2e-tenant-level',
        '$(printf '%s' "${K_TENANT}" | sha256sum | awk '{print $1}')',
        '${K_TENANT:0:12}', 'write', NOW());
SQL

  # Both projects are created THROUGH the api with the tenant-level key, so the
  # fixture itself is evidence that a tenant-level key still creates.
  # `|| return 1` + `|| die` at each call site: a command substitution normally
  # clears errexit, so without them a failed seed curl would be reported only as
  # an empty project id (Codex R2 Low).
  create_project() {
    local resp
    resp=$(curl --fail-with-body -sS -X POST \
      -H "Authorization: Bearer ${K_TENANT}" -H 'Content-Type: application/json' \
      -d "{\"name\":\"$1\"}" "${SBOMHUB_URL}/api/v1/cli/projects") || return 1
    printf '%s' "${resp}" | jq -r '.project.id // empty'
  }
  PROJECT_OWN="$(create_project "${PROJECT_OWN_NAME}")"     || die "seed: POST /api/v1/cli/projects failed for '${PROJECT_OWN_NAME}'"
  PROJECT_SIBLING="$(create_project "${PROJECT_SIBLING_NAME}")" || die "seed: POST /api/v1/cli/projects failed for '${PROJECT_SIBLING_NAME}'"
  [ -n "${PROJECT_OWN}" ] && [ -n "${PROJECT_SIBLING}" ] || die "failed to seed the two projects"
  assert_uuid "${PROJECT_OWN}"     "project id returned by POST /api/v1/cli/projects"
  assert_uuid "${PROJECT_SIBLING}" "project id returned by POST /api/v1/cli/projects"

  psql_exec <<SQL
INSERT INTO api_keys (id, tenant_id, project_id, name, key_hash, key_prefix, permissions, created_at)
VALUES ('$(uuidgen)', '${TENANT_ID}', '${PROJECT_OWN}', 'project-scope-e2e-project-scoped',
        '$(printf '%s' "${K_SCOPED}" | sha256sum | awk '{print $1}')',
        '${K_SCOPED:0:12}', 'write', NOW());
SQL

  # One SBOM in P_own so the path-param read routes have something to answer with.
  curl --fail-with-body -sS -o /dev/null -X POST \
    -H "Authorization: Bearer ${K_TENANT}" -H 'Content-Type: application/json' \
    --data-binary "@${SBOM_FIXTURE}" \
    "${SBOMHUB_URL}/api/v1/projects/${PROJECT_OWN}/sbom"
fi

# A project in ANOTHER tenant. project_scope.go claims the refusal is identical
# for "a sibling project that exists, a foreign tenant's project, and a UUID that
# was never allocated" — the foreign-tenant leg of that was untested until Codex
# R1 (Medium) pointed it out. Seeded straight through psql: nothing in this
# script ever authenticates as tenant 2, it only needs a real project id whose
# tenant is not the key's.
FOREIGN_TENANT_ID="$(uuidgen)"
PROJECT_FOREIGN="$(uuidgen)"
assert_uuid "${FOREIGN_TENANT_ID}" "seeded foreign tenant id"
assert_uuid "${PROJECT_FOREIGN}"   "seeded foreign project id"
psql_exec <<SQL
INSERT INTO tenants (id, clerk_org_id, name, slug, plan)
VALUES ('${FOREIGN_TENANT_ID}', 'ci_${FOREIGN_TENANT_ID}', 'project-scope-e2e-foreign',
        'project-scope-e2e-foreign-${FOREIGN_TENANT_ID:0:8}', 'free')
ON CONFLICT (id) DO NOTHING;

INSERT INTO projects (id, tenant_id, name, description)
VALUES ('${PROJECT_FOREIGN}', '${FOREIGN_TENANT_ID}', 'project-scope-e2e-foreign-project', '')
ON CONFLICT (id) DO NOTHING;
SQL

note "tenant=${TENANT_ID}"
note "P_own=${PROJECT_OWN} (${PROJECT_OWN_NAME})"
note "P_sibling=${PROJECT_SIBLING} (${PROJECT_SIBLING_NAME})"
note "P_foreign=${PROJECT_FOREIGN} (tenant ${FOREIGN_TENANT_ID}, a REAL project in another tenant)"

# Fixture sanity: the two keys must actually be what the matrix assumes they
# are. A run where K_scoped had project_id NULL would pass every "not 403"
# assertion and prove nothing.
SCOPED_KEY_PROJECT=$(psql_query "SELECT COALESCE(project_id::text,'NULL') FROM api_keys WHERE key_hash = '$(printf '%s' "${K_SCOPED}" | sha256sum | awk '{print $1}')'")
TENANT_KEY_PROJECT=$(psql_query "SELECT COALESCE(project_id::text,'NULL') FROM api_keys WHERE key_hash = '$(printf '%s' "${K_TENANT}" | sha256sum | awk '{print $1}')'")
[ "${SCOPED_KEY_PROJECT}" = "${PROJECT_OWN}" ] || die "K_scoped.project_id is '${SCOPED_KEY_PROJECT}', want '${PROJECT_OWN}' — the fixture does not test what it claims to"
[ "${TENANT_KEY_PROJECT}" = "NULL" ]           || die "K_tenant.project_id is '${TENANT_KEY_PROJECT}', want NULL — the negative control is not a control"
note "K_scoped.project_id = ${SCOPED_KEY_PROJECT}, K_tenant.project_id = NULL  (verified in api_keys)"

# ---------------------------------------------------------------------------
# Step 2: the matrix — every apiKeyRouteScope entry, both key kinds
# ---------------------------------------------------------------------------
echo "=== Step 2: drive the matrix ==="
printf '%-25s  %-64s %6s %6s %8s %8s %6s %8s\n' KIND ROUTE own sib foreign unalloc bad TENANT-KEY
printf -- '-%.0s' {1..145}; echo

while IFS='|' read -r kind route; do
  s_own="-" ; s_sib="-" ; s_foreign="-" ; s_unalloc="-" ; s_bad="-"

  # Negative control pass: the tenant-level key, always against P_own. Runs for
  # EVERY class — a tenant-level key must never see a 403 anywhere in the table.
  t_own=$(request "${K_TENANT}" "${route}" "${PROJECT_OWN}" "${WORK}/t.body")
  [ "${t_own}" != "403" ] || fail "NEGATIVE CONTROL: tenant-level key got 403 on '${route}' — either the scope filter leaked onto tenant-level keys, or the stack is broken"
  assert_not_ratelimited "${t_own}" "'${route}' (tenant-level key)"
  assert_registered "${WORK}/t.body" "${route}"

  case "${kind}" in
    scopeProjectPathParam)
      s_own=$(request     "${K_SCOPED}" "${route}" "${PROJECT_OWN}"        "${WORK}/own.body")
      s_sib=$(request     "${K_SCOPED}" "${route}" "${PROJECT_SIBLING}"    "${WORK}/sib.body")
      s_foreign=$(request "${K_SCOPED}" "${route}" "${PROJECT_FOREIGN}"    "${WORK}/foreign.body")
      s_unalloc=$(request "${K_SCOPED}" "${route}" "${UNALLOCATED_PROJECT}" "${WORK}/unalloc.body")
      s_bad=$(request     "${K_SCOPED}" "${route}" "${MALFORMED_PROJECT}"  "${WORK}/bad.body")

      [ "${s_own}" != "403" ] || fail "'${route}' with :id = the key's OWN project returned 403"
      assert_not_ratelimited "${s_own}" "'${route}' (scoped key, own project)"
      # Stronger than "not 403": inside its own project a project-scoped key must
      # be INDISTINGUISHABLE from a tenant-level one. This needs no hardcoded
      # per-route expectation, so it survives handler changes.
      [ "${s_own}" = "${t_own}" ] || fail "'${route}' on P_own: scoped key got ${s_own}, tenant-level key got ${t_own} — scoping changed behaviour inside the key's own project"

      for pair in "sib:${s_sib}:sibling project" "foreign:${s_foreign}:foreign tenant's project" "unalloc:${s_unalloc}:unallocated UUID" "bad:${s_bad}:malformed :id"; do
        tag="${pair%%:*}"; rest="${pair#*:}"; code="${rest%%:*}"; what="${rest#*:}"
        [ "${code}" = "403" ] || fail "'${route}' with ${what} returned ${code}, want 403"
        assert_refusal_body "${WORK}/${tag}.body" "${route} (${what})"
      done
      ;;

    scopeTenantWide)
      s_own=$(request "${K_SCOPED}" "${route}" "${PROJECT_OWN}" "${WORK}/own.body")
      [ "${s_own}" = "403" ] || fail "'${route}' is scopeTenantWide but a project-scoped key got ${s_own}, want 403"
      assert_refusal_body "${WORK}/own.body" "${route} (tenant-wide)"
      ;;

    scopeProjectListNarrowed|scopeHandlerChecked)
      # Admitted by the middleware; the substantive assertions are in Steps 3-4.
      # No scoped-vs-tenant status comparison here: these two classes are
      # SUPPOSED to answer differently for the two credentials (narrowed list,
      # refused create).
      s_own=$(request "${K_SCOPED}" "${route}" "${PROJECT_OWN}" "${WORK}/own.body")
      [ "${s_own}" != "403" ] || fail "'${route}' is ${kind} (admitted at the middleware) but a project-scoped key got 403"
      assert_not_ratelimited "${s_own}" "'${route}' (scoped key)"
      ;;

    scopeNoProjectResource)
      # "allowed through UNCHANGED" is the promise, so "not 403" is too weak
      # (Codex R1 Medium): a 401/500 that only a scoped key sees would pass it.
      # Require the scoped key to get the same status as a tenant-level one.
      s_own=$(request "${K_SCOPED}" "${route}" "${PROJECT_OWN}" "${WORK}/own.body")
      [ "${s_own}" != "403" ] || fail "'${route}' is scopeNoProjectResource but a project-scoped key got 403"
      assert_not_ratelimited "${s_own}" "'${route}' (scoped key)"
      [ "${s_own}" = "${t_own}" ] || fail "'${route}' is scopeNoProjectResource ('allowed through unchanged') but the scoped key got ${s_own} where a tenant-level key got ${t_own}"
      ;;
  esac

  printf '%-25s  %-64s %6s %6s %8s %8s %6s %8s\n' \
    "${kind#scope}" "${route}" "${s_own}" "${s_sib}" "${s_foreign}" "${s_unalloc}" "${s_bad}" "${t_own}"
done < "${WORK}/routes.txt"

# ---------------------------------------------------------------------------
# Step 3: scopeProjectListNarrowed — the handler must narrow, not refuse
# ---------------------------------------------------------------------------
echo "=== Step 3: narrowed project lists ==="

CLI_LIST_CODE=$(http GET "${SBOMHUB_URL}/api/v1/cli/projects" "${WORK}/cli.list" -H "Authorization: Bearer ${K_SCOPED}")
[ "${CLI_LIST_CODE}" = "200" ] || fail "GET /api/v1/cli/projects with a scoped key: ${CLI_LIST_CODE}, want 200"
assert_not_ratelimited "${CLI_LIST_CODE}" "GET /api/v1/cli/projects"
# `|| echo` keeps a broken/unexpected body from aborting the run under `set -e`,
# so the verdict block still reports the full failure count.
CLI_IDS=$(jq -r '[.projects[].id] | join(",")' <"${WORK}/cli.list" 2>/dev/null || echo "<unparseable>")
CLI_TOTAL=$(jq -r '.total' <"${WORK}/cli.list" 2>/dev/null || echo "<unparseable>")
CLI_LEN=$(jq -r '.projects | length' <"${WORK}/cli.list" 2>/dev/null || echo "<unparseable>")
[ "${CLI_IDS}" = "${PROJECT_OWN}" ] || fail "GET /api/v1/cli/projects returned ids [${CLI_IDS}], want exactly [${PROJECT_OWN}]"
[ "${CLI_TOTAL}" = "1" ]            || fail "GET /api/v1/cli/projects total=${CLI_TOTAL}, want 1"
[ "${CLI_TOTAL}" = "${CLI_LEN}" ]   || fail "GET /api/v1/cli/projects total=${CLI_TOTAL} disagrees with array length ${CLI_LEN} — total must be the length of the array beside it, not a tenant-wide count"
case "${CLI_IDS}" in *"${PROJECT_SIBLING}"*) fail "GET /api/v1/cli/projects LEAKED the sibling project ${PROJECT_SIBLING}" ;; esac
note "GET /api/v1/cli/projects -> 200 $(tr -d '\n' <"${WORK}/cli.list" | head -c 200)"

MCP_LIST_CODE=$(http GET "${SBOMHUB_URL}/api/v1/mcp/projects" "${WORK}/mcp.list" -H "Authorization: Bearer ${K_SCOPED}")
[ "${MCP_LIST_CODE}" = "200" ] || fail "GET /api/v1/mcp/projects with a scoped key: ${MCP_LIST_CODE}, want 200"
assert_not_ratelimited "${MCP_LIST_CODE}" "GET /api/v1/mcp/projects"
[ "$(jq -r 'type' <"${WORK}/mcp.list" 2>/dev/null || echo "<unparseable>")" = "array" ] || fail "GET /api/v1/mcp/projects is not a bare array"
MCP_IDS=$(jq -r '[.[].id] | join(",")' <"${WORK}/mcp.list" 2>/dev/null || echo "<unparseable>")
[ "${MCP_IDS}" = "${PROJECT_OWN}" ] || fail "GET /api/v1/mcp/projects returned ids [${MCP_IDS}], want exactly [${PROJECT_OWN}]"
note "GET /api/v1/mcp/projects  -> 200 ids=[${MCP_IDS}] (length $(jq -r 'length' <"${WORK}/mcp.list" 2>/dev/null || echo '?'))"

# Negative control + anti-vacuity: the tenant-level key must see BOTH projects
# through the same two routes. If it saw one, "narrowed to one" would be
# meaningless.
for pair in "cli:/api/v1/cli/projects:.projects" "mcp:/api/v1/mcp/projects:."; do
  tag="${pair%%:*}"; rest="${pair#*:}"; p="${rest%%:*}"; sel="${rest#*:}"
  http GET "${SBOMHUB_URL}${p}" "${WORK}/${tag}.tenant" -H "Authorization: Bearer ${K_TENANT}" >/dev/null
  ids=$(jq -r "[${sel}[].id] | join(\",\")" <"${WORK}/${tag}.tenant" 2>/dev/null || echo "<unparseable>")
  case "${ids}" in
    *"${PROJECT_OWN}"*) ;; *) fail "NEGATIVE CONTROL: tenant-level key does not see P_own through ${p}" ;;
  esac
  case "${ids}" in
    *"${PROJECT_SIBLING}"*) ;; *) fail "NEGATIVE CONTROL: tenant-level key does not see P_sibling through ${p} — 'narrowed to one' proves nothing if the tenant list is also one" ;;
  esac
  note "tenant-level key on ${p} sees both projects (anti-vacuity control)"
done

# ---------------------------------------------------------------------------
# Step 4: scopeHandlerChecked — refuse, create nothing, and give no name oracle
# ---------------------------------------------------------------------------
echo "=== Step 4: handler-checked routes (POST /cli/projects, POST /cli/upload) ==="

UNKNOWN_NAME="a3-scope-never-existed-$(openssl rand -hex 4)"
PROJECTS_BEFORE=$(psql_query "SELECT COUNT(*) FROM projects WHERE tenant_id = '${TENANT_ID}'")
SBOMS_SIBLING_BEFORE=$(psql_query "SELECT COUNT(*) FROM sboms WHERE project_id = '${PROJECT_SIBLING}'")
SBOMS_TENANT_BEFORE=$(psql_query "SELECT COUNT(*) FROM sboms WHERE tenant_id = '${TENANT_ID}'")

# --- POST /api/v1/cli/projects with a brand-new name: the escape hatch ---
c1=$(http POST "${SBOMHUB_URL}/api/v1/cli/projects" "${WORK}/cp.new" \
  -H "Authorization: Bearer ${K_SCOPED}" -H 'Content-Type: application/json' -d "{\"name\":\"${UNKNOWN_NAME}\"}")
[ "${c1}" = "403" ] || fail "POST /api/v1/cli/projects with a NEW name returned ${c1}, want 403"
assert_refusal_body "${WORK}/cp.new" "POST /api/v1/cli/projects (new name)"
note "POST /api/v1/cli/projects '${UNKNOWN_NAME}' -> ${c1} $(tr -d '\n' <"${WORK}/cp.new")"

# --- POST /api/v1/cli/projects naming the sibling ---
c2=$(http POST "${SBOMHUB_URL}/api/v1/cli/projects" "${WORK}/cp.sib" \
  -H "Authorization: Bearer ${K_SCOPED}" -H 'Content-Type: application/json' -d "{\"name\":\"${PROJECT_SIBLING_NAME}\"}")
[ "${c2}" = "403" ] || fail "POST /api/v1/cli/projects naming the SIBLING returned ${c2}, want 403"
assert_refusal_body "${WORK}/cp.sib" "POST /api/v1/cli/projects (sibling name)"

# The name oracle. This is the failure mode a previous session actually found:
# if "a project by that name exists but is not yours" answers differently from
# "no such project", the route enumerates the tenant's project names.
cmp -s "${WORK}/cp.sib" "${WORK}/cp.new" \
  || fail "NAME ORACLE on POST /api/v1/cli/projects: sibling-name and unknown-name refusals differ on the wire ('$(tr -d '\n' <"${WORK}/cp.sib")' vs '$(tr -d '\n' <"${WORK}/cp.new")')"
[ "${c1}" = "${c2}" ] || fail "NAME ORACLE on POST /api/v1/cli/projects: sibling-name status ${c2} != unknown-name status ${c1}"
note "POST /api/v1/cli/projects: sibling-name and unknown-name refusals are byte-identical"

PROJECTS_AFTER=$(psql_query "SELECT COUNT(*) FROM projects WHERE tenant_id = '${TENANT_ID}'")
[ "${PROJECTS_AFTER}" = "${PROJECTS_BEFORE}" ] || fail "projects row count went ${PROJECTS_BEFORE} -> ${PROJECTS_AFTER} across two refused POST /cli/projects — the refusal created a project"
NAMED=$(psql_query "SELECT COUNT(*) FROM projects WHERE tenant_id = '${TENANT_ID}' AND name = '${UNKNOWN_NAME}'")
[ "${NAMED}" = "0" ] || fail "a project named '${UNKNOWN_NAME}' exists after a 403 — the refusal created it"
note "projects rows unchanged at ${PROJECTS_AFTER}; no row named '${UNKNOWN_NAME}'"

# --- POST /api/v1/cli/upload naming the sibling / an unknown project ---
u1=$(http POST "${SBOMHUB_URL}/api/v1/cli/upload" "${WORK}/up.sib" \
  -H "Authorization: Bearer ${K_SCOPED}" -F "project_name=${PROJECT_SIBLING_NAME}" -F "sbom=@${SBOM_FIXTURE}")
[ "${u1}" = "403" ] || fail "POST /api/v1/cli/upload naming the SIBLING returned ${u1}, want 403"
assert_refusal_body "${WORK}/up.sib" "POST /api/v1/cli/upload (sibling name)"

u2=$(http POST "${SBOMHUB_URL}/api/v1/cli/upload" "${WORK}/up.new" \
  -H "Authorization: Bearer ${K_SCOPED}" -F "project_name=${UNKNOWN_NAME}" -F "sbom=@${SBOM_FIXTURE}")
[ "${u2}" = "403" ] || fail "POST /api/v1/cli/upload with a NEW name returned ${u2}, want 403"
assert_refusal_body "${WORK}/up.new" "POST /api/v1/cli/upload (new name)"

cmp -s "${WORK}/up.sib" "${WORK}/up.new" \
  || fail "NAME ORACLE on POST /api/v1/cli/upload: sibling-name and unknown-name refusals differ on the wire"
[ "${u1}" = "${u2}" ] || fail "NAME ORACLE on POST /api/v1/cli/upload: sibling-name status ${u1} != unknown-name status ${u2}"
note "POST /api/v1/cli/upload '${PROJECT_SIBLING_NAME}' -> ${u1}; '${UNKNOWN_NAME}' -> ${u2}; byte-identical"

SBOMS_SIBLING_AFTER=$(psql_query "SELECT COUNT(*) FROM sboms WHERE project_id = '${PROJECT_SIBLING}'")
SBOMS_TENANT_AFTER=$(psql_query "SELECT COUNT(*) FROM sboms WHERE tenant_id = '${TENANT_ID}'")
[ "${SBOMS_SIBLING_AFTER}" = "${SBOMS_SIBLING_BEFORE}" ] || fail "sboms in the SIBLING project went ${SBOMS_SIBLING_BEFORE} -> ${SBOMS_SIBLING_AFTER} across two refused uploads"
[ "${SBOMS_TENANT_AFTER}" = "${SBOMS_TENANT_BEFORE}" ]   || fail "sboms in the tenant went ${SBOMS_TENANT_BEFORE} -> ${SBOMS_TENANT_AFTER} across two refused uploads"
note "sboms rows unchanged (sibling=${SBOMS_SIBLING_AFTER}, tenant=${SBOMS_TENANT_AFTER})"

# The two project-row assertions above were taken BEFORE the uploads. An upload
# that created the project and then refused the SBOM would satisfy every
# assertion so far, so re-check both after the uploads too (Codex R1 High).
PROJECTS_AFTER_UPLOADS=$(psql_query "SELECT COUNT(*) FROM projects WHERE tenant_id = '${TENANT_ID}'")
NAMED_AFTER_UPLOADS=$(psql_query "SELECT COUNT(*) FROM projects WHERE tenant_id = '${TENANT_ID}' AND name = '${UNKNOWN_NAME}'")
[ "${PROJECTS_AFTER_UPLOADS}" = "${PROJECTS_BEFORE}" ] || fail "projects row count went ${PROJECTS_BEFORE} -> ${PROJECTS_AFTER_UPLOADS} across the refused /cli/upload calls — a refused upload created a project"
[ "${NAMED_AFTER_UPLOADS}" = "0" ] || fail "a project named '${UNKNOWN_NAME}' exists after the refused uploads — /cli/upload created it before refusing"
note "projects rows still ${PROJECTS_AFTER_UPLOADS} after the refused uploads; still no row named '${UNKNOWN_NAME}'"

# Anti-vacuity: the same two routes must still WORK for the key's own project,
# otherwise the row-count assertions above would hold on a stack that refuses
# everything. Baselines taken here so the deltas the two SUCCESSFUL calls are
# allowed to make can be stated exactly (Codex R2 Medium): +1 sbom in P_own and
# nowhere else, and no new project at all.
PROJECTS_BEFORE_OK=$(psql_query "SELECT COUNT(*) FROM projects WHERE tenant_id = '${TENANT_ID}'")
SBOMS_OWN_BEFORE_OK=$(psql_query "SELECT COUNT(*) FROM sboms WHERE project_id = '${PROJECT_OWN}'")
SBOMS_TENANT_BEFORE_OK=$(psql_query "SELECT COUNT(*) FROM sboms WHERE tenant_id = '${TENANT_ID}'")
w1=$(http POST "${SBOMHUB_URL}/api/v1/cli/projects" "${WORK}/cp.own" \
  -H "Authorization: Bearer ${K_SCOPED}" -H 'Content-Type: application/json' -d "{\"name\":\"${PROJECT_OWN_NAME}\"}")
[ "${w1}" = "200" ] || fail "POST /api/v1/cli/projects naming the key's OWN project returned ${w1}, want 200 (idempotent get-existing)"
assert_not_ratelimited "${w1}" "POST /api/v1/cli/projects (own project)"
[ "$(jq -r '.created' <"${WORK}/cp.own")" = "false" ] || fail "POST /api/v1/cli/projects on the OWN project reported created=true — a scoped key must never create"
[ "$(jq -r '.project.id' <"${WORK}/cp.own")" = "${PROJECT_OWN}" ] || fail "POST /api/v1/cli/projects on the OWN project returned the wrong project"
w2=$(http POST "${SBOMHUB_URL}/api/v1/cli/upload" "${WORK}/up.own" \
  -H "Authorization: Bearer ${K_SCOPED}" -F "project_name=${PROJECT_OWN_NAME}" -F "sbom=@${SBOM_FIXTURE}")
[ "${w2}" = "200" ] || fail "POST /api/v1/cli/upload into the key's OWN project returned ${w2}, want 200"
assert_not_ratelimited "${w2}" "POST /api/v1/cli/upload (own project)"
[ "$(jq -r '.project_created' <"${WORK}/up.own" 2>/dev/null || echo '?')" = "false" ] || fail "POST /api/v1/cli/upload reported project_created=true for a scoped key"
# A 200 is not enough: the row has to have landed in the key's OWN project.
# Follow the sbom_id the response returns back into the database (Codex R1
# Medium) — a write redirected to the sibling would otherwise pass.
[ "$(jq -r '.project_id' <"${WORK}/up.own" 2>/dev/null || echo '?')" = "${PROJECT_OWN}" ] || fail "POST /api/v1/cli/upload into the OWN project reported project_id $(jq -r '.project_id' <"${WORK}/up.own" 2>/dev/null || echo '?'), want ${PROJECT_OWN}"
UP_SBOM_ID=$(jq -r '.sbom_id // empty' <"${WORK}/up.own" 2>/dev/null || echo "")
[ -n "${UP_SBOM_ID}" ] || fail "POST /api/v1/cli/upload into the OWN project returned no sbom_id"
if [ -n "${UP_SBOM_ID}" ]; then
  assert_uuid "${UP_SBOM_ID}" "sbom_id returned by POST /api/v1/cli/upload"
  UP_SBOM_PROJECT=$(psql_query "SELECT COALESCE(project_id::text,'NULL') FROM sboms WHERE id = '${UP_SBOM_ID}'")
  [ "${UP_SBOM_PROJECT}" = "${PROJECT_OWN}" ] || fail "the SBOM created by the own-project upload (${UP_SBOM_ID}) persisted under project '${UP_SBOM_PROJECT}', want ${PROJECT_OWN}"
fi
SBOMS_SIBLING_FINAL=$(psql_query "SELECT COUNT(*) FROM sboms WHERE project_id = '${PROJECT_SIBLING}'")
[ "${SBOMS_SIBLING_FINAL}" = "${SBOMS_SIBLING_BEFORE}" ] || fail "the SUCCESSFUL own-project upload changed the sibling's sboms count (${SBOMS_SIBLING_BEFORE} -> ${SBOMS_SIBLING_FINAL})"

# Exact deltas for the two successful calls. "one valid own-project SBOM came
# back" does not by itself rule out the server ALSO creating a project or
# writing further sboms elsewhere in the tenant.
PROJECTS_FINAL=$(psql_query "SELECT COUNT(*) FROM projects WHERE tenant_id = '${TENANT_ID}'")
SBOMS_OWN_FINAL=$(psql_query "SELECT COUNT(*) FROM sboms WHERE project_id = '${PROJECT_OWN}'")
SBOMS_TENANT_FINAL=$(psql_query "SELECT COUNT(*) FROM sboms WHERE tenant_id = '${TENANT_ID}'")
[ "${PROJECTS_FINAL}" = "${PROJECTS_BEFORE_OK}" ] || fail "the two SUCCESSFUL own-project calls changed the tenant's projects count (${PROJECTS_BEFORE_OK} -> ${PROJECTS_FINAL}) — a scoped key must never create a project"
[ "${SBOMS_OWN_FINAL}" = "$((SBOMS_OWN_BEFORE_OK + 1))" ] || fail "sboms in P_own went ${SBOMS_OWN_BEFORE_OK} -> ${SBOMS_OWN_FINAL}, want exactly +1 from the one successful upload"
[ "${SBOMS_TENANT_FINAL}" = "$((SBOMS_TENANT_BEFORE_OK + 1))" ] || fail "sboms in the tenant went ${SBOMS_TENANT_BEFORE_OK} -> ${SBOMS_TENANT_FINAL}, want exactly +1 — the successful upload wrote rows outside P_own"
note "anti-vacuity: own-project create -> ${w1} created=false; own-project upload -> ${w2}, sbom ${UP_SBOM_ID} persisted under P_own, sibling count still ${SBOMS_SIBLING_FINAL}"

# --- scopeNoProjectResource: 'allowed through unchanged', byte for byte ---
# The matrix compares statuses on the live /cli/check path, which calls OSV and
# is therefore not byte-reproducible. Drive the deterministic handler-level
# rejection (empty components) instead, where both credentials must produce the
# SAME status AND the SAME bytes. That is what "unchanged" means and it needs no
# network.
chk_scoped_code=$(http POST "${SBOMHUB_URL}/api/v1/cli/check" "${WORK}/chk.scoped" \
  -H "Authorization: Bearer ${K_SCOPED}" -H 'Content-Type: application/json' -d '{"components":[]}')
chk_tenant_code=$(http POST "${SBOMHUB_URL}/api/v1/cli/check" "${WORK}/chk.tenant" \
  -H "Authorization: Bearer ${K_TENANT}" -H 'Content-Type: application/json' -d '{"components":[]}')
[ "${chk_scoped_code}" = "${chk_tenant_code}" ] || fail "POST /api/v1/cli/check (deterministic empty-components path): scoped key got ${chk_scoped_code}, tenant-level key got ${chk_tenant_code} — scopeNoProjectResource promises the route is reached unchanged"
cmp -s "${WORK}/chk.scoped" "${WORK}/chk.tenant" || fail "POST /api/v1/cli/check answers a project-scoped key with different bytes than a tenant-level one: '$(tr -d '\n' <"${WORK}/chk.scoped")' vs '$(tr -d '\n' <"${WORK}/chk.tenant")'"

# Equality alone is not enough (Codex R5 Medium): two identical 500s satisfy it,
# and so does a route that has slipped OUT from behind APIKeyAuth while its
# handler keeps answering 400. Pin what the answer has to BE, and prove the
# route is still authenticated.
[ "${chk_scoped_code}" = "400" ] || fail "POST /api/v1/cli/check with empty components returned ${chk_scoped_code}, want 400 — the two credentials agreeing on some other status says nothing about the route being reached"
CHK_ERR=$(jq -r '.error // "<none>"' <"${WORK}/chk.scoped" 2>/dev/null || echo "<not json>")
[ "${CHK_ERR}" = "components array is required and cannot be empty" ] || fail "POST /api/v1/cli/check with empty components answered '${CHK_ERR}' — that is not CLIHandler.Check's validation error, so the request did not reach the handler"
for bad in "" "sbh_$(openssl rand -hex 16)"; do
  if [ -z "${bad}" ]; then
    chk_unauth=$(http POST "${SBOMHUB_URL}/api/v1/cli/check" "${WORK}/chk.unauth" -H 'Content-Type: application/json' -d '{"components":[]}')
    what="no credential"
  else
    chk_unauth=$(http POST "${SBOMHUB_URL}/api/v1/cli/check" "${WORK}/chk.unauth" -H "Authorization: Bearer ${bad}" -H 'Content-Type: application/json' -d '{"components":[]}')
    what="an unknown sbh_ key"
  fi
  [ "${chk_unauth}" = "401" ] || fail "POST /api/v1/cli/check with ${what} returned ${chk_unauth}, want 401 — the route is no longer behind APIKeyAuth, so its 'reached unchanged' result above proves nothing about the scope filter"
done
note "POST /api/v1/cli/check (empty components): both credentials -> ${chk_scoped_code} $(tr -d '\n' <"${WORK}/chk.scoped")"
note "POST /api/v1/cli/check without a valid credential -> 401 (route is still behind APIKeyAuth)"

# ---------------------------------------------------------------------------
# Step 4b: the SAME key in the OTHER header
#
# Everything above authenticates with `Authorization: Bearer`. apps/api also
# accepts the key in `X-API-Key` — APIKeyAuth always did, MultiAuth only since
# e84142c — and until then a request carrying only that header was not refused
# either: with Authorization empty it fell through to Auth(), whose self-hosted
# branch provisions the DEFAULT tenant's Owner. A project-scoped key therefore
# reached a SIBLING project with 200, because the scope comparison never ran on
# a key that was never read.
#
# Two shipped clients send exactly that header to a MultiAuth route
# (packages/mcp-server, .github/workflows/sbom-upload.yml), so this is checked
# on the wire rather than only in Go tests. Four cells, and each is a different
# claim:
#
#   scoped key, own project      -> 200   the header authenticates at all
#   scoped key, sibling project  -> 403   ...and carries the key's scope with it
#   unusable value               -> 401   fail-closed: a presented credential
#                                         that cannot be used ENDS the request
#   no header at all             -> 200   ...but the absence of one still does
#                                         not (the self-host promise)
#
# The last two together are the whole point: "no credential" and "a credential
# I cannot use" must not resolve to the same identity.
#
# NOTE: the 200s below assume this stack runs SBOMHUB_AUTH_MODE=anonymous, which
# is what the workflow driving this script sets and what makes the no-header
# cell meaningful at all. Under `clerk` the no-header cell would be 401.
# ---------------------------------------------------------------------------
echo "=== Step 4b: X-API-Key on a MultiAuth route ==="

XKEY_ROUTE="/api/v1/projects"

xk_own=$(http GET "${SBOMHUB_URL}${XKEY_ROUTE}/${PROJECT_OWN}/sbom" "${WORK}/xk.own" \
  -H "X-API-Key: ${K_SCOPED}")
[ "${xk_own}" = "200" ] || fail "X-API-Key with the scoped key on its OWN project returned ${xk_own}, want 200 — apps/api documents that header for API keys and MultiAuth must read it"
note "X-API-Key scoped  GET ${XKEY_ROUTE}/<own>/sbom -> ${xk_own}"

xk_sib=$(http GET "${SBOMHUB_URL}${XKEY_ROUTE}/${PROJECT_SIBLING}/sbom" "${WORK}/xk.sib" \
  -H "X-API-Key: ${K_SCOPED}")
[ "${xk_sib}" = "403" ] || fail "X-API-Key with the scoped key on a SIBLING project returned ${xk_sib}, want 403. Authorization: Bearer with the same key answers 403 here; a header that authenticates without carrying the key's project scope is worse than one that does not authenticate at all"
assert_refusal_body "${WORK}/xk.sib" "GET ${XKEY_ROUTE}/:id/sbom (X-API-Key, sibling)"
note "X-API-Key scoped  GET ${XKEY_ROUTE}/<sibling>/sbom -> ${xk_sib} $(tr -d '\n' <"${WORK}/xk.sib")"

# scan-status: the route the MCP server reads the asynchronous scan state from.
# 404 is the expected answer for a made-up sbom_id — what matters is that the
# request was ADMITTED for the key's own project and REFUSED for the sibling.
# Asserted as one status, not "anything but 401/403" (Codex R5 Low): a 5xx from
# the middleware chain also avoids those two and would prove nothing about the
# request having been ADMITTED. `DUMMY_SUBRESOURCE` is a well-formed UUID that
# is not one of this project's SBOMs, so SbomHandler.ScanStatus maps
# GetVulnerabilitiesBySbom's ErrNoRows to exactly 404 — a handler answer, which
# is the evidence wanted here.
xk_scan_own=$(http GET "${SBOMHUB_URL}${XKEY_ROUTE}/${PROJECT_OWN}/sboms/${DUMMY_SUBRESOURCE}/scan-status" \
  "${WORK}/xk.scan.own" -H "X-API-Key: ${K_SCOPED}")
[ "${xk_scan_own}" = "404" ] || fail "scan-status for the scoped key's OWN project (with an sbom_id that is not this project's) returned ${xk_scan_own} ($(tr -d '\n' <"${WORK}/xk.scan.own")), want 404 from SbomHandler.ScanStatus. 403 would mean the scope filter refused the key's own project; 401 would mean MultiAuth is not reading ${XKEY_ROUTE##*/}'s X-API-Key at all; anything else did not reach the handler. The MCP server reads the scan state through this route and would report every count as unverifiable."
xk_scan_sib=$(http GET "${SBOMHUB_URL}${XKEY_ROUTE}/${PROJECT_SIBLING}/sboms/${DUMMY_SUBRESOURCE}/scan-status" \
  "${WORK}/xk.scan.sib" -H "X-API-Key: ${K_SCOPED}")
[ "${xk_scan_sib}" = "403" ] || fail "scan-status for a SIBLING project returned ${xk_scan_sib}, want 403"
assert_refusal_body "${WORK}/xk.scan.sib" "GET .../sboms/:sbom_id/scan-status (X-API-Key, sibling)"
note "X-API-Key scoped  GET .../sboms/<dummy>/scan-status -> own ${xk_scan_own} / sibling ${xk_scan_sib}"

XK_BAD_CODES=""
for bad in "sbh_$(openssl rand -hex 16)" "definitely-not-a-key"; do
  xk_bad=$(http GET "${SBOMHUB_URL}${XKEY_ROUTE}/${PROJECT_OWN}/sbom" "${WORK}/xk.bad" \
    -H "X-API-Key: ${bad}")
  XK_BAD_CODES="${XK_BAD_CODES}${XK_BAD_CODES:+/}${xk_bad}"
  [ "${xk_bad}" = "401" ] || fail "X-API-Key carrying an unusable value returned ${xk_bad}, want 401. Anything else means the value was DISCARDED and the request served as somebody else — the fail-open shape M48 removed elsewhere"
done
# The observed codes, not the expected ones: a note that says "-> 401"
# unconditionally is a line in the log that is false on exactly the runs where
# the log matters.
note "X-API-Key unusable values (unknown sbh_ / not key-shaped) -> ${XK_BAD_CODES} (want 401/401: fail-closed, no fall-through to the default identity)"

# The negative control for the line above, on the SAME url: without the header
# the request must still get PAST authentication, because that fall-through is
# the documented self-host behaviour. 401 here would mean the fix tightened more
# than it was supposed to.
#
# "Past authentication" is asserted as `not 401`, not as 200: the anonymous
# fall-through resolves to the DEFAULT tenant, and this script's fixtures live
# in a tenant it seeded, so RLS hides the project and the handler answers 404.
# That 404 is itself the evidence — it comes from SbomHandler.Get, which only
# runs after the middleware admitted the request. The contrast that matters is
# 404-from-the-handler versus the 401-from-the-middleware above, on one URL.
#
# Asserted as an ALLOWLIST, not as "anything but 401/403" (Codex R4 Low): a 500
# from the default-tenant provisioning or from TenantTx also happens BEFORE the
# handler, so accepting it would let a broken stack satisfy a control whose whole
# claim is that the handler was reached.
#
# Two statuses qualify, and both are handler answers:
#   404 — this script's own fixtures, where the project belongs to the tenant it
#         seeded and RLS hides it from the default tenant (SbomHandler.Get maps
#         GetLatest's ErrNoRows to 404);
#   200 — a pre-seeded run (SBOMHUB_PROJECT_OWN et al.) whose project happens to
#         live in the default tenant.
xk_none=$(http GET "${SBOMHUB_URL}${XKEY_ROUTE}/${PROJECT_OWN}/sbom" "${WORK}/xk.none")
case "${xk_none}" in
  200|404) ;;
  401) fail "NEGATIVE CONTROL: a request with NO credential returned 401 on an anonymous self-host stack. Refusing an UNUSABLE header must not also refuse the ABSENCE of one — 'self-host first' promises a header-less curl still works" ;;
  403) fail "NEGATIVE CONTROL: a request with NO credential returned 403 — a credential-less request has no project scope to violate, so this is the scope filter running on an identity that has none" ;;
  *)   fail "NEGATIVE CONTROL: a request with NO credential returned ${xk_none} ($(tr -d '\n' <"${WORK}/xk.none")). Only a HANDLER answer (404 under this script's own fixtures, 200 for a pre-seeded default-tenant project) shows the request was admitted; a 5xx comes from the middleware chain and proves nothing" ;;
esac
note "no header         GET ${XKEY_ROUTE}/<own>/sbom -> ${xk_none} (a handler answer: admitted, then resolved under the default tenant)"

# ---------------------------------------------------------------------------
# Step 5: default-deny — an unclassified path under /mcp or /cli is 403, not 404
# ---------------------------------------------------------------------------
echo "=== Step 5: default-deny on Echo's RouteNotFound catch-all ==="

for prefix in mcp cli; do
  nope="/api/v1/${prefix}/a3-scope-e2e-no-such-route-$(openssl rand -hex 3)"
  code=$(http GET "${SBOMHUB_URL}${nope}" "${WORK}/dd.body" -H "Authorization: Bearer ${K_SCOPED}")
  [ "${code}" = "403" ] || fail "default-deny: ${nope} with a project-scoped key returned ${code}, want 403 (an unclassified route must be REFUSED, not 404'd)"
  assert_refusal_body "${WORK}/dd.body" "${nope} (unclassified route)"
  note "scoped  GET ${nope} -> ${code} $(tr -d '\n' <"${WORK}/dd.body")"

  tcode=$(http GET "${SBOMHUB_URL}${nope}" "${WORK}/dd.tenant" -H "Authorization: Bearer ${K_TENANT}")
  [ "${tcode}" != "403" ] || fail "NEGATIVE CONTROL: tenant-level key got 403 on ${nope} — the catch-all denial is not specific to project-scoped keys"
  note "tenant  GET ${nope} -> ${tcode} $(tr -d '\n' <"${WORK}/dd.tenant")  (negative control)"
done

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
echo ""
echo "================================================================"
if [ "${FAILURES}" -ne 0 ]; then
  echo "project-scope E2E: ${FAILURES} FAILED assertion(s)"
  echo "================================================================"
  exit 1
fi
echo "project-scope E2E: PASSED"
echo "  routes driven   = ${ROUTE_COUNT} (every apiKeyRouteScope entry)"
echo "  scoped key      = project_id ${PROJECT_OWN}"
echo "  refused :id set = sibling ${PROJECT_SIBLING} / foreign-tenant ${PROJECT_FOREIGN} / unallocated ${UNALLOCATED_PROJECT} / malformed '${MALFORMED_PROJECT}'"
echo "  tenant key      = project_id NULL (negative control: 0 unexpected 403s)"
echo "  refusal body    = $(tr -d '\n' <"${REFUSAL_REF}") ($(wc -c <"${REFUSAL_REF}") bytes, byte-identical everywhere)"
echo "================================================================"
