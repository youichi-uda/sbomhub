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
#     sibling project, unallocated UUID, malformed :id, unclassified route,
#     unknown project name — which is the property that makes the refusal
#     useless as an existence oracle. The Go tests assert status only, except
#     one handler-level test that compares echo.HTTPError message strings for
#     POST /cli/projects;
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
# project_scope.go itself (see derive_route_table). Copying the table into this
# script would mean a route added there is silently untested here — exactly the
# failure mode the table's own doc comment says default-deny exists to prevent.
# Structural guards below fail the run if the parse degrades, if a class is
# unknown, or if a route uses a path parameter this script has no substitution
# for (i.e. the request recipe would be guessing).
#
# WHY grep AND NOT `go run` A HELPER THAT CALLS APIKeyRouteScopeKeys()
#
# The exported helpers give the KEYS (APIKeyRouteScopeKeys) and the narrowed
# subset (APIKeyProjectListNarrowedRoutes) but not each route's class, which is
# what decides the expected status. Parsing the map literal yields strictly
# more, and keeps the runner free of a Go toolchain.
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

psql_exec()  { ${PSQL_CMD}; }              # SQL on stdin
psql_query() { ${PSQL_CMD} -At -c "$1"; }  # scalar out

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
assert_refusal_body() {
  local file="$1" label="$2"
  if [ ! -s "${REFUSAL_REF}" ]; then
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

# `|| true` so a grep that matches NOTHING (the regex went stale against a
# reformatted table) reaches structural guard 1 with its explanation, instead of
# aborting the pipeline silently under `set -o pipefail`.
derive_route_table() {
  { grep -oE '^[[:space:]]*"[A-Z]+ /api/v1/[^"]*":[[:space:]]*\{scope[A-Za-z]+' "${SCOPE_TABLE_SRC}" || true; } \
    | sed -E 's/^[[:space:]]*"([^"]*)":[[:space:]]*\{(scope[A-Za-z]+)/\2|\1/' \
    | sort
}
derive_route_table > "${WORK}/routes.txt"
ROUTE_COUNT=$(wc -l < "${WORK}/routes.txt")

# Structural guard 1: the parse must find something.
[ "${ROUTE_COUNT}" -ge 1 ] || die "derived 0 routes from ${SCOPE_TABLE_SRC} — the map literal format changed and this script's regex is stale"

# Structural guard 2: the parse must find EVERY entry. Count the projectScopeRule
# literals inside the map body — `{scope...` appears exactly once per entry and
# is INDEPENDENT of the key regex above, so a key written in a shape that regex
# skips (multi-line key, key and kind on separate lines, ...) shows up as a
# mismatch instead of silently going untested.
MAP_KEY_COUNT=$(awk '
  /^var apiKeyRouteScope = map\[string\]projectScopeRule\{/ { inmap=1; next }
  inmap && /^\}/ { inmap=0 }
  inmap && /\{scope[A-Za-z]+/ { n++ }
  END { print n+0 }
' "${SCOPE_TABLE_SRC}")
if [ "${ROUTE_COUNT}" -ne "${MAP_KEY_COUNT}" ]; then
  die "derived ${ROUTE_COUNT} routes but the apiKeyRouteScope literal has ${MAP_KEY_COUNT} keys — some entry is written in a shape this script does not parse and would go UNTESTED"
fi

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
  note "using pre-seeded fixtures (SBOMHUB_SCOPED_KEY et al. supplied)"
else
  RUN_TAG="$(openssl rand -hex 4)"
  TENANT_ID="$(uuidgen)"
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
  create_project() {
    local resp
    resp=$(curl --fail-with-body -sS -X POST \
      -H "Authorization: Bearer ${K_TENANT}" -H 'Content-Type: application/json' \
      -d "{\"name\":\"$1\"}" "${SBOMHUB_URL}/api/v1/cli/projects")
    printf '%s' "${resp}" | jq -r '.project.id // empty'
  }
  PROJECT_OWN="$(create_project "${PROJECT_OWN_NAME}")"
  PROJECT_SIBLING="$(create_project "${PROJECT_SIBLING_NAME}")"
  [ -n "${PROJECT_OWN}" ] && [ -n "${PROJECT_SIBLING}" ] || die "failed to seed the two projects"

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

note "tenant=${TENANT_ID}"
note "P_own=${PROJECT_OWN} (${PROJECT_OWN_NAME})"
note "P_sibling=${PROJECT_SIBLING} (${PROJECT_SIBLING_NAME})"

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
printf '%-25s  %-64s %6s %6s %6s %6s %8s\n' KIND ROUTE own sib unalloc bad TENANT-KEY
printf -- '-%.0s' {1..130}; echo

while IFS='|' read -r kind route; do
  s_own="-" ; s_sib="-" ; s_unalloc="-" ; s_bad="-"

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
      s_unalloc=$(request "${K_SCOPED}" "${route}" "${UNALLOCATED_PROJECT}" "${WORK}/unalloc.body")
      s_bad=$(request     "${K_SCOPED}" "${route}" "${MALFORMED_PROJECT}"  "${WORK}/bad.body")

      [ "${s_own}" != "403" ] || fail "'${route}' with :id = the key's OWN project returned 403"
      assert_not_ratelimited "${s_own}" "'${route}' (scoped key, own project)"
      # Stronger than "not 403": inside its own project a project-scoped key must
      # be INDISTINGUISHABLE from a tenant-level one. This needs no hardcoded
      # per-route expectation, so it survives handler changes.
      [ "${s_own}" = "${t_own}" ] || fail "'${route}' on P_own: scoped key got ${s_own}, tenant-level key got ${t_own} — scoping changed behaviour inside the key's own project"

      for pair in "sib:${s_sib}:sibling project" "unalloc:${s_unalloc}:unallocated UUID" "bad:${s_bad}:malformed :id"; do
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

    scopeProjectListNarrowed|scopeHandlerChecked|scopeNoProjectResource)
      # Admitted by the middleware; the substantive assertions are in Steps 3-5.
      s_own=$(request "${K_SCOPED}" "${route}" "${PROJECT_OWN}" "${WORK}/own.body")
      [ "${s_own}" != "403" ] || fail "'${route}' is ${kind} (admitted at the middleware) but a project-scoped key got 403"
      assert_not_ratelimited "${s_own}" "'${route}' (scoped key)"
      ;;
  esac

  printf '%-25s  %-64s %6s %6s %6s %6s %8s\n' \
    "${kind#scope}" "${route}" "${s_own}" "${s_sib}" "${s_unalloc}" "${s_bad}" "${t_own}"
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

# Anti-vacuity: the same two routes must still WORK for the key's own project,
# otherwise the row-count assertions above would hold on a stack that refuses
# everything.
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
[ "$(jq -r '.project_created' <"${WORK}/up.own")" = "false" ] || fail "POST /api/v1/cli/upload reported project_created=true for a scoped key"
note "anti-vacuity: own-project create -> ${w1} created=false, own-project upload -> ${w2}"

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
echo "  tenant key      = project_id NULL (negative control: 0 unexpected 403s)"
echo "  refusal body    = $(tr -d '\n' <"${REFUSAL_REF}") ($(wc -c <"${REFUSAL_REF}") bytes, byte-identical everywhere)"
echo "================================================================"
