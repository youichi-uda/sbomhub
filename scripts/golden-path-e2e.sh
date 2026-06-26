#!/usr/bin/env bash
# SBOMHub - Golden Path E2E (issue #43)
#
# Drives the 12-step "5 分 Golden Path" against a live api on localhost,
# from project create through Evidence Pack bundle. Used by
# .github/workflows/golden-path-e2e.yml — the workflow is the only
# expected runner (assumes docker compose stack + postgres + tenant +
# API key already seeded by the caller).
#
# Contract:
#   - SBOMHUB_URL           : api base URL (e.g. http://localhost:8080)
#   - SBOMHUB_API_KEY       : raw sbh_... key (write-capable)
#   - SBOMHUB_TENANT_ID     : tenant UUID matching the API key (psql seed)
#   - SBOMHUB_PROJECT_NAME  : project name to create via /cli/projects
#   - SBOMHUB_SBOM_FIXTURE  : path to a CycloneDX JSON containing log4j-core
#                             (the script assumes the log4j-core component
#                             will be present after upload — used to seed
#                             a CVE-2021-44228 link for triage).
#   - COMPOSE_PSQL_SVC      : docker compose service name for postgres
#                             (default: postgres). Used to inject the
#                             seed vulnerability row + component link
#                             via `docker compose exec`.
#
# Asserts:
#   - Triage /run returns ai_disabled=true (M1 F4 AI-disabled fallback)
#   - CRA /run returns ai_disabled=true (M2 F4 AI-disabled fallback)
#   - Evidence Pack bundle contains the three section headers:
#       "## 1. Approved VEX Statements"
#       "## 2. Approved CRA Reports"
#       "## 3. METI 自己評価 / METI Self-Assessment"
#
# Exit codes:
#   0 — all 12 steps passed
#   non-zero — first failed step (script aborts via `set -e`)

set -euo pipefail

# ----------------------------------------------------------------------------
# Required inputs
# ----------------------------------------------------------------------------

: "${SBOMHUB_URL:?SBOMHUB_URL is required}"
: "${SBOMHUB_API_KEY:?SBOMHUB_API_KEY is required}"
: "${SBOMHUB_TENANT_ID:?SBOMHUB_TENANT_ID is required}"
: "${SBOMHUB_PROJECT_NAME:?SBOMHUB_PROJECT_NAME is required}"
: "${SBOMHUB_SBOM_FIXTURE:?SBOMHUB_SBOM_FIXTURE is required}"

COMPOSE_PSQL_SVC="${COMPOSE_PSQL_SVC:-postgres}"

if [ ! -f "${SBOMHUB_SBOM_FIXTURE}" ]; then
  echo "::error::SBOM fixture not found: ${SBOMHUB_SBOM_FIXTURE}"
  exit 1
fi

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

# auth_curl wraps `curl --fail-with-body` with the API-key header and
# JSON content type. Errors out on 4xx/5xx, dumps the response body so
# CI logs show the api's error envelope.
auth_curl() {
  local method="$1"; shift
  local url="$1"; shift
  curl --fail-with-body -sS -X "${method}" \
    -H "Authorization: Bearer ${SBOMHUB_API_KEY}" \
    -H "Content-Type: application/json" \
    "$@" \
    "${url}"
}

# psql_exec runs a SQL script against the compose postgres service as
# the superuser (sbomhub). The seed SQL only touches the
# vulnerabilities + component_vulnerabilities tables; vulnerabilities
# has no RLS (global cache) and component_vulnerabilities is a global
# join table, so the superuser path is the canonical one.
psql_exec() {
  docker compose exec -T "${COMPOSE_PSQL_SVC}" \
    psql -v ON_ERROR_STOP=1 -U sbomhub -d sbomhub -X -q
}

# psql_query runs a SELECT and returns the first column of the first
# row (-At = unaligned, tuples-only).
psql_query() {
  docker compose exec -T "${COMPOSE_PSQL_SVC}" \
    psql -v ON_ERROR_STOP=1 -U sbomhub -d sbomhub -At -c "$1"
}

assert_eq() {
  local got="$1"
  local want="$2"
  local label="$3"
  if [ "${got}" != "${want}" ]; then
    echo "::error::${label}: got '${got}', want '${want}'"
    exit 1
  fi
  echo "  OK ${label} = ${got}"
}

assert_ge() {
  local got="$1"
  local want="$2"
  local label="$3"
  if [ "${got}" -lt "${want}" ]; then
    echo "::error::${label}: got ${got}, want >= ${want}"
    exit 1
  fi
  echo "  OK ${label} = ${got} (>= ${want})"
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local label="$3"
  if ! printf '%s' "${haystack}" | grep -qF -- "${needle}"; then
    echo "::error::${label}: bundle does not contain expected marker"
    echo "needle: ${needle}"
    exit 1
  fi
  echo "  OK ${label} contains '${needle}'"
}

# ----------------------------------------------------------------------------
# Step 1: POST /api/v1/cli/projects — create the project
# ----------------------------------------------------------------------------
echo "=== Step 1: create project '${SBOMHUB_PROJECT_NAME}' ==="
PROJECT_RESP=$(auth_curl POST "${SBOMHUB_URL}/api/v1/cli/projects" \
  -d "{\"name\":\"${SBOMHUB_PROJECT_NAME}\",\"description\":\"Golden Path E2E project\"}")
echo "create-project response: ${PROJECT_RESP}"
PROJECT_ID=$(printf '%s' "${PROJECT_RESP}" | jq -r '.project.id // .id // .ID // empty')
if [ -z "${PROJECT_ID}" ] || [ "${PROJECT_ID}" = "null" ]; then
  echo "::error::failed to parse project id from /cli/projects response"
  exit 1
fi
echo "  OK project_id = ${PROJECT_ID}"

# ----------------------------------------------------------------------------
# Step 2: POST /api/v1/projects/:id/sbom — upload the Log4Shell CycloneDX
# ----------------------------------------------------------------------------
echo "=== Step 2: upload Log4Shell SBOM ==="
SBOM_RESP=$(curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer ${SBOMHUB_API_KEY}" \
  -H "Content-Type: application/json" \
  --data-binary "@${SBOMHUB_SBOM_FIXTURE}" \
  "${SBOMHUB_URL}/api/v1/projects/${PROJECT_ID}/sbom")
echo "upload-sbom response: ${SBOM_RESP}"
SBOM_ID=$(printf '%s' "${SBOM_RESP}" | jq -r '.id // .ID // empty')
if [ -z "${SBOM_ID}" ] || [ "${SBOM_ID}" = "null" ]; then
  echo "::error::failed to parse sbom id from upload response"
  exit 1
fi
echo "  OK sbom_id = ${SBOM_ID}"

# ----------------------------------------------------------------------------
# Step 3: seed CVE-2021-44228 (Log4Shell) + link to the uploaded log4j-core
#         component. Bypasses the post-upload NVD scan path because CI has
#         no NVD_API_KEY and the public NVD endpoint is rate-limited; the
#         goal of the Golden Path is to exercise triage + CRA + METI +
#         Evidence Pack, not to re-prove the NVD scanner.
# ----------------------------------------------------------------------------
echo "=== Step 3: seed Log4Shell vulnerability + component link ==="
VULN_ID="11111111-2222-4333-8444-555555555555"
psql_exec <<SQL
INSERT INTO vulnerabilities (
    id, cve_id, description, severity, cvss_score,
    source, published_at, updated_at, tenant_id
) VALUES (
    '${VULN_ID}',
    'CVE-2021-44228',
    'Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.',
    'CRITICAL',
    10.0,
    'NVD',
    NOW(),
    NOW(),
    NULL
)
ON CONFLICT (cve_id) DO UPDATE SET updated_at = NOW();

-- Link the freshly-uploaded log4j-core 2.14.0 component to CVE-2021-44228.
-- component_vulnerabilities has no RLS (global join table), so the
-- superuser path is canonical here. The join through (sboms.project_id,
-- components.name) is the tenant-scope check at the SQL layer.
INSERT INTO component_vulnerabilities (component_id, vulnerability_id, detected_at)
SELECT c.id, '${VULN_ID}', NOW()
FROM components c
JOIN sboms s ON s.id = c.sbom_id
WHERE s.project_id = '${PROJECT_ID}'
  AND c.name = 'log4j-core'
ON CONFLICT (component_id, vulnerability_id) DO NOTHING;
SQL

# Confirm at least one link row landed; if not, the SBOM upload either
# named the component differently or the project_id did not match.
LINK_COUNT=$(psql_query "
  SELECT COUNT(*)
  FROM component_vulnerabilities cv
  JOIN components c ON c.id = cv.component_id
  JOIN sboms s ON s.id = c.sbom_id
  WHERE s.project_id = '${PROJECT_ID}' AND cv.vulnerability_id = '${VULN_ID}'
")
assert_ge "${LINK_COUNT}" 1 "seeded component_vulnerabilities rows"

# ----------------------------------------------------------------------------
# Step 4: POST /api/v1/projects/:id/triage/run — expect ai_disabled=true
# ----------------------------------------------------------------------------
echo "=== Step 4: trigger AI VEX triage (AI-disabled fallback) ==="
TRIAGE_RESP=$(auth_curl POST "${SBOMHUB_URL}/api/v1/projects/${PROJECT_ID}/triage/run" \
  -d "{\"vulnerability_id\":\"${VULN_ID}\",\"cve_id\":\"CVE-2021-44228\"}")
echo "triage/run response: ${TRIAGE_RESP}"
AI_DISABLED=$(printf '%s' "${TRIAGE_RESP}" | jq -r '.ai_disabled // false')
assert_eq "${AI_DISABLED}" "true" "triage ai_disabled flag (M1 F4 fallback)"

# Pick the first draft id from the fan-out. With one log4j-core link
# the fan-out collapses to one draft, but the response shape uses an
# array regardless.
# ※要確認 (M1 残課題 #18): vex_drafts wire shape は現状 PascalCase
# (repository.VEXDraft が json tag 未付与、 cra_reports + meti_assessments で M2/M3 完了済)。
# .drafts[0].ID / .draft.ID を先に試し、 将来 snake_case 統一時の .id も fallback。
DRAFT_ID=$(printf '%s' "${TRIAGE_RESP}" | jq -r '.drafts[0].ID // .draft.ID // .drafts[0].id // .draft.id // empty')
if [ -z "${DRAFT_ID}" ] || [ "${DRAFT_ID}" = "null" ]; then
  echo "::error::triage/run did not return a draft id"
  exit 1
fi
echo "  OK draft_id = ${DRAFT_ID}"

# ----------------------------------------------------------------------------
# Step 5: GET /api/v1/projects/:id/vex-drafts — expect >=1
# ----------------------------------------------------------------------------
echo "=== Step 5: list vex_drafts ==="
DRAFTS_RESP=$(auth_curl GET "${SBOMHUB_URL}/api/v1/projects/${PROJECT_ID}/vex-drafts")
# response shape: bare array or {drafts: [...]} — try both
DRAFT_COUNT=$(printf '%s' "${DRAFTS_RESP}" | jq -r 'if type == "array" then length elif .drafts then (.drafts | length) else 0 end')
assert_ge "${DRAFT_COUNT}" 1 "vex_drafts row count"

# ----------------------------------------------------------------------------
# Step 6: PUT /api/v1/projects/:id/vex-drafts/:draft_id/decision (approve)
# ----------------------------------------------------------------------------
echo "=== Step 6: approve vex_draft ${DRAFT_ID} ==="
DECISION_RESP=$(auth_curl PUT \
  "${SBOMHUB_URL}/api/v1/projects/${PROJECT_ID}/vex-drafts/${DRAFT_ID}/decision" \
  -d '{"decision":"approved","note":"Golden Path E2E approved"}')
echo "decision response: ${DECISION_RESP}"
NEW_DECISION=$(printf '%s' "${DECISION_RESP}" | jq -r '.Decision // .decision // empty')
assert_eq "${NEW_DECISION}" "approved" "vex_draft decision"

# ----------------------------------------------------------------------------
# Step 7: POST /api/v1/projects/:id/cra-reports/run — expect ai_disabled=true
# ----------------------------------------------------------------------------
echo "=== Step 7: trigger CRA report drafting (AI-disabled fallback) ==="
# The runner requires an approved VEX draft for (project, cve), which
# Step 6 just produced. Pass the regulatory pass-through fields so the
# template renderer has something to fill in (the LLM never sees these
# — buildTemplateData enforces no-hallucination).
CRA_REQ=$(jq -nc \
  --arg v "${VULN_ID}" \
  '{
     vulnerability_id: $v,
     cve_id: "CVE-2021-44228",
     report_type: "early_warning",
     lang: "ja",
     product_name: "Golden Path E2E Product",
     product_version: "1.0.0",
     vendor_name: "Golden Path E2E Vendor",
     reporter_name: "Golden Path E2E",
     reporter_role: "CISO",
     contact_email: "e2e@example.com",
     contact_phone: "+81-3-0000-0000",
     awareness_time: "2026-06-24T00:00:00Z"
   }')
CRA_RESP=$(auth_curl POST \
  "${SBOMHUB_URL}/api/v1/projects/${PROJECT_ID}/cra-reports/run" \
  -d "${CRA_REQ}")
echo "cra-reports/run response: ${CRA_RESP}"
CRA_AI_DISABLED=$(printf '%s' "${CRA_RESP}" | jq -r '.ai_disabled // false')
assert_eq "${CRA_AI_DISABLED}" "true" "cra-reports ai_disabled flag (M2 F4 fallback)"
CRA_ID=$(printf '%s' "${CRA_RESP}" | jq -r '.report.id // .report.ID // empty')
if [ -z "${CRA_ID}" ] || [ "${CRA_ID}" = "null" ]; then
  echo "::error::cra-reports/run did not return a report id"
  exit 1
fi
echo "  OK cra_report_id = ${CRA_ID}"

# ----------------------------------------------------------------------------
# Step 8: PUT /api/v1/projects/:id/cra-reports/:report_id/decision (approve)
# ----------------------------------------------------------------------------
echo "=== Step 8: approve cra_report ${CRA_ID} ==="
CRA_DECISION_RESP=$(auth_curl PUT \
  "${SBOMHUB_URL}/api/v1/projects/${PROJECT_ID}/cra-reports/${CRA_ID}/decision" \
  -d '{"decision":"approved","decision_note":"Golden Path E2E approved"}')
echo "cra decision response: ${CRA_DECISION_RESP}"
CRA_NEW_DECISION=$(printf '%s' "${CRA_DECISION_RESP}" | jq -r '.decision // .Decision // empty')
assert_eq "${CRA_NEW_DECISION}" "approved" "cra_report decision"

# ----------------------------------------------------------------------------
# Step 9: POST /api/v1/projects/:id/meti/assessment/refresh
# ----------------------------------------------------------------------------
echo "=== Step 9: refresh METI 27-criterion assessment ==="
METI_RESP=$(auth_curl POST \
  "${SBOMHUB_URL}/api/v1/projects/${PROJECT_ID}/meti/assessment/refresh" \
  -d '{}')
echo "meti refresh response (truncated): $(printf '%s' "${METI_RESP}" | head -c 400)..."
REFRESHED=$(printf '%s' "${METI_RESP}" | jq -r '.refreshed // 0')
# The catalog ships with 27 criteria; we allow any value >= 1 so the
# assertion survives a future criterion-count bump without churn here.
# ※要確認: tighten to ==27 if/when the catalog count is frozen for v1.
assert_ge "${REFRESHED}" 1 "meti refreshed criterion count"

# ----------------------------------------------------------------------------
# Step 10: POST /api/v1/projects/:id/evidence-pack/build — fetch bundle
# ----------------------------------------------------------------------------
echo "=== Step 10: build Evidence Pack markdown bundle ==="
# Bundle body is markdown (text/markdown), not JSON; --fail-with-body
# still surfaces non-2xx bodies on stderr.
BUNDLE=$(curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer ${SBOMHUB_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{}' \
  "${SBOMHUB_URL}/api/v1/projects/${PROJECT_ID}/evidence-pack/build")

BUNDLE_LEN=$(printf '%s' "${BUNDLE}" | wc -c)
assert_ge "${BUNDLE_LEN}" 100 "evidence pack bundle length (bytes)"

# ----------------------------------------------------------------------------
# Step 11: assert each of the three required section headers is present
# ----------------------------------------------------------------------------
echo "=== Step 11: assert Evidence Pack section headers ==="
assert_contains "${BUNDLE}" "## 1. Approved VEX Statements" "VEX section header"
assert_contains "${BUNDLE}" "## 2. Approved CRA Reports"   "CRA section header"
assert_contains "${BUNDLE}" "## 3. METI 自己評価"          "METI section header"

# ----------------------------------------------------------------------------
# Step 12: assert the bundle actually folded in our approved artefacts
#          (not just empty section stubs)
# ----------------------------------------------------------------------------
echo "=== Step 12: assert approved artefacts populate their sections ==="
assert_contains "${BUNDLE}" "CVE-2021-44228" "Log4Shell CVE id in bundle"
# The METI section's per-phase subheading is rendered as
# "### 3.1 Phase: env\_setup" (underscore is markdown-escaped).
assert_contains "${BUNDLE}" "Phase: env" "METI env_setup phase rendered"

echo ""
echo "================================================================"
echo "Golden Path E2E: ALL 12 STEPS PASSED"
echo "  project_id      = ${PROJECT_ID}"
echo "  sbom_id         = ${SBOM_ID}"
echo "  vulnerability   = CVE-2021-44228 (Log4Shell)"
echo "  vex_draft       = ${DRAFT_ID} (approved)"
echo "  cra_report      = ${CRA_ID} (approved, AI-disabled)"
echo "  meti_refreshed  = ${REFRESHED} criteria"
echo "  bundle_bytes    = ${BUNDLE_LEN}"
echo "================================================================"
