#!/usr/bin/env bash
#
# verify-encryption.sh — ENCRYPTION_KEY decrypt smoke test for SBOMHub.
#
# Issue: youichi-uda/sbomhub#53 (M5 Wave M5-5).
# Pairs with: apps/api/cmd/decrypt-test/main.go (the Go binary that owns the
# AES-256-GCM decrypt logic — single source of truth shared with the runtime
# API server via internal/service/llm.Decrypt).
#
# Purpose:
#   Confirm that the currently-configured ENCRYPTION_KEY can decrypt at least
#   one existing encrypted-column row in the DB. This is a *fail-fast smoke
#   test*, not full data verification — it answers the binary question
#   "is this key correct for this DB" without round-tripping every secret.
#
# Typical operator workflows:
#   * After restore (post-Step 7 of restore.sh): confirm restored secrets
#     match the restored DB.
#   * After ENCRYPTION_KEY rotation (Step 4 of docs/encryption-key-rotation.md):
#     confirm the new key + re-encrypted rows are consistent before traffic.
#   * Drift check from cron: catch silent key/ciphertext divergence between
#     secrets store and DB before users hit "failed to decrypt" in the UI.
#
# Security posture:
#   * The plaintext is NEVER printed. The Go binary emits a SHA256 hash of the
#     plaintext on success — the operator can compare hashes across rotations
#     without ever seeing the API token / secret in plain text.
#   * ENCRYPTION_KEY env / legacy --key are passed to the Go binary via env
#     so they never appear on the process command line / ps output.
#   * --key-file is passed through to decrypt-test so the Go binary reads the
#     raw file bytes directly, including any trailing newline.
#
# Exit code contract (matches apps/api/cmd/decrypt-test/main.go):
#   0   ok                        decrypt succeeded
#   1   key mismatch / corrupt    decrypt failed (wrong key or tampered row)
#   2   db error                  connection / query failure
#   3   no encrypted row to test  table empty / NULL ciphertext (setup incomplete)
#   64  usage / flag error
#   65  Go toolchain / binary missing (script-level prereq error)
#
# Usage:
#   ENCRYPTION_KEY=... ./scripts/verify-encryption.sh [--db-url <DSN>] \
#       [--key-file <path>] [--table T] [--column C] [--format bytea|base64]
#
# Env (defaults):
#   ENCRYPTION_KEY       master key (required unless --key-file is used)
#   DATABASE_URL         Postgres DSN (required; --db-url argv overrides)
#   DECRYPT_TEST_BIN     pre-built decrypt-test binary path; if unset the
#                        script falls back to `go run ./cmd/decrypt-test`
#                        from apps/api (requires Go toolchain in PATH).
#   GO_BIN               `go` binary to use for the fallback (default: `go`)
#
# Examples:
#   # 1. Manual, BYOK LLM key path (default):
#   export DATABASE_URL="postgres://sbomhub_app:...@127.0.0.1:5432/sbomhub?sslmode=disable"
#   ENCRYPTION_KEY="$(cat /run/secrets/encryption_key)" \
#       ./scripts/verify-encryption.sh
#
#   # Equivalent file-based key path that avoids putting the secret in argv:
#   export DATABASE_URL="postgres://sbomhub_app:...@127.0.0.1:5432/sbomhub?sslmode=disable"
#   ./scripts/verify-encryption.sh \
#       --key-file /run/secrets/encryption_key
#   # --key-file preserves raw file bytes; unlike command substitution, a
#   # trailing newline remains part of the key material seen by decrypt-test.
#
#   # 2. Issue-tracker token path (TEXT base64):
#   ./scripts/verify-encryption.sh \
#       --table issue_tracker_connections \
#       --column auth_token_encrypted
#
#   # 3. From restore.sh post-step (VERIFY_ENCRYPTION=1).

set -euo pipefail

# ---------------------------------------------------------------------------
# arg parse
# ---------------------------------------------------------------------------

KEY="${ENCRYPTION_KEY:-}"
DB_URL="${DATABASE_URL:-}"
KEY_FILE=""
TABLE=""
COLUMN=""
FORMAT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --key)
            echo "[verify-encryption] WARN: --key is deprecated because secrets in argv can leak via ps; use ENCRYPTION_KEY env or --key-file instead." >&2
            KEY="${2:-}"; shift 2 ;;
        --key=*)
            echo "[verify-encryption] WARN: --key is deprecated because secrets in argv can leak via ps; use ENCRYPTION_KEY env or --key-file instead." >&2
            KEY="${1#--key=}"; shift ;;
        --key-file)
            KEY_FILE="${2:-}"; shift 2 ;;
        --key-file=*)
            KEY_FILE="${1#--key-file=}"; shift ;;
        --db-url)
            DB_URL="${2:-}"; shift 2 ;;
        --db-url=*)
            DB_URL="${1#--db-url=}"; shift ;;
        --table)
            TABLE="${2:-}"; shift 2 ;;
        --table=*)
            TABLE="${1#--table=}"; shift ;;
        --column)
            COLUMN="${2:-}"; shift 2 ;;
        --column=*)
            COLUMN="${1#--column=}"; shift ;;
        --format)
            FORMAT="${2:-}"; shift 2 ;;
        --format=*)
            FORMAT="${1#--format=}"; shift ;;
        -h|--help)
            sed -n '1,/^set -euo/p' "$0" | sed -n '/^#/p' >&2
            exit 0
            ;;
        *)
            echo "[verify-encryption] FATAL: unknown argument: $1" >&2
            exit 64
            ;;
    esac
done

if [[ -n "${KEY_FILE}" ]]; then
    if [[ ! -r "${KEY_FILE}" ]]; then
        echo "[verify-encryption] FATAL: --key-file is not readable: ${KEY_FILE}" >&2
        exit 64
    fi
fi

if [[ -z "${KEY}" && -z "${KEY_FILE}" ]]; then
    echo "[verify-encryption] FATAL: ENCRYPTION_KEY env or --key-file is required" >&2
    exit 64
fi
if [[ -z "${DB_URL}" ]]; then
    echo "[verify-encryption] FATAL: DATABASE_URL (env or --db-url) is required" >&2
    echo "[verify-encryption]        e.g. postgres://sbomhub_app:...@postgres:5432/sbomhub?sslmode=disable" >&2
    exit 64
fi

# ---------------------------------------------------------------------------
# locate decrypt-test binary
# ---------------------------------------------------------------------------
#
# Two paths, in this preference order:
#   1. DECRYPT_TEST_BIN env (pre-built binary, fastest, suitable for cron).
#   2. `go run ./cmd/decrypt-test` from apps/api (works in a source checkout
#      without a separate build step). Requires Go toolchain.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
API_DIR="$(cd "${DOCKER_DIR}/../apps/api" 2>/dev/null && pwd || true)"

run_decrypt_test() {
    local args=("$@")
    if [[ -n "${DECRYPT_TEST_BIN:-}" ]]; then
        if [[ ! -x "${DECRYPT_TEST_BIN}" ]]; then
            echo "[verify-encryption] FATAL: DECRYPT_TEST_BIN is set but not executable: ${DECRYPT_TEST_BIN}" >&2
            exit 65
        fi
        ENCRYPTION_KEY="${KEY}" DATABASE_URL="${DB_URL}" \
            "${DECRYPT_TEST_BIN}" "${args[@]}"
        return $?
    fi

    local go_bin="${GO_BIN:-go}"
    if ! command -v "${go_bin}" >/dev/null 2>&1; then
        echo "[verify-encryption] FATAL: neither DECRYPT_TEST_BIN nor '${go_bin}' (Go toolchain) is available." >&2
        echo "[verify-encryption]        Either build the binary once with:" >&2
        echo "[verify-encryption]            (cd apps/api && go build -o ../../docker/bin/decrypt-test ./cmd/decrypt-test)" >&2
        echo "[verify-encryption]        and export DECRYPT_TEST_BIN=docker/bin/decrypt-test," >&2
        echo "[verify-encryption]        or install Go and put it in PATH." >&2
        exit 65
    fi
    if [[ -z "${API_DIR}" || ! -d "${API_DIR}" ]]; then
        echo "[verify-encryption] FATAL: apps/api source tree not found; cannot fall back to 'go run'." >&2
        echo "[verify-encryption]        Build the binary and point DECRYPT_TEST_BIN at it." >&2
        exit 65
    fi
    (
        cd "${API_DIR}"
        ENCRYPTION_KEY="${KEY}" DATABASE_URL="${DB_URL}" \
            "${go_bin}" run ./cmd/decrypt-test "${args[@]}"
    )
}

# ---------------------------------------------------------------------------
# build argv (we deliberately do NOT pass --key / --db-url on argv — the Go
# binary reads them from env, keeping those secret values out of
# /proc/<pid>/cmdline. --key-file is passed through by path so decrypt-test can
# read raw file bytes without shell command-substitution newline trimming.)
# ---------------------------------------------------------------------------

ARGS=()
if [[ -n "${KEY_FILE}" ]]; then
    ARGS+=("--key-file" "${KEY_FILE}")
fi
if [[ -n "${TABLE}" ]]; then
    ARGS+=("--table" "${TABLE}")
fi
if [[ -n "${COLUMN}" ]]; then
    ARGS+=("--column" "${COLUMN}")
fi
if [[ -n "${FORMAT}" ]]; then
    ARGS+=("--format" "${FORMAT}")
fi

echo "[verify-encryption] running decrypt-test (table=${TABLE:-tenant_llm_config} column=${COLUMN:-encrypted_api_key})..." >&2

# Capture exit code without losing the 0..127 contract.
set +e
run_decrypt_test "${ARGS[@]}"
RC=$?
set -e

case "${RC}" in
    0)
        echo "[verify-encryption] OK: decrypt round-trip succeeded." >&2
        ;;
    1)
        echo "[verify-encryption] FAIL: key mismatch or ciphertext corrupt (exit 1)." >&2
        echo "[verify-encryption]       - Wrong ENCRYPTION_KEY for this DB, OR" >&2
        echo "[verify-encryption]       - tampered ciphertext / column-format mismatch." >&2
        echo "[verify-encryption]       Cross-check secrets/encryption_key.txt against the value the API server" >&2
        echo "[verify-encryption]       used when this row was last encrypted (see docs/encryption-key-rotation.md)." >&2
        ;;
    2)
        echo "[verify-encryption] FAIL: DB connection or query error (exit 2)." >&2
        echo "[verify-encryption]       Check DATABASE_URL and that the role has SELECT on the target table." >&2
        ;;
    3)
        echo "[verify-encryption] WARN: no encrypted row to test (exit 3)." >&2
        echo "[verify-encryption]       Either no BYOK row has been written yet, or another table was targeted." >&2
        echo "[verify-encryption]       Re-run against issue_tracker_connections.auth_token_encrypted if you" >&2
        echo "[verify-encryption]       have a Jira/Backlog connection configured:" >&2
        echo "[verify-encryption]         $0 --table issue_tracker_connections --column auth_token_encrypted" >&2
        ;;
    64)
        echo "[verify-encryption] FAIL: usage / flag error (exit 64)." >&2
        ;;
    65)
        echo "[verify-encryption] FAIL: prerequisite missing (exit 65)." >&2
        ;;
    *)
        echo "[verify-encryption] FAIL: unexpected exit code ${RC}." >&2
        ;;
esac

exit "${RC}"
