#!/usr/bin/env bash
#
# SBOMHub nightly ENCRYPTION_KEY decrypt smoke test cron wrapper.
#
# Designed for cron / systemd timer one-line invocation.
# Preserves verify-encryption.sh exit code while logging to syslog.

set -uo pipefail

INSTALL_DIR="${SBOMHUB_INSTALL_DIR:-/opt/sbomhub}"
APP_PW_FILE="${SBOMHUB_APP_PW_FILE:-${INSTALL_DIR}/docker/secrets/postgres_app_password.txt}"
KEY_FILE="${SBOMHUB_KEY_FILE:-${INSTALL_DIR}/docker/secrets/encryption_key.txt}"
DB_HOST="${SBOMHUB_DB_HOST:-127.0.0.1}"
DB_PORT="${SBOMHUB_DB_PORT:-5432}"
DB_NAME="${SBOMHUB_DB_NAME:-sbomhub}"
DB_USER="${SBOMHUB_DB_USER:-sbomhub_app}"
DB_SSL="${SBOMHUB_DB_SSLMODE:-disable}"

# URL encode helper shared with the operator docs. This keeps the cron path
# portable to minimal hosts without requiring a Python runtime.
urlenc() {
    printf '%s' "$1" | sed -e 's/%/%25/g' -e 's/+/%2B/g' -e 's|/|%2F|g' \
        -e 's/=/%3D/g' -e 's/@/%40/g' -e 's/:/%3A/g' \
        -e 's/?/%3F/g' -e 's/#/%23/g' -e 's/&/%26/g'
}

if [[ ! -r "${APP_PW_FILE}" ]]; then
    logger -t sbomhub-verify -p daemon.err "FATAL: cannot read ${APP_PW_FILE}"
    exit 65
fi
if [[ ! -r "${KEY_FILE}" ]]; then
    logger -t sbomhub-verify -p daemon.err "FATAL: cannot read ${KEY_FILE}"
    exit 65
fi

APP_PW="$(cat "${APP_PW_FILE}")"
APP_PW_ENC="$(urlenc "${APP_PW}")"
export DATABASE_URL="postgres://${DB_USER}:${APP_PW_ENC}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=${DB_SSL}"

cd "${INSTALL_DIR}" || {
    logger -t sbomhub-verify -p daemon.err "FATAL: cannot cd to ${INSTALL_DIR}"
    unset APP_PW APP_PW_ENC DATABASE_URL
    exit 65
}

"${INSTALL_DIR}/docker/scripts/verify-encryption.sh" --key-file "${KEY_FILE}" \
    > >(logger -t sbomhub-verify -p daemon.info) \
    2> >(logger -t sbomhub-verify -p daemon.err)
RC=$?

# Best-effort cleanup of plaintext password values from this process.
unset APP_PW APP_PW_ENC DATABASE_URL

exit "${RC}"
