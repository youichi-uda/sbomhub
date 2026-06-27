#!/usr/bin/env sh
# SBOMHub shared env helpers (M7-2).
# Source this file: . docker/scripts/_env_helpers.sh

# Defensive .env value extractor:
# - count check (missing / duplicate fail-loud)
# - quote strip (matches Compose env loader)
# - empty check AFTER strip (catches "" / '' empty values)
read_env_var() {
    key="$1"
    count="$(grep -c "^${key}=" .env || true)"
    if [ "$count" -eq 0 ]; then
        echo "[FATAL] ${key} is missing in .env" >&2
        exit 1
    fi
    if [ "$count" -gt 1 ]; then
        echo "[FATAL] ${key} is duplicated in .env (${count} occurrences); resolve manually" >&2
        exit 1
    fi
    raw="$(grep "^${key}=" .env | cut -d= -f2-)"
    raw="${raw#\"}"
    raw="${raw%\"}"
    raw="${raw#\'}"
    raw="${raw%\'}"
    if [ -z "$raw" ]; then
        echo "[FATAL] ${key} is empty (or only whitespace/quotes) in .env" >&2
        exit 1
    fi
    printf '%s' "$raw"
}

# Defensive .env value writer (in-place update via temp file):
# - Pass value via env (WRITE_ENV_VALUE) to avoid argv leak (F136 pattern)
# - Verify post-update count is 1 (defense against awk regex drift)
write_env_var() {
    key="$1"
    value="$2"
    tmp="$(mktemp)"
    WRITE_ENV_VALUE="$value" awk -v key="${key}=" '
        BEGIN { val = ENVIRON["WRITE_ENV_VALUE"] }
        $0 ~ "^" key { print key val; next }
        { print }
    ' .env > "$tmp"
    count="$(grep -c "^${key}=" "$tmp" || true)"
    if [ "$count" -ne 1 ]; then
        rm -f "$tmp"
        echo "[FATAL] write_env_var: ${key} count after update is ${count}, expected 1" >&2
        exit 1
    fi
    mv "$tmp" .env
}

# URL encode helper (F106):
# - Compose env loader compatible URL encoding for special chars
urlenc() {
    printf '%s' "$1" | sed -e 's/%/%25/g' -e 's/+/%2B/g' -e 's|/|%2F|g' \
        -e 's/=/%3D/g' -e 's/@/%40/g' -e 's/:/%3A/g' \
        -e 's/?/%3F/g' -e 's/#/%23/g' -e 's/&/%26/g'
}

pgpass_escape() {
    raw="$1"
    # .pgpass is line-based; embedded newline/CR would corrupt record boundaries.
    if [ "$(printf '%s' "$raw" | tr -d '\n\r')" != "$raw" ]; then
        echo "[FATAL] pgpass_escape: password contains newline/CR, refusing (.pgpass is line-based)" >&2
        exit 1
    fi
    # .pgpass field values must escape backslash and colon.
    printf '%s' "$raw" | sed -e 's/\\/\\\\/g' -e 's/:/\\:/g'
}
