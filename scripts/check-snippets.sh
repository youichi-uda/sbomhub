#!/usr/bin/env bash
# scripts/check-snippets.sh
#
# Enforces single-source ownership of canonical code snippets under
# docs/snippets/. Each snippet declares one or more "signature" lines via
# an HTML comment of the form:
#
#   <!-- check-snippets:signature: <verbatim line that must live ONLY in this snippet> -->
#
# The script scans the rest of the repository for those signatures. Any
# match outside docs/snippets/ is treated as snippet drift: the docs file
# should link to the snippet instead of duplicating the code.
#
# Usage:
#   bash scripts/check-snippets.sh
#
# Exit codes:
#   0 - no drift detected
#   1 - drift detected, or snippet directory missing / has no signatures

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SNIPPET_DIR="$REPO_ROOT/docs/snippets"

if [ ! -d "$SNIPPET_DIR" ]; then
  echo "error: snippet dir not found: $SNIPPET_DIR" >&2
  exit 1
fi

fail=0
found_signature=0

# Build the list of files to grep. Excludes vendored / build dirs and the
# snippet directory itself (signatures legitimately live there).
search_files() {
  find "$REPO_ROOT" \
    \( -path "$REPO_ROOT/.git" -o \
       -path "$REPO_ROOT/node_modules" -o \
       -path "$REPO_ROOT/docs/snippets" -o \
       -path "*/node_modules" -o \
       -path "*/dist" -o \
       -path "*/.next" \) -prune -o \
    -type f \
    \( -name "*.md" -o -name "*.tsx" -o -name "*.ts" -o \
       -name "*.yml" -o -name "*.yaml" -o -name "*.sh" \) \
    -print
}

mapfile -t SEARCH_TARGETS < <(search_files)

for snippet in "$SNIPPET_DIR"/*.md; do
  [ -f "$snippet" ] || continue

  # Pull every signature declared in this snippet.
  while IFS= read -r raw; do
    # Strip the HTML-comment wrapper:
    #   <!-- check-snippets:signature: <PAYLOAD> -->
    sig="$(printf '%s' "$raw" \
      | sed -E 's@^.*check-snippets:signature:[[:space:]]*@@; s@[[:space:]]*-->.*$@@')"

    if [ -z "$sig" ]; then
      continue
    fi
    found_signature=1

    # Look for the signature in every search target.
    matches=()
    for target in "${SEARCH_TARGETS[@]}"; do
      if grep -Fq -- "$sig" "$target" 2>/dev/null; then
        matches+=("$target")
      fi
    done

    if [ "${#matches[@]}" -gt 0 ]; then
      echo "FAIL: canonical snippet line duplicated outside docs/snippets/" >&2
      echo "  declared in : ${snippet#$REPO_ROOT/}" >&2
      echo "  signature   : $sig" >&2
      echo "  also in     :" >&2
      for m in "${matches[@]}"; do
        echo "    ${m#$REPO_ROOT/}" >&2
      done
      echo "  fix         : replace the duplicated block with a link to the snippet." >&2
      echo "" >&2
      fail=1
    fi
  done < <(grep -E '<!--[[:space:]]*check-snippets:signature:' "$snippet" || true)
done

if [ "$found_signature" -eq 0 ]; then
  echo "error: no <!-- check-snippets:signature: ... --> declarations found under $SNIPPET_DIR" >&2
  echo "       every snippet must declare at least one signature line." >&2
  exit 1
fi

if [ "$fail" -ne 0 ]; then
  echo "Snippet drift detected. Update the listed files to link to docs/snippets/ instead of inlining the snippet." >&2
  exit 1
fi

echo "OK: all canonical snippets are single-sourced."
