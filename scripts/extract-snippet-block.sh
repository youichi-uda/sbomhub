#!/usr/bin/env bash
# scripts/extract-snippet-block.sh
#
# Extracts the body of a fenced code block that lives between a pair of
# HTML-comment markers in a markdown file:
#
#   <!-- ${MARKER}:start -->
#   ```bash
#   ...code...
#   ```
#   <!-- /${MARKER} -->
#
# The output is the raw code (no fence lines, no marker lines) so it can be
# `eval`'d or piped to `bash`. We deliberately strip the ``` fences only
# inside the marker block; fences elsewhere in the document are ignored.
#
# Used by .github/workflows/docs-curl-smoke.yml to extract the canonical
# `curl` example from docs/snippets/curl-upload.md and execute it against a
# live api, so the docs cannot silently drift away from the actual API
# contract (Trust Rescue P1 #11 / 9.3.3).
#
# Usage:
#   bash scripts/extract-snippet-block.sh <markdown-file> <marker-name>
#
# Example:
#   bash scripts/extract-snippet-block.sh \
#       docs/snippets/curl-upload.md ci:smoke-test
#
# Exit codes:
#   0 - block extracted (may be empty if the block contained no code)
#   2 - usage error
#   3 - file missing or unreadable

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <markdown-file> <marker-name>" >&2
  echo "  marker-name is the bare name; the script looks for" >&2
  echo "    <!-- <name>:start -->  and  <!-- /<name> -->" >&2
  exit 2
fi

file="$1"
marker="$2"

if [ ! -r "$file" ]; then
  echo "error: cannot read markdown file: $file" >&2
  exit 3
fi

awk -v start_marker="<!-- ${marker}:start -->" \
    -v end_marker="<!-- /${marker} -->" '
  # Trim trailing CR so CRLF-checked-out files still match the markers.
  { sub(/\r$/, "") }

  $0 == start_marker { in_block = 1; in_code = 0; next }
  $0 == end_marker   { in_block = 0; in_code = 0; next }

  # Inside the marker block, toggle on every ``` line so we only emit
  # the code between the fences (not the fence lines themselves, nor any
  # narrative text that might sit between the markers and the fence).
  in_block && /^[[:space:]]*```/ { in_code = !in_code; next }

  in_block && in_code { print }
' "$file"
