#!/usr/bin/env bash
# extract-retracted.sh — read go.mod's retract block and print one
# "VERSION<TAB>REASON" line per retracted version.
#
# Used by:
#   - packages/.github/workflows/publish.yml (to exclude retracted
#     versions from apt/yum/arch/tarball mirrors and to write
#     get.dotsecenv.com/retracted.txt)
#   - scripts/install.sh (to refuse to install retracted versions)
#
# Reads ./go.mod by default; pass a path as $1 to override.
#
# Output format:
#   v0.6.10<TAB>no release published
#   v0.6.11<TAB>tag moved; duplicate upload attempted
#
# Supports both Go retract forms:
#   retract v1.2.3 // reason
#   retract (
#       v1.2.3 // reason
#       v1.2.4 // reason
#   )
#
# Version ranges (`retract [v1.0.0, v1.1.0]`) are NOT supported here;
# add explicit per-version entries if you need to retract a range.

set -euo pipefail

GO_MOD="${1:-go.mod}"
[ -f "$GO_MOD" ] || { echo "go.mod not found: $GO_MOD" >&2; exit 1; }

awk '
    function emit(version, reason) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", version)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", reason)
        if (version != "") printf "%s\t%s\n", version, reason
    }

    # Block form: retract (
    /^retract[[:space:]]*\(/ { in_block = 1; next }
    in_block && /^[[:space:]]*\)/ { in_block = 0; next }
    in_block {
        line = $0
        sub(/^[[:space:]]+/, "", line)
        if (line == "" || line ~ /^\/\//) next

        # Extract version (first token) and reason (after // if any).
        version = ""; reason = ""
        if (match(line, /^v[0-9]+\.[0-9]+\.[0-9]+[^[:space:]]*/)) {
            version = substr(line, RSTART, RLENGTH)
            rest = substr(line, RSTART + RLENGTH)
            if (match(rest, /\/\//)) {
                reason = substr(rest, RSTART + RLENGTH)
            }
        }
        emit(version, reason)
        next
    }

    # Single-line form: retract v1.2.3 // reason
    /^retract[[:space:]]+v[0-9]/ {
        line = $0
        sub(/^retract[[:space:]]+/, "", line)
        version = ""; reason = ""
        if (match(line, /^v[0-9]+\.[0-9]+\.[0-9]+[^[:space:]]*/)) {
            version = substr(line, RSTART, RLENGTH)
            rest = substr(line, RSTART + RLENGTH)
            if (match(rest, /\/\//)) {
                reason = substr(rest, RSTART + RLENGTH)
            }
        }
        emit(version, reason)
    }
' "$GO_MOD"
