#!/usr/bin/env bash
# extract-retracted.sh — emit retracted versions from a go.mod retract block.
#
# Uses the canonical Go tooling (`go mod edit -json`) for parsing rather
# than regex/awk, so we inherit the toolchain's exact semantics — block
# vs single-line forms, line continuations, comments — without
# reimplementing them.
#
# Used by:
#   - .github/workflows/release.yml (to generate packages/retracted.txt
#     before pushing the monorepo packages/ source to the satellite)
#   - scripts/install.sh (to refuse to install retracted versions)
#
# Output: one "VERSION<TAB>REASON" line per retracted version.
#
# Range retracts (`retract [v1.0.0, v1.1.0]`) emit a single line for
# their Low version. In practice this project retracts specific
# releases, not ranges; widen here only if that changes.
#
# Reads ./go.mod by default; pass a path as $1 to override.

set -euo pipefail

GO_MOD="${1:-go.mod}"
[ -f "$GO_MOD" ] || { echo "go.mod not found: $GO_MOD" >&2; exit 1; }

command -v go  >/dev/null || { echo "go not found in PATH" >&2; exit 1; }
command -v jq  >/dev/null || { echo "jq not found in PATH" >&2; exit 1; }

go mod edit -json "$GO_MOD" | \
    jq -r '(.Retract // [])[] | "\(.Low)\t\(.Rationale // "")"'
