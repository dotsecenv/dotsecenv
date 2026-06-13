#!/usr/bin/env bash
#
# CLI reference drift check.
#
# The website CLI reference (website/src/content/docs/reference.mdx) is
# hand-curated and NOT generated, so it can drift from the real CLI. This
# script generates the command + flag inventory from source and verifies every
# command and command-specific flag is documented in reference.mdx. Run it
# before every release.
#
# Exit codes: 0 = no drift, 1 = drift detected, 2 = setup error.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && cd ../.. && pwd)"
REF="$ROOT/website/src/content/docs/reference.mdx"

command -v go >/dev/null 2>&1 || { echo "error: go toolchain not found on PATH" >&2; exit 2; }
command -v make >/dev/null 2>&1 || { echo "error: make not found on PATH" >&2; exit 2; }
[ -f "$REF" ] || { echo "error: reference page not found: $REF" >&2; exit 2; }

# Generate the CLI inventory via the canonical Makefile target so the
# generation command stays a single source of truth. `make docs` writes the
# per-command markdown to build/cli; remove any stale output first so a deleted
# command does not leave a lingering file.
CLI="$ROOT/build/cli"
echo "==> generating CLI inventory from source (make docs)"
rm -rf "$CLI"
( cd "$ROOT" && make docs >/dev/null )

drift=0

echo
echo "==> commands missing a heading in reference.mdx"
for f in "$CLI"/*.md; do
  base="$(basename "$f" .md)"            # e.g. dotsecenv_secret_get
  cmd="${base//_/ }"                     # e.g. dotsecenv secret get
  doc="${cmd#dotsecenv}"; doc="${doc# }" # e.g. secret get   (root -> "")
  needle="${doc:-dotsecenv}"             # root command -> the "## dotsecenv" heading
  if ! grep -qE "^#{1,6} ${needle}\$" "$REF"; then
    echo "  MISSING command: '${cmd}' (expected a heading '${needle}')"
    drift=1
  fi
done

echo
echo "==> command-specific flags missing from reference.mdx"
for f in "$CLI"/*.md; do
  base="$(basename "$f" .md)"
  cmd="${base//_/ }"
  # Long flags from the command's OWN "### Options" block (not inherited ones).
  flags="$(awk '
    /^### Options$/ { inopt = 1; next }
    /^### /         { inopt = 0 }
    inopt           { print }
  ' "$f" | grep -oE -- '--[a-zA-Z][a-zA-Z0-9-]*' | sort -u | grep -vx -- '--help' || true)"
  for fl in $flags; do
    if ! grep -qF -- "$fl" "$REF"; then
      echo "  MISSING flag: '${fl}' (command '${cmd}')"
      drift=1
    fi
  done
done

echo
echo "==> duplicate headings in reference.mdx"
dupes="$(grep -E '^#{2,3} ' "$REF" | sed -E 's/^#{2,3} //' | sort | uniq -d || true)"
if [ -n "$dupes" ]; then
  while IFS= read -r d; do echo "  DUPLICATE heading: '${d}'"; done <<<"$dupes"
  drift=1
fi

echo
if [ "$drift" -ne 0 ]; then
  cat >&2 <<'EOF'
RESULT: drift detected.

Update website/src/content/docs/reference.mdx to add the missing command(s) or
flag(s) (match the page's style: description, options table, examples) and
remove any duplicate/stale section, then re-run this check until it passes.

Known false positives: `completion bash|zsh|fish` are documented under
`## completion` as `### Bash|Zsh|Fish`, not as `### completion <shell>`.
EOF
  exit 1
fi
echo "RESULT: no drift — every command and flag is documented, no duplicate headings."
