#!/usr/bin/env bash
#
# Assess changelog completeness.
#
# Lists PRs merged since the last release tag that are NOT yet recorded under
# the "## Upcoming" section of the website changelog. Run it in the release
# PR (and any time you want to verify the changelog is keeping up). Release
# notes are meant to build up one entry per PR, so this should normally be
# empty.
#
# Exit codes: 0 = changelog covers everything since the last tag,
#             1 = some commits are missing, 2 = setup error.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && cd ../.. && pwd)"
CL="$ROOT/website/src/content/docs/changelog.mdx"

command -v git >/dev/null 2>&1 || { echo "error: git not found on PATH" >&2; exit 2; }
[ -f "$CL" ] || { echo "error: changelog not found: $CL" >&2; exit 2; }

git -C "$ROOT" fetch --tags --quiet origin 2>/dev/null || true
LAST="$(git -C "$ROOT" describe --tags --abbrev=0 2>/dev/null || true)"
[ -n "$LAST" ] || { echo "error: no release tags found (git describe --tags)" >&2; exit 2; }
echo "==> last release tag: $LAST"

# PR numbers already recorded under "## Upcoming" (until the next "## ").
recorded="$(awk '/^## Upcoming$/ {f=1; next} /^## / {f=0} f' "$CL" \
  | grep -oE '#[0-9]+' | tr -d '#' | sort -u || true)"

echo
echo "==> commits since ${LAST} not yet under '## Upcoming':"
missing=0
while IFS= read -r subject; do
  [ -n "$subject" ] || continue
  pr="$(printf '%s' "$subject" | grep -oE '\(#[0-9]+\)$' | grep -oE '[0-9]+' || true)"
  if [ -n "$pr" ] && printf '%s\n' "$recorded" | grep -qx "$pr"; then
    continue
  fi
  printf '  %-10s %s\n' "${pr:+#$pr}" "$subject"
  missing=$((missing + 1))
done < <(git -C "$ROOT" log "${LAST}..HEAD" --pretty='%s')

echo
if [ "$missing" -ne 0 ]; then
  echo "RESULT: ${missing} commit(s) since ${LAST} are not in 'Upcoming'." >&2
  echo "Add an entry for each (see skills/changelog/SKILL.md) before releasing." >&2
  exit 1
fi
echo "RESULT: 'Upcoming' covers every commit since ${LAST}."
