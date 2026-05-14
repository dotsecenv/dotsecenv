#!/usr/bin/env bash
#
# Sync a monorepo subdirectory to a satellite repo's root, commit (signed),
# push to its main, and create + push a signed tag.
#
# Required env:
#   SOURCE_DIR     path to the monorepo subdirectory to publish (e.g. "plugin")
#   SATELLITE_DIR  path to the satellite checkout (e.g. "plugin-satellite")
#   TAG            release tag (e.g. "v0.6.2")
#   SHA            monorepo commit SHA being published (for .release-sha sidecar)
#
# Required git config (set by the caller, typically via
# crazy-max/ghaction-import-gpg + GIT_*_NAME/EMAIL env):
#   user.signingkey  pointing at the [S]-capable subkey (with ! suffix)
#   commit.gpgsign   true
#
# Required tools in PATH (caller installs):
#   rsync, git, rt (releasetools/cli@v0 in CI, mise/brew locally)
#
# Behaviour:
#   1. rsync source -> satellite root (excluding .git). Deletions propagate.
#   2. Write .release-sha sidecar.
#   3. If there are content changes, commit them (signed) and push to main.
#      If not, skip the commit but still tag (tag points at current main).
#   4. Create a signed tag at HEAD and push it via `rt git::release`.

set -euo pipefail

: "${SOURCE_DIR:?SOURCE_DIR is required}"
: "${SATELLITE_DIR:?SATELLITE_DIR is required}"
: "${TAG:?TAG is required}"
: "${SHA:?SHA is required}"

# Sync source -> satellite. --delete makes deletions propagate. Exclude .git
# so we don't blow away the satellite's git metadata.
rsync -a --delete --exclude='.git' "${SOURCE_DIR}/" "${SATELLITE_DIR}/"
echo "${SHA}" > "${SATELLITE_DIR}/.release-sha"

cd "${SATELLITE_DIR}"
git add -A

if git diff --cached --quiet; then
  echo "No content changes for ${TAG}; skipping commit"
else
  git commit -S -m "publish: ${TAG}" -m "Sourced from dotsecenv/dotsecenv@${SHA}"
  git push origin HEAD:main
fi

# Tag the satellite at its current main HEAD (just-pushed if we committed,
# previous tip otherwise) using releasetools/rt — same tool the previous
# satellite-side tag-release.yml used, kept for consistency and so any
# release-tooling conventions (signing, message format) stay uniform across
# repos. Idempotent: if a local tag of the same name lingers from a prior
# partial run, delete it first.
git tag -d "${TAG}" 2>/dev/null || true
rt git::release --sign --push "${TAG}"
