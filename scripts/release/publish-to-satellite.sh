#!/usr/bin/env bash
#
# Sync a monorepo subdirectory to a satellite repo's root, commit, push to
# its main, and create + push a tag.
#
# The commit + push use the GitHub App's [bot] identity (derived from the
# token via /user). The satellite's ruleset has this App in the bypass
# list, so unsigned commits + direct push to main are accepted; no GPG
# signing is needed in this flow. (Archive signing for binaries still
# happens in goreleaser via its own GPG_PRIVATE_KEY import.)
#
# Required env:
#   SOURCE_DIR     path to the monorepo subdirectory to publish (e.g. "plugin")
#   SATELLITE_DIR  path to the satellite checkout (e.g. "plugin-satellite")
#   TAG            release tag (e.g. "v0.6.2")
#   SHA            monorepo commit SHA being published (for .release-sha sidecar)
#   APP_TOKEN      installation token used to authenticate the push and look
#                  up the App's bot identity
#
# Required tools in PATH (caller installs):
#   rsync, git, jq, curl, rt (releasetools/cli@v0 in CI, mise/brew locally)

set -euo pipefail

: "${SOURCE_DIR:?SOURCE_DIR is required}"
: "${SATELLITE_DIR:?SATELLITE_DIR is required}"
: "${TAG:?TAG is required}"
: "${SHA:?SHA is required}"
: "${APP_TOKEN:?APP_TOKEN is required}"

# Resolve the App's bot user. /user returns the authenticated identity for
# the token; for a GitHub App installation token, that's "<slug>[bot]".
bot_json=$(curl -fsS -H "Authorization: Bearer ${APP_TOKEN}" \
                    -H "Accept: application/vnd.github+json" \
                    https://api.github.com/user)
bot_login=$(jq -r .login <<<"${bot_json}")
bot_id=$(jq -r .id <<<"${bot_json}")
bot_email="${bot_id}+${bot_login}@users.noreply.github.com"
echo "Committer identity: ${bot_login} <${bot_email}>"

# Sync source -> satellite. --delete makes deletions propagate. Exclude
# .git so we don't blow away the satellite's git metadata.
rsync -a --delete --exclude='.git' "${SOURCE_DIR}/" "${SATELLITE_DIR}/"
echo "${SHA}" > "${SATELLITE_DIR}/.release-sha"

cd "${SATELLITE_DIR}"
git config user.name "${bot_login}"
git config user.email "${bot_email}"
git add -A

if git diff --cached --quiet; then
  echo "No content changes for ${TAG}; skipping commit"
else
  git commit -m "publish: ${TAG}" -m "Sourced from dotsecenv/dotsecenv@${SHA}"
  git push origin HEAD:main
fi

# Tag the satellite at its current main HEAD (just-pushed if we committed,
# previous tip otherwise). Idempotent: if a local tag of the same name
# lingers from a prior partial run, delete it first. rt creates an
# annotated tag and pushes it; the App's bypass also covers tag refs.
git tag -d "${TAG}" 2>/dev/null || true
rt git::release --push "${TAG}"
