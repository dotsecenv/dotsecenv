#!/usr/bin/env bash
#
# Sync a monorepo subdirectory to a satellite repo, creating a SIGNED commit
# on its main branch via GitHub's GraphQL `createCommitOnBranch` mutation,
# then push a lightweight tag at that commit.
#
# GraphQL-created commits are signed server-side by GitHub when issued with
# an App installation token, so the satellite's "required signatures" rule
# is satisfied without any GPG handling on the runner. The App also lives
# in the ruleset's bypass list, so the PR-required rule passes too.
#
# Required env:
#   SOURCE_DIR       path to the monorepo subdirectory to publish (e.g. "plugin")
#   SATELLITE_DIR    path to a checkout of the satellite (e.g. "plugin-satellite")
#                    used only for listing what's currently on the satellite
#                    so we can compute deletions
#   SATELLITE_REPO   "<owner>/<repo>" of the satellite (e.g. "dotsecenv/plugin")
#   TAG              release tag (e.g. "v0.6.7")
#   SHA              monorepo commit SHA being published (for .release-sha sidecar)
#   GH_TOKEN         App installation token used by gh to call the API
#
# Required tools in PATH (caller installs):
#   gh, jq, find, base64

set -euo pipefail

: "${SOURCE_DIR:?SOURCE_DIR is required}"
: "${SATELLITE_DIR:?SATELLITE_DIR is required}"
: "${SATELLITE_REPO:?SATELLITE_REPO is required}"
: "${TAG:?TAG is required}"
: "${SHA:?SHA is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"

# Write the .release-sha sidecar into the source tree so it shows up as
# part of the additions array along with everything else.
echo "${SHA}" > "${SOURCE_DIR}/.release-sha"

# List every file we want present on the satellite after this publish.
SOURCE_FILES=$(mktemp)
( cd "${SOURCE_DIR}" \
  && find . -type f -not -path './.git/*' \
  | sed 's|^\./||' \
  | LC_ALL=C sort -u ) > "${SOURCE_FILES}"

# List every file currently on the satellite (so we can delete anything
# that's no longer in source).
SATELLITE_FILES=$(mktemp)
( cd "${SATELLITE_DIR}" \
  && find . -type f -not -path './.git/*' \
  | sed 's|^\./||' \
  | LC_ALL=C sort -u ) > "${SATELLITE_FILES}"

# additions = every file in source/  (each with base64-encoded contents)
# deletions = files in satellite/ that are NOT in source/
#
# These can run into megabytes of base64 — too large to pass as `jq --argjson`
# arguments (kernel argv limit, ~128KB on Linux) — so we materialize them to
# files and have jq slurp them via --slurpfile.
ADDITIONS_FILE=$(mktemp)
(
  cd "${SOURCE_DIR}"
  while IFS= read -r f; do
    contents=$(base64 < "$f" | tr -d '\n')
    jq -n --arg path "$f" --arg contents "$contents" '{path: $path, contents: $contents}'
  done < "${SOURCE_FILES}" | jq -s .
) > "${ADDITIONS_FILE}"

DELETIONS_FILE=$(mktemp)
(
  comm -23 "${SATELLITE_FILES}" "${SOURCE_FILES}" | while IFS= read -r f; do
    jq -n --arg path "$f" '{path: $path}'
  done | jq -s .
) > "${DELETIONS_FILE}"

# Current head oid -- required by the mutation as expectedHeadOid to detect
# races. If something else pushes between this fetch and the mutation, the
# mutation fails loudly rather than silently overwriting.
EXPECTED_OID=$(gh api "repos/${SATELLITE_REPO}/branches/main" --jq .commit.sha)
echo "Current ${SATELLITE_REPO}/main HEAD: ${EXPECTED_OID}"

# Build the mutation input via files (additions content is too big for argv).
INPUT_FILE=$(mktemp)
jq -n \
  --arg repo "${SATELLITE_REPO}" \
  --arg headline "publish: ${TAG}" \
  --arg body "Sourced from dotsecenv/dotsecenv@${SHA}" \
  --arg oid "${EXPECTED_OID}" \
  --slurpfile additions "${ADDITIONS_FILE}" \
  --slurpfile deletions "${DELETIONS_FILE}" \
  '{
    branch: { repositoryNameWithOwner: $repo, branchName: "main" },
    message: { headline: $headline, body: $body },
    expectedHeadOid: $oid,
    fileChanges: {
      additions: $additions[0],
      deletions: $deletions[0]
    }
  }' > "${INPUT_FILE}"

# Run the mutation. GitHub signs the commit server-side with its bot key.
# Stream the input via stdin to keep it off the command line.
NEW_OID=$(gh api graphql -F input=@"${INPUT_FILE}" \
      -f query='mutation($input: CreateCommitOnBranchInput!) {
        createCommitOnBranch(input: $input) {
          commit { oid url }
        }
      }' \
  | jq -r .data.createCommitOnBranch.commit.oid)

if [ -z "${NEW_OID}" ] || [ "${NEW_OID}" = "null" ]; then
  echo "::error::createCommitOnBranch returned no commit oid" >&2
  exit 1
fi
echo "Signed commit ${NEW_OID} created on ${SATELLITE_REPO}/main"

# Create a lightweight tag at the new commit. (Annotated tags would require
# a separate `POST /git/tags` then `POST /git/refs`; lightweight is what
# plugin managers use anyway.)
gh api -X POST "repos/${SATELLITE_REPO}/git/refs" \
  -f ref="refs/tags/${TAG}" \
  -f sha="${NEW_OID}" \
  > /dev/null
echo "Tagged ${TAG} -> ${NEW_OID}"
