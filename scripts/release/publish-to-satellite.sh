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
# Provenance is recorded as RFC-822 git trailers in the satellite commit
# body, parseable via `git interpret-trailers --parse`. The trailer set:
#
#   Source-Commit: dotsecenv/dotsecenv@<sha>          (linkable in GitHub UI)
#   Source-SHA:    <sha>                              (parseable, no splitting)
#   Source-Path:   <SOURCE_DIR>                       (plugin | packages)
#   Source-Tag:    <TAG>                              (omitted when TAG is empty)
#   Published-By:  <PUBLISHED_BY URL>                 (omitted when not set)
#
# Required env:
#   SOURCE_DIR       path to the monorepo subdirectory to publish (e.g. "plugin")
#   SATELLITE_DIR    path to a checkout of the satellite (e.g. "plugin-satellite")
#                    used only for listing what's currently on the satellite
#                    so we can compute deletions
#   SATELLITE_REPO   "<owner>/<repo>" of the satellite (e.g. "dotsecenv/plugin")
#   SHA              monorepo commit SHA being published (recorded in trailers)
#   GH_TOKEN         App installation token used by gh to call the API
#
# Optional env:
#   TAG              release tag (e.g. "v0.6.7"). When set, a lightweight
#                    tag is created on the satellite at the new commit and
#                    a Source-Tag trailer is emitted. When empty, no tag
#                    is created — useful for ad-hoc workflow_dispatch
#                    publishes that aren't tied to a release version.
#   PUBLISHED_BY     URL of the CI run that produced this publish (typically
#                    "${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}").
#                    When set, a Published-By trailer is emitted, linkifying
#                    the originating workflow run in the satellite commit view.
#                    When unset, the trailer is omitted — keeps the script
#                    callable from a local shell for one-off testing.
#
# Required tools in PATH (caller installs):
#   gh, jq, find, base64

set -euo pipefail

: "${SOURCE_DIR:?SOURCE_DIR is required}"
: "${SATELLITE_DIR:?SATELLITE_DIR is required}"
: "${SATELLITE_REPO:?SATELLITE_REPO is required}"
: "${SHA:?SHA is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"
TAG="${TAG:-}"
PUBLISHED_BY="${PUBLISHED_BY:-}"

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

# Build the CreateCommitOnBranchInput object via files (additions content
# is too big for argv).
if [ -n "${TAG}" ]; then
  HEADLINE="publish: ${TAG}"
else
  HEADLINE="publish: ad-hoc (${SHA:0:7})"
fi

# Build the RFC-822 trailer block for the commit body. Each trailer is
# a single Key: value line; the block is the entire commit body, so
# `git interpret-trailers --parse` will recognize all of them.
BODY=$(
  printf 'Source-Commit: dotsecenv/dotsecenv@%s\n' "${SHA}"
  printf 'Source-SHA: %s\n' "${SHA}"
  printf 'Source-Path: %s\n' "${SOURCE_DIR}"
  [ -n "${TAG}" ] && printf 'Source-Tag: %s\n' "${TAG}"
  [ -n "${PUBLISHED_BY}" ] && printf 'Published-By: %s\n' "${PUBLISHED_BY}"
)

INPUT_FILE=$(mktemp)
jq -n \
  --arg repo "${SATELLITE_REPO}" \
  --arg headline "${HEADLINE}" \
  --arg body "${BODY}" \
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

# Build the full GraphQL request body. We can't use
# `gh api graphql -F input=@file` because gh's -F flag reads the file
# as a STRING (it only auto-detects bool/number, not JSON), and the
# server rejects the resulting variables.input value as "invalid value
# for type CreateCommitOnBranchInput!". Build {query, variables} ourselves
# and send via --input.
REQUEST_FILE=$(mktemp)
jq -n \
  --arg query 'mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid url } } }' \
  --slurpfile input "${INPUT_FILE}" \
  '{query: $query, variables: {input: $input[0]}}' > "${REQUEST_FILE}"

# Run the mutation. GitHub signs the commit server-side with its bot key.
RESPONSE=$(gh api graphql --input "${REQUEST_FILE}")
NEW_OID=$(jq -r '.data.createCommitOnBranch.commit.oid // empty' <<<"${RESPONSE}")

if [ -z "${NEW_OID}" ]; then
  echo "::error::createCommitOnBranch returned no commit oid"
  echo "Full response from GitHub:" >&2
  jq . <<<"${RESPONSE}" >&2 || echo "${RESPONSE}" >&2
  exit 1
fi
echo "Signed commit ${NEW_OID} created on ${SATELLITE_REPO}/main"

# Create a lightweight tag at the new commit IF a TAG was supplied.
# (Annotated tags would require a separate `POST /git/tags` then
# `POST /git/refs`; lightweight is what plugin managers use anyway.)
# Ad-hoc workflow_dispatch publishes pass TAG="" and skip the tag step —
# the satellite's history just shows the publish commit without a ref.
if [ -n "${TAG}" ]; then
  gh api -X POST "repos/${SATELLITE_REPO}/git/refs" \
    -f ref="refs/tags/${TAG}" \
    -f sha="${NEW_OID}" \
    > /dev/null
  echo "Tagged ${TAG} -> ${NEW_OID}"
else
  echo "No TAG supplied; skipped tag creation (ad-hoc publish)"
fi
