#!/usr/bin/env bash
#
# Commit a single file (the homebrew cask) to a target branch via
# GitHub's GraphQL `createCommitOnBranch` mutation, producing a
# server-signed commit. Mirrors publish-to-satellite.sh for the
# single-file case so we avoid GPG handling on the runner — the App
# installation token used by gh signs the commit server-side.
#
# Required env:
#   TAP_REPO     "<owner>/<repo>" of the homebrew tap (e.g.
#                "dotsecenv/homebrew-tap")
#   TAP_BRANCH   target branch on the tap (typically "main")
#   CASK_PATH    path of the cask file within the tap repo (e.g.
#                "Casks/dotsecenv.rb")
#   CASK_FILE    local file path containing the new cask contents
#                (typically equal to CASK_PATH, when the tap is the
#                workspace cwd)
#   HEADLINE     commit message headline
#   BODY         commit message body (RFC-822 trailer paragraph,
#                parseable via `git interpret-trailers --parse`)
#   GH_TOKEN     App installation token used by gh to call the API
#
# Output:
#   prints "commit_sha=<sha>" on stdout for the caller to capture
#   (e.g. into $GITHUB_OUTPUT)
#
# Required tools in PATH: gh, jq, base64

set -euo pipefail

: "${TAP_REPO:?TAP_REPO is required}"
: "${TAP_BRANCH:?TAP_BRANCH is required}"
: "${CASK_PATH:?CASK_PATH is required}"
: "${CASK_FILE:?CASK_FILE is required}"
: "${HEADLINE:?HEADLINE is required}"
: "${BODY:?BODY is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"

# Current head OID — required by the mutation as expectedHeadOid to
# detect races. If something else pushes between this fetch and the
# mutation, the mutation fails loudly rather than silently overwriting.
EXPECTED_OID=$(gh api "repos/${TAP_REPO}/branches/${TAP_BRANCH}" --jq .commit.sha)
echo "Current ${TAP_REPO}/${TAP_BRANCH} HEAD: ${EXPECTED_OID}"

# Build the CreateCommitOnBranchInput payload. createCommitOnBranch
# expects file contents base64-encoded. We materialize the JSON to a
# file because the same `gh api graphql -F` quirk that bites
# publish-to-satellite.sh applies here: -F reads the value as a STRING,
# not JSON, so building the request body ourselves and sending via
# --input is the only reliable path.
CONTENTS=$(base64 < "${CASK_FILE}" | tr -d '\n')

INPUT_FILE=$(mktemp)
REQUEST_FILE=$(mktemp)
trap 'rm -f "${INPUT_FILE}" "${REQUEST_FILE}"' EXIT

jq -n \
  --arg repo "${TAP_REPO}" \
  --arg branch "${TAP_BRANCH}" \
  --arg headline "${HEADLINE}" \
  --arg body "${BODY}" \
  --arg oid "${EXPECTED_OID}" \
  --arg path "${CASK_PATH}" \
  --arg contents "${CONTENTS}" \
  '{
    branch: { repositoryNameWithOwner: $repo, branchName: $branch },
    message: { headline: $headline, body: $body },
    expectedHeadOid: $oid,
    fileChanges: {
      additions: [ { path: $path, contents: $contents } ]
    }
  }' > "${INPUT_FILE}"

jq -n \
  --arg query 'mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid url } } }' \
  --slurpfile input "${INPUT_FILE}" \
  '{query: $query, variables: {input: $input[0]}}' > "${REQUEST_FILE}"

RESPONSE=$(gh api graphql --input "${REQUEST_FILE}")
NEW_OID=$(jq -r '.data.createCommitOnBranch.commit.oid // empty' <<<"${RESPONSE}")

if [ -z "${NEW_OID}" ]; then
  echo "::error::createCommitOnBranch returned no commit oid"
  echo "Full response from GitHub:" >&2
  jq . <<<"${RESPONSE}" >&2 || echo "${RESPONSE}" >&2
  exit 1
fi

echo "Signed commit ${NEW_OID} created on ${TAP_REPO}/${TAP_BRANCH}"
echo "commit_sha=${NEW_OID}"
