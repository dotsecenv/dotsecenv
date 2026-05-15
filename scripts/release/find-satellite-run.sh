#!/usr/bin/env bash
#
# Discover the workflow run on a satellite repo triggered by a
# repository_dispatch we just sent, write its URL to the calling job's
# step summary, and emit `run_id` / `run_url` to $GITHUB_OUTPUT so a
# downstream wait job can poll the known run directly.
#
# Required env:
#   SATELLITE_REPO       "<owner>/<repo>" (e.g. dotsecenv/packages, or
#                        dotsecenv/dotsecenv when self-dispatching)
#   SINCE                ISO8601 timestamp; only runs created on/after this
#                        are candidates. Pass the pre-dispatch timestamp.
#   GH_TOKEN             token with `actions: read` on SATELLITE_REPO
#
# Optional env:
#   WORKFLOW_FILE        e.g. "action-e2e.yml" — narrows discovery to runs
#                        of that specific workflow. Use this when a single
#                        dispatcher fires multiple repository_dispatch
#                        events that map to different workflows; otherwise
#                        a discovery for the wrong one may collide.
#   DISCOVER_TIMEOUT_S   max seconds to look for the dispatched run (default 60)

set -euo pipefail

: "${SATELLITE_REPO:?SATELLITE_REPO is required}"
: "${SINCE:?SINCE is required (ISO8601)}"
: "${GH_TOKEN:?GH_TOKEN is required}"

DISCOVER_TIMEOUT_S=${DISCOVER_TIMEOUT_S:-60}
WORKFLOW_FILE=${WORKFLOW_FILE:-}

if [ -n "$WORKFLOW_FILE" ]; then
  RUNS_API="repos/${SATELLITE_REPO}/actions/workflows/${WORKFLOW_FILE}/runs"
else
  RUNS_API="repos/${SATELLITE_REPO}/actions/runs"
fi

summary() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$@" >> "$GITHUB_STEP_SUMMARY"
  fi
}

echo "Looking for repository_dispatch run on ${SATELLITE_REPO}${WORKFLOW_FILE:+ (${WORKFLOW_FILE})} since ${SINCE}..."
deadline=$(( $(date +%s) + DISCOVER_TIMEOUT_S ))
run_id=""

while [ "$(date +%s)" -lt "$deadline" ]; do
  json=$(gh api "${RUNS_API}?event=repository_dispatch&created=>=${SINCE}&per_page=5")
  count=$(jq -r '.total_count // 0' <<<"$json")
  if [ "$count" -gt 0 ]; then
    run_id=$(jq -r '.workflow_runs[0].id' <<<"$json")
    run_url=$(jq -r '.workflow_runs[0].html_url' <<<"$json")
    run_name=$(jq -r '.workflow_runs[0].name // .workflow_runs[0].display_title // "run"' <<<"$json")
    echo "Found run: ${run_name} #${run_id}"
    echo "URL: ${run_url}"
    break
  fi
  sleep 5
done

if [ -z "$run_id" ]; then
  echo "::error::No repository_dispatch run appeared on ${SATELLITE_REPO} within ${DISCOVER_TIMEOUT_S}s"
  summary "## ❌ Satellite publish on \`${SATELLITE_REPO}\` — NOT STARTED" \
          "" \
          "No \`repository_dispatch\` run appeared on [\`${SATELLITE_REPO}\`](https://github.com/${SATELLITE_REPO}/actions) within ${DISCOVER_TIMEOUT_S}s of dispatch."
  exit 1
fi

summary "## Satellite publish on \`${SATELLITE_REPO}\`" \
        "" \
        "Dispatched run: [${run_name} #${run_id}](${run_url})"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "run_id=${run_id}"
    echo "run_url=${run_url}"
    echo "run_name=${run_name}"
  } >> "$GITHUB_OUTPUT"
fi
