#!/usr/bin/env bash
#
# Discover the workflow run on a satellite repo triggered by an event we
# just caused (default: a push from releasetools/actions/signed-push's
# signed commit), write its URL to the calling job's step summary, and emit
# `run_id` / `run_url` to $GITHUB_OUTPUT so a downstream wait job can
# poll the known run directly.
#
# Required env:
#   SATELLITE_REPO       "<owner>/<repo>" (e.g. dotsecenv/packages, or
#                        dotsecenv/dotsecenv when self-dispatching)
#   SINCE                ISO8601 timestamp; only runs created on/after this
#                        are candidates. Pass the pre-trigger timestamp.
#   GH_TOKEN             token with `actions: read` on SATELLITE_REPO
#
# Optional env:
#   EVENT                workflow trigger event to filter on (default "push").
#                        Set to "repository_dispatch" for legacy dispatch
#                        flows, or any other GitHub events API value.
#   WORKFLOW_FILE        e.g. "publish.yml" — narrows discovery to runs
#                        of that specific workflow. Use this when a single
#                        trigger fires multiple events that map to different
#                        workflows; otherwise a discovery for the wrong one
#                        may collide.
#   HEAD_SHA             exact published satellite commit to match.
#   DISCOVER_TIMEOUT_S   max seconds to look for the triggered run (default 60)

set -euo pipefail

: "${SATELLITE_REPO:?SATELLITE_REPO is required}"
: "${SINCE:?SINCE is required (ISO8601)}"
: "${GH_TOKEN:?GH_TOKEN is required}"

DISCOVER_TIMEOUT_S=${DISCOVER_TIMEOUT_S:-60}
WORKFLOW_FILE=${WORKFLOW_FILE:-}
EVENT=${EVENT:-push}
HEAD_SHA=${HEAD_SHA:-}

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

echo "Looking for ${EVENT} run on ${SATELLITE_REPO}${WORKFLOW_FILE:+ (${WORKFLOW_FILE})} since ${SINCE}..."
deadline=$(( $(date +%s) + DISCOVER_TIMEOUT_S ))
run_id=""

while [ "$(date +%s)" -lt "$deadline" ]; do
  json=$(gh api "${RUNS_API}?event=${EVENT}&created=>=${SINCE}&per_page=100")
  run=$(jq -c --arg sha "$HEAD_SHA" \
    '[.workflow_runs[] | select($sha == "" or .head_sha == $sha)][0] // empty' <<<"$json")
  if [ -n "$run" ]; then
    run_id=$(jq -r '.id' <<<"$run")
    run_url=$(jq -r '.html_url' <<<"$run")
    run_name=$(jq -r '.name // .display_title // "run"' <<<"$run")
    echo "Found run: ${run_name} #${run_id}"
    echo "URL: ${run_url}"
    break
  fi
  sleep 5
done

if [ -z "$run_id" ]; then
  echo "::error::No ${EVENT} run appeared on ${SATELLITE_REPO} within ${DISCOVER_TIMEOUT_S}s"
  summary "## ❌ Satellite publish on \`${SATELLITE_REPO}\` — NOT STARTED" \
          "" \
          "No \`${EVENT}\` run appeared on [\`${SATELLITE_REPO}\`](https://github.com/${SATELLITE_REPO}/actions) within ${DISCOVER_TIMEOUT_S}s of trigger."
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
