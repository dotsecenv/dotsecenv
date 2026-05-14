#!/usr/bin/env bash
#
# Wait for the workflow run on a satellite repo triggered by our
# repository_dispatch and exit non-zero if it doesn't succeed.
#
# Surfaces the satellite run's URL via $GITHUB_STEP_SUMMARY so the
# calling job's run page links straight at the downstream run.
#
# Required env:
#   SATELLITE_REPO   "<owner>/<repo>" of the satellite (e.g. dotsecenv/packages)
#   SINCE            ISO8601 timestamp; only runs created on/after this date
#                    are candidates. Pass the dispatcher's
#                    pre-dispatch timestamp.
#   GH_TOKEN         token with `actions: read` on SATELLITE_REPO
#
# Optional env:
#   DISCOVER_TIMEOUT_S   max seconds to look for the dispatched run (default 60)
#   WAIT_TIMEOUT_S       max seconds to wait for the run to complete (default 1500)
#   POLL_INTERVAL_S      seconds between status polls (default 15)

set -euo pipefail

: "${SATELLITE_REPO:?SATELLITE_REPO is required}"
: "${SINCE:?SINCE is required (ISO8601)}"
: "${GH_TOKEN:?GH_TOKEN is required}"

DISCOVER_TIMEOUT_S=${DISCOVER_TIMEOUT_S:-60}
WAIT_TIMEOUT_S=${WAIT_TIMEOUT_S:-1500}
POLL_INTERVAL_S=${POLL_INTERVAL_S:-15}

summary() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$@" >> "$GITHUB_STEP_SUMMARY"
  fi
}

# --- 1. Discover the dispatched run ------------------------------------------
echo "Looking for repository_dispatch run on ${SATELLITE_REPO} since ${SINCE}..."
deadline=$(( $(date +%s) + DISCOVER_TIMEOUT_S ))
run_id=""
run_url=""
run_name=""

while [ "$(date +%s)" -lt "$deadline" ]; do
  json=$(gh api "repos/${SATELLITE_REPO}/actions/runs?event=repository_dispatch&created=>=${SINCE}&per_page=5")
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
  summary "## ❌ Packages publish — NOT STARTED" \
          "" \
          "No \`repository_dispatch\` run appeared on [\`${SATELLITE_REPO}\`](https://github.com/${SATELLITE_REPO}/actions) within ${DISCOVER_TIMEOUT_S}s of the dispatch."
  exit 1
fi

summary "## Packages publish on \`${SATELLITE_REPO}\`" \
        "" \
        "Watching [${run_name} #${run_id}](${run_url})."

# --- 2. Poll until terminal --------------------------------------------------
wait_deadline=$(( $(date +%s) + WAIT_TIMEOUT_S ))
while [ "$(date +%s)" -lt "$wait_deadline" ]; do
  detail=$(gh api "repos/${SATELLITE_REPO}/actions/runs/${run_id}")
  status=$(jq -r .status <<<"$detail")
  conclusion=$(jq -r .conclusion <<<"$detail")
  echo "$(date -u +%H:%M:%SZ) status=${status} conclusion=${conclusion}"
  if [ "$status" = "completed" ]; then
    case "$conclusion" in
      success)
        summary "" "**Result:** ✅ success"
        exit 0
        ;;
      *)
        summary "" "**Result:** ❌ ${conclusion}"
        echo "::error::Packages publish ended: ${conclusion}"
        exit 1
        ;;
    esac
  fi
  sleep "$POLL_INTERVAL_S"
done

echo "::error::Packages publish on ${SATELLITE_REPO} did not complete within ${WAIT_TIMEOUT_S}s"
summary "" "**Result:** ⏱️ timed out after ${WAIT_TIMEOUT_S}s"
exit 1
