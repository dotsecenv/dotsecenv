#!/usr/bin/env bash
#
# Poll a known workflow run on a satellite repo until it reaches a
# terminal state. Writes the final result to $GITHUB_STEP_SUMMARY and
# exits non-zero if the run didn't succeed.
#
# Pair with find-satellite-run.sh: that script discovers the run and
# emits run_id; this one watches it.
#
# Required env:
#   SATELLITE_REPO       "<owner>/<repo>" (e.g. dotsecenv/packages)
#   RUN_ID               numeric workflow run id
#   GH_TOKEN             token with `actions: read` on SATELLITE_REPO
#
# Optional env:
#   WAIT_TIMEOUT_S       max seconds to wait for the run (default 1500)
#   POLL_INTERVAL_S      seconds between status polls (default 15)

set -euo pipefail

: "${SATELLITE_REPO:?SATELLITE_REPO is required}"
: "${RUN_ID:?RUN_ID is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"

WAIT_TIMEOUT_S=${WAIT_TIMEOUT_S:-1500}
POLL_INTERVAL_S=${POLL_INTERVAL_S:-15}

summary() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$@" >> "$GITHUB_STEP_SUMMARY"
  fi
}

detail=$(gh api "repos/${SATELLITE_REPO}/actions/runs/${RUN_ID}")
run_url=$(jq -r .html_url <<<"$detail")
run_name=$(jq -r '.name // .display_title // "run"' <<<"$detail")

summary "## Satellite publish on \`${SATELLITE_REPO}\`" \
        "" \
        "Watching [${run_name} #${RUN_ID}](${run_url})."

wait_deadline=$(( $(date +%s) + WAIT_TIMEOUT_S ))
while [ "$(date +%s)" -lt "$wait_deadline" ]; do
  detail=$(gh api "repos/${SATELLITE_REPO}/actions/runs/${RUN_ID}")
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
        echo "::error::${SATELLITE_REPO} run ${RUN_ID} ended: ${conclusion}"
        exit 1
        ;;
    esac
  fi
  sleep "$POLL_INTERVAL_S"
done

echo "::error::${SATELLITE_REPO} run ${RUN_ID} did not complete within ${WAIT_TIMEOUT_S}s"
summary "" "**Result:** ⏱️ timed out after ${WAIT_TIMEOUT_S}s"
exit 1
