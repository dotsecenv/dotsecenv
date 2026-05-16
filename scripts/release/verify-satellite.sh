#!/usr/bin/env bash
#
# Verify that a satellite checkout matches what the monorepo's source
# subdirectory says it should be — byte-for-byte, mode-for-mode.
#
# The publish flow (publish-to-satellite.sh) syncs every file under
# SOURCE_DIR into the satellite via GitHub's GraphQL createCommitOnBranch
# mutation. Provenance lives in RFC-822 git trailers in the satellite's
# HEAD commit body (Source-Commit, Source-SHA, Source-Path, Source-Tag,
# Published-By), parseable via `git interpret-trailers --parse`. So a
# healthy satellite at commit SHA contains exactly the files under
# SOURCE_DIR at SHA. Anything else is drift: a missed file, an out-of-
# band edit on the satellite, a publish bug, or a stale satellite that
# didn't receive a later push.
#
# This script:
#   1. Diffs the file LISTS (source-only / satellite-only / common),
#      with GENERATED_PATHS whitelisted as expected on the satellite.
#   2. Diffs the file CONTENTS and Unix mode for files present in both.
#   3. If EXPECTED_SHA is set, validates the Source-SHA trailer in
#      the satellite's HEAD commit body matches it.
#
# Exits non-zero on any drift. The diff payload (capped) is printed to
# stdout and additionally written to $GITHUB_STEP_SUMMARY when running
# in GitHub Actions, so the workflow run page shows what differs.
#
# Required env:
#   SOURCE_DIR        path to the monorepo subdirectory (e.g. "plugin")
#   SATELLITE_DIR     path to a checkout of the satellite (e.g. "plugin-satellite")
#
# Optional env:
#   EXPECTED_SHA      monorepo commit SHA the satellite should be at.
#                     Validates the Source-SHA trailer in the satellite's
#                     HEAD commit body matches. If unset, the SHA-pinning
#                     check is skipped.
#   GENERATED_PATHS   newline-separated paths the publish workflow
#                     writes into the satellite but that don't live
#                     in the monorepo source tree (e.g. "retracted.txt"
#                     for the packages satellite, generated from go.mod
#                     by extract-retracted.sh).
#   MAX_DIFF_BYTES    cap for the printed diff payload (default 65536).
#                     Stops the workflow log from blowing up if drift
#                     is enormous; the file LIST is always printed in
#                     full so you can still see what differs.
#
# Required tools in PATH:
#   find, diff, cmp, comm, sort, sed, awk, stat
#   (git is only needed when EXPECTED_SHA is set, to read the
#    Source-SHA trailer on the satellite's HEAD commit)

set -euo pipefail

: "${SOURCE_DIR:?SOURCE_DIR is required}"
: "${SATELLITE_DIR:?SATELLITE_DIR is required}"
EXPECTED_SHA="${EXPECTED_SHA:-}"
GENERATED_PATHS="${GENERATED_PATHS:-}"
MAX_DIFF_BYTES="${MAX_DIFF_BYTES:-65536}"

DRIFT=0
REPORT=$(mktemp)
trap 'rm -f "${REPORT}"' EXIT

say() { echo "$@" | tee -a "${REPORT}"; }

say "Verifying satellite:"
say "  source    : ${SOURCE_DIR}"
say "  satellite : ${SATELLITE_DIR}"
[ -n "${EXPECTED_SHA}" ] && say "  expected  : ${EXPECTED_SHA}"

# ---------- Source-SHA trailer ----------------------------------------------
# The publish flow writes a Source-SHA trailer to the satellite commit
# body. Read it via `git interpret-trailers --parse` and check that it
# matches what the caller expects.
if [ -n "${EXPECTED_SHA}" ]; then
  if command -v git >/dev/null 2>&1 && [ -d "${SATELLITE_DIR}/.git" ]; then
    TRAILER_SHA=$(git -C "${SATELLITE_DIR}" log -1 --format=%B \
      | git interpret-trailers --parse \
      | awk -F': ' '$1=="Source-SHA"{print $2}')
    if [ -z "${TRAILER_SHA}" ]; then
      say "  Source-SHA trailer: MISSING on satellite HEAD commit"
      DRIFT=1
    elif [ "${TRAILER_SHA}" = "${EXPECTED_SHA}" ]; then
      say "  Source-SHA trailer: OK (${TRAILER_SHA:0:12})"
    else
      say "  Source-SHA trailer: DRIFT — trailer says ${TRAILER_SHA:0:12}, expected ${EXPECTED_SHA:0:12}"
      DRIFT=1
    fi
  else
    say "  Source-SHA trailer: SKIPPED (no git available or satellite has no .git/)"
  fi
fi

# ---------- File-list comparison --------------------------------------------
# Build NL-separated exclude list for satellite-side listing.
#
# `.release-sha` was a legacy sidecar from before the trailer convention
# landed; the publish flow no longer writes it. Existing satellites still
# carry the file until their next publish, and the GraphQL publish auto-
# deletes any satellite file not in source — so this entry is purely
# transitional and can be removed once both satellites have been
# republished. Until then, we whitelist it here so the file-list check
# doesn't flag it as an unexpected satellite-only file.
SAT_EXCLUDES=".release-sha"
if [ -n "${GENERATED_PATHS}" ]; then
  SAT_EXCLUDES="${SAT_EXCLUDES}
${GENERATED_PATHS}"
fi

SRC_LIST=$(mktemp); SAT_LIST=$(mktemp)
trap 'rm -f "${REPORT}" "${SRC_LIST}" "${SAT_LIST}"' EXIT

( cd "${SOURCE_DIR}" && find . -type f -not -path './.git/*' | sed 's|^\./||' ) \
  | LC_ALL=C sort -u > "${SRC_LIST}"

( cd "${SATELLITE_DIR}" && find . -type f -not -path './.git/*' | sed 's|^\./||' ) \
  | grep -vxF "${SAT_EXCLUDES}" \
  | LC_ALL=C sort -u > "${SAT_LIST}"

SRC_ONLY=$(comm -23 "${SRC_LIST}" "${SAT_LIST}")
SAT_ONLY=$(comm -13 "${SRC_LIST}" "${SAT_LIST}")
COMMON=$(comm -12 "${SRC_LIST}" "${SAT_LIST}")

if [ -n "${SRC_ONLY}" ]; then
  say ""
  say "Files in monorepo but missing from satellite:"
  echo "${SRC_ONLY}" | sed 's/^/  - /' | tee -a "${REPORT}"
  DRIFT=1
fi
if [ -n "${SAT_ONLY}" ]; then
  say ""
  say "Files on satellite but missing from monorepo (and not in GENERATED_PATHS):"
  echo "${SAT_ONLY}" | sed 's/^/  + /' | tee -a "${REPORT}"
  DRIFT=1
fi

# ---------- Per-file content + mode comparison ------------------------------
DIFFS=$(mktemp); trap 'rm -f "${REPORT}" "${SRC_LIST}" "${SAT_LIST}" "${DIFFS}"' EXIT
CONTENT_COUNT=0; MODE_COUNT=0; COMMON_COUNT=0

stat_mode() {
  # GNU stat first (this is what Actions runners use), BSD/macOS fallback.
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}

while IFS= read -r f; do
  [ -z "$f" ] && continue
  COMMON_COUNT=$((COMMON_COUNT + 1))
  if ! cmp -s "${SOURCE_DIR}/${f}" "${SATELLITE_DIR}/${f}"; then
    CONTENT_COUNT=$((CONTENT_COUNT + 1))
    {
      echo
      echo "--- content diff: ${f} ---"
      diff -u "${SOURCE_DIR}/${f}" "${SATELLITE_DIR}/${f}" \
        | sed -e "s|${SOURCE_DIR}|MONO|g" -e "s|${SATELLITE_DIR}|SAT|g"
    } >> "${DIFFS}"
  fi
  SM=$(stat_mode "${SOURCE_DIR}/${f}")
  TM=$(stat_mode "${SATELLITE_DIR}/${f}")
  # Compare exec bit only (publish flow doesn't preserve setuid/sticky).
  if [ "$(( 0${SM} & 0111 ))" -ne "$(( 0${TM} & 0111 ))" ]; then
    MODE_COUNT=$((MODE_COUNT + 1))
    {
      echo
      echo "--- mode drift: ${f}  (mono=${SM} sat=${TM})"
    } >> "${DIFFS}"
  fi
done <<< "${COMMON}"

if [ "${CONTENT_COUNT}" -gt 0 ] || [ "${MODE_COUNT}" -gt 0 ]; then
  say ""
  say "${CONTENT_COUNT} content drift(s), ${MODE_COUNT} exec-bit drift(s) across ${COMMON_COUNT} common files:"
  # Cap diff payload — runaway diff shouldn't bloat the log forever.
  head -c "${MAX_DIFF_BYTES}" "${DIFFS}" | tee -a "${REPORT}"
  if [ "$(wc -c < "${DIFFS}")" -gt "${MAX_DIFF_BYTES}" ]; then
    say ""
    say "... (diff payload truncated at ${MAX_DIFF_BYTES} bytes)"
  fi
  DRIFT=1
else
  say ""
  say "Contents: all ${COMMON_COUNT} common files byte-identical, exec bits match."
fi

# ---------- Mirror to GitHub Actions step summary ---------------------------
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    if [ "${DRIFT}" -eq 0 ]; then
      echo "### ✅ Satellite \`${SATELLITE_DIR}\` matches \`${SOURCE_DIR}\`"
    else
      echo "### ❌ Satellite drift detected in \`${SATELLITE_DIR}\`"
    fi
    echo
    echo '```'
    cat "${REPORT}"
    echo '```'
  } >> "${GITHUB_STEP_SUMMARY}"
fi

if [ "${DRIFT}" -ne 0 ]; then
  echo "::error::Satellite ${SATELLITE_DIR} has drifted from ${SOURCE_DIR}"
  exit 1
fi
exit 0
