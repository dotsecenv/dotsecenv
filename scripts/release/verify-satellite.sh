#!/usr/bin/env bash
#
# Verify that a satellite checkout matches what the monorepo's source
# subdirectory says it should be — byte-for-byte, mode-for-mode.
#
# The publish flow (publish-to-satellite.sh) syncs every file under
# SOURCE_DIR into the satellite via GitHub's GraphQL createCommitOnBranch
# mutation, plus a .release-sha sidecar pointing at the monorepo commit.
# So a healthy satellite at commit SHA contains exactly:
#
#   (files under SOURCE_DIR at SHA)  +  .release-sha
#
# Anything else is drift: a missed file, an out-of-band edit on the
# satellite, a publish bug, or a stale satellite that didn't receive a
# later push.
#
# This script:
#   1. Diffs the file LISTS (source-only / satellite-only / common),
#      with GENERATED_PATHS whitelisted as expected on the satellite.
#   2. Diffs the file CONTENTS and Unix mode for files present in both.
#   3. If EXPECTED_SHA is set, validates the satellite's .release-sha
#      and/or commit-body trailer matches it.
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
#                     Validates the .release-sha sidecar AND the
#                     "Sourced from dotsecenv/dotsecenv@<sha>" trailer
#                     in the satellite's HEAD commit body. If unset,
#                     SHA-pinning checks are skipped.
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
#   (git is only needed when EXPECTED_SHA is set, to check the commit
#    body trailer on the satellite)

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

# ---------- .release-sha + commit-body trailer ------------------------------
# Both should encode the same SHA. The sidecar is a one-line file; the
# trailer is in the satellite HEAD's commit message body, written by
# publish-to-satellite.sh.
if [ -n "${EXPECTED_SHA}" ]; then
  if [ -f "${SATELLITE_DIR}/.release-sha" ]; then
    SIDECAR_SHA="$(tr -d '[:space:]' < "${SATELLITE_DIR}/.release-sha")"
    if [ "${SIDECAR_SHA}" = "${EXPECTED_SHA}" ]; then
      say "  .release-sha: OK (${SIDECAR_SHA:0:12})"
    else
      say "  .release-sha: DRIFT — file says ${SIDECAR_SHA:0:12}, expected ${EXPECTED_SHA:0:12}"
      DRIFT=1
    fi
  else
    say "  .release-sha: MISSING on satellite"
    DRIFT=1
  fi

  if command -v git >/dev/null 2>&1 && [ -d "${SATELLITE_DIR}/.git" ]; then
    TRAILER_SHA=$(git -C "${SATELLITE_DIR}" log -1 --format=%B \
      | sed -n 's|^Sourced from dotsecenv/dotsecenv@||p' | head -1)
    if [ -z "${TRAILER_SHA}" ]; then
      say "  commit body: MISSING 'Sourced from dotsecenv/dotsecenv@<sha>' trailer"
      DRIFT=1
    elif [ "${TRAILER_SHA}" = "${EXPECTED_SHA}" ]; then
      say "  commit body: OK (${TRAILER_SHA:0:12})"
    else
      say "  commit body: DRIFT — trailer says ${TRAILER_SHA:0:12}, expected ${EXPECTED_SHA:0:12}"
      DRIFT=1
    fi
  fi
fi

# ---------- File-list comparison --------------------------------------------
# Build NL-separated exclude list for satellite-side listing: always
# .release-sha (sidecar checked above), plus any caller-supplied
# generated paths (e.g. retracted.txt).
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
