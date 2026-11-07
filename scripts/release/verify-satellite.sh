#!/usr/bin/env bash
#
# Authenticate a satellite commit and compare its files with its source.
# Run this script from a trusted monorepo checkout. The adjacent provenance
# verifier requires a GitHub-signed release App commit, source ancestry on
# main, and a maintainer-signed tag for release publishes.
#
# Exits non-zero on any drift. The diff payload (capped) is printed to
# stdout and additionally written to $GITHUB_STEP_SUMMARY when running
# in GitHub Actions, so the workflow run page shows what differs.
#
# Required env:
#   SOURCE_DIR        path to the monorepo subdirectory (e.g. "plugin")
#   SATELLITE_DIR     path to a checkout of the satellite (e.g. "satellite/")
#   SATELLITE_REPO    dotsecenv/plugin or dotsecenv/packages
#   MONOREPO_DIR      trusted monorepo checkout with origin/main and tags
#   GH_TOKEN          GitHub API token for public commit signature metadata
#
# Optional env:
#   EXPECTED_SHA      monorepo commit SHA the satellite should be at.
#                     Must match Source-SHA when provided.
#   EXPECTED_TAG      release tag that must match Source-Tag when provided.
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
#   python3, gh, git, find, diff, cmp, comm, sort, sed, stat, grep

set -euo pipefail

: "${SOURCE_DIR:?SOURCE_DIR is required}"
: "${SATELLITE_DIR:?SATELLITE_DIR is required}"
EXPECTED_SHA="${EXPECTED_SHA:-}"
GENERATED_PATHS="${GENERATED_PATHS:-}"
MAX_DIFF_BYTES="${MAX_DIFF_BYTES:-65536}"

PROVENANCE=$(python3 "$(dirname "$0")/verify-satellite-provenance.py")
SOURCE_SHA=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["source_sha"])' <<< "$PROVENANCE")
if [ "$(git -C "${SOURCE_DIR}" rev-parse HEAD)" != "${SOURCE_SHA}" ]; then
  echo "::error::Source checkout does not match authenticated Source-SHA" >&2
  exit 1
fi
if find "${SOURCE_DIR}" "${SATELLITE_DIR}" -name $'*\n*' -print -quit | grep -q .; then
  echo "::error::Newline filenames cannot be compared safely" >&2
  exit 1
fi

DRIFT=0
REPORT=$(mktemp)
trap 'rm -f "${REPORT}"' EXIT

say() { echo "$@" | tee -a "${REPORT}"; }

say "Verifying satellite:"
say "  source    : ${SOURCE_DIR}"
say "  satellite : ${SATELLITE_DIR}"
[ -n "${EXPECTED_SHA}" ] && say "  expected  : ${EXPECTED_SHA}"

say "  authenticated Source-SHA: ${SOURCE_SHA}"

# ---------- File-list comparison --------------------------------------------
# Build NL-separated exclude list for satellite-side listing: just
# caller-supplied generated paths (e.g. "retracted.txt" for the packages
# satellite, generated from go.mod by extract-retracted.sh).
SAT_EXCLUDES="${GENERATED_PATHS}"

SRC_LIST=$(mktemp); SAT_LIST=$(mktemp)
trap 'rm -f "${REPORT}" "${SRC_LIST}" "${SAT_LIST}"' EXIT

( cd "${SOURCE_DIR}" && find . \( -type f -o -type l \) -not -path './.git' -not -path './.git/*' | sed 's|^\./||' ) \
  | LC_ALL=C sort -u > "${SRC_LIST}"

# When SAT_EXCLUDES is empty, skip the grep — `grep -vxF ""` would match
# empty lines (harmless here, since find never emits them, but odd to read).
if [ -n "${SAT_EXCLUDES}" ]; then
  ( cd "${SATELLITE_DIR}" && find . \( -type f -o -type l \) -not -path './.git' -not -path './.git/*' | sed 's|^\./||' ) \
    | grep -vxF "${SAT_EXCLUDES}" \
    | LC_ALL=C sort -u > "${SAT_LIST}"
else
  ( cd "${SATELLITE_DIR}" && find . \( -type f -o -type l \) -not -path './.git' -not -path './.git/*' | sed 's|^\./||' ) \
    | LC_ALL=C sort -u > "${SAT_LIST}"
fi

# Match the LC_ALL=C used for sort above. Without it, GNU comm uses the
# system locale's collation, which can disagree with LC_ALL=C sort about
# how dotfiles order vs alphanumerics — leading to spurious "not in
# sorted order" errors, a non-zero comm exit, and (under set -e) the
# script bailing before printing which files actually drifted.
SRC_ONLY=$(LC_ALL=C comm -23 "${SRC_LIST}" "${SAT_LIST}")
SAT_ONLY=$(LC_ALL=C comm -13 "${SRC_LIST}" "${SAT_LIST}")
COMMON=$(LC_ALL=C comm -12 "${SRC_LIST}" "${SAT_LIST}")

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
  if [ -L "${SOURCE_DIR}/${f}" ] || [ -L "${SATELLITE_DIR}/${f}" ]; then
    if [ ! -L "${SOURCE_DIR}/${f}" ] || [ ! -L "${SATELLITE_DIR}/${f}" ] \
      || ! python3 -c 'import os,sys; sys.exit(os.readlink(sys.argv[1]) != os.readlink(sys.argv[2]))' \
        "${SOURCE_DIR}/${f}" "${SATELLITE_DIR}/${f}"; then
      CONTENT_COUNT=$((CONTENT_COUNT + 1))
      echo "--- symlink drift: ${f} ---" >> "${DIFFS}"
    fi
    continue
  fi
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
