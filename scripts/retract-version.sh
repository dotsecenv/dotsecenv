#!/usr/bin/env bash
# retract-version.sh — mark a released version as retracted.
#
# Does three things per version:
#   1. Adds an entry to go.mod's `retract` block (propagates to all Go
#      module consumers via the module proxy).
#   2. Deletes every asset from the corresponding GitHub release (so a
#      direct curl/wget or `gh release download` cannot pull the
#      retracted binary).
#   3. Renames the GitHub release to "[RETRACTED] vX.Y.Z" and appends a
#      notice to the body so the GitHub UI shows the retraction.
#
# The git tag is preserved so prior consumers can still resolve it
# (Go module retraction needs the tag to remain reachable). Combine
# with a tag protection rule to prevent re-creation.
#
# Idempotent: re-running for an already-retracted version is a no-op
# beyond a confirmation print.

set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 [options] <version> [<version>...]

Options:
  --reason TEXT     Comment placed inline with each retract entry and
                    appended to the GitHub release body.
                    Default: "retracted release"
  --no-commit       Edit go.mod but do not create a git commit.
  --no-release      Skip GitHub release modifications (asset delete,
                    title rename, body update).
  --dry-run         Print what would happen without making changes.
  --yes             Skip interactive confirmation.
  -h, --help        Show this help.

Examples:
  $0 --reason "no release published" v0.6.10
  $0 --reason "tag moved; duplicate upload" --yes v0.6.11
EOF
}

REASON="retracted release"
COMMIT=1
TOUCH_RELEASE=1
DRY_RUN=0
ASSUME_YES=0
VERSIONS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --reason)      REASON="$2"; shift 2 ;;
        --reason=*)    REASON="${1#*=}"; shift ;;
        --no-commit)   COMMIT=0; shift ;;
        --no-release)  TOUCH_RELEASE=0; shift ;;
        --dry-run)     DRY_RUN=1; shift ;;
        --yes|-y)      ASSUME_YES=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        -*)            echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)             VERSIONS+=("$1"); shift ;;
    esac
done

[ ${#VERSIONS[@]} -gt 0 ] || { usage >&2; exit 2; }

REPO_ROOT="$(git rev-parse --show-toplevel)"
GO_MOD="${REPO_ROOT}/go.mod"
[ -f "$GO_MOD" ] || { echo "go.mod not found at $GO_MOD" >&2; exit 1; }

# ----- helpers --------------------------------------------------------------

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'warn: %s\n' "$*" >&2; }
err()  { printf 'error: %s\n' "$*" >&2; exit 1; }

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] %s\n' "$*"
    else
        "$@"
    fi
}

valid_version() {
    printf '%s' "$1" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.+-]+)?$'
}

# Is version already retracted in go.mod?
already_retracted() {
    local v="$1"
    awk -v ver="$v" '
        /^retract[[:space:]]*\(/ { inblock=1; next }
        inblock && /^\)/         { inblock=0; next }
        inblock && $1 == ver     { found=1; exit }
        $0 ~ "^retract[[:space:]]+" ver "([[:space:]]|$)" { found=1; exit }
        END { exit found ? 0 : 1 }
    ' "$GO_MOD"
}

# Append (or create) the retract block in go.mod.
add_retract_entry() {
    local version="$1" reason="$2"
    local entry
    entry=$(printf '\t%s // %s' "$version" "$reason")

    if grep -qE '^retract[[:space:]]*\(' "$GO_MOD"; then
        # Insert before the closing `)` of the existing block.
        if [ "$DRY_RUN" -eq 1 ]; then
            printf '[dry-run] insert into existing retract block: %s\n' "$entry"
        else
            awk -v new="$entry" '
                /^retract[[:space:]]*\(/ { inblock=1; print; next }
                inblock && /^\)/         { print new; inblock=0; print; next }
                { print }
            ' "$GO_MOD" > "$GO_MOD.tmp"
            mv "$GO_MOD.tmp" "$GO_MOD"
        fi
    else
        # Create a new block at end of file.
        if [ "$DRY_RUN" -eq 1 ]; then
            printf '[dry-run] create new retract block with: %s\n' "$entry"
        else
            {
                printf '\nretract (\n'
                printf '%s\n' "$entry"
                printf ')\n'
            } >> "$GO_MOD"
        fi
    fi
}

# Delete every asset on a GitHub release for the given tag.
delete_release_assets() {
    local tag="$1"
    local assets
    assets=$(gh api "repos/${REPO_OWNER}/${REPO_NAME}/releases/tags/${tag}" \
        --jq '.assets[].name' 2>/dev/null || true)

    if [ -z "$assets" ]; then
        log "no assets to delete on ${tag}"
        return 0
    fi

    while IFS= read -r asset; do
        [ -z "$asset" ] && continue
        log "  deleting asset: $asset"
        run gh release delete-asset "$tag" "$asset" --yes \
            --repo "${REPO_OWNER}/${REPO_NAME}"
    done <<<"$assets"
}

# Rename release title to "[RETRACTED] vX.Y.Z" and append notice to body.
# Idempotent: the [RETRACTED] prefix is added only once.
mark_release_yanked() {
    local tag="$1" reason="$2"
    local current_title current_body new_title new_body marker

    current_title=$(gh api "repos/${REPO_OWNER}/${REPO_NAME}/releases/tags/${tag}" \
        --jq '.name // .tag_name' 2>/dev/null || echo "")
    current_body=$(gh api "repos/${REPO_OWNER}/${REPO_NAME}/releases/tags/${tag}" \
        --jq '.body // ""' 2>/dev/null || echo "")

    case "$current_title" in
        "[RETRACTED]"*) new_title="$current_title" ;;
        *)           new_title="[RETRACTED] ${current_title}" ;;
    esac

    marker="> **This release has been retracted.**"
    if printf '%s' "$current_body" | grep -qF "$marker"; then
        new_body="$current_body"
    else
        new_body=$(printf '%s\n\n%s %s\n' "$marker" \
                    "> Reason:" "$reason"; printf '\n%s\n' "$current_body")
    fi

    log "  marking release ${tag} as [RETRACTED] and prerelease"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] new title: %s\n' "$new_title"
        printf '[dry-run] set prerelease=true (excludes from releases/latest)\n'
    else
        # --prerelease excludes the release from the `releases/latest`
        # GitHub API endpoint that install.sh resolves "latest" against,
        # so users defaulting to "latest" skip the retracted version.
        # The packages publish workflow's existing prerelease filter
        # also benefits.
        printf '%s' "$new_body" | \
            gh release edit "$tag" --repo "${REPO_OWNER}/${REPO_NAME}" \
                --title "$new_title" --prerelease --notes-file -
    fi
}

# ----- main -----------------------------------------------------------------

# Resolve owner/name from origin remote for gh CLI calls.
ORIGIN_URL=$(git config --get remote.origin.url)
case "$ORIGIN_URL" in
    *github.com:*)   REPO_FULL="${ORIGIN_URL#*github.com:}" ;;
    *github.com/*)   REPO_FULL="${ORIGIN_URL#*github.com/}" ;;
    *)               err "remote.origin.url is not a github.com URL: $ORIGIN_URL" ;;
esac
REPO_FULL="${REPO_FULL%.git}"
REPO_OWNER="${REPO_FULL%%/*}"
REPO_NAME="${REPO_FULL#*/}"

# Validate versions and warn on missing tags.
for v in "${VERSIONS[@]}"; do
    valid_version "$v" || err "not a vX.Y.Z version: $v"
    if ! git rev-parse --verify --quiet "refs/tags/$v" >/dev/null; then
        warn "tag $v does not exist in this local repo (continuing anyway; the retract will still take effect once the next version is tagged)"
    fi
done

# Confirm.
log "About to retract the following version(s) of ${REPO_OWNER}/${REPO_NAME}:"
for v in "${VERSIONS[@]}"; do
    printf '  - %s\n' "$v"
done
log "Reason: ${REASON}"
log "Actions: edit go.mod retract block$([ $COMMIT -eq 1 ] && echo ', commit')$([ $TOUCH_RELEASE -eq 1 ] && echo ', delete release assets, mark release [RETRACTED]')$([ $DRY_RUN -eq 1 ] && echo ' (DRY RUN)')"

if [ "$ASSUME_YES" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    printf 'Proceed? [y/N] '
    read -r reply
    case "$reply" in
        y|Y|yes|YES) ;;
        *) err "aborted" ;;
    esac
fi

# Edit go.mod.
for v in "${VERSIONS[@]}"; do
    if already_retracted "$v"; then
        log "${v}: already in go.mod retract block — skipping"
    else
        log "${v}: adding to go.mod retract block"
        add_retract_entry "$v" "$REASON"
    fi
done

# Normalize formatting.
if [ "$DRY_RUN" -eq 0 ]; then
    (cd "$REPO_ROOT" && go mod edit -fmt)
fi

# GitHub release modifications.
if [ "$TOUCH_RELEASE" -eq 1 ]; then
    for v in "${VERSIONS[@]}"; do
        if gh api "repos/${REPO_OWNER}/${REPO_NAME}/releases/tags/${v}" \
                >/dev/null 2>&1; then
            log "${v}: modifying GitHub release"
            delete_release_assets "$v"
            mark_release_yanked "$v" "$REASON"
        else
            log "${v}: no GitHub release exists — nothing to delete"
        fi
    done
fi

# Show diff and commit.
if [ "$DRY_RUN" -eq 1 ]; then
    log "dry run complete; no changes written"
    exit 0
fi

if ! git -C "$REPO_ROOT" diff --quiet go.mod; then
    log "go.mod diff:"
    git -C "$REPO_ROOT" --no-pager diff go.mod | sed 's/^/    /'

    if [ "$COMMIT" -eq 1 ]; then
        msg_subject="chore: retract ${VERSIONS[*]}"
        log "committing: $msg_subject"
        git -C "$REPO_ROOT" add go.mod
        git -C "$REPO_ROOT" commit -m "$msg_subject" \
            -m "Reason: ${REASON}" \
            -m "Retraction propagates to Go module consumers via the module proxy. GitHub release assets have been deleted to block direct downloads."
    else
        log "skipping commit (--no-commit)"
    fi
else
    log "no go.mod changes to commit"
fi

log "done"
