---
name: changelog
description: >
  Keep the website changelog (website/src/content/docs/changelog.mdx) building
  up continuously, one entry per PR. Use when opening a PR (add a one-line
  entry under "Upcoming"), when preparing a release (stamp "Upcoming" to
  the version tag), or to assess which merged PRs are missing from the
  changelog. Triggers on: changelog, release notes, upcoming,
  changelog entry, add changelog, before release, release PR.
---

# Changelog / Release Notes

Release notes are built up continuously. Every PR adds one line under a standing
**`## Upcoming`** section in `website/src/content/docs/changelog.mdx`, and
the release PR stamps that section to the version tag. This keeps the changelog
from falling behind the actual releases.

Categories follow the Conventional Commit type: `feat` -> **Features**,
`fix` -> **Bug Fixes**, everything else (`docs`, `chore`, `refactor`, `test`,
`ci`, dependency bumps) -> **Other**. Entries end with the PR number.

```mdx
## Upcoming

_Unreleased_

### Features
- Short, user-facing description (#PR)

### Bug Fixes
- ... (#PR)

### Other
- ... (#PR)
```

## Add an entry (do this on every PR)

When you open a PR, add ONE line under `## Upcoming`, in the matching
subsection, as part of the PR's own diff:

- Write it for someone reading release notes, not as a commit message.
- Put it in the subsection for the PR's type (`feat`/`fix`/other). Create the
  subsection if it does not exist yet, keeping the order
  Features -> Bug Fixes -> Other.
- End with the PR number once the PR exists: `- <description> (#<PR>)`.

This per-PR edit is the whole point: the release notes accumulate as work lands.

## Assess (release PR, or any spot check)

List merged PRs since the last release tag that are not yet under "Next
release":

```bash
bash skills/changelog/assess.sh
```

It exits non-zero when commits since the last tag are missing. Add the missing
entries before releasing. (Maps commits to PRs via the `(#NN)` suffix that
GitHub adds to squash-merge subjects.)

## Stamp the release (release PR)

In the PR that cuts `vX.Y.Z`:

1. Run `bash skills/changelog/assess.sh` and add any missing entries.
2. Rename the header `## Upcoming` -> `## vX.Y.Z`, and replace
   `_Unreleased_` with `_<Month Day, Year>_` (today's date).
3. Remove any subsection that ended up with no entries.
4. Add a fresh, empty `## Upcoming` section (with `_Unreleased_`) at the top
   of the version list, ready for the next cycle.

Then proceed with the tag per [CLAUDE.md](../../CLAUDE.md) "Release new version".
The optional Twitter/X announcement guidance lives in
[website/CLAUDE.md](../../website/CLAUDE.md) "Changelog Generation".

## Prerequisites

Git with tags available (`git fetch --tags`). No build step is required.
