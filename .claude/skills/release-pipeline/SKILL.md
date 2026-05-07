---
name: release-pipeline
description: >
  Operate and reason about the dotsecenv monorepo release pipeline.
  Use this skill when working on .github/workflows/release.yml, when a release
  fails or partially succeeds, when extending the pipeline with new publish
  targets, or when answering questions about why the design rejects auto-rollback
  and draft releases. Covers cross-repo status reporting, the no-draft rule,
  fix-forward recovery, and the release-complete integrity gate.
  Triggers on: release pipeline, partial publish, brew install fails, GitHub
  release draft, repository_dispatch, cross-repo status, release-complete,
  goreleaser, homebrew tap, dotsecenv/{packages,plugin,website,homebrew-tap,action}.
---

# dotsecenv Release Pipeline

The release pipeline lives entirely in `dotsecenv/dotsecenv/.github/workflows/release.yml`. It orchestrates publishing the CLI binary, Homebrew cask, shell plugin, website, packages repos, and (eventually) the GitHub Action — all in a single workflow run whose `gh run view <id>` graph captures the full release end-to-end. There is no `repository_dispatch` fan-out; downstream satellites are publish targets, not orchestrators.

## Architecture in one paragraph

The monorepo is the source of truth. Plugin (`dotsecenv/plugin`), website (`dotsecenv/website`), packages (`dotsecenv/packages`), homebrew-tap (`dotsecenv/homebrew-tap`), and action (`dotsecenv/action` — currently deferred) are *artifact-only* satellites. The release workflow builds binaries via GoReleaser, notarizes macOS, refreshes checksums, then in parallel: pushes the cask to homebrew-tap and runs `brew install dotsecenv` inline; pushes plugin source to dotsecenv/plugin and tags it; builds Astro and pushes `dist/` to dotsecenv/website; builds APT/YUM/Arch repo metadata and pushes to dotsecenv/packages; smoke-tests the action against the just-tagged release. Each cross-repo publish has explicit status awareness: satellites that own GH Pages deploy (website, packages) post a Commit Status back to the monorepo's release SHA via `gh api`, and the monorepo's `wait-*` jobs block on those statuses with a 15-minute timeout. The terminal `release-complete` job asserts every required `needs[j].result == 'success'` and fails red otherwise.

## The no-draft rule

**Do not put the GitHub release in `draft: true` and try to flip it to public at the end of the pipeline.** This pattern fails because:

- `brew install dotsecenv` fetches from `https://github.com/dotsecenv/dotsecenv/releases/download/<ver>/...` over **anonymous HTTPS**. Draft assets are not served to anonymous fetchers — Homebrew gets 404. The inline `brew install` smoke deadlocks against `release-complete` because `release-complete` `needs:` `update-homebrew-tap`.
- The `smoke-action` job runs `uses: dotsecenv/dotsecenv@<tag>` on a generic ubuntu runner. If the action's composite uses `gh release download` and the runner's `${{ github.token }}` is scoped to the smoke runner's repo (not `dotsecenv/dotsecenv`), it cannot read drafts on the foreign repo and 404s.

GoReleaser publishes the GH release as **public** in the `goreleaser` job. Recovery from a partial-publish failure is **fix-forward via a patch release**, not automatic rollback. This matches `cli/cli` and standard OSS Go-CLI practice.

## Failure handling — what to do when the graph fails red

The `release-complete` job is the integrity gate. It explicitly asserts each required `needs[j].result == 'success'` (a *skipped* job is not a green check). When it fails:

| Failed job | What's already happened | Runbook |
|------------|--------------------------|---------|
| `update-homebrew-tap` (`brew install` smoke) | Cask was pushed to `dotsecenv/homebrew-tap`. GH release is public. Users running `brew install dotsecenv` *now* hit the broken cask. | (a) `git -C dotsecenv/homebrew-tap revert HEAD` and push (restores prior cask); (b) `gh release delete <tag> -R dotsecenv/dotsecenv` and `git push origin :<tag>`; (c) investigate failure; (d) fix forward; (e) retag (with the new pipeline). |
| `wait-website` | Cask, plugin, packages may already be published. Website is one release behind. CLI is installable; docs lag. | Fix the website, re-run `publish-website` via `workflow_dispatch` against the same tag, OR ship a patch release that supersedes. Do not delete the GH release. |
| `wait-packages` | Same as wait-website. APT/YUM repo state is whatever the last successful push left it. | Fix forward; re-run `build-packages` via `workflow_dispatch` against the same tag, OR ship a patch release. |
| `publish-plugin` | Plugin tag may not exist. Cask may already point to a CLI version that the plugin tag doesn't yet match. | Manually push to `dotsecenv/plugin` from the monorepo `plugin/` tree at `<tag>` and tag the satellite. |
| `smoke-action` | GH release is public. `action.yml` at root works against the just-published binaries (or doesn't, which is why smoke failed). | Fix the action; ship a patch release. The action stays at the `<tag>` reference users pin to today; fix-forward via a new minor/patch is the only recovery. |

**Each satellite's atomicity is its own concern.** Silent partial publishes are eliminated (the maintainer sees the red graph), but each satellite's published state is whatever the last successful push left it. The pipeline does not auto-rollback satellites; the maintainer's runbook is fix-forward.

## Cross-repo Commit Status pattern

The `wait-website` and `wait-packages` jobs do not poll for satellite workflow runs by `head_sha` — that pattern is racy under re-runs and parallel runs sharing a SHA. Instead:

1. The monorepo's `publish-website` (or `build-packages`) writes a sidecar file `dist/.release-sha` containing `${{ github.sha }}` before pushing to the satellite.
2. The satellite's deploy workflow reads `.release-sha` from the pushed `dist/`.
3. After deploying, the satellite POSTs a Commit Status to the monorepo via:
   ```bash
   gh api -X POST /repos/dotsecenv/dotsecenv/statuses/$(cat dist/.release-sha) \
     -f context=release/website \
     -f state=success     # or "failure"
   ```
   The satellite uses the GitHub App token (NOT its own `GITHUB_TOKEN`) so it has `Commit statuses: write` on `dotsecenv/dotsecenv`.
4. The monorepo's `wait-website` job loops on `gh api repos/dotsecenv/dotsecenv/commits/${{ github.sha }}/statuses --jq '.[] | select(.context=="release/website") | .state'` until terminal, with a 15-minute timeout.

**App permission prerequisite**: `RELEASE_APP` must have `Commit statuses: write` on `dotsecenv/dotsecenv` for satellites to post status back. Verify before adding new `wait-*` jobs.

## Security non-negotiables

- **No `secrets: inherit`**. Every job is top-level and references only the secrets it needs in `env:`.
- **Per-job App tokens** with minimal `repositories:` scope. `publish-plugin` mints for `plugin` only, etc.
- **Workflow-level `permissions: {}`** with each job opting in.
- **SHA-pin all third-party actions** with version comments. Renovate/Dependabot keeps them updated.
- **Pin GoReleaser config exactly** (e.g., `version: "~> v2.5"`, not floating `~> v2`).
- **`harden-runner`** audit-mode in every job, block-mode on hermetic-test, build, notarize, refresh-checksums.
- **Cleanup `${runner.temp}/gpg.key`** in `notarize-macos`'s `Cleanup secrets` step.
- **`concurrency`** group `release-${{ github.ref_name }}` prevents simultaneous releases racing on the same tag.

## When extending the pipeline

To add a new publish target:

1. Add a top-level job in `release.yml` (do not split into reusable workflow files — the single-file DAG is the design).
2. Mint a per-job App token with `repositories:` scoped to the new target only.
3. If the satellite owns its own GH Pages deploy: write `dist/.release-sha` sidecar, push, add a `wait-<target>` job that polls Commit Status `release/<target>`. Update the satellite's deploy workflow to post the status back.
4. If the publish step can be self-contained (push and immediately verify): do it inline. No separate `wait-` job needed.
5. Add the new job to `release-complete`'s `needs:` array AND the loop that asserts `needs[j].result == 'success'`.
6. SHA-pin any new third-party actions used.
7. Update this skill doc with the new component's failure-handling row.

## Reference precedent

`cli/cli` (GitHub CLI) is the closest precedent: single repo, single Go module, one self-contained release workflow that does Linux RPM/DEB (`createrepo`/`reprepro`), notarized macOS PKG, signed Windows MSI/EXE, and pushes apt/yum content to `cli.github.com` inline. No `repository_dispatch`. Homebrew bumps via `mislav/bump-homebrew-formula-action`.

GoReleaser keeps its docs site `www/` inside the binary repo. fzf has in-repo `shell/` plugin source. None of these projects use cross-repo workflow dispatch for release.

## What this design rejects (and why)

- **Reusable workflow split** (one file per release stage): zero reuse since each callee has one caller; doubles the files to read; introduces `secrets: inherit` blast-radius hazards. Single `release.yml` with top-level jobs is more readable.
- **`repository_dispatch` fan-out**: fire-and-forget; failure surfaces nowhere; the original problem.
- **Run-id polling on satellite workflows**: brittle under re-runs, race-prone with parallel runs sharing a SHA. Commit Statuses are idempotent, named, and deterministic.
- **Draft GH release until terminal**: breaks `brew install` and cross-runner `gh release download` (above).
- **Auto-rollback on partial failure**: not implementable cleanly across five satellites with distinct atomicity. Fix-forward via patch release is the OSS norm.
