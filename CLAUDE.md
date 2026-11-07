# Follow these rules

## Release new version

- **Pre-release gate:** run the CLI reference drift check and resolve any drift before tagging — `bash .agents/skills/cli-reference-drift/check.sh` (see [.agents/skills/cli-reference-drift/SKILL.md](.agents/skills/cli-reference-drift/SKILL.md)). The website CLI reference (`website/src/content/docs/reference.mdx`) is hand-curated and must stay in sync with the binary.
- **Changelog:** in the release PR, run `bash .agents/skills/changelog/assess.sh` to confirm every merged PR since the last tag is recorded, then stamp the `## Upcoming` section of `website/src/content/docs/changelog.mdx` to `vX.Y.Z` + date (see [.agents/skills/changelog/SKILL.md](.agents/skills/changelog/SKILL.md)).
- **Agent plugin versions:** before tagging, run `uv run --script scripts/set-plugin-version.py X.Y.Z`, `uv run --script scripts/validate-agent-plugins.py X.Y.Z`, and `git diff --check`, then commit the synchronized `.claude-plugin/plugin.json` and `.codex-plugin/plugin.json` versions. The scripts have no third-party dependencies; `uv` supplies the Python runtime. The marketplace catalog version is independent.
- When asked to release, use `rt git::release --major --sign --push vX.Y.Z` where X.Y.Z is the version to release
- Then push the tag to the origin

## Satellite repositories (plugin, packages)

`plugin/` and `packages/` in this monorepo are the **source of truth**. CI mirrors them to their standalone satellite repos (`dotsecenv/plugin`, `dotsecenv/packages`). Never edit the satellites directly and never accept PRs there; edits made on a satellite are overwritten by the next publish.

The release workflow (`.github/workflows/release.yml`) mirrors each source directory to its satellite's `main` and adds a version tag. Run `Publish Satellites` (`.github/workflows/publish-satellites.yml`) from monorepo `main` for updates between releases; it publishes without a tag. Both use `releasetools/actions/signed-push` and record `Source-Commit`, `Source-SHA`, `Source-Path`, and, on releases, `Source-Tag` in the commit body.

`scripts/release/verify-satellite-provenance.py` checks the exact satellite commit through GitHub's API before trusting those trailers. The signature must be valid and made by GitHub, and the author must be `dotsecenv-automated-releases[bot]`. `Source-Commit` and `Source-Path` must match the expected monorepo and satellite. `Source-SHA` must be reachable from monorepo `main`. A release's `Source-Tag` must point to that commit and be an annotated tag with a valid signature from `MihaiBojin`. Untagged ad-hoc publishes still require signature and ancestry checks.

The drift workflow runs verifier code from a separate trusted `main` checkout. It compares the authenticated source revision with the satellite's files and executable bits, including symlink targets. The generated `packages/retracted.txt` is compared after regeneration from the authenticated `go.mod`.

Packages deployment starts only through `workflow_dispatch`. The release and ad-hoc workflows dispatch it after publishing, passing the source SHA and the release tag when present. The release App needs Actions write permission on `packages`. A job with `permissions: {}` and no distribution secrets authenticates provenance and checks the mirrored files. Both jobs that use secrets depend on that gate, and the build checks out its validated satellite SHA. The release App must supply `source_sha`; `MihaiBojin` can rebuild manually with `keep_versions`, using authenticated HEAD trailers when the source inputs are empty.

The org-scoped `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` are sign-only distribution credentials used by the monorepo and packages workflows. The plugin satellite requires neither. Workflow checks trust protected monorepo `main` and do not prevent a credential with workflow-editing access from replacing the satellite workflow itself.

A bug reported on a satellite (e.g. `dotsecenv/plugin#29` about `conf.d/dotsecenv.fish`) is fixed here under `plugin/` with a matching `plugin/tests/` change, and reaches the satellite on the next publish. `plugin/AGENTS.md` states this in the satellite for anyone landing there. Reference satellite issues/PRs as `plugin#N` / `packages#N`. The plugin test suite is `make -C plugin test-plugins` (bash/zsh/fish).

## Policy directory conventions

- Policy fragments live at `/etc/dotsecenv/policy.d/*.yaml`, owned `root:root`, mode `0644` or stricter
- Filename ordering matches Unix `*.d` convention (sudoers.d, systemd, nginx): files load lexically; for scalar policy fields in future phases, lexically-later fragments override earlier ones
- Naming convention: `00-base, 50-team, 99-overrides`
- For allow-list fields (Phase 1: `approved_algorithms`), filename order is irrelevant — fragments union
- `policy.DefaultDir` in `pkg/dotsecenv/policy/policy.go` is exposed as a `var` (not `const`) so tests can override; **production code MUST NOT reassign it**
- `policy validate` is meant to run in CI for ops repos shipping policy; exit codes are distinct per error category

## Documentation hygiene

When writing or editing user-facing prose (READMEs, recipes, tutorials, runbooks, guides, concept pages, code comments, CLI help strings, error messages):

- Run the content through the `/humanizer` skill before committing. Scan for em-dash overuse, rule-of-three decoration, AI vocabulary (`delve`, `underscores`, `leverage`, `seamless`, `tapestry`, `robust`), copula avoidance, signposting ("Let me dive into…"), fragmented headers, and inline-header vertical lists (`**Bold:** restatement`).
- Keep the focus on the tool. Do not prescribe company policy, comms channels, escalation paths, or org-specific workflow (on-call channels, security logs, "loop in legal", HR procedures). Document what dotsecenv does and how to use it; leave the org-side wrapping to the reader.
- Match the terse, direct voice in `website/src/content/docs/tutorials/` and `website/src/content/docs/runbooks/`. The Tier-3 offboarding section in `skills/secrets/SKILL.md` is the compact-runbook reference: numbered steps, one-sentence explanations, single `<Aside>` for the append-only contract.
