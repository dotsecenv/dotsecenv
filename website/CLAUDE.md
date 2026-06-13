# Website Project Instructions

## Documentation hygiene

Run any new or edited MDX prose through the `/humanizer` skill before committing. Scan for em-dash overuse, rule-of-three decoration, AI vocabulary (`delve`, `underscores`, `leverage`, `seamless`, `tapestry`, `robust`), copula avoidance, signposting, fragmented headers, and inline-header vertical lists.

Keep the focus on the tool. Do not prescribe company policy, comms channels, escalation paths, or org-specific workflow (on-call channels, security logs, "loop in legal", HR procedures). Tutorials, guides, and runbooks document what dotsecenv does and how to use it; the org-side wrapping is the reader's problem.

Match the terse, direct voice of existing pages. The Tier-3 offboarding section in `../skills/secrets/SKILL.md` is the compact-runbook reference: numbered steps in `<Steps>`, one-sentence explanations, single `<Aside>` for the load-bearing caveat (append-only, recipient set, etc.).

When documenting CI/CD, use the canonical secret names and always state whether a key is repo-scoped or org-wide. A vault-decryption keypair is `GPG_PRIVATE_KEY` repo-scoped (a repository secret) or `ORG_GPG_PRIVATE_KEY` org-wide (an organization secret), with `_PASSPHRASE` and per-environment `_DEV/_STAGING/_PROD` variants; keys are ASCII-armored, never base64; log in by fingerprint (`dotsecenv login <FINGERPRINT>`, never `DOTSECENV_FINGERPRINT`). See [Key Scope](src/content/docs/concepts/key-scope.mdx).

## Changelog Generation

The changelog (`src/content/docs/changelog.mdx`) builds up continuously: every PR adds a one-line entry under the standing `## Upcoming` section, and the release PR stamps that section to the version tag. The `changelog` skill (`../skills/changelog/SKILL.md`) drives this; this section is the reference for format and the release stamp.

**Per PR:** add one line under `## Upcoming`, in the subsection for the PR's type (see the table below), ending with the PR number.

**At release (in the release PR):**

1. From the repo root, run `bash skills/changelog/assess.sh` to list any merged PRs since the last tag that are missing from "Upcoming", and add an entry for each. This is the "assess all commits since the last release" step.
2. Rename `## Upcoming` to `## vX.Y.Z` and replace `_Unreleased_` with `_Month Day, Year_` (today's date). Drop any subsection left empty.
3. Open a fresh, empty `## Upcoming` section at the top for the next cycle.

Plugin changes live in the separate `plugin` repo; reference them as `plugin#N` when they belong in a dotsecenv release note.

### Changelog Entry Format

```mdx
## Upcoming

_Unreleased_

### Features
- Feature description here (#PR)

### Bug Fixes
- Fix description here (#PR)

### Other
- Other changes here (#PR)
```

At release, `## Upcoming` / `_Unreleased_` becomes `## vX.Y.Z` / `_Month Day, Year_`, and a fresh empty `## Upcoming` is opened above it.

### Commit Message Convention

Use Conventional Commits for changelog-friendly messages:

| Type | Category | Example |
|------|----------|---------|
| `feat:` | Features | `feat: add list mode to secret get` |
| `fix:` | Bug Fixes | `fix: remove extra newline from output` |
| `refactor:` | Other | `refactor: simplify error handling` |
| `chore:` | Other | `chore: update dependencies` |
| `docs:` | Other | `docs: update README` |
| `test:` | Other | `test: add e2e tests` |
| `ci:` | Other | `ci: add security review workflow` |

Use `feat!:` or `fix!:` suffix for breaking changes.

### Twitter/X Announcement Posts

After generating the changelog entry, output 1–3 Twitter/X announcement posts in the terminal. Do **not** commit these anywhere — they are for copy-pasting to X/Twitter only.

Guidelines:
- Keep each post under 280 characters
- Lead with the version number and the most notable change
- Use a direct, informative tone (no hype or excessive emojis)
- If the release has multiple highlights, use separate posts for each
- Format each post as a fenced code block for easy copy-paste

Example output:

```
dotsecenv v0.5.0 is out! New `dse up` command loads ancestor .secenv files when jumping into subdirectories. Plus fixes for zsh secret leaks and unnecessary vault calls.

https://dotsecenv.sh/changelog
```

```
dotsecenv v0.5.0 fixes a zsh bug where `local` declarations could leak secret values on directory re-entry. Upgrade recommended.
```
