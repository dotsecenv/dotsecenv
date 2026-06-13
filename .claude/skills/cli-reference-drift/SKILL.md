---
name: cli-reference-drift
description: >
  Check the website CLI reference (website/src/content/docs/reference.mdx) for
  drift against the actual dotsecenv CLI, and run it before cutting a release.
  Use when preparing a release, when asked to verify the CLI docs are in sync or
  check reference drift, or after adding or changing a command or flag.
  Triggers on: release, cli reference drift, reference out of date,
  docs in sync, before release, new command, new flag.
---

# CLI Reference Drift Check

The website CLI reference at `website/src/content/docs/reference.mdx` is
hand-curated (it carries examples, JSON output schemas, sample outputs, exit
codes, and a config-file reference that cobra cannot generate). Because it is
hand-written, it can drift from the actual CLI. Run this check before every
release to catch commands or flags that exist in the binary but are missing
from the page.

## Run it

```bash
bash .claude/skills/cli-reference-drift/check.sh
```

The script runs the repo's `make docs` target to generate the live command and
flag inventory from source (into `build/cli`), then compares it against
`reference.mdx`. It exits non-zero when it finds drift. No network is needed
(dependencies are vendored); a Go toolchain and `make` on `PATH` are required.

## What it reports

- **MISSING command** — a CLI command with no matching `##`/`###` heading in
  `reference.mdx`.
- **MISSING flag** — a command-specific (long) flag not mentioned anywhere in
  `reference.mdx`.
- **DUPLICATE heading** — the same `##`/`###` heading text appears more than
  once (a copy-paste or stale-section bug).

## Act on the report

For each genuine finding, edit `reference.mdx`:

- Missing command or flag: add it in the page's existing style — a heading, a
  one-line description, an **Options** table, and at least one **Examples**
  block. Place it under the right parent section (e.g. a new `secret`
  subcommand goes under `## secret`).
- Duplicate or stale heading: remove the redundant section.

Re-run the check until it reports `no drift`.

Known false positives to ignore:

- `completion bash` / `zsh` / `fish` are documented under `## completion` as
  `### Bash` / `### Zsh` / `### Fish`, not as `### completion <shell>`.

## Release gate

This is a pre-release step. Before running `rt git::release` (see
[CLAUDE.md](../../CLAUDE.md) "Release new version"), run this check and resolve
any drift. Do not release with an out-of-sync CLI reference. The page is the
canonical CLI reference at <https://dotsecenv.com/reference/>; keeping it honest
is the point of this check.
