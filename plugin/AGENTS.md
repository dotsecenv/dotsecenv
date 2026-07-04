# AGENTS.md

**This repository is a generated mirror. Do not edit it or open pull requests here.**

The source of truth for the dotsecenv shell plugins lives in the
[`dotsecenv/dotsecenv`](https://github.com/dotsecenv/dotsecenv) monorepo under
[`plugin/`](https://github.com/dotsecenv/dotsecenv/tree/main/plugin). CI publishes
that directory to this repo on each dotsecenv release, and ad-hoc for dependency
and doc updates, via a signed push. Anything committed directly here is
overwritten on the next publish.

## Working on an issue filed here

- Reproduce and fix in `dotsecenv/dotsecenv` under `plugin/`. The files map 1:1:
  `conf.d/dotsecenv.fish` (fish), `dotsecenv.plugin.bash`, `dotsecenv.plugin.zsh`,
  and the shared `_dotsecenv_core.sh`.
- Add or update coverage in `plugin/tests/`, then run `make -C plugin test-plugins`
  (bash, zsh, and fish).
- Open the pull request against `dotsecenv/dotsecenv:main`, not this repo.

## Behavior notes for triage

- The plugins auto-load `.secenv` only in **interactive** shells. In a
  non-interactive shell (`fish -c`, a script, an editor capturing output) they
  stay silent and do not spawn the CLI. If a diagnostic line leaks into captured
  command output, that is a bug in the interactivity guards; see the fish
  `conf.d/dotsecenv.fish` load-time / PWD-hook entry points and the bash/zsh
  load-time / `chpwd` equivalents.

Each mirrored commit records its origin in the commit body: `Source-Commit`,
`Source-SHA`, `Source-Path`, and `Source-Tag` (on release). See
[CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide.
