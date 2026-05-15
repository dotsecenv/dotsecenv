# AGENTS.md

Onboarding guide for AI coding agents (Claude Code, Cursor, Aider, OpenAI Codex,
etc.) working on this repository. Human contributors should start with
[README.md](./README.md) and [CONTRIBUTING.md](./CONTRIBUTING.md) instead — this
file is the single canonical entrypoint for agents.

## Overview

`dotsecenv` is a Go CLI for managing GPG-encrypted environment secrets. Vaults
are append-only, signed JSONL files; encryption follows
[RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html) OpenPGP with mandatory
AEAD (AES-256-GCM), and signatures meet
[FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final). Release binaries are
pure-Go (no CGO) and built against Go 1.26's native FIPS 140-3 module
(`GOFIPS140=v1.26.0`), with [SLSA Build Level 3](https://slsa.dev/) provenance
attestations.

This repo also ships a Claude Code plugin (`.claude-plugin/`), a GitHub Action
(`action.yml`), a Terraform credentials helper (`contrib/`), and a hermetic
end-to-end test harness verified by network-namespace + strace in CI.

## Repository layout

| Path                | Purpose                                                                        |
| ------------------- | ------------------------------------------------------------------------------ |
| `cmd/dotsecenv/`    | CLI entrypoint (Cobra). One file per command (`cmd_init.go`, `cmd_secret.go`). |
| `internal/cli/`     | CLI command implementations, validators, interactive helpers, error mapping.   |
| `internal/xdg/`     | XDG Base Directory resolution.                                                 |
| `pkg/dotsecenv/`    | Public packages: `config/`, `crypto/`, `gpg/`, `identity/`, `output/`, `policy/`, `vault/`. |
| `contrib/`          | `terraform-credentials-dotsecenv` Bash credentials helper for Terraform/OpenTofu. |
| `demos/`            | `demo.sh` for asciinema recording (driven by `make demo`).                     |
| `skills/`           | Claude Code skills (`secenv/SKILL.md`, `secrets/SKILL.md`).                    |
| `.claude-plugin/`   | Claude Code plugin manifest (`plugin.json`, `marketplace.json`).               |
| `scripts/`          | `install.sh`, `e2e.sh`, `e2e-install.sh`, `e2e-terraform.sh`, `sandbox.sh`, `notarize-macos.sh`, `generate_release_key.sh`. |
| `.github/workflows/` | CI + release: `ci.yml` (Go DAG), `ci-plugin.yml`, `ci-website.yml`, `ci-release.yml` (goreleaser snapshot), `e2e-hermetic.yml`, `e2e-install.yml`, `post-release-action.yml` (reusable, post-release action smoke), `lint-workflows.yml` (actionlint), `release.yml`, `deploy-website.yml`. |
| `vendor/`           | Vendored Go dependencies (used by `make build` for hermetic builds).           |
| `action.yml`        | Composite GitHub Action for installing dotsecenv in CI.                        |
| `.goreleaser.yaml`  | Release pipeline (signs, attests, packages deb/rpm/archlinux).                 |
| `lefthook.yml`      | Git hook config: `pre-commit` runs `make lint`, `pre-push` runs `make clean test build e2e`. |
| `.mise.toml`        | Tool versions for [mise](https://mise.jdx.dev) (installs `dotsecenv` itself for downstream consumers). |

## Build / test / lint / e2e

All commands run from the repo root. The Makefile is the source of truth.

### One-time setup

```bash
make install-tools   # installs lefthook, golangci-lint v2.11.4, syft, goreleaser
make hooks           # installs lefthook git hooks
```

### Day-to-day

| Goal                          | Command                                                        |
| ----------------------------- | -------------------------------------------------------------- |
| Build the binary              | `make build` — produces `bin/dotsecenv`. Sets `CGO_ENABLED=0 GOFIPS140=v1.26.0`, builds with `-mod=vendor`. |
| Build + symlink to `~/.local/bin` | `make build-link`                                              |
| Format Go code                | `make fmt`                                                     |
| Lint (vet, fmt check, golangci-lint, `go mod tidy`) | `make lint`                                                    |
| Unit + integration tests      | `make test` — `go test -v -p 1 ./...`                          |
| Tests with race detector      | `make test-race`                                               |
| End-to-end tests (CLI)        | `make build e2e` — `bin/dotsecenv` must exist; runs `scripts/e2e.sh` in an isolated `mktemp -d` HOME with its own GPG, XDG, and PATH. |
| E2E for Terraform helper      | `make build e2e-terraform`                                     |
| E2E for `install.sh` (network needed) | `make e2e-install`                                             |
| Snapshot release build        | `make release-test` (skips sign, publish, nfpm). Run before merging changes to `.goreleaser.yaml`, `Makefile` release targets, or `tools.go` version pins. CI auto-runs it via `ci-release.yml` when those paths change. |
| Generate completions/docs/man | `make completions`, `make docs`, `make man`                    |
| Interactive sandbox shell     | `make sandbox`                                                 |
| Run everything                | `make all`                                                     |

The pre-push hook runs `make clean test build e2e` — if you commit, you should
expect that to run before push.

### What CI actually runs

Each workflow is path-scoped to its own area. A change touching only one
area triggers only that workflow:

- **`ci.yml`** — Go DAG on `ubuntu-latest` + `macos-latest`. Triggers on
  Go source, `Makefile`, `action.yml`, `.goreleaser.yaml`, `.golangci.yaml`,
  `tools.go`. Runs (in order): `make clean lint build test` → `make build e2e`
  → `make build e2e-terraform` → composite action self-test (default-args
  and init-config variants, both `build-from-source: true`) → `make build
  completions docs man`. Note: `make release-test` is no longer in this
  pipeline — see `ci-release.yml` below.
- **`ci-release.yml`** — `make release-test` (goreleaser snapshot, skips
  sign/publish/nfpm). Triggers only on `.goreleaser.yaml`, `Makefile`,
  `tools.go`, or the workflow file. Run `make release-test` locally
  before merging PRs that touch any of those.
- **`ci-plugin.yml`** — shell tests under `plugin/`, scoped to `plugin/**`.
- **`ci-website.yml`** — Astro build under `website/`, scoped to `website/**`.
- **`e2e-install.yml`** — exercises `scripts/install.sh` against real GH
  releases. Scoped to `scripts/install.sh` + `scripts/e2e-install.sh`.
  Independent of Go (`install.sh` fetches its own binary).
- **`e2e-hermetic.yml`** — re-runs `make e2e` under `step-security/harden-runner`
  (egress blocked) **and** under `unshare --net` with `strace` tracing every
  `connect()` syscall. Any external network call fails the job. Don't break
  this — the proof of hermeticity is the test. PR-only, scoped to Go paths.
- **`post-release-action.yml`** — POST-release smoke. Reusable workflow
  (`workflow_call`) that exercises the released action ref
  (`dotsecenv/dotsecenv@v0`) against a released binary. Invoked from
  `release.yml` after the release is public; `workflow_dispatch`-able for
  ad-hoc reruns against an arbitrary version (`-f version=v0.1.5`).
  PR-time action coverage lives in `ci.yml`'s `e2e-action-default-args`
  and `e2e-action-init-config` jobs instead, which exercise `./` against
  the PR's SHA — this workflow only makes sense after a release exists.
- **`lint-workflows.yml`** — runs `actionlint` on changes under
  `.github/workflows/**`. The only PR-time validation for `release.yml`
  and `post-release-action.yml`, which are otherwise tag-triggered /
  `workflow_call`-only and never fire pre-merge.
- **`release.yml`** — full release pipeline (tag-triggered; no
  `workflow_dispatch` — releasing is reserved for signed semver tags).
  Its `wait-ci`
  job blocks `goreleaser` until each path-scoped CI workflow (ci.yml,
  e2e-install.yml, ci-plugin.yml, ci-website.yml, lint-workflows.yml) has
  passed on the tagged SHA — or warns-and-proceeds if a workflow's path
  filter excluded the commit. `ci-release.yml` is intentionally omitted
  from the gate (its goreleaser snapshot duplicates the `goreleaser` job
  about to run). See the workflow's top-of-file DAG comment for stage layout.

### Force-running CI

Every CI workflow except `release.yml` has a `workflow_dispatch:` trigger,
so you can run any of them manually against any branch — path filters are
bypassed for manual dispatches:

```bash
gh workflow run ci.yml --ref my-branch
gh workflow run e2e-hermetic.yml --ref my-branch
gh workflow run ci-release.yml --ref my-branch
# etc.
```

To re-run an existing run (without re-pushing), use `gh run rerun <id>`
or the "Re-run all jobs" button in the GitHub UI.

`release.yml` is intentionally NOT dispatchable — releasing is reserved
for signed semver tags pushed via `rt git::release`. To rerun a release
that failed mid-pipeline, fix forward with a patch tag.

## Conventions

- **Go version:** 1.26.2 (see `go.mod`). Go 1.26+ required.
- **FIPS 140-3:** Release binaries set `GOFIPS140=v1.26.0` and `CGO_ENABLED=0`.
  The build is pure-Go; **don't add CGO dependencies**.
- **Vendoring:** Dependencies are vendored. `make build` uses `-mod=vendor`.
  After changing imports, run `go mod tidy && go mod vendor`.
- **Commit messages:** Conventional Commits with PR-number suffix, e.g.
  `feat: behavior.* and gpg.program policy fields (last-set-wins) (#116)`.
  Allowed types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`,
  `style`. Breaking changes use `!`, e.g. `refactor!: drop SUID mode (#110)`.
  `Co-Authored-By` footers are welcome (e.g. for AI agents that helped
  produce the change).
- **Branches:** `feat/*`, `fix/*`, `docs/*`, etc. (see `CONTRIBUTING.md`).
- **PRs only:** All changes land on `main` through pull requests. Don't
  push commits directly to `main`, even when your account holds a bypass
  permission. Open a PR against `main` and let CI run.
- **No change without tests:** Every behavior change ships with tests
  that lock the new behavior in. New struct fields, new branches in
  control flow, new flag handling, new error paths — each gets at least
  one test that fails on the unchanged code. Pure refactors that go
  through existing tests are the only exception.
- **Linters:** `golangci-lint` v2.11.4 — pinned because v2.12.x had a
  checksum mismatch on release. Don't bump back to `latest` without verifying.
- **Releases:** Triggered by pushing a signed semver tag. Use
  [`releasetools-cli`](https://github.com/releasetools/cli):

  ```bash
  rt git::release --major --sign --push vX.Y.Z
  ```

  This creates both `vX.Y.Z` and `vX` tags, signs them, and pushes. The
  `release.yml` workflow runs hermetic e2e first, then GoReleaser, then
  notarizes Darwin archives, then re-signs checksums, then triggers downstream
  repos (`packages`, `homebrew-tap`, `plugin`, `website`).
- **Hooks:** Managed by [lefthook](https://github.com/evilmartians/lefthook).
  `make hooks` installs them. **Don't bypass with `--no-verify`** — fix the
  lint or test failure instead.
- **`pnpm` / Node tooling:** Not applicable here; this is a Go-only project.
  Don't add `package.json` or Node toolchain.

## Don't do X

These are grounded in the actual repo state — read the cited file before
making changes that look like they might violate them.

- **Don't reassign `policy.DefaultDir` in production code.** It's a `var` in
  `pkg/dotsecenv/policy/policy.go` (line 31) only so tests can override; see
  the explicit warning in [CLAUDE.md](./CLAUDE.md). Production callers use
  the `Load()` helper.
- **Don't bypass signature verification or skip provenance attestation
  flags.** The release pipeline (`release.yml`) attests every artifact via
  `actions/attest-build-provenance`. The composite action's
  `verify-provenance: true` default is load-bearing for SLSA Build Level 3.
- **Don't commit GPG private keys, real secrets, or vault files containing
  real data.** `.gitignore` excludes `.dotsecenv/` for this reason. Test
  vaults belong under `pkg/dotsecenv/vault/testdata/` with synthetic keys.
- **Don't add CGO dependencies.** Release binaries are pure-Go FIPS
  (`CGO_ENABLED=0`). A CGO dependency would break `GOFIPS140=v1.26.0`,
  fail the hermetic build, and complicate cross-compilation in
  `.goreleaser.yaml`.
- **Don't bypass git hooks (`--no-verify`).** Pre-commit runs `make lint`;
  pre-push runs `make clean test build e2e`. If a hook fails, fix the cause.
- **Don't push directly to `main`.** Branch protection allows bypass for
  some accounts, but the convention is: branch, commit, push the branch,
  open a PR. Direct pushes skip CI gates and review, and force-pushing
  `main` to undo a direct push rewrites public history.
- **Don't modify cryptographic invariants without explicit review.** This
  includes: vault entry signature checks, the SHA-256 hash chain in JSONL
  entries, the append-only writer, multi-recipient PGP encryption, and the
  approved-algorithms allow-list. Tests in
  `pkg/dotsecenv/vault/integration_test.go` and
  `cmd/dotsecenv/security_test.go` lock these in — if your change requires
  changing those tests, surface that explicitly in the PR.
- **Don't alter the hermetic E2E harness so it can reach the network.** The
  whole point is the strace assertion in `.github/workflows/e2e-hermetic.yml`
  proving zero external `connect()` calls.
- **Don't run any of the destructive Tier 3 commands from the
  `dotsecenv:secrets` skill (`secret store`, `secret share`, `secret revoke`,
  `secret forget`, `init`, `login`) unless the user explicitly asked.** See
  `skills/secrets/SKILL.md`.

## Where to find more

| Topic                            | File                                            |
| -------------------------------- | ----------------------------------------------- |
| Long-form user docs              | [README.md](./README.md)                        |
| Release tagging + `policy.d` conventions | [CLAUDE.md](./CLAUDE.md)                        |
| Contribution workflow, branches  | [CONTRIBUTING.md](./CONTRIBUTING.md)            |
| Vulnerability reporting          | [SECURITY.md](./SECURITY.md)                    |
| Code of Conduct                  | [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)      |
| Full docs site (Diátaxis)        | <https://dotsecenv.com>                         |
| Team-lead vault setup tutorial   | <https://dotsecenv.com/tutorials/team-vault-setup/> |
| Audit trail concepts and queries | <https://dotsecenv.com/concepts/audit-trail/>   |
| GPG agent operational reference  | <https://dotsecenv.com/guides/gpg-agent/>       |
| Claude Code skill: `.secenv` files | [skills/secenv/SKILL.md](./skills/secenv/SKILL.md) |
| Claude Code skill: vault ops     | [skills/secrets/SKILL.md](./skills/secrets/SKILL.md) |
| Plugin manifest                  | [.claude-plugin/plugin.json](./.claude-plugin/plugin.json) |
| Composite GitHub Action          | [action.yml](./action.yml)                      |
| Release pipeline                 | [.goreleaser.yaml](./.goreleaser.yaml)          |

## Useful invariants

These properties hold throughout the codebase and you can rely on them when
reasoning about behavior. They are also what reviewers will check.

- **Append-only signed JSONL vault.** Each line is one JSON object: a header
  on line 1, then `identity`, `secret`, or `value` entries. New entries are
  appended; existing entries are never rewritten. The format is documented
  in `README.md` and implemented in `pkg/dotsecenv/vault/`.
- **Every identity, secret, and value entry is individually signed.** The
  signer is recorded in `signed_by` and verified against the identity's
  public key on every read. Validation is performed by `dotsecenv validate`
  and is run on every vault load.
- **SHA-256 hash on every entry.** Entries embed a `hash` field that hashes
  the canonical entry contents; tampering with stored bytes is detected at
  load time independent of the signature.
- **XDG Base Directory compliance.** Config defaults to
  `$XDG_CONFIG_HOME/dotsecenv/config` (typically `~/.config/dotsecenv/config`);
  vaults default to `$XDG_DATA_HOME/dotsecenv/vault`. `DOTSECENV_CONFIG`
  overrides; `-c` overrides everything. See `internal/xdg/`.
- **Stable numeric exit codes.** Defined in
  `pkg/dotsecenv/output/exitcodes.go` and documented in `README.md`. Codes
  `0`–`9` map to specific error categories (success, general, config, vault,
  GPG, auth, validation, fingerprint, access denied, algorithm). Don't
  renumber or repurpose them — scripts and CI depend on them.
- **Policy directory at `/etc/dotsecenv/policy.d/`.** Fragments must be
  owned `root:root`, mode `0644` or stricter. Allow-list fields union
  across fragments; scalar fields are last-fragment-wins in lexical order
  (Unix `*.d` convention: `00-base, 50-team, 99-overrides`). See
  [CLAUDE.md](./CLAUDE.md) and the README's "Policy Directory" section.
- **Multi-recipient PGP encryption.** A single `value` entry carries one
  ciphertext encrypted to multiple recipients (the union of fingerprints
  in `available_to`). Sharing or revoking access re-encrypts only that
  value entry; previous entries are preserved verbatim.
- **No identity in policy.** `login` and `vault` are forbidden keys in
  policy fragments — identity is per-user (cryptographically bound to a
  private key) and policy must not erase user vaults. See the policy
  fragment loader in `pkg/dotsecenv/policy/`.
