# dotsecenv examples

Self-contained, copy-pasteable scenarios that exercise the dotsecenv CLI end to
end. Each example lives in its own subdirectory and is designed to be read,
copied, and adapted by humans and AI coding agents alike.

The examples favour **runnability and correctness** over breadth: every command
shown is a real `dotsecenv` invocation that has been verified against the CLI
help surface and (where possible) executed in an isolated environment.

For narrative documentation see <https://dotsecenv.com>. For the canonical CLI
reference see `dotsecenv --help` or the man pages installed by
`make install`/`install.sh`.

## Index

| #  | Example                                                  | What it shows                                                                | Prereqs                              |
| -- | -------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------ |
| 01 | [quickstart](./01-quickstart/)                           | `init config` -> `init vault` -> `login` -> `secret store` -> `secret get`   | `dotsecenv`, `gpg`                   |
| 02 | [team-share-revoke](./02-team-share-revoke/)             | Multi-recipient encryption with two ephemeral identities; share, then revoke | `dotsecenv`, `gpg`                   |
| 03 | [ci-cd-github-action](./03-ci-cd-github-action/)         | Use the `dotsecenv/dotsecenv` GitHub Action to install and decrypt in CI     | A GitHub repo, a CI-only GPG key     |
| 04 | [policy-directory](./04-policy-directory/)               | Drop YAML fragments into `/etc/dotsecenv/policy.d/` to constrain users       | Root or fakeroot for `/etc/...`      |
| 05 | [secenv-shell-plugin](./05-secenv-shell-plugin/)         | Reference `.secenv` file demonstrating every supported placeholder syntax    | The dotsecenv shell plugin installed |

Examples 01 and 02 ship a `run.sh` that executes the full flow end to end in
an ephemeral working directory. Examples 03, 04, and 05 are configuration
artifacts (a workflow YAML, two policy fragments, a `.secenv` file) — they
ship with a `README.md` that explains how to install and use them, but there
is nothing to "run".

## Safety conventions

Every runnable script in this directory follows the same isolation pattern,
borrowed from `scripts/sandbox.sh` and `demos/demo.sh`:

- **Ephemeral working directory.** `TMP=$(mktemp -d)` holds the config, the
  vault, and a private GPG home. No file outside `$TMP` is touched.
- **Isolated `GNUPGHOME`.** Every script sets `GNUPGHOME=$TMP/gnupg` before
  invoking `gpg` or `dotsecenv`. **Your real keyring is never touched.**
- **Explicit config and vault paths.** Scripts pass `-c "$TMP/config"` and
  `-v "$TMP/vault"` to every command rather than relying on the XDG default
  location.
- **Cleanup on exit.** A `trap 'rm -rf "$TMP"; gpgconf --kill all || true'
  EXIT` guarantees the tempdir is removed and the per-tempdir gpg-agent is
  shut down even if the script fails partway through.
- **`set -euo pipefail`.** Errors abort immediately so partial state is never
  reported as success.
- **Unattended GPG operations.** The example keys are generated with
  `--no-passphrase` (CI-only mode) so the scripts do not block on a pinentry
  prompt. **Do not use `--no-passphrase` for real keys.** See
  <https://dotsecenv.com/concepts/threat-model/> for the threat model
  motivating passphrase-protected keys.

## Running an example

Build the binary first (the scripts assume `bin/dotsecenv` exists in the repo
root):

```bash
make build
```

Then `cd` into the example and run its script:

```bash
cd examples/01-quickstart
./run.sh
```

If you have the dotsecenv binary on your `PATH` (via `install.sh`, Homebrew,
the package managers, etc.) the scripts use that instead. To force the use
of the repo-local build, run them from the repo root with `./bin/dotsecenv` on
your `PATH` (`PATH="$PWD/bin:$PATH" ./examples/01-quickstart/run.sh`).

## Where to next

- Tutorials: <https://dotsecenv.com/tutorials/>
- Concepts (threat model, FIPS compliance, append-only vault): <https://dotsecenv.com/concepts/>
- Guides (CI/CD, shell plugins, Terraform, Claude Code): <https://dotsecenv.com/guides/>
