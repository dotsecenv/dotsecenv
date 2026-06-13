# dotsecenv examples

Self-contained, copy-pasteable scenarios that exercise the dotsecenv CLI end to
end. Each example lives in its own subdirectory. The audience is humans and AI
coding agents in roughly equal measure: both copy from these.

The examples favour runnability over breadth. Every command shown is a real
`dotsecenv` invocation, verified against the CLI help surface and, where
possible, executed in an isolated environment.

For narrative documentation see <https://dotsecenv.com>. For the canonical CLI
reference see `dotsecenv --help` or the man pages installed by
`make install`/`install.sh`.

## Index

| #  | Example | What it shows | Spine tutorial |
| -- | ------- | ------------- | -------------- |
| 01 | [quickstart](./01-quickstart/) | `init config` -> `init vault` -> `login` -> `secret store` -> `secret get` | [Your First Secret](https://dotsecenv.com/tutorials/first-secret/) |
| 02 | [team-share-revoke](./02-team-share-revoke/) | Multi-recipient encryption with two ephemeral identities; share, then revoke | [Share a Secret](https://dotsecenv.com/tutorials/share-secret/) |
| 03 | [ci-cd-github-action](./03-ci-cd-github-action/) | Repo-scoped CI: install and decrypt via the GitHub Action (`GPG_PRIVATE_KEY`) | [CI/CD Secrets](https://dotsecenv.com/tutorials/ci-cd-secrets/) |
| 04 | [policy-directory](./04-policy-directory/) | Drop YAML fragments into `/etc/dotsecenv/policy.d/` to constrain users | [Apply a Security Policy](https://dotsecenv.com/tutorials/apply-a-policy/) |
| 05 | [secenv-shell-plugin](./05-secenv-shell-plugin/) | Reference `.secenv` file demonstrating every supported placeholder syntax | [Reloading Secrets](https://dotsecenv.com/tutorials/reload-secrets/) |
| 06 | [multi-environment-fips](./06-multi-environment-fips/) | Vault-per-environment under FIPS 186-5 policy; per-env CI keys (`GPG_PRIVATE_KEY_DEV`...) | [Team Vault Setup](https://dotsecenv.com/tutorials/team-vault-setup/) |
| 07 | [org-wide-keypair](./07-org-wide-keypair/) | Org-wide CI: one keypair shared across repos via an organization secret (`ORG_GPG_PRIVATE_KEY`) | [Org-wide Keypair in CI](https://dotsecenv.com/tutorials/org-wide-keypair/) |

Examples 01, 02, and 06 ship a `run.sh` that executes the full flow end to
end in an ephemeral working directory. Examples 03, 04, 05, and 07 are
configuration artifacts (workflow YAML, policy fragments, a `.secenv` file)
that ship with a `README.md` explaining how to install and use them; there is
nothing to "run".

## Safety conventions

Every runnable script in this directory follows the same isolation pattern,
borrowed from `scripts/sandbox.sh` and `demos/demo.sh`:

- `TMP=$(mktemp -d)` holds the config, vault, and a private GPG home. No
  file outside `$TMP` is touched.
- `GNUPGHOME=$TMP/gnupg` for every `gpg` and `dotsecenv` invocation, so your
  real keyring stays untouched.
- Scripts pass `-c "$TMP/config"` and `-v "$TMP/vault"` to every command
  rather than relying on the XDG default location.
- `trap 'rm -rf "$TMP"; gpgconf --kill all || true' EXIT` removes the tempdir
  and shuts down the per-tempdir gpg-agent on every exit path, including
  Ctrl-C and partial failures.
- `set -euo pipefail` aborts on the first error so partial state cannot
  masquerade as success.
- Example keys use `--no-passphrase` (CI-only mode) so the scripts do not
  block on a pinentry prompt. Do not use `--no-passphrase` for real keys —
  see <https://dotsecenv.com/concepts/threat-model/> for why.

## Secret naming

The CI examples (03, 06, 07) store a GPG private key as a GitHub Actions
secret so dotsecenv can decrypt the committed vault. The secret name encodes
the key's scope:

| Scope                 | Where it lives                      | Secret name                                |
| --------------------- | ----------------------------------- | ------------------------------------------ |
| Repo-scoped (default) | a repository secret                 | `GPG_PRIVATE_KEY`                          |
| Org-wide              | an organization secret              | `ORG_GPG_PRIVATE_KEY`                      |
| Per-environment       | a repository secret per environment | `GPG_PRIVATE_KEY_DEV` / `_STAGING` / `_PROD` |

Add `GPG_PASSPHRASE` (or `ORG_GPG_PASSPHRASE`) only when the key carries a
passphrase. Keys are ASCII-armored (`gpg --armor --export-secret-keys`), never
base64. Log in by fingerprint (`dotsecenv login <FINGERPRINT>`). Prefer the
narrowest scope that works: an org-wide key that leaks exposes every repo's
vault it is a recipient of. See <https://dotsecenv.com/concepts/key-scope/>.

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
