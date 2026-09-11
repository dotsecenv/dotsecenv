# dotsecenv

Encrypted environment secrets you can commit, shared by GPG fingerprint.

[![CI](https://github.com/dotsecenv/dotsecenv/actions/workflows/ci.yml/badge.svg)](https://github.com/dotsecenv/dotsecenv/actions/workflows/ci.yml)
[![Release](https://github.com/dotsecenv/dotsecenv/actions/workflows/release.yml/badge.svg)](https://github.com/dotsecenv/dotsecenv/actions/workflows/release.yml)
[![E2E Action (post-release)](https://github.com/dotsecenv/dotsecenv/actions/workflows/e2e-action-post-release.yml/badge.svg)](https://github.com/dotsecenv/dotsecenv/actions/workflows/e2e-action-post-release.yml)
[![Hermetic E2E](https://github.com/dotsecenv/dotsecenv/actions/workflows/e2e-hermetic.yml/badge.svg)](https://github.com/dotsecenv/dotsecenv/actions/workflows/e2e-hermetic.yml)
[![CI Plugin](https://github.com/dotsecenv/dotsecenv/actions/workflows/ci-plugin.yml/badge.svg)](https://github.com/dotsecenv/dotsecenv/actions/workflows/ci-plugin.yml)
[![Deploy Website](https://github.com/dotsecenv/dotsecenv/actions/workflows/deploy-website.yml/badge.svg)](https://github.com/dotsecenv/dotsecenv/actions/workflows/deploy-website.yml)
[![Publish Packages](https://github.com/dotsecenv/packages/actions/workflows/publish.yml/badge.svg)](https://github.com/dotsecenv/packages/actions/workflows/publish.yml)
[![Homebrew install](https://github.com/dotsecenv/homebrew-tap/actions/workflows/post-release.yml/badge.svg)](https://github.com/dotsecenv/homebrew-tap/actions/workflows/post-release.yml)

dotsecenv replaces the `.env` file you cannot commit. It encrypts every value to a list of GPG public keys, and
only the people whose fingerprints are on that list can read the result. That makes the vault file safe to keep
next to your code. You run no server and share no master key.

A vault is an append-only file of signed JSON lines. `secret store` appends a line, and no command rewrites a past
one. Run `git log` over the vault and you can see what was stored, when, and which keys could read it.

The shell plugin reads a `.secenv` file when you enter a directory and exports the secrets it references. Your
project gets its environment without a plaintext file on disk.

Full documentation is at [dotsecenv.com](https://dotsecenv.com).

## Install

```bash
curl -fsSL https://get.dotsecenv.com/install.sh | bash
```

The installer verifies checksums and GPG signatures, then adds the shell plugin, completions, and man pages.
Homebrew and mise work too, as do the signed apt, dnf, and pacman repositories at
[get.dotsecenv.com](https://get.dotsecenv.com):

```bash
brew tap dotsecenv/tap && brew trust dotsecenv/tap && brew install dotsecenv
mise use github:dotsecenv/dotsecenv
```

The [installation guide](https://dotsecenv.com/tutorials/installation/) documents every installer flag, each
package repository, and how to install from a downloaded archive.

dotsecenv runs on macOS and Linux. Windows is not supported and not planned.

## Quick start

You need a GPG key. Run `dotsecenv identity create` if you do not have one yet.

```bash
dotsecenv init config                              # write ~/.config/dotsecenv/config
dotsecenv init vault                               # create the vault (pick one when prompted)
dotsecenv login                                    # pick your key from your GPG keyring
echo "s3cr3t" | dotsecenv secret store DB_PASSWORD # values are read from stdin
dotsecenv secret get DB_PASSWORD
```

To load that secret whenever you enter a project directory, reference it from a `.secenv` file:

```bash
echo 'DB_PASSWORD={dotsecenv}' > .secenv
```

[Getting Started](https://dotsecenv.com/getting-started/) runs the same flow with the shell plugin turned on.
[`examples/`](./examples/) holds eight worked scenarios; four of them ship a `run.sh` that builds an isolated
vault and tears it down again.

## Share with your team

Sharing re-encrypts a secret for another fingerprint. Import your teammate's public key first, then:

```bash
dotsecenv secret share DB_PASSWORD <THEIR_FINGERPRINT>
dotsecenv secret revoke DB_PASSWORD <THEIR_FINGERPRINT>
dotsecenv vault describe          # who can read what
```

Both commands change future writes only. A revoked key still decrypts every entry written while that fingerprint
was a recipient, including entries already in git history, so rotate the secret at its source as well. The
[offboarding runbook](https://dotsecenv.com/runbooks/team-member-offboarding/) and the
[key rotation runbook](https://dotsecenv.com/runbooks/rotate-compromised-key/) cover both halves.

## CI

The GitHub Action installs the binary and verifies its provenance:

```yaml
- uses: dotsecenv/dotsecenv@v0
- run: dotsecenv secret get DATABASE_URL
```

The [GitHub Action guide](https://dotsecenv.com/guides/github-action/) covers version pinning, building from
source, and getting a private key onto the runner.

## Documentation

| Topic | Where |
| --- | --- |
| Install and first secret | [Getting Started](https://dotsecenv.com/getting-started/) |
| Every command and flag | [CLI reference](https://dotsecenv.com/reference/) |
| `.secenv` files and the shell plugin | [Shell plugins](https://dotsecenv.com/guides/shell-plugins/) |
| Vault file layout | [Vault format](https://dotsecenv.com/concepts/vault-format/) |
| What the design protects | [Security model](https://dotsecenv.com/concepts/security-model/) |
| Org-wide algorithm and vault rules | [Security policies](https://dotsecenv.com/concepts/security-policies/) |
| Claude Code and Codex plugins | [Claude Code guide](https://dotsecenv.com/guides/claude-code/) |
| Release history | [Changelog](https://dotsecenv.com/changelog/) |

## Security

Vault entries use AES-256-GCM inside RFC 9580 multi-recipient OpenPGP. Every entry carries a signature and a
SHA-256 hash, and dotsecenv verifies both on each read. Algorithm defaults meet FIPS 186-5 minimums, release
binaries link Go's FIPS 140-3 module, and every release ships SLSA Build Level 3 provenance. Each pull request
runs the end-to-end suite inside a network-isolated namespace that proves the binary opens no outbound connection.

None of that helps against a stolen private key, a process that can already reach your gpg-agent, or root on your
machine. The [security model](https://dotsecenv.com/concepts/security-model/) and
[threat model](https://dotsecenv.com/concepts/threat-model/) draw the boundaries.

Report a vulnerability through [SECURITY.md](./SECURITY.md) rather than a public issue.

## Contributing

[CONTRIBUTING.md](./CONTRIBUTING.md) covers the build, the test suites, and linting. [AGENTS.md](./AGENTS.md)
describes the repository layout and the invariants a change has to preserve.

## License

Apache 2.0. See [LICENSE](./LICENSE).

## Acknowledgments

- [SOPS](https://github.com/getsops/sops) for the idea of storing encrypted secrets alongside source code
- [ProtonMail gopenpgp](https://github.com/protonmail/gopenpgp) for PGP cryptography
- [Cobra](https://github.com/spf13/cobra) for the CLI framework
