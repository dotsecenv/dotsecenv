# dotsecenv: safe environment secrets

[![CI](https://github.com/dotsecenv/dotsecenv/actions/workflows/ci.yml/badge.svg)](https://github.com/dotsecenv/dotsecenv/actions/workflows/ci.yml)
[![Release](https://github.com/dotsecenv/dotsecenv/actions/workflows/release.yml/badge.svg)](https://github.com/dotsecenv/dotsecenv/actions/workflows/release.yml)
[![GitHub Action E2E](https://github.com/dotsecenv/dotsecenv/actions/workflows/action-e2e.yml/badge.svg)](https://github.com/dotsecenv/dotsecenv/actions/workflows/action-e2e.yml)
[![Hermetic E2E](https://github.com/dotsecenv/dotsecenv/actions/workflows/hermetic-e2e.yml/badge.svg)](https://github.com/dotsecenv/dotsecenv/actions/workflows/hermetic-e2e.yml)
[![Publish Packages](https://github.com/dotsecenv/packages/actions/workflows/publish.yml/badge.svg)](https://github.com/dotsecenv/packages/actions/workflows/publish.yml)
[![Homebrew install](https://github.com/dotsecenv/homebrew-tap/actions/workflows/post-release.yml/badge.svg)](https://github.com/dotsecenv/homebrew-tap/actions/workflows/post-release.yml)
[![Shell plugins CI](https://github.com/dotsecenv/plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/dotsecenv/plugin/actions/workflows/ci.yml)
[![Publish Website](https://github.com/dotsecenv/website/actions/workflows/deploy-website.yml/badge.svg)](https://github.com/dotsecenv/website/actions/workflows/deploy-website.yml)

A complete Go CLI application for securely managing environment secrets with GPG-based encryption, multi-user support, and FIPS 186-5 compliant algorithm defaults.

## Quick Start

### Store your first secret

```bash
# After installation (see below)
dotsecenv init config
dotsecenv init vault -v ~/.local/share/dotsecenv/vault
dotsecenv login <YOUR GPG FINGERPRINT> # gpg --list-public-keys
echo "xyz" | dotsecenv secret store TEST_SECRET
# Subsequently, you can decrypt secrets
# as long as you hold the corresponding secret key in GPG agent
dotsecenv secret get TEST_SECRET # should output "xyz"
```

### Installation

#### Mise (universal)

```bash
mise use github:dotsecenv/dotsecenv
```

### MacOS/Homebrew

```bash
brew tap dotsecenv/tap
brew install dotsecenv
```

### Linux package managers

Package repositories for Debian/Ubuntu, RHEL/CentOS/Fedora, and Arch Linux are available at [get.dotsecenv.com](https://get.dotsecenv.com).

#### Binary Download

Download the latest release for your platform from the [Releases page](https://github.com/dotsecenv/dotsecenv/releases).

#### Linux Packages (.deb / .rpm / .archlinux)

Download the appropriate package from the [Releases page](https://github.com/dotsecenv/dotsecenv/releases) and install it:

**Debian/Ubuntu:**

```bash
sudo dpkg -i dotsecenv_amd64.deb
```

**RHEL/CentOS/Fedora:**

```bash
sudo rpm -i dotsecenv_amd64.rpm
```

**Arch Linux:**

```bash
sudo pacman -U dotsecenv_amd64.pkg.tar.zst
```

#### Windows

> **NOTICE:** dotsecenv on Windows is currently WIP. You can follow [this issue](https://github.com/dotsecenv/dotsecenv/issues/8) for updates.

Download the `.zip` file for your architecture from the [Releases page](https://github.com/dotsecenv/dotsecenv/releases):

- `dotsecenv_vX.X.X_Windows_x86_64.zip` for 64-bit Intel/AMD
- `dotsecenv_vX.X.X_Windows_arm64.zip` for ARM64

Extract and add the binary location to your PATH.

**GPG Requirement**: Install [Gpg4win](https://www.gpg4win.org/) for GPG support. If GPG is not in your PATH, `dotsecenv init config` will attempt to detect it automatically, or you can set `gpg_program` in your config file.

#### Build from Source

```bash
# Clone the repository
git clone https://github.com/dotsecenv/dotsecenv.git
cd dotsecenv

# Build using make
make build

# Binary will be at bin/dotsecenv
```

### GitHub Action

Use the official GitHub Action to install `dotsecenv` in your CI/CD workflows:

```yaml
- uses: dotsecenv/dotsecenv@v0
```

The action downloads the appropriate binary for your runner's architecture and verifies its integrity.

#### Inputs

Release binaries achieve [SLSA Build Level 3](#security-features) compliance with verified provenance attestations. Using `build-from-source: true` or `verify-provenance: false` bypasses these security guarantees and is generally NOT recommended.

| Input               | Default  | Description                                        |
| ------------------- | -------- | -------------------------------------------------- |
| `version`           | `latest` | Version to install (e.g., `v1.2.3` or `latest`)    |
| `build-from-source` | `false`  | Build from source instead of downloading a release |
| `verify-provenance` | `true`   | Verify GPG signatures, checksums, and attestations |

#### Outputs

| Output        | Description                                 |
| ------------- | ------------------------------------------- |
| `version`     | The version of dotsecenv that was installed |
| `binary-path` | Full path to the installed binary           |

#### Examples

**Basic usage (latest release):**

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: dotsecenv/dotsecenv@v0
      - run: dotsecenv secret get DATABASE_URL
```

**Pin to a specific version:**

```yaml
- uses: dotsecenv/dotsecenv@v0
  with:
    version: v0.0.1
```

**Build from source:**

```yaml
- uses: dotsecenv/dotsecenv@v0
  with:
    build-from-source: true
```

### Shell Completions

dotsecenv supports shell completions for Bash, Zsh, Fish, and PowerShell.

#### Bash

Requires the `bash-completion` package:

```bash
# macOS
brew install bash-completion@2

# Debian/Ubuntu
sudo apt install bash-completion

# RHEL/CentOS/Fedora
sudo dnf install bash-completion

# Arch
sudo pacman -S bash-completion
```

Add to `~/.bashrc` or `~/.bash_profile`:

```bash
# Load bash-completion (macOS with Homebrew)
[[ -r "$(brew --prefix)/etc/profile.d/bash_completion.sh" ]] && . "$(brew --prefix)/etc/profile.d/bash_completion.sh"

# dotsecenv completions
if command -v dotsecenv &> /dev/null; then
  eval "$(dotsecenv completion bash)"
fi
```

#### Zsh

Add to `~/.zshrc`:

```zsh
# dotsecenv completions
if command -v dotsecenv &> /dev/null; then
  eval "$(dotsecenv completion zsh)"
fi
```

#### Fish

Add to `~/.config/fish/config.fish`:

```fish
# dotsecenv completions
if command -v dotsecenv &> /dev/null
  dotsecenv completion fish | source
end
```

#### PowerShell

Add to your PowerShell profile (`$PROFILE`):

```powershell
# dotsecenv completions
if (Get-Command dotsecenv -ErrorAction SilentlyContinue) {
  dotsecenv completion powershell | Out-String | Invoke-Expression
}
```

#### Pre-installed Paths

If you installed via a package manager (Homebrew, deb, rpm, Arch), completions are pre-installed at these paths:

| Shell | Homebrew (macOS/Linux)                                            | Linux Packages (deb/rpm/Arch)                         |
| ----- | ----------------------------------------------------------------- | ----------------------------------------------------- |
| Bash  | `$(brew --prefix)/etc/bash_completion.d/dotsecenv`                | `/usr/share/bash-completion/completions/dotsecenv`    |
| Zsh   | `$(brew --prefix)/share/zsh/site-functions/_dotsecenv`            | `/usr/share/zsh/site-functions/_dotsecenv`            |
| Fish  | `$(brew --prefix)/share/fish/vendor_completions.d/dotsecenv.fish` | `/usr/share/fish/vendor_completions.d/dotsecenv.fish` |

### Shell Plugins

Shell plugins that automatically load `.env` and `.secenv` files when entering directories
are available for `zsh`, `bash`, and `fish`.

For example, given a `/path/to/project/.secenv` file, e.g.:

```env
A_SECRET={dotsecenv}
ANOTHER_SECRET={dotsecenv/SOME_OTHER_KEY}
MY_NAMESPACED_SECRET={dotsecenv/my::SECRET}
```

The three keys will be available as environment variables, when cd-ing into `/path/to/project/`.

#### Install shell plugins

You can install zsh/bash/fish plugins with:

```bash
curl -fsSL https://raw.githubusercontent.com/dotsecenv/plugin/main/install.sh | bash
```

For plugin manager installation and additional details, see [github.com/dotsecenv/plugin#installation](https://github.com/dotsecenv/plugin#installation).

### Basic Usage

```bash
# Initialize configuration
## Create default config
dotsecenv init config
## Specify where to store the config
dotsecenv init config -c /path/to/config
## Initialize the config with a single vault
dotsecenv init config -v /path/to/vault
## Customize both the config and the vault location
dotsecenv init config -c ... -v ...
## Skip GPG detection (for systems without GPG installed)
dotsecenv init config --no-gpg-program
## Set GPG program path explicitly (without validation)
dotsecenv init config --gpg-program /usr/local/bin/gpg

# Initialize a vault
## Interactive prompt, asking which vault to initialize
dotsecenv init vault
## Specify which vault to initialize
dotsecenv init vault -v /path/to/vault

# Login with your GPG fingerprint
dotsecenv login <FINGERPRINT>

# Store a secret (reads value from stdin)
echo "secret-value" | dotsecenv secret store MY_SECRET

# Retrieve a secret
dotsecenv secret get MY_SECRET
dotsecenv secret get MY_SECRET --all   # All values across all vaults
dotsecenv secret get MY_SECRET --last  # Most recent value across all vaults
dotsecenv secret get MY_SECRET --json  # Output as JSON

# Share a secret with another identity (auto-adds identity if needed)
dotsecenv secret share MY_SECRET <TARGET_FINGERPRINT>

# Revoke access to a secret
dotsecenv secret revoke MY_SECRET <TARGET_FINGERPRINT>

# Describe vaults with identities and secrets
dotsecenv vault describe
dotsecenv vault describe --json

# Run health checks on vaults and environment
dotsecenv vault doctor
dotsecenv vault doctor --json

# Validate vault and config
dotsecenv validate
dotsecenv validate --fix  # Attempt to fix issues
```

## Command Reference

### Global Flags

| Flag       | Short | Description                                 |
| ---------- | ----- | ------------------------------------------- |
| `--config` | `-c`  | Path to config file                         |
| `--vault`  | `-v`  | Path to vault file or vault index (1-based) |
| `--silent` | `-s`  | Silent mode (suppress warnings)             |

### Commands

| Command                                         | Description                                  |
| ----------------------------------------------- | -------------------------------------------- |
| `init config [--gpg-program\|--no-gpg-program]` | Initialize configuration file                |
| `init vault`                                    | Initialize vault file(s)                     |
| `login FINGERPRINT`                             | Initialize user identity                     |
| `secret store SECRET`                           | Store an encrypted secret (reads from stdin) |
| `secret get SECRET [--all\|--last\|--json]`     | Retrieve a secret value                      |
| `secret share SECRET FINGERPRINT [--all]`       | Share a secret with another identity         |
| `secret revoke SECRET FINGERPRINT [--all]`      | Revoke access to a secret                    |
| `vault describe [--json]`                       | Describe vaults with identities and secrets  |
| `vault doctor [--json]`                         | Run health checks and fix issues             |
| `validate [--fix]`                              | Validate vault and config integrity          |
| `version`                                       | Show version information                     |
| `completion`                                    | Generate shell completion scripts            |

## Features

- **Explicit Initialization**: Safe bootstrapping of configuration and vaults
- **Encrypted at Rest**: All secrets are encrypted using AES-256-GCM (RFC 9580)
- **Multi-User Support**: Secrets can be encrypted for multiple identities using GPG multi-recipient encryption
- **Portable Vault**: The vault file can be safely committed to git and shared between machines
- **Secret Sharing**: Share and revoke access to secrets with other team members
- **Append-Only Design**: Cryptographic history is preserved for audit trails
- **GPG Agent Integration**: Leverages gpg-agent for secure key management
- **XDG Compliance**: Respects XDG Base Directory Specification for configuration files
- **SUID Mode Support**: Restricted operations when running with elevated privileges
- **JSON Output**: Machine-readable output format for scripting

## Configuration

### Config File Resolution

The configuration file location is determined in the following order of precedence:

1. **`-c` flag** (highest priority): Explicitly specify a config file path
2. **`DOTSECENV_CONFIG` environment variable**: Override the default location
3. **XDG default**: `$XDG_CONFIG_HOME/dotsecenv/config` (typically `~/.config/dotsecenv/config`)
4. **SUID mode**: `/etc/dotsecenv/config` (when running with elevated privileges)

When both `-c` and `DOTSECENV_CONFIG` are specified, the `-c` flag takes precedence and a warning is printed to stderr (unless `-s` silent mode is enabled):

```
warning: DOTSECENV_CONFIG environment variable ignored because -c flag was specified
```

In SUID mode, the `DOTSECENV_CONFIG` environment variable is ignored for security reasons.

### Config File Format

Example config:

```yaml
# Default configuration uses FIPS 186-5 compliant algorithm minimums
approved_algorithms:
  - algo: ECC
    curves:
      - P-384
      - P-521
    min_bits: 384
  - algo: EdDSA
    curves:
      - Ed25519
      - Ed448
    min_bits: 255
  - algo: RSA
    min_bits: 2048
vault:
  - /path/to/vault1
strict: false
gpg:
  program: gpg # Path to GPG executable
```

### GPG Configuration

The `gpg.program` option specifies the path to the GPG executable. The behavior depends on whether the value is specified and whether strict mode is enabled:

**Resolution order:**

1. **Explicit configuration**: If `gpg.program` is set, it must be an absolute path to an existing, executable program
2. **PATH inference**: If `gpg.program` is not set (or empty), dotsecenv will look up `gpg` from your system PATH and print a warning to stderr
3. **Strict mode**: In strict mode (`strict: true`), `gpg.program` must be explicitly configured - PATH inference is not allowed

**Examples:**

```yaml
# Explicit path (recommended for production/strict mode)
gpg:
  program: /usr/bin/gpg

# Not specified - will infer from PATH with a warning
gpg:
  program: ""

# Windows with Gpg4win
gpg:
  program: "C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe"
```

**Automatic detection**: When running `dotsecenv init config`, dotsecenv will detect available GPG installations and set `gpg.program` to the detected absolute path. If multiple GPG installations are found, you'll be prompted to choose one.

**When to use explicit paths:**

- In strict mode (required)
- When you have multiple GPG versions installed
- When GPG is installed in a non-standard location
- In CI/CD environments where PATH may vary

## Vault File Format

Default vault location: `$XDG_DATA_HOME/dotsecenv/vault`

The vault uses a JSONL (JSON Lines) format for efficient append operations and indexed lookups.
Each entry includes a hash and cryptographic signature to prevent against tampering.

**Header (Line 1):**

```json
{
  "version": 1,
  "identities": [
    ["FINGERPRINT1", 2],
    ["FINGERPRINT2", 3]
  ],
  "secrets": { "SECRET_KEY": { "secret": 4, "values": [5, 6] } }
}
```

**Identity Entry:**

```json
{
  "type": "identity",
  "data": {
    "added_at": "2024-11-09T12:00:00Z",
    "algorithm": "ECC",
    "algorithm_bits": 521,
    "curve": "P-521",
    "created_at": "2024-10-01T10:00:00Z",
    "fingerprint": "1E378219F90018AB2102B2131C238966B12A6F21",
    "hash": "sha256:...",
    "public_key": "base64...",
    "signed_by": "1E378219F90018AB2102B2131C238966B12A6F21",
    "signature": "base64...",
    "uid": "user@example.com"
  }
}
```

**Secret Definition Entry:**

```json
{
  "type": "secret",
  "data": {
    "added_at": "2024-11-09T12:05:00Z",
    "hash": "sha256:...",
    "key": "DATABASE_URL",
    "signature": "base64...",
    "signed_by": "1E378219F90018AB2102B2131C238966B12A6F21"
  }
}
```

**Secret Value Entry:**

```json
{
  "type": "value",
  "secret": "DATABASE_URL",
  "data": {
    "added_at": "2024-11-09T12:05:00Z",
    "available_to": ["1E378219F90018AB2102B2131C238966B12A6F21"],
    "hash": "sha256:...",
    "signature": "base64...",
    "signed_by": "1E378219F90018AB2102B2131C238966B12A6F21",
    "value": "base64-encrypted-value"
  }
}
```

## Security Features

- **[RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html) OpenPGP compliance**: Modern OpenPGP standard with mandatory AEAD encryption
- **AES-256-GCM symmetric encryption**: NIST-approved authenticated encryption ([SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final))
- **[FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) digital signatures**: RSA, ECDSA, and EdDSA signature schemes for vault entry authenticity and non-repudiation
- **FIPS 186-5 compliant defaults**: Algorithm minimums meet the Digital Signature Standard requirements
- **FIPS 140-3 Crypto**: Release binaries are built with Go's native FIPS 140-3 cryptographic module (`GOFIPS140=v1.0.0`) for NIST-validated cryptographic primitives on all platforms
- Multi-recipient PGP encryption with hybrid cryptography
- Hash-based integrity checking (SHA-256/SHA-512)
- GPG agent integration for secure key management
- Full secret encryption/decryption lifecycle
- Validation logic with optional auto-fix
- SUID mode restrictions for elevated privilege protection
- [SLSA Build Level 3](https://slsa.dev/spec/v1.2/build-requirements): Release binaries include verifiable provenance attestations generated via GitHub's [attest-build-provenance](https://github.com/actions/attest-build-provenance) action on hardened GitHub-hosted runners
- **Hermetic E2E Testing**: Every pull request runs e2e tests in a network-isolated Linux namespace with eBPF verification via [harden-runner](https://github.com/step-security/harden-runner), proving zero external network connections. See [Security Model](https://dotsecenv.com/concepts/security-model/#hermetic-testing).

### SUID Mode Restrictions

When running with SUID privileges, the following restrictions apply:

- `-c` and `-v` flags are blocked
- `DOTSECENV_CONFIG` and `DOTSECENV_FINGERPRINT` environment variables are ignored
- Config defaults to `/etc/dotsecenv/config`
- Write operations are blocked: `login`, `init config`, `init vault`, `secret store`, `secret share`, `secret revoke`

This prevents privilege escalation attacks when the binary is installed with elevated permissions.

## Exit Codes

| Code | Name                  | Description                      |
| ---- | --------------------- | -------------------------------- |
| `0`  | Success               | Operation completed successfully |
| `1`  | General Error         | Unspecified error                |
| `2`  | Config Error          | Configuration file issue         |
| `3`  | Vault Error           | Vault file issue                 |
| `4`  | GPG Error             | GPG operation failed             |
| `5`  | Auth Error            | Authentication failed            |
| `6`  | Validation Error      | Validation failed                |
| `7`  | Fingerprint Required  | No fingerprint configured        |
| `8`  | Access Denied         | Permission denied                |
| `9`  | Algorithm Not Allowed | Algorithm not in allow-list      |

## Environment Variables

| Variable                | Description                                             |
| ----------------------- | ------------------------------------------------------- |
| `DOTSECENV_CONFIG`      | Override config file path (ignored in SUID mode)        |
| `DOTSECENV_FINGERPRINT` | Override fingerprint from config (ignored in SUID mode) |
| `XDG_CONFIG_HOME`       | Override config directory (defaults to: `~/.config`)    |
| `XDG_DATA_HOME`         | Override data directory (defaults to: `~/.local/share`) |

## Known Limitations

### Ed448 Keys (GnuPG v5 Format)

Ed448 keys generated by GnuPG 2.4+ use the OpenPGP v5 key format, which is not yet fully supported by the underlying cryptographic library (gopenpgp/go-crypto). This results in a parsing error when trying to add Ed448 identities:

```shell
failed to get public key: failed to parse public key: gopenpgp: error in reading key ring: openpgp: invalid data: first packet was not a public/private key
```

**Workaround**: Use Ed25519 keys instead, which are fully supported and provide equivalent security for most use cases. Ed25519 keys use the OpenPGP v4 format which has full library support.

**Status**: This limitation will be resolved when:

- GnuPG adopts RFC 9580 v6 format for Ed448 keys, OR
- go-crypto adds compatibility for GnuPG's v5 Ed448 format

Ed448 is included in the approved algorithms configuration to ensure readiness when support becomes available.

## FAQ

### How do I generate a GPG key?

```bash
# Generate a new GPG key and choose sensible defaults, i.e.:
# - (9) ECC (sign and encrypt)
# - (1) Curve 25519
# - Key expiration: 1y
gpg --full-generate-key
```

### agent_genkey failed: No pinentry

If you are unable to generate a key due to this error, install `pinentry`:

```bash
# macOS
brew install pinentry-mac

# Linux
sudo apt-get install pinentry
sudo dnf install pinentry-tty
sudo yum install pinentry-tty
sudo pacman -S pinentry-tty
# etc.
```

In rare cases you may need to add a `pinentry-program` line to your `~/.gnupg/gpg-agent.conf` and restart the gpg-agent (`killall gpg-agent`).

### gpg: signing failed: Inappropriate ioctl for device

This error occurs when GPG cannot find the terminal for pinentry input. Add the following to your shell profile (`~/.bashrc`, `~/.zshrc`):

```bash
export GPG_TTY=$(tty)
```

Or for fish shell, add the following to `~/.config/fish/config.fish`:

```fish
set -gx GPG_TTY (tty)
```

Then restart your shell or run the command directly.

### gpg: decryption failed

If you encounter this error, first try to define GPG_TTY (see above) before searching
for other possible solutions.

```shell
$ dotsecenv secret get bla
failed to decrypt secret: failed to decrypt with gpg-agent: exit status 2
GPG error: gpg: decryption failed: No secret key
```

## Development

### Setup

```bash
# Install all development tools (lefthook, golangci-lint, syft, goreleaser)
make install-tools
```

### Building

```bash
# Build with FIPS 140-3 crypto (no CGO required)
make build
```

The default `make build` uses Go's native FIPS 140-3 cryptographic module (`GOFIPS140=v1.0.0`), which provides NIST-validated cryptographic primitives on all platforms without requiring CGO. See [go.dev/blog/fips140](https://go.dev/blog/fips140) for details.

### Testing

```bash
# Run all tests
make test

# Run tests with race condition detection
make test-race

# Run end-to-end tests
make build e2e
```

### Linting

```bash
# Run linting (installs golangci-lint if needed)
make lint
```

### Releasing

Releases are triggered by pushing a signed semver tag. Following GitHub Actions conventions, a major version tag (e.g., `v0`) should also be maintained to allow users to pin to a major version.

The [releasetools-cli](https://github.com/releasetools/cli) simplifies this process:

```bash
rt git::release --major --sign --force --push v0.1.2
```

This creates both `v0.1.2` and `v0` tags pointing to the same commit, signs them, and pushes to the remote.

## Security Considerations

### What dotsecenv Protects Against

- Accidental exposure of unencrypted secrets in version control
- Secrets stored in plaintext on disk
- Access to secrets by unauthorized users without GPG keys
- Tampering with vault entries (signature verification)
- Privilege escalation via SUID binaries
- Stealth network exfiltration of secrets during CI/CD (hermetic testing)

### What dotsecenv DOES NOT Protect Against

- Operating system-level access (root/admin can always read memory)
- Compromised GPG private keys
- Quantum computing attacks (future consideration)
- Side-channel attacks
- Physical memory dumps
- Environment snooping

### Recommendations

1. **Private Keys**: Never commit GPG private keys to repositories
2. **Key Management**: Use gpg-agent with passphrase protection
3. **Vault Files**: Can be committed to git, technically safe in public repositories, but not recommended
4. **Multi-User Systems**: Use strong user isolation and file permissions
5. **Monitoring**: Audit all secret access in production environments
6. **Rotation**: Periodically rotate encryption keys by updating and then re-encrypting secrets

## License

Apache 2.0 License. See LICENSE file for details.

## Acknowledgments

- [SOPS](https://github.com/getsops/sops) for the idea of storing encrypted secrets alongside source code
- [ProtonMail gopenpgp](https://github.com/protonmail/gopenpgp) for PGP cryptography
- [Cobra](https://github.com/spf13/cobra) for CLI framework
- [Go standard library](https://golang.org/) for easy multi-platform functionality
