# dotsecenv: Safe Environment Secrets

A complete Go CLI application for securely managing environment secrets with GPG-based encryption, multi-user support, and FIPS 140-3 compliance.

## Quick Start

### Store your first secret

```bash
# After installation (see below)
dotsecenv init config
dotsecenv init vault -v ~/.local/share/dotsecenv/vault
dotsecenv login <YOUR GPG FINGERPRINT> # gpg --list-public-keys
echo "xyz" | dotsecenv secret put TEST_SECRET
# Subsequently, you can decrypt secrets
# as long as you hold the corresponding secret key in GPG agent
dotsecenv secret get TEST_SECRET # should output "xyz"
```

### Installation

#### Mise (universal)

```bash
mise use ubi:dotsecenv/dotsecenv
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

Please [open a GitHub issue](https://github.com/dotsecenv/dotsecenv/issues/new/choose) if you need a Windows variant!

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

The action automatically detects the release associated with the current commit and downloads the appropriate binary for your runner's architecture.

#### Inputs

Release binaries achieve [SLSA Build Level 3](#security-features) compliance with verified provenance attestations. Using `build-from-source: true` or `verify-provenance: false` bypasses these security guarantees and is generally NOT recommended.

| Input | Default | Description |
| ----- | ------- | ----------- |
| `build-from-source` | `false` | Build from source instead of downloading a release |
| `verify-provenance` | `true` | Verify GPG signatures, checksums, and attestations |

#### Outputs

| Output | Description |
| ------ | ----------- |
| `version` | The version of dotsecenv that was installed |
| `binary-path` | Full path to the installed binary |

#### Examples

**Basic usage (download release):**

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Required for tag detection
      - uses: dotsecenv/dotsecenv@v1
      - run: dotsecenv secret get DATABASE_URL
```

**Build from source (for untagged commits):**

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dotsecenv/dotsecenv@v1
        with:
          build-from-source: true
      - run: dotsecenv version
```

**Skip provenance verification:**

```yaml
- uses: dotsecenv/dotsecenv@v1
  with:
    verify-provenance: false
```

### Shell Completions

dotsecenv supports shell completions for Bash, Zsh, and Fish.

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

#### Pre-installed Paths

If you installed via a package manager (Homebrew, deb, rpm, Arch), completions are pre-installed at these paths:

| Shell | Homebrew (macOS/Linux)                                            | Linux Packages (deb/rpm/Arch)                         |
| ----- | ----------------------------------------------------------------- | ----------------------------------------------------- |
| Bash  | `$(brew --prefix)/etc/bash_completion.d/dotsecenv`                | `/usr/share/bash-completion/completions/dotsecenv`    |
| Zsh   | `$(brew --prefix)/share/zsh/site-functions/_dotsecenv`            | `/usr/share/zsh/site-functions/_dotsecenv`            |
| Fish  | `$(brew --prefix)/share/fish/vendor_completions.d/dotsecenv.fish` | `/usr/share/fish/vendor_completions.d/dotsecenv.fish` |

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

# Initialize a vault
## Interactive prompt, asking which vault to initialize
dotsecenv init vault
## Specify which vault to initialize
dotsecenv init vault -v /path/to/vault

# Login with your GPG fingerprint
dotsecenv login <FINGERPRINT>

# Add an identity to the vault
dotsecenv vault identity add <FINGERPRINT>
dotsecenv vault identity add <FINGERPRINT> --all  # Add to all vaults

# Store a secret (reads value from stdin)
echo "secret-value" | dotsecenv secret put MY_SECRET

# Retrieve a secret
dotsecenv secret get MY_SECRET
dotsecenv secret get MY_SECRET --all   # All values across all vaults
dotsecenv secret get MY_SECRET --last  # Most recent value across all vaults
dotsecenv secret get MY_SECRET --json  # Output as JSON

# Share a secret with another identity
dotsecenv secret share MY_SECRET <TARGET_FINGERPRINT>

# Revoke access to a secret
dotsecenv secret revoke MY_SECRET <TARGET_FINGERPRINT>

# List vaults and secrets
dotsecenv vault list
dotsecenv vault list --json

# List identities in vaults
dotsecenv vault identity list
dotsecenv vault identity list --json

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

| Command                                     | Description                                  |
| ------------------------------------------- | -------------------------------------------- |
| `init config [--fips]`                      | Initialize configuration file                |
| `init vault`                                | Initialize vault file(s)                     |
| `login FINGERPRINT`                         | Initialize user identity                     |
| `secret put SECRET`                         | Store an encrypted secret (reads from stdin) |
| `secret get SECRET [--all\|--last\|--json]` | Retrieve a secret value                      |
| `secret share SECRET FINGERPRINT [--all]`   | Share a secret with another identity         |
| `secret revoke SECRET FINGERPRINT [--all]`  | Revoke access to a secret                    |
| `vault list [--json]`                       | List configured vaults and their secrets     |
| `vault identity add FINGERPRINT [--all]`    | Add an identity to vault(s)                  |
| `vault identity list [--json]`              | List identities in configured vaults         |
| `validate [--fix]`                          | Validate vault and config integrity          |
| `version`                                   | Show version information                     |
| `completion`                                | Generate shell completion scripts            |

## Features

- **Explicit Initialization**: Safe bootstrapping of configuration and vaults
- **Encrypted at Rest**: All secrets are encrypted using FIPS 140-3 compliant algorithms (AES-256-GCM)
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
approved_algorithms:
  - algo: ECC
    curves:
      - P-256
      - P-384
      - P-521
    min_bits: 256
  - algo: EdDSA
    curves:
      - Ed25519
    min_bits: 255
  - algo: RSA
    min_bits: 1024
vault:
  - /path/to/vault1
strict: false
```

### FIPS Mode

Initialize with FIPS 140-3 compliant algorithms only:

```bash
dotsecenv init config --fips
```

This enforces stricter algorithm requirements:

- RSA: minimum 3072 bits
- ECC: minimum P-384 curve (384 bits)

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

- FIPS 140-3 algorithm enforcement (if desired)
- Multi-recipient PGP encryption
- Detached signatures for identity and secret verification
- Hash-based integrity checking
- GPG agent integration for key management
- Full secret encryption/decryption lifecycle
- Validation logic with optional auto-fix
- SUID mode restrictions for elevated privilege protection
- [SLSA Build Level 3](https://slsa.dev/spec/v1.2/build-requirements): Release binaries include verifiable provenance attestations generated via GitHub's [attest-build-provenance](https://github.com/actions/attest-build-provenance) action on hardened GitHub-hosted runners

### SUID Mode Restrictions

When running with SUID privileges, the following restrictions apply:

- `-c` and `-v` flags are blocked
- `DOTSECENV_CONFIG` and `DOTSECENV_FINGERPRINT` environment variables are ignored
- Config defaults to `/etc/dotsecenv/config`
- Write operations are blocked: `login`, `init config`, `init vault`, `secret put`, `secret share`, `secret revoke`, `vault identity add`

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

In rare cases you may need to add a `pinentry-program` line to your `~/.gnupg/gpg-agent.conf` and restart the gpg-agent (`killall gpg-agent`):

## Development

### Building

```bash
# Build the binary
make build
```

### Testing

```bash
# Run all tests
make test

# Run tests with race condition detection
make test-race

# Run end-to-end tests
make e2e
```

### Linting

```bash
# Run linting (installs golangci-lint if needed)
make lint
```

## Security Considerations

### What dotsecenv Protects Against

- Accidental exposure of unencrypted secrets in version control
- Secrets stored in plaintext on disk
- Access to secrets by unauthorized users without GPG keys
- Tampering with vault entries (signature verification)
- Privilege escalation via SUID binaries

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
7. **FIPS Mode**: Use `--fips` flag for environments requiring FIPS 140-3 compliance

## License

Apache 2.0 License. See LICENSE file for details.

## Acknowledgments

- [ProtonMail gopenpgp](https://github.com/protonmail/gopenpgp) for PGP cryptography
- [Cobra](https://github.com/spf13/cobra) for CLI framework
- [Go standard library](https://golang.org/) for core functionality
