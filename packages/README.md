# dotsecenv Packages

[![Publish Packages](https://github.com/dotsecenv/packages/actions/workflows/publish.yml/badge.svg)](https://github.com/dotsecenv/packages/actions/workflows/publish.yml)

The `dotsecenv` packages are hosted here for Debian/Ubuntu, Fedora/RedHat, Arch Linux/Manjaro, and macOS.

Public GPG Key: [key.asc](https://get.dotsecenv.com/key.asc)

```text
pub   rsa4096 2026-05-14 [SC] [expires: 2028-05-13]
      0B8DB28079ACFA7497F0B8FE647E9C8219626442
uid           DotSecEnv Releases (Automated Release Signing Key) <release@dotsecenv.com>
```

The key can be verified using the [OpenPGP Keyserver](https://keys.openpgp.org/search?q=0B8DB28079ACFA7497F0B8FE647E9C8219626442) or on [Keybase](https://keybase.io/dotsecenv).

```shell
# OpenPGP Keyserver
gpg --keyserver keys.openpgp.org --recv-keys 0B8DB28079ACFA7497F0B8FE647E9C8219626442

# or Keybase
curl https://keybase.io/dotsecenv/pgp_keys.asc | gpg --import
```

Releases up to and including **v0.6.3** were signed with the previous key
(`E60A1740BAEF49284D22EA7D3C376348F0921C59`). To verify those older
signatures, also import the old key. The `key.asc` file at
[get.dotsecenv.com/key.asc](https://get.dotsecenv.com/key.asc) contains
both keys concatenated, so a single import covers all releases.

> [!IMPORTANT] > **For project details, documentation, and source code**
>
> **Visit the project's repository at [github.com/dotsecenv/dotsecenv](https://github.com/dotsecenv/dotsecenv).**

## Install Script (recommended)

The universal installer is the fastest way to get dotsecenv on any macOS or Linux system. It auto-detects your platform, downloads the correct binary, verifies checksums and GPG signatures, and installs shell completions, man pages, and the shell plugin.

```bash
curl -fsSL https://get.dotsecenv.com/install.sh | bash
```

Install a specific version or customize behavior with CLI flags:

```bash
curl -fsSL https://get.dotsecenv.com/install.sh | bash -s -- --version v1.2.3
```

Or use environment variables for CI/CD pipelines:

```bash
VERSION=v1.2.3 INSTALL_DIR=/opt/bin curl -fsSL https://get.dotsecenv.com/install.sh | bash
```

Run with `--help` for all available options. See the [main repo](https://github.com/dotsecenv/dotsecenv#install-script-recommended) for the full options reference.

---

If you prefer to use a native package manager, choose your distribution below:

## Debian / Ubuntu

1. **Trust the GPG Key**:

   ```bash
   curl -fsSL https://get.dotsecenv.com/key.asc | sudo gpg --dearmor -o /etc/apt/keyrings/dotsecenv.gpg
   ```

2. **Add the Repository**:

   ```bash
   echo "deb [signed-by=/etc/apt/keyrings/dotsecenv.gpg] https://get.dotsecenv.com/apt/ ./" | sudo tee /etc/apt/sources.list.d/dotsecenv.list
   ```

3. **Install**:

   ```bash
   sudo apt-get update
   sudo apt-get install dotsecenv
   ```

## Fedora / RedHat / CentOS

1. **Add the Repository**:

   ```bash
   cat <<EOF | sudo tee /etc/yum.repos.d/dotsecenv.repo
   [dotsecenv]
   name=DotSecEnv Repository
   baseurl=https://get.dotsecenv.com/yum/
   enabled=1
   gpgcheck=1
   repo_gpgcheck=1
   gpgkey=https://get.dotsecenv.com/key.asc
   EOF
   ```

2. **Install**:

   ```bash
   sudo dnf install dotsecenv
   ```

## Arch Linux / Manjaro

1. **Add to `pacman.conf`**:

   ```bash
   cat <<'EOF' | sudo tee -a /etc/pacman.conf
   [dotsecenv]
   Server = https://get.dotsecenv.com/arch/$arch
   SigLevel = Required DatabaseOptional
   EOF
   ```

2. **Trust the Key**:
   You need to locally sign the key for pacman to trust it.

   ```bash
   curl -fsSL https://get.dotsecenv.com/key.asc | sudo pacman-key --add -
   sudo pacman-key --lsign-key 0B8DB28079ACFA7497F0B8FE647E9C8219626442
   ```

3. **Install**:

   ```bash
   sudo pacman -Sy dotsecenv
   ```

## Linux (Direct Download)

Download the binary for your architecture:

```bash
# Get latest version
DOTSECENV_VERSION=$(curl -s https://api.github.com/repos/dotsecenv/dotsecenv/releases/latest | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')

# x86_64
curl -LO "https://get.dotsecenv.com/linux/dotsecenv_${DOTSECENV_VERSION}_Linux_x86_64.tar.gz"

# ARM64
curl -LO "https://get.dotsecenv.com/linux/dotsecenv_${DOTSECENV_VERSION}_Linux_arm64.tar.gz"
```

Verify and install:

```bash
# Verify checksum
curl -s https://get.dotsecenv.com/linux/checksums.txt | sha256sum -c --ignore-missing

# Extract and install
tar -xzf dotsecenv_*.tar.gz
sudo mv dotsecenv /usr/local/bin/
```

## macOS (Direct Download)

Download the binary for your architecture:

```bash
# Get latest version
DOTSECENV_VERSION=$(curl -s https://api.github.com/repos/dotsecenv/dotsecenv/releases/latest | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')

# Apple Silicon (M1/M2/M3)
curl -LO "https://get.dotsecenv.com/darwin/dotsecenv_${DOTSECENV_VERSION}_Darwin_arm64.tar.gz"

# Intel
curl -LO "https://get.dotsecenv.com/darwin/dotsecenv_${DOTSECENV_VERSION}_Darwin_x86_64.tar.gz"
```

Verify and install:

```bash
# Verify checksum
curl -s https://get.dotsecenv.com/darwin/checksums.txt | sha256sum -c --ignore-missing

# Extract and install
tar -xzf dotsecenv_*.tar.gz
sudo mv dotsecenv /usr/local/bin/
```

## macOS (Homebrew)

MacOS builds are also available via Homebrew. Add the tap and install:

```bash
brew tap dotsecenv/tap
brew install dotsecenv
```

## Shell Plugins

Shell plugins that automatically load `.env` and `.secenv` files when entering directories
are available for `zsh`, `bash`, and `fish`.

```bash
curl -fsSL https://raw.githubusercontent.com/dotsecenv/plugin/main/install.sh | bash
```

For plugin manager installation and additional details, see [github.com/dotsecenv/plugin#installation](https://github.com/dotsecenv/plugin#installation).
