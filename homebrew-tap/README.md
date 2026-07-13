<!--
Source of truth: dotsecenv/dotsecenv at homebrew-tap/README.md. The release
pipeline (update-homebrew-tap in dotsecenv/dotsecenv's release.yml) pushes this
file to dotsecenv/homebrew-tap on each release. Edit it in the monorepo, not in
the tap repo — direct edits there are overwritten on the next release.
-->

# dotsecenv Homebrew Tap

[![Homebrew install](https://github.com/dotsecenv/homebrew-tap/actions/workflows/post-release.yml/badge.svg)](https://github.com/dotsecenv/homebrew-tap/actions/workflows/post-release.yml)

This is the official Homebrew tap for [dotsecenv](https://dotsecenv.com).

## Installation

Add the tap, trust it, and install:

```bash
brew tap dotsecenv/tap
brew trust dotsecenv/tap
brew install dotsecenv
```

Homebrew 6.0 requires trusting third-party taps before installing from them. If an existing install fails with `Refusing to load cask dotsecenv/tap/dotsecenv from untrusted tap`, run `brew trust dotsecenv/tap` once. To trust only the cask instead of the whole tap, use `brew trust --cask dotsecenv/tap/dotsecenv`.

## Shell Plugins

The cask installs the zsh, bash, and fish plugins (automatic `.env`/`.secenv` loading) to `$(brew --prefix)/share/dotsecenv/plugin/`. Enable the one for your shell:

```bash
# zsh (~/.zshrc)
source "$(brew --prefix)/share/dotsecenv/plugin/dotsecenv.plugin.zsh"

# bash (~/.bashrc)
source "$(brew --prefix)/share/dotsecenv/plugin/dotsecenv.plugin.bash"
```

```fish
# fish (~/.config/fish/config.fish)
source (brew --prefix)/share/dotsecenv/plugin/conf.d/dotsecenv.fish
```

See the [shell plugins guide](https://dotsecenv.com/guides/shell-plugins/) for usage.

## Code Signing and Notarization

All macOS binaries are:

- **Code-signed** with an Apple Developer ID certificate
- **Notarized** by Apple for Gatekeeper compatibility

The Homebrew cask automatically removes the quarantine attribute during installation, so you won't see Gatekeeper warnings.

### Verifying the Signature

You can verify the code signature and notarization status:

```bash
# Verify code signature
codesign --verify --verbose "$(brew --prefix)/bin/dotsecenv"
# Expected: valid on disk

# Verify notarization status
spctl --assess --verbose "$(brew --prefix)/bin/dotsecenv"
# Expected: accepted
# source=Notarized Developer ID
```

## Documentation

For more information, see the [main repository](https://github.com/dotsecenv/dotsecenv).
