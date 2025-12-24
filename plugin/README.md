# dotsecenv/plugin

Shell plugins for [dotsecenv](https://github.com/dotsecenv/dotsecenv) that automatically load `.env` and `.secenv` files when entering directories.

## Features

- Automatically loads `.env` and `.secenv` files when you `cd` into a directory
- Unsets environment variables when you leave the directory
- Fetches secrets from your dotsecenv vault using `{dotsecenv}` syntax
- Security checks: refuses to load world-writable files or files not owned by you
- Trust system: prompts before loading `.secenv` files from untrusted directories
- Convenient aliases: `dse`, `secret`, `secretcp`

## Installation

### Quick Install (All Shells)

```bash
curl -fsSL https://raw.githubusercontent.com/dotsecenv/plugin/main/install.sh | bash
```

### Plugin Managers

#### Zsh - Oh My Zsh

```bash
git clone https://github.com/dotsecenv/plugin ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/dotsecenv

# Add to plugins in ~/.zshrc
plugins=(... dotsecenv)
```

#### Zsh - Zinit

```zsh
zinit light dotsecenv/plugin
```

#### Zsh - Antidote

Add to `~/.zsh_plugins`:

```
dotsecenv/plugin
```

#### Bash - Oh My Bash

```bash
git clone https://github.com/dotsecenv/plugin ~/.oh-my-bash/custom/plugins/dotsecenv

# Add to plugins in ~/.bashrc
plugins=(... dotsecenv)
```

#### Fish - Fisher

```fish
fisher install dotsecenv/plugin
```

#### Fish - Oh My Fish

```fish
omf install https://github.com/dotsecenv/plugin
```

### Manual Installation

#### Zsh

Add to your `~/.zshrc`:

```zsh
source /path/to/dotsecenv/plugin/dotsecenv.plugin.zsh
```

#### Bash

Add to your `~/.bashrc` or `~/.bash_profile`:

```bash
source /path/to/dotsecenv/plugin/dotsecenv.plugin.bash
```

#### Fish

Add to your `~/.config/fish/config.fish`:

```fish
source /path/to/dotsecenv/plugin/conf.d/dotsecenv.fish
```

## File Syntax

### Plain environment variables (`.env`)

```bash
DATABASE_HOST=localhost
DATABASE_PORT=5432
API_KEY=my-api-key
```

### Secret references (`.secenv`)

```bash
# Fetch secret named "DATABASE_PASSWORD" and export as DATABASE_PASSWORD
DATABASE_PASSWORD={dotsecenv}

# Fetch secret named "prod-api-key" and export as API_KEY
API_KEY={dotsecenv:prod-api-key}

# Plain values work here too
DEBUG=true
```

### Two-Phase Loading

1. **Phase 1**: All plain `KEY=value` entries are loaded first
2. **Phase 2**: All `{dotsecenv}` references are resolved via the CLI

If both `.env` and `.secenv` define the same variable, `.secenv` takes precedence (with a warning).

## Aliases

| Alias           | Command                                  | Description                 |
| --------------- | ---------------------------------------- | --------------------------- |
| `dse`           | `dotsecenv`                              | Shorthand for dotsecenv CLI |
| `secret NAME`   | `dotsecenv secret get NAME`              | Retrieve a secret           |
| `secretcp NAME` | `dotsecenv secret get NAME \| clipboard` | Copy secret to clipboard    |

### Clipboard Support

The `secretcp` alias supports:

- **macOS**: `pbcopy`
- **Linux (X11)**: `xclip` or `xsel`
- **Linux (Wayland)**: `wl-copy`

## Trust System

When you first enter a directory containing a `.secenv` file, you'll be prompted:

```shell
dotsecenv: found .secenv in /path/to/project
Load secrets? [y]es / [n]o / [a]lways:
```

| Response       | Behavior                                   |
| -------------- | ------------------------------------------ |
| `y` / `yes`    | Load secrets for this shell session only   |
| `n` / `no`     | Skip loading, don't ask again this session |
| `a` / `always` | Trust this directory permanently           |

Permanently trusted directories are stored in `~/.config/dotsecenv/trusted_dirs`.

## Security

The plugins perform security checks before loading files:

1. **Ownership**: Files must be owned by the current user or root
2. **Permissions**: Files must not be world-writable

If a file fails these checks, it will be refused with a warning:

```shell
dotsecenv: refusing to load /path/.secenv - world-writable
```

## Configuration

| Variable                      | Default                              | Description              |
| ----------------------------- | ------------------------------------ | ------------------------ |
| `DOTSECENV_CONFIG_DIR`        | `~/.config/dotsecenv`                | Configuration directory  |
| `DOTSECENV_TRUSTED_DIRS_FILE` | `$DOTSECENV_CONFIG_DIR/trusted_dirs` | Trusted directories list |

## Requirements

- [dotsecenv](https://github.com/dotsecenv/dotsecenv) CLI installed and in PATH
- bash 5.0+, zsh 5.0+, or fish 3.0+

## Uninstalling

```shell
curl -fsSL https://raw.githubusercontent.com/dotsecenv/plugin/main/install.sh | bash -s -- --uninstall
```

Or manually remove the source line from your shell's RC file.

## License

Apache-2.0
