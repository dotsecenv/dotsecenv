---
name: secenv
description: >
  Interpret .secenv files and resolve dotsecenv vault references.
  Use when the user asks about .secenv files, wants to create or edit them,
  debug why a secret isn't loading, understand vault configuration,
  or troubleshoot the shell plugin. Triggers on: .secenv, secenv file,
  secret not loading, vault path, dotsecenv config, shell plugin.
---

# .secenv File Interpretation Skill

This skill teaches you how to read, write, and debug `.secenv` files and their relationship to dotsecenv vaults and config. For CLI operations (storing, retrieving, sharing secrets), defer to the `/dotsecenv:secrets` skill.

## .secenv File Format

A `.secenv` file is a line-based file with `KEY=VALUE` pairs. It lives in a project directory and is loaded by the [shell plugin](https://dotsecenv.com/guides/shell-plugins/) when the user `cd`s into that directory.

### Syntax

```bash
# Plain environment variables
DATABASE_HOST=localhost
DATABASE_PORT=5432

# Quoted values (quotes are stripped on load)
APP_NAME="My Application"
DESCRIPTION='Has spaces'

# Secret references — fetched from a dotsecenv vault at load time
# Same name: variable name = secret key name
DATABASE_PASSWORD={dotsecenv}

# Explicit name: variable name differs from secret key
MY_API_KEY={dotsecenv/API_KEY}

# Name ommitted: empty string is used after dotsecenv/ reference
MY_API_KEY={dotsecenv/}

# Namespaced secret (:: separator)
DB_PASS={dotsecenv/prod::DB_PASSWORD}

# Comments
# This line is ignored

# Empty lines are ignored
```

### Line Types

| Pattern                        | Type                | Behavior                                 |
| ------------------------------ | ------------------- | ---------------------------------------- |
| `KEY=value`                    | Plain               | Exported as-is                           |
| `KEY="value"` or `KEY='value'` | Plain (quoted)      | Quotes stripped, then exported           |
| `KEY={dotsecenv}`              | Secret (same name)  | Fetches secret named `KEY` from vault    |
| `KEY={dotsecenv/}`             | Secret (same name)  | Fetches secret named `KEY` from vault    |
| `KEY={dotsecenv/SECRET}`       | Secret (explicit)   | Fetches secret named `SECRET` from vault |
| `KEY={dotsecenv/ns::SECRET}`   | Secret (namespaced) | Fetches secret `ns::SECRET` from vault   |
| `# comment`                    | Comment             | Ignored                                  |
| Empty line                     | —                   | Ignored                                  |

### Key Format Rules

- Variable names must match `^[A-Za-z_][A-Za-z0-9_]*$`
- Secret key names use `::` as namespace separator: `namespace::KEY_NAME` (e.g., `prod::DB_PASSWORD`)
- Only one `/` allowed in `{dotsecenv/...}` references; a second `/` is rejected by the parser
- The part after `{dotsecenv/` can be a plain key (`API_KEY`) or namespaced (`prod::DB_PASSWORD`)

## How .secenv Files Are Loaded

The shell plugin loads `.secenv` files in **two phases**:

1. **Phase 1**: All plain `KEY=value` lines are exported first
2. **Phase 2**: All `{dotsecenv}` references are resolved via the CLI

This ensures plain variables are available before secret resolution. The plugin also loads ancestor `.secenv` files — if `/project/.secenv` and `/project/src/.secenv` both exist, entering `/project/src/` loads both, with child values shadowing parent values for the same key.

## Vault Resolution (Critical for Debugging)

When the shell plugin encounters a `{dotsecenv}` reference, it calls the dotsecenv CLI to fetch the secret. The CLI finds the vault using the **dotsecenv config file**.

### Config File Location

Resolved in this order:

1. `DOTSECENV_CONFIG` environment variable
2. `$XDG_CONFIG_HOME/dotsecenv/config` (default: `~/.config/dotsecenv/config`)

### Config Vault Paths

The config file (YAML) lists vault paths:

```yaml
vault:
  - ~/.local/share/dotsecenv/vault # absolute (tilde-expanded)
  - /shared/team/vault # absolute
  - .dotsecenv/vault # relative to CWD
```

### Relative Path Resolution

**Relative vault paths (like `.dotsecenv/vault`) are resolved relative to the current working directory, NOT relative to the config file.**

This is why the shell plugin `cd`s into the directory containing `.secenv` before calling the CLI. For example:

```
/project/.secenv         → references DATABASE_PASSWORD={dotsecenv}
/project/.dotsecenv/vault → contains the encrypted secret
~/.config/dotsecenv/config → lists ".dotsecenv/vault" as a vault path
```

When the plugin loads `/project/.secenv`, it `cd`s to `/project/` first, then runs `dotsecenv secret get DATABASE_PASSWORD`. The CLI reads the config, sees `.dotsecenv/vault`, and resolves it to `/project/.dotsecenv/vault`.

## How to Help the User

### Creating a .secenv File

When the user wants to create a `.secenv` file:

1. Ask which variables they need (plain vs. secret)
2. For secrets, check if they exist in a vault first:

   ```bash
   # List secrets in the default vault
   dotsecenv secret get --json

   # Or check a specific vault
   dotsecenv vault describe --json
   ```

3. Write the `.secenv` file with the correct syntax
4. Remind them the shell plugin needs to be installed for auto-loading

### Debugging "Secret Not Found"

When a secret referenced in `.secenv` fails to load:

1. **Read the `.secenv` file** and identify the `{dotsecenv}` references
2. **Read the config** to find vault paths:

   ```bash
   cat ~/.config/dotsecenv/config 2>/dev/null || cat "${XDG_CONFIG_HOME:-$HOME/.config}/dotsecenv/config"
   ```

3. **Check if any vault paths are relative** (like `.dotsecenv/vault`)
4. If relative, the vault must exist in the **same directory as the `.secenv` file**, not in the current working directory of the Claude session
5. **Check if the vault file exists** at the resolved path:

   ```bash
   # For a .secenv in /project/, check relative vault path
   ls -la /project/.dotsecenv/vault
   ```

6. **List secrets in that vault** to see if the referenced secret exists:

   ```bash
   dotsecenv secret get --json -v /project/.dotsecenv/vault
   ```

7. **Check identities** — the user's fingerprint must be in the vault's `available_to` list for that secret:

   ```bash
   dotsecenv vault describe --json -v /project/.dotsecenv/vault
   ```

### Debugging "Vault Not Found"

1. Read the config file and list all vault paths
2. For each relative path, explain that it resolves relative to where the shell plugin runs (the `.secenv` directory)
3. Check if the vault file actually exists at the expected location
4. If the user needs to create a vault: defer to `/dotsecenv:secrets` — that's an `init` operation

### Editing a .secenv File

When adding or modifying entries:

- Plain values: write directly
- Secret references: verify the secret exists in a reachable vault before writing `{dotsecenv}` or `{dotsecenv/SECRET_NAME}`
- Maintain the existing style (quoting, spacing, comment conventions)
- Keep plain variables grouped together and secrets grouped together (matches the two-phase loading)

### Understanding Ancestor Loading

If the user has nested `.secenv` files:

```
/project/.secenv           → APP_ENV=production, DATABASE_URL={dotsecenv}
/project/services/.secenv  → SERVICE_NAME=api, API_KEY={dotsecenv}
```

When entering `/project/services/`:

- Both files load (parent first, then child)
- Child values shadow parent values with the same key
- Leaving `/project/services/` for `/other/` unloads both

## Security Checks

The shell plugin performs these checks before loading a `.secenv` file:

1. **Ownership** — file must be owned by the current user or root
2. **Permissions** — file must NOT be world-writable
3. **Trust** — user must trust the directory (prompted on first load, can persist)

When creating `.secenv` files, ensure correct ownership and permissions:

```bash
chmod 600 .secenv  # owner read/write only
```
