# Example 05 — `.secenv` shell plugin reference

A heavily-commented `.secenv` file demonstrating every placeholder syntax
the dotsecenv shell plugin understands. Drop the patterns you need into
your own project's `.secenv` and the plugin will export plain values and
decrypted secrets when you `cd` into the directory.

## What this demonstrates

- Plain `KEY=value` exports (single-quoted, double-quoted, unquoted).
- Secret references with all four forms:
  - `{dotsecenv}` — fetch a secret with the same name as the variable.
  - `{dotsecenv/}` — same; empty after the slash.
  - `{dotsecenv/EXPLICIT_NAME}` — fetch a differently-named secret.
  - `{dotsecenv/namespace::KEY}` — namespaced lookup.
- Two-phase loading semantics (plain values phase 1, secret resolution
  phase 2).
- Trust model: ownership, permissions, and per-directory trust.

## Run it

This example is configuration, not a script. To exercise it:

1. Install the dotsecenv shell plugin: see
   <https://dotsecenv.com/guides/shell-plugins/> for distro-specific
   commands. The `install.sh` from <https://get.dotsecenv.com/install.sh>
   auto-detects your plugin manager (Oh My Zsh, Zinit, Antidote, Oh My Bash,
   Fisher, Oh My Fish) and installs the plugin where it belongs.
2. Drop a vault next to a project, e.g. `~/projects/my-app/.dotsecenv/vault`.
3. Copy the patterns you want from `.secenv` in this directory into
   `~/projects/my-app/.secenv` and adjust the secret names.
4. `chmod 600 ~/projects/my-app/.secenv` so the plugin trusts the file.
5. `cd ~/projects/my-app/`. The plugin sources the file, exports the plain
   values, and shells out to `dotsecenv secret get` for the secret
   references.
6. Verify with: `echo $APP_NAME; echo $DATABASE_PASSWORD`.

## What to look for

When you `cd` into the directory the plugin runs (roughly):

```
.secenv loaded: 6 plain export(s), 4 secret reference(s)
```

If the plugin can't decrypt a secret you'll see:

```
.secenv: secret 'DATABASE_PASSWORD' not found in any configured vault
```

Common causes (with diagnoses): see "Debugging" below.

## Files

- `.secenv` — the reference file. Every supported syntax appears at least
  once with comments explaining what it means.
- `README.md` — this file.

## Cleanup

Nothing to clean up — `.secenv` files are inert until the plugin loads them.
If you copied this `.secenv` somewhere and want to undo: just delete it.

## Loading order — important detail

The plugin loads `.secenv` files **bottom-up to root**, so deeper directories
shadow shallower ones for the same key. Concretely:

```
~/projects/my-app/.secenv          APP_ENV=production  DATABASE_URL={dotsecenv}
~/projects/my-app/services/api/.secenv  SERVICE_NAME=api
```

Entering `~/projects/my-app/services/api/` loads BOTH files. `APP_ENV` and
`DATABASE_URL` come from the parent; `SERVICE_NAME` comes from the child.
If `services/api/.secenv` also set `APP_ENV=staging`, the staging value
would win because it's closer to the cwd.

## Vault path resolution gotcha

Relative vault paths in your dotsecenv config (e.g. `.dotsecenv/vault`) are
resolved relative to the **current working directory** when the plugin
calls the CLI, NOT relative to the config file. The plugin always `cd`s to
the directory containing the `.secenv` before invoking dotsecenv, so
`./dotsecenv/vault` works as you'd expect.

If you have a project-local vault and the plugin reports "vault not found",
the most common culprit is that you sourced the `.secenv` from a different
directory than the one containing the vault. The shell plugin handles this
for you on `cd`; only manual sourcing trips on it.

## Debugging

| Symptom                                                         | Likely cause                                    | Fix                                                                        |
| --------------------------------------------------------------- | ----------------------------------------------- | -------------------------------------------------------------------------- |
| Plugin doesn't activate on `cd`                                 | Plugin not installed or not sourced             | Reinstall via `install.sh`; restart shell                                  |
| `refusing to load <file> - world-writable`                      | `.secenv` mode has the world-write bit set      | `chmod go-w .secenv` (`chmod 600` also works)                              |
| `refusing to load <file> - not owned by current user or root`   | File belongs to another non-root user           | `chown $(id -u) .secenv`                                                   |
| `skipping <dir>/.secenv - no TTY for trust prompt`              | Running in CI or a non-interactive shell        | Skip the plugin in CI; call `dotsecenv secret get` directly                |
| Trust prompt asks every new shell                               | Answered `y` (session) instead of `a` (always)  | Re-enter the directory and answer `a` to persist trust                     |
| `secret X not found in any configured vault`                    | Vault path mismatch or secret key not in vault  | `dotsecenv vault describe` to inspect; `dotsecenv secret get` to list keys |
| `secret X failed to decrypt`                                    | Your GPG fingerprint isn't a recipient          | Have a teammate run `dotsecenv secret share X $YOUR_FINGERPRINT`           |

For deeper debugging the in-repo skill `skills/secenv/SKILL.md` is the
canonical reference (and is what the dotsecenv Claude Code plugin uses).

## Related

- Tutorial: <https://dotsecenv.com/tutorials/reload-secrets/>
- Shell plugins guide: <https://dotsecenv.com/guides/shell-plugins/>
- The canonical syntax reference: `skills/secenv/SKILL.md` in this repo.
- Plugin source: <https://github.com/dotsecenv/plugin>
- Example 01 (the vault that the `{dotsecenv}` references read from):
  [../01-quickstart/](../01-quickstart/)
