# Migrate from `.env` to dotsecenv

dotsecenv replaces a `.env` file with one important difference: it
stores secrets one key at a time, not as a single text blob. There is
no bulk-import command, because the unit of encryption and audit is
the individual secret.

> **Looking for a step-by-step walkthrough?** The canonical version
> is the [Migrate from .env tutorial](https://dotsecenv.com/tutorials/migrate-from-dotenv/)
> on dotsecenv.com. The [.env how-to section](https://dotsecenv.com/how-to/#work-with-env-files)
> has additional patterns (`.env` for non-sensitive config alongside
> `.secenv` for secrets).

## Mental model

| `.env` file                          | dotsecenv                                    |
|--------------------------------------|----------------------------------------------|
| One file per project, plain text     | One vault file per project, encrypted        |
| Edit a line to change a value        | `secret store NAME` writes a new entry       |
| Cannot commit safely                 | Vault file commits safely to git             |
| No history of who could read what    | Append-only; recipients tracked per entry    |
| Loaded by `source .env` at runtime   | Loaded by the [shell plugin] at runtime      |

[shell plugin]: ../examples/05-secenv-shell-plugin/

## One-time migration

Given a `.env` like:

```
DATABASE_URL=postgres://localhost/app
API_KEY=sk_live_abc123
SENTRY_DSN=https://x@sentry.io/1
```

Bootstrap the vault and store each line as a separate secret:

```bash
dotsecenv init config
dotsecenv init vault -v ~/.local/share/dotsecenv/vault
dotsecenv login <YOUR_GPG_FINGERPRINT>

# Simple loop. Inspect quoted/multi-line values manually before relying
# on this — IFS='=' splits on the first '=' only.
while IFS='=' read -r name value; do
  case "$name" in ''|\#*) continue ;; esac
  printf '%s' "$value" | dotsecenv secret store "$name"
done < .env
```

Then **delete the plaintext `.env`** and `.gitignore` it for safety:

```bash
rm .env
echo '.env' >> .gitignore
```

Commit the encrypted vault. The `.secenv`-suffixed vault file is
safe to track because every entry is encrypted to your team's
public keys.

## Loading at runtime

Use the [shell plugin](../examples/05-secenv-shell-plugin/) to
populate the environment when you `cd` into the project. This
replaces `source .env`. Drop a `.secenv` file in the project root
that references the secrets by name:

```sh
# project-root/.secenv  (chmod 600)
APP_ENV=production
DATABASE_URL={dotsecenv}
API_KEY={dotsecenv}
SENTRY_DSN={dotsecenv}
```

The `{dotsecenv}` placeholder fetches a secret with the same name
as the variable. Other supported forms:

- `{dotsecenv/EXPLICIT_NAME}`: fetch a differently-named secret.
- `{dotsecenv/namespace::KEY}`: namespaced lookup.

When you `cd` in, the plugin exports plain `KEY=value` lines as
environment variables and shells out to `dotsecenv secret get` to
resolve each `{dotsecenv}` reference. See
[example 05](../examples/05-secenv-shell-plugin/) for the full
syntax reference and the trust model (`chmod 600`, ownership,
per-directory trust).

## What changes about your workflow

- **Editing values.** Instead of editing a line in `.env`, run
  `echo NEW | dotsecenv secret store NAME`. The old value is
  preserved in the vault for audit (see
  [add a secret](add-secret.md)).
- **Sharing values.** Instead of pasting `.env` over Slack, add a
  teammate as a recipient with
  `dotsecenv secret share NAME <THEIR_FINGERPRINT> --all`.
- **Rotating values.** Instead of "rotate everything when someone
  leaves", revoke and rotate the affected secrets. See
  [rotate a compromised key](rotate-compromised-key.md).

## See also

- Tutorial: [Migrate from .env](https://dotsecenv.com/tutorials/migrate-from-dotenv/)
- How-to: [Work with .env Files](https://dotsecenv.com/how-to/#work-with-env-files)
- Guide: [Shell Plugins](https://dotsecenv.com/guides/shell-plugins/)
- Runnable example: [`examples/05-secenv-shell-plugin/`](../examples/05-secenv-shell-plugin/)
- Recipe: [Add a secret](add-secret.md)
- Recipe: [Rotate a compromised key](rotate-compromised-key.md)
