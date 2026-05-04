# Example 01 — Quickstart

The minimum useful flow: encrypt one secret, decrypt it, and inspect the
vault. End-to-end runnable in under ten seconds with zero state outside a
tempdir.

## What this demonstrates

- The four bootstrap commands every dotsecenv user runs once: `init config`,
  `init vault`, `login`, plus `identity create` if you do not already have a
  GPG key.
- The two everyday commands: `secret store` (stdin -> encrypted vault entry)
  and `secret get` (vault entry -> stdout).
- Two read-only inspection commands: `vault describe` (identities and secret
  keys) and `validate` (structural sanity check on config and vault).

## Run it

From inside this directory:

```bash
./run.sh
```

The script generates an ephemeral RSA-4096 key in an isolated `GNUPGHOME`,
walks through the full flow against a tempdir-only config and vault, and
removes everything on exit.

## Expected output

You should see a sequence that looks roughly like this (timestamps and
fingerprints will differ):

```
==> using binary: /path/to/dotsecenv
==> tempdir: /tmp/tmp.XXXXXXXX
==> GNUPGHOME: /tmp/tmp.XXXXXXXX/gnupg
==> generating CI-only RSA-4096 key (no passphrase)
==> fingerprint: FA5760BB43B4949DDD46342735EF443EF68A9396
==> dotsecenv init config (pointing -v at our isolated vault path)
Initialized config file: /tmp/tmp.XXXXXXXX/config
==> dotsecenv init vault
Initialized empty vault: /tmp/tmp.XXXXXXXX/vault
==> dotsecenv login (records a signed login proof in the config)
Logging in with identity: Quickstart Demo <quickstart@example.invalid> (RSA 4096-bit)
Login successful! Signed proof stored in config.
==> dotsecenv secret store DATABASE_PASSWORD
Secret 'DATABASE_PASSWORD' stored successfully
==> dotsecenv secret get DATABASE_PASSWORD
my-database-password
==> dotsecenv secret get  (no args -> list keys, never values)
DATABASE_PASSWORD
==> dotsecenv vault describe
Vault 1 (/tmp/tmp.XXXXXXXX/vault):
  Identities:
    - Quickstart Demo <quickstart@example.invalid> (FA5760BB43B...)
  Secrets:
    - DATABASE_PASSWORD
==> dotsecenv validate
... all checks passed ...
==> done.
```

You will also see a "decrypting in non-interactive terminal" warning printed
to stderr by `secret get`. That warning is correct: real-world workflows
should run inside a TTY (or behind the shell plugin) so the GPG agent can
prompt for the passphrase. The script suppresses it would defeat the purpose
of the warning, so we leave it visible.

## Files

- `run.sh` — the full, runnable flow. Idempotent (re-runnable from scratch
  every time because every artifact lives in a fresh tempdir).
- `README.md` — this file.

## Cleanup

The script's `trap ... EXIT` removes the tempdir and shuts down the
per-tempdir gpg-agent on every exit path (success, failure, Ctrl-C). There is
nothing to clean up by hand.

## Adapting this to your machine

Three things change when you run dotsecenv outside a script:

1. **Use your real GPG key** instead of generating one. Drop the
   `identity create` block; capture the fingerprint with
   `gpg --list-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}'`
   (or whichever key you prefer).
2. **Drop the `-c "$CONFIG"` flags.** dotsecenv uses
   `$XDG_CONFIG_HOME/dotsecenv/config` (typically
   `~/.config/dotsecenv/config`) by default — that is the right place for
   your real config to live.
3. **Pick a real vault location.** `~/.local/share/dotsecenv/vault` is the
   convention used by `install.sh`; project-local vaults live at
   `./.dotsecenv/vault` and are picked up by the shell plugin.

## Related

- Tutorial: <https://dotsecenv.com/tutorials/quickstart/>
- Concepts (vault format, append-only history): <https://dotsecenv.com/concepts/>
- The `demos/demo.sh` recording in this repo is the asciinema source for the
  homepage demo and follows the same flow.
