# Example 08 — Compact a vault

How `dotsecenv vault compact` shrinks a vault by dropping superseded
secret-value versions, without touching identities or decrypting anything.

## What this demonstrates

- Append-only growth: every `secret store` adds a new value record and keeps
  the old ones. Storing `DB_PASSWORD` three times and `AWS_KEY` four times
  leaves seven superseded versions behind.
- Minimal keep rule: compaction keeps, per current identity, the newest value
  that identity can decrypt. When the latest value already covers every current
  identity, each secret collapses to one value.
- Deleted secrets are removed whole. `TEMP_TOKEN` is stored then forgotten;
  compaction drops its definition and tombstone entirely.
- No decryption: compaction reads only access lists and value order. The dry
  run (`vault compact --json`) reports the plan as before/after counts without
  reading a single plaintext.
- Kept values are preserved verbatim, so signatures stay valid. `validate`
  passes and `secret get` still returns the latest value after the rewrite.

## Run it

```bash
./run.sh
```

## Expected output (key moments)

```
==> vault before compaction:
...
    JSON lines (1 header + records): 17

==> compaction plan (dry run; --json without --yes writes nothing):
{
  "vault": "...",
  "applied": false,
  "secrets": [
    { "key": "DB_PASSWORD", "before": 4, "after": 1 },
    { "key": "AWS_KEY", "before": 5, "after": 1 },
    { "key": "TEMP_TOKEN", "before": 2, "after": 0, "removed": true }
  ],
  "values_before": 11,
  "values_after": 2,
  "values_dropped": 9,
  "secrets_removed": 1
}

==> vault after compaction:
...
    JSON lines (1 header + records): 7

==> validate the compacted vault
    validate: OK

==> secret get still returns the latest value
    DB_PASSWORD expected: db-v3
    actual:              db-v3
    AWS_KEY expected:     aws-v4
    actual:              aws-v4

==> TEMP_TOKEN was deleted, so compaction removed it entirely:
    TEMP_TOKEN absent (as expected)
```

The shape is what matters: many versions in, one latest per secret out, deleted
secrets gone. `DB_PASSWORD` shows four values (three stores plus the share that
re-encrypts the latest to Bob) collapsing to one.

## How the keep rule works

For each secret, compaction walks the current identities (everything in the
vault header). For each one it finds the newest value whose `available_to`
includes that fingerprint — exactly the value `secret get` would return for
that identity — and keeps it. Everything else is dropped.

Two consequences fall out for free:

- Revocation collapses cleanly. A value readable only by a revoked fingerprint
  (one no longer in the vault's identities) is nobody's newest, so it is
  dropped. Values still shared with a current identity stay.
- A secret nobody current can read keeps its latest value as a floor, so it is
  never silently emptied. Its decryptability is unchanged.

The default is the minimal rule. A conservative variant ("keep the newest value
per distinct recipient set") would keep more; dotsecenv ships the minimal rule.

## Safety

- `vault compact` with no flags prints the plan and asks before writing.
  `--yes` skips the prompt (and prompts are auto-skipped in CI).
- `--json` reports the plan and writes only when combined with `--yes`.
- The script backs up the vault to `<vault>.bak` before applying. Restore with
  `cp <vault>.bak <vault>` if a run looks wrong.

## Files

- `run.sh` — end-to-end demonstration in a throwaway tempdir.
- `README.md` — this file.

## Cleanup

The script's `trap ... EXIT` removes the tempdir and shuts down the per-tempdir
gpg-agent on every exit path.

## Related

- Example 02 (share, revoke, rotate — the append-only model this builds on):
  [../02-team-share-revoke/](../02-team-share-revoke/)
- Concepts (append-only vault):
  <https://dotsecenv.com/concepts/threat-model/>
