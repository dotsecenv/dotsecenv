# Rotate a compromised GPG key

How to remove a compromised private key's access from your dotsecenv
vaults — and what the append-only design means for the keys that
already saw past secrets.

The same workflow applies whether the compromised key is yours or a
teammate's.

## Mental model first

dotsecenv vaults are **append-only** and entries are encrypted to
GPG public keys. This has two consequences for rotation:

1. **You cannot edit the past.** Old vault entries remain in the
   file and in `git` history, encrypted to whoever held the
   recipient list at the time. The compromised private key still
   decrypts those entries — and any clone of the repo retains them.
2. **Revoking a recipient only affects future writes.** After
   `secret revoke`, new `secret store` entries are no longer
   encrypted to the revoked recipient. Past entries are unchanged.

The durable mitigation is therefore to **rotate the underlying
secret at its source** (issue a new database password, regenerate
the API key, etc.) and then store the new value. The leaked key can
still decrypt the old value, but the old value no longer
authenticates to anything.

## Runbook

### 1. Generate or import a replacement identity

If the compromised key is yours, generate a new GPG key pair
(`gpg --full-generate-key`), publish the new public key to your
team, and import the new public key into each teammate's keyring so
they can encrypt to you.

### 2. Revoke the compromised recipient from each affected secret

For every secret the compromised key could read, run:

```bash
dotsecenv secret revoke <SECRET_NAME> <COMPROMISED_FINGERPRINT> --all
```

`--all` extends the revoke to every vault that already holds
`<SECRET_NAME>`. Repeat per secret name. After this step, future
`secret store` calls will not encrypt to the compromised key.

### 3. Add the replacement recipient

```bash
dotsecenv secret share <SECRET_NAME> <NEW_FINGERPRINT> --all
```

This adds the new identity to the recipient set going forward.

### 4. Rotate each affected secret at its source

For each secret the compromised key could decrypt, generate a new
underlying value (rotate the DB password, reissue the API key) and
store it:

```bash
echo "<new-value>" | dotsecenv secret store <SECRET_NAME>
```

This is the step that actually neutralizes the compromise. The
leaked key can still decrypt every entry written before this point,
but those entries hold values that no longer work.

### 5. Verify

```bash
dotsecenv vault doctor                 # health checks
dotsecenv vault describe               # confirm recipient lists
```

Every current secret should now list the replacement key as a
recipient and **not** the compromised key. Past entries still show
the compromised key — that is expected and unavoidable.

### 6. Commit and push

The new vault entries land in the file. Commit and push as usual.
The git history retains the old entries; that is part of the audit
trail.

## What you cannot do

- **Erase a leaked encrypted entry from the vault file.**
  Append-only by design. Rewriting `git` history with
  `git filter-repo` is possible, but anyone who already cloned the
  repo still has the old data, and the compromised key still
  decrypts it.
- **Re-encrypt an existing entry to a different recipient set.**
  `secret share` and `secret revoke` only affect future writes;
  they do not mutate past entries.

## See also

- [Add a secret](add-secret.md)
- [Migrate from .env](migrate-from-dotenv.md)
- [Team share + revoke + rotate example](../examples/02-team-share-revoke/)
- [SECURITY.md](../SECURITY.md)
- [Threat model](https://dotsecenv.com/concepts/threat-model/)
