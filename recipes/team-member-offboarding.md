# Offboard a departing team member

How to remove a leaving teammate's GPG key from every vault they
could read, in what order to rotate the secrets they had access
to, and what to say to whom along the way. Covers routine
offboarding (planned departure) and urgent offboarding (hostile
exit, suspected key compromise).

The same workflow applies whether you are removing a teammate's
key or your own (end of an internal role rotation).

> **Doing this because the key is compromised rather than because
> someone is leaving?** Use
> [Rotate a compromised GPG key](rotate-compromised-key.md). The
> mechanics overlap; the comms differ.

## Mental model first

dotsecenv vaults are append-only and entries are encrypted to GPG
public keys. Two consequences for offboarding:

1. **The leaver's key still decrypts everything written before
   you revoke.** Past entries remain in the vault file and in
   `git` history, encrypted to whoever held the recipient list at
   the time. Anyone who already cloned the repo retains the old
   data, and the leaver's private key still decrypts it.
2. **Revoke is forward-looking.** After `secret revoke`, new
   `secret store` writes are no longer encrypted to the leaver.
   Past entries are unchanged.

The durable mitigation is to rotate every secret the leaver could
read at its source (issue a new database password, reissue the
API key) and store the new value. The leaver's key still decrypts
the old value, but the old value no longer authenticates to
anything.

## Pre-flight

Before touching any vault:

- **Confirm the departure with HR or the leaver's manager** and
  the effective date. Offboarding GPG access typically maps to
  the same timestamp as deprovisioning their email and SSO.
- **Announce the rotation window.** Post in the on-call channel:
  "Rotating shared credentials starting at T+0; expect short
  interruptions to <list services>." This prevents surprise pages
  when consumers point at the new value.
- **Inventory the scope.** Get the leaver's GPG fingerprint
  (`gpg --list-keys their_email@company.com`) and list every
  secret they currently hold:

  ```bash
  LEAVER_FP="ABCD1234..."  # the 40-char fingerprint

  for v in $(dotsecenv vault describe --json | jq -r '.[].vault'); do
    echo "== $v =="
    dotsecenv vault describe --json -v "$v" \
      | jq -r --arg fp "$LEAVER_FP" \
          '.[].secrets[] | select((.available_to // []) | index($fp)) | .key'
  done
  ```

  The output is the rotation worklist. Order it by blast radius:
  production credentials first, then staging, then dev.

## Runbook

### 1. Revoke the leaver from every secret they could read

Use the wildcard form to cover every secret in one pass:

```bash
dotsecenv secret revoke "*" "$LEAVER_FP" --all
```

`"*"` matches every secret name, and `--all` extends the revoke
to every vault that holds the secret. After this step, future
`secret store` writes will not encrypt to the leaver.

For per-secret control (or if you only want to revoke from a
subset of secrets), loop over the worklist from pre-flight:

```bash
for secret in $(dotsecenv vault describe --json \
                  | jq -r --arg fp "$LEAVER_FP" \
                      '.[].secrets[] | select((.available_to // []) | index($fp)) | .key' \
                  | sort -u); do
  dotsecenv secret revoke "$secret" "$LEAVER_FP" --all
done
```

### 2. Verify the revocation took effect

Re-run the inventory query. The leaver's fingerprint should now
appear in **zero** current recipient lists:

```bash
for v in $(dotsecenv vault describe --json | jq -r '.[].vault'); do
  dotsecenv vault describe --json -v "$v" \
    | jq -r --arg fp "$LEAVER_FP" \
        '.[].secrets[] | select((.available_to // []) | index($fp)) | .key'
done
# Empty output means success.
```

Confirm vault health:

```bash
dotsecenv vault doctor
```

`vault doctor` exits non-zero if it finds a vault it cannot read,
a stale format version, or fragmentation issues introduced by the
revoke pass.

### 3. Rotate each secret at its source, production first

This step is what actually neutralizes the offboarding. Until you
do this, the leaver's private key still decrypts the old
ciphertext (which is also in `git` history). Re-encrypting to a
new recipient set does not change this; the underlying credential
has to change.

Work the worklist in blast-radius order. For each secret:

```bash
# 1. Generate a new credential at the source (DB console, IDP,
#    cloud provider, API key issuer, etc.)
# 2. Store the new value:
echo "<new-value>" | dotsecenv secret store SECRET_NAME

# 3. Roll the new credential out to consumers (deploys, CI, etc.)
```

The team pattern is: rotate one secret end-to-end, verify the
dependent service still works, then move on. Batch rotation
across many secrets at once tends to leave half-broken
environments.

### 4. Confirm and audit-log the offboarding

```bash
dotsecenv vault doctor        # health
dotsecenv vault describe      # confirm no current entry lists LEAVER_FP
```

Record the change in your team's security log: which fingerprint,
which secrets were rotated, who performed the revoke, and the
timestamp. The vault's own append-only history doubles as your
audit trail. `git log -p path/to/vault` shows every revoke and
rotation in order.

### 5. Commit and push

```bash
git add path/to/vault
git commit -m "Offboard <name>: revoke $LEAVER_FP, rotate N secrets"
git push
```

Other team members pull and continue working. The leaver's
private key still decrypts the old entries in the file (which is
unavoidable); it cannot decrypt the new ones.

## Error handling

| Symptom                                                            | Cause                                                                  | Fix                                                                                              |
|--------------------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `secret revoke ... --all` says "no matching secret"                | Wildcard not quoted; the shell expanded `*` to local filenames         | Quote it: `"*"`                                                                                  |
| `vault describe` is missing a vault you expected                   | Vault path not in user `vault:` config, or not allowed by policy       | Add it with `-v` once, or list it under `vault:` in `~/.config/dotsecenv/config.yaml`            |
| Decrypt failure when rotating (`secret store` followed by `get`)   | Your own login fingerprint was accidentally revoked from this secret   | Re-share to yourself: `dotsecenv secret share SECRET YOUR_FP --all`, then re-run `secret store`  |
| Revoke succeeds in some vaults, fails in others                    | A vault file is read-only or owned by another user                     | Run revoke per vault with `-v` and a writeable path; fix permissions on the offending file       |
| Leaver's fingerprint is not in your local keyring                  | You never imported their public key, or it expired and was purged      | Revoke still works without the public key; you only need the fingerprint string                  |

## What you cannot do

- **Erase a leaked encrypted entry from the vault file.**
  Append-only by design. Rewriting `git` history with
  `git filter-repo` is technically possible, but anyone who
  already cloned the repo retains the old data, and the leaver's
  key still decrypts it.
- **Re-encrypt an existing entry to a different recipient set.**
  `secret share` and `secret revoke` only affect future writes;
  they do not mutate past entries. Source rotation is the only
  fix.
- **Recall a value the leaver memorized or saved elsewhere.**
  Revocation governs ciphertext, not knowledge. A teammate who
  read the DB password yesterday still remembers the DB password
  today. Rotating it at the source is what makes their memory
  worthless.

## Talking to the leaver

For a planned, friendly exit, a short factual note avoids
ambiguity:

> Your access to the team's GPG vaults was revoked effective
> <date>. Past values you previously had access to remain in our
> vault history and on any machines you used during your time on
> the team. We are rotating those values, so they will no longer
> work for any production service after <rotation cutoff>. Please
> delete the team vault file from any personal machines.

For hostile or compromised exits, skip the comms with the leaver
and proceed straight to revoke + rotate. Loop in legal afterward.

## See also

- Recipe: [Rotate a compromised GPG key](rotate-compromised-key.md)
- Recipe: [Add a secret](add-secret.md)
- Tutorial: [Revoke Access](https://dotsecenv.com/tutorials/revoke-access/)
- Tutorial: [Team Onboarding](https://dotsecenv.com/tutorials/team-onboarding/)
- Concept: [Threat Model](https://dotsecenv.com/concepts/threat-model/)
- Concept: [Vault Format](https://dotsecenv.com/concepts/vault-format/)
- Runnable example: [`examples/02-team-share-revoke/`](../examples/02-team-share-revoke/)
- Repo: [SECURITY.md](../SECURITY.md)
