# Example 02 — Team share + revoke + rotate

How dotsecenv's multi-recipient encryption and revocation work in practice.
Two ephemeral identities share a vault, then walk through the append-only
history semantics that make `revoke` a forward-looking operation rather than
a delete.

## What this demonstrates

- Multi-recipient encryption: Alice stores `API_KEY` and shares it with Bob;
  both can decrypt it independently with their own private keys.
- Independent keyrings: the script uses two separate `GNUPGHOME` directories,
  one per identity, to keep each user's secret key isolated from the other.
  This matches production (one key per machine). Public keys move between
  them just as they would over email or chat.
- Revoke is forward-looking: `secret revoke FP` removes a fingerprint from
  the recipient set for *future* writes. It does not rewrite history.
- Rotation is what actually hides a value. After Alice revokes Bob she
  rotates the secret with `secret store`; the new entry is encrypted only
  to her. Bob's `secret get` falls back to the most recent entry he was a
  recipient of (the old v1), and `secret get --all` produces decryption
  errors for the rotated entry he is no longer a recipient of.

## Run it

```bash
./run.sh
```

## Expected output (key moments)

```
==> [Bob] login with Bob's keyring and decrypt API_KEY
    expected: v1-shared
    actual:   v1-shared

==> [Alice] revoke Bob from API_KEY, then rotate API_KEY=v2
... revoked access to secret 'API_KEY' for <Bob's fingerprint>
Secret 'API_KEY' stored successfully

==> [Alice] reads the latest value (expected: v2-rotated)
    actual:   v2-rotated

==> [Bob] tries to read after revoke + rotate.
    actual:   v1-shared        # <-- the OLD value, NOT v2-rotated

==> [Bob] secret get --all shows every entry he can decrypt.
    Notice v2-rotated is absent: it was only ever encrypted to Alice.
... warning: failed to decrypt value from <timestamp>: ... No secret key
... <ciphertext entries Bob is not a recipient of fail>
2026-... v1-shared           # <-- the only entry Bob can still decrypt
```

The decryption-failure warnings on Bob's `--all` listing are the demo's
punchline: the v2 ciphertext exists in the vault file (the format is
append-only) but Bob does not hold the right private key to read it.

## Why two `GNUPGHOME` directories?

If you put both Alice's and Bob's secret keys in a single keyring the demo
becomes misleading: the GPG agent will silently use whichever key works,
which masks the access-control story. With one `GNUPGHOME` per identity,
each `dotsecenv` invocation can only succeed if the *invoker's* private key
is allowed to decrypt the entry — which is the real production constraint.

In real life:
- Alice's machine has her secret key only.
- Bob exports his **public** key (`gpg --armor --export FP`) and sends it to
  Alice (email, chat, key server, however).
- Alice imports it (`gpg --import bob.pub`) and shares secrets to Bob's
  fingerprint.
- Each laptop only ever holds its owner's secret key.

The script collapses both keyrings into one tempdir for repeatability, but
keeps them strictly partitioned via `GNUPGHOME=...` on every command.

## Operational guidance

- Revoke before rotating, not after. If you forget to revoke, the next write
  still encrypts to the old recipient set. The order in this example
  (`revoke`, then `store` to rotate) is the right one.
- Bob's old plaintext still leaks if he saved it anywhere. Revocation is
  about ciphertext access, not memory: a former teammate who already
  decrypted v1 still knows v1. Hiding the value for real requires changing
  it at the source (rotate the database password, issue a new API key, etc.).
- `secret share --all` shares to every vault where the secret already
  exists, which is useful when you keep prod/staging vaults side by side.
  See `dotsecenv secret share --help`.
- `secret revoke --all` is the symmetric operation for revocation.

## Files

- `run.sh` — full end-to-end demonstration with two isolated `GNUPGHOME`s.
- `README.md` — this file.

## Cleanup

The script's `trap ... EXIT` removes the tempdir and shuts down per-tempdir
gpg-agents on every exit path.

## Related

- Tutorial: <https://dotsecenv.com/tutorials/share-secret/>
- Tutorial: <https://dotsecenv.com/tutorials/revoke-access/>
- Tutorial: <https://dotsecenv.com/tutorials/team-onboarding/>
- Concepts (append-only vault, threat model):
  <https://dotsecenv.com/concepts/threat-model/>
- Example 01 (the basic vault flow this builds on):
  [../01-quickstart/](../01-quickstart/)
