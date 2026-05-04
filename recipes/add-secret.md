# Add a secret to a vault

Add or update a secret in a dotsecenv vault. Every `secret store`
call appends a new entry, so the vault keeps a full history of
prior values.

> **Looking for a step-by-step walkthrough?** The canonical
> long-form versions live on dotsecenv.com:
> [First Secret tutorial](https://dotsecenv.com/tutorials/first-secret/)
> for the guided path, and
> [Create a Secret how-to](https://dotsecenv.com/how-to/#create-a-secret)
> for short reference snippets (stdin, file, namespace, specific vault).

## Command

```bash
echo "<value>" | dotsecenv secret store <NAME>
```

`secret store` reads the value from stdin and appends a new entry to
the active vault. There is no `secret add` or `secret update`.
Storing a value is the single operation, whether the name exists or
not.

## How append-only works

Each call to `secret store` writes a new line to the vault. Vaults
are append-only signed JSONL files: every prior version of every
secret remains in the file as its own line, encrypted to whichever
recipients were valid at the time it was written.

When you read with `secret get`, the latest entry wins. `vault
describe` shows the full history.

## Inspect the audit trail

```bash
dotsecenv vault describe                # human-readable, lists every entry
dotsecenv vault describe --json         # machine-readable
dotsecenv secret get NAME --all         # all historical values for one secret
dotsecenv secret get NAME --last        # the most recent value
```

`vault describe` lists every entry, the recipients each was
encrypted to, and the signature on each line. Together with `git
log` on the vault file, this is your audit trail.

## Why this design

- **Audit trail.** You can prove what value was stored, when, and
  to whom it was encrypted.
- **Rotation safety.** Adding a new value never overwrites or
  destroys the prior one. To replace a value the new entry must be
  written; the old entry remains as evidence.
- **No edits in place.** No command mutates a past entry. The file
  only grows forward.

## Limitations

Append-only means **history cannot be removed by the tool**. If a
former recipient must lose access to a value, see
[Rotate a compromised key](rotate-compromised-key.md): revocation
hides future entries from a recipient, but old entries remain in
the file (and in `git` history) and remain decryptable by anyone
holding the matching private key. The durable mitigation is to
rotate the underlying secret at its source.

## See also

- Tutorial: [First Secret](https://dotsecenv.com/tutorials/first-secret/)
- How-to: [Create a Secret](https://dotsecenv.com/how-to/#create-a-secret)
- Concept: [Vault Format](https://dotsecenv.com/concepts/vault-format/)
- Runnable example: [`examples/01-quickstart/`](../examples/01-quickstart/)
- Recipe: [Rotate a compromised key](rotate-compromised-key.md)
