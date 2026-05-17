# Example 06 — Multi-environment + FIPS 186-5

A complete strategy for running dotsecenv across development,
staging, and production with separate GPG identities per environment
and FIPS 186-5 algorithm enforcement applied uniformly.

## What this demonstrates

- **Vault-per-environment.** Three independent vault files
  (`vault-dev`, `vault-staging`, `vault-prod`) committed alongside
  the code. Each vault carries its own recipient set; the same
  `DATABASE_URL` key in each vault holds a different value.
- **Identity-per-role, not per-environment.** Three identities
  (Alice, Bob, Ops). The vault recipient lists, not the identities
  themselves, gate which environment each person can read. Alice
  reads dev + staging; Bob reads dev only; Ops reads staging +
  production.
- **FIPS 186-5 enforcement via policy fragment.** A single
  `policy.d/00-corp-fips.yaml` fragment, installed once at
  `/etc/dotsecenv/policy.d/`, constrains every dotsecenv user on
  the machine to ECC P-384/P-521, Ed25519/Ed448, or RSA ≥ 3072 keys.
  All three demo identities use ECC P-384 to satisfy this policy.
- **GNUPGHOME isolation.** Each identity lives in its own
  `$GNUPGHOME` directory, mirroring production's "one private key per
  machine" pattern. Public keys move between users with
  `gpg --export | gpg --import`, the same dance you would do over
  email or chat.

## FIPS 186-5 vs FIPS 140-3 — read this before claiming compliance

These are two different things and dotsecenv treats them differently:

| Standard       | What it governs                            | Where it lives in dotsecenv                                            |
|----------------|--------------------------------------------|------------------------------------------------------------------------|
| FIPS 186-5     | Approved digital-signature algorithms      | `approved_algorithms` policy fragment + the user config's allow-list   |
| FIPS 140-3     | Validated cryptographic module             | Build-time flag `GOFIPS140=v1.26.0` on `go build`; the binary's module |

This example covers FIPS 186-5 only. The policy fragment in
`policy.d/00-corp-fips.yaml` enforces algorithm selection at runtime.
For FIPS 140-3 you also need a validated binary, which means building
dotsecenv with `GOFIPS140=v1.26.0` on a NIST-listed Operating
Environment and pinning that binary into every machine and runner.
See [compliance docs](https://dotsecenv.com/concepts/compliance/#module-locking)
for the validated-module discussion.

A regulated deployment usually wants both.

## Run it

```bash
./run.sh
```

Expected output ends with the access matrix:

```
==> Access matrix (each user attempts to decrypt DATABASE_URL in each vault)
    USER    DEV     STAGING PROD
    Alice   OK      OK      denied
    Bob     OK      denied  denied
    Ops     denied  OK      OK
```

The "denied" cells are the cryptographic enforcement. A user whose
fingerprint is not on a vault's recipient list has no GPG session key
for that vault's entries. `secret get -v <vault>` returns a non-zero
exit code without ever printing plaintext.

## Identity strategy: pick one of three patterns

This example uses **GNUPGHOME isolation** (one keyring per identity)
because it is the most realistic on a single demo machine. Production
teams pick from three patterns depending on their physical-machine
distribution:

1. **One machine per environment.** Each environment runs on a
   dedicated runner / laptop / build node that holds exactly the
   secret key for that environment. No `$GNUPGHOME` switching needed.
   This is what the [Team Vault Setup tutorial](https://dotsecenv.com/tutorials/team-vault-setup/#variations)
   describes under "Multiple vaults".
2. **GNUPGHOME-switching on one machine.** A single laptop holds
   multiple keyrings under different `$GNUPGHOME` paths. Shell
   wrappers (`alias dse-dev='GNUPGHOME=~/.gnupg-dev dotsecenv'`)
   route every command to the correct keyring. The runnable demo in
   this directory and [example 02](../02-team-share-revoke/) both
   use this pattern.
3. **Single identity, recipient-set partitioning.** One person holds
   one identity. Different vaults list different subsets of the team
   on their recipient lists. Access is controlled entirely by which
   vault you share a secret into. See the
   [Share a Secret tutorial](https://dotsecenv.com/tutorials/share-secret/).

The patterns are not mutually exclusive. A real deployment often
combines (1) for production CI runners with (2) for developer
laptops.

## Policy install on a real machine

```bash
sudo install -o root -g root -m 0644 \
  policy.d/00-corp-fips.yaml /etc/dotsecenv/policy.d/00-corp-fips.yaml
dotsecenv policy validate
# expect: policy valid (1 fragment(s) in /etc/dotsecenv/policy.d)
```

`dotsecenv policy validate` exits with distinct codes per error
category so CI jobs can act on them:

- 0 — no policy enforced (the directory does not exist), or all
  fragments are structurally valid.
- 1 — empty allow-list field (omit the field instead of setting an
  empty list).
- 2 — malformed YAML, or a forbidden top-level key (only
  `approved_algorithms`, `approved_vault_paths`, `behavior`, and
  `gpg` are accepted).
- 8 — insecure permissions on the directory or a fragment, or a
  fragment that is not readable as the invoking user.

Drop the fragment into every developer laptop and every CI runner.
Allow-list fields union across fragments, so a team that wants
stricter rules adds a `50-team.yaml` with a narrower allow-list
rather than rewriting the corporate baseline.

## CI integration

`ci.yml` ships a GitHub Actions workflow that:

1. Validates `policy.d/00-corp-fips.yaml` once per push
   (`dotsecenv policy validate`).
2. Fans out a matrix job over `dev` / `staging` / `production`,
   each importing a different repo-secret-stored GPG identity for
   that environment.
3. Runs `dotsecenv vault doctor --json` per environment before
   decrypting.
4. Decrypts only that environment's secrets and feeds them into
   `$GITHUB_ENV` (masked via `::add-mask::`).

Copy `ci.yml` to `.github/workflows/deploy.yml` in your application
repo and configure three repo secrets:
`DOTSECENV_GPG_PRIVATE_KEY_DEV`,
`DOTSECENV_GPG_PRIVATE_KEY_STAGING`,
`DOTSECENV_GPG_PRIVATE_KEY_PROD`.

## Files

- `run.sh` — end-to-end demo with three GNUPGHOMEs and three vaults.
- `policy.d/00-corp-fips.yaml` — FIPS 186-5 algorithm policy fragment
  intended for `/etc/dotsecenv/policy.d/`.
- `ci.yml` — GitHub Actions workflow with per-environment matrix and
  policy validation.
- `README.md` — this file.

## Cleanup

`run.sh` traps `EXIT` and removes the tempdir, plus shuts down the
per-tempdir gpg-agents. Nothing is written outside `mktemp -d`.

## Related

- Tutorial: [Team Vault Setup](https://dotsecenv.com/tutorials/team-vault-setup/) — multi-vault `--all` flag and per-env recipient subsets.
- Tutorial: [Share a Secret](https://dotsecenv.com/tutorials/share-secret/) — recipient-set partitioning on a single vault.
- Concept: [Compliance](https://dotsecenv.com/concepts/compliance/) — FIPS 186-5 vs FIPS 140-3, build-time module locking.
- Concept: [Security Policies](https://dotsecenv.com/concepts/security-policies/) — policy.d directory contract, merge semantics, exit codes.
- Example: [04-policy-directory](../04-policy-directory/) — the
  policy.d fragment story without the multi-environment overlay.
- Example: [02-team-share-revoke](../02-team-share-revoke/) — the
  GNUPGHOME-isolation pattern this example builds on.
