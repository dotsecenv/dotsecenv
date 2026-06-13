# Example 07 — Org-wide CI keypair

One CI keypair, shared across many repositories. The private key lives once as
a GitHub **organization** secret named `ORG_GPG_PRIVATE_KEY`; every repo that
needs it imports the same key in CI and decrypts its own committed vault.

This is the org-wide counterpart to
[example 03](../03-ci-cd-github-action/), which scopes one key per repository.
Read example 03 first — the workflow here is identical except for the secret's
scope.

## What this demonstrates

- A single org-wide CI keypair stored as a GitHub organization secret
  (`ORG_GPG_PRIVATE_KEY`) and consumed by multiple repositories.
- A repository-access policy on that org secret that lists exactly which repos
  may read it.
- The same masking + login-by-fingerprint workflow as example 03, importing
  from the org secret instead of a per-repo secret.

## Why org-wide?

One key to provision, one key to rotate. When a fleet of repos all deploy with
the same set of shared secrets, minting and tracking a separate CI key per repo
is busywork. An org-wide key collapses that to a single identity: generate it
once, grant a fixed list of repos read access, and `secret share` it into each
vault.

The trade is blast radius. A repo-scoped key (example 03) leaks one repo's
secrets; the org-wide key leaks every vault it is a recipient of. Reach for
this pattern only when the convenience is worth that exposure. The
[Key Scope concept](/concepts/key-scope/) covers the decision in full.

## Bootstrap procedure (do this once)

You need one CI identity, its private key as an **organization** secret with a
repo-access list, and its public key on the recipient list of every vault that
should be readable in CI.

```bash
# 1. On a developer machine, generate ONE org-wide CI key (NO PASSPHRASE
#    because GitHub Actions cannot answer a pinentry prompt).
dotsecenv identity create \
  --algo RSA4096 \
  --name "Org CI" \
  --email "ci@your-org.example" \
  --no-passphrase

# 2. Capture the fingerprint and export the private key in ASCII-armored form.
FP=$(gpg --list-secret-keys --with-colons "ci@your-org.example" \
  | awk -F: '/^fpr:/ { print $10; exit }')
gpg --armor --export-secret-keys "$FP" > /tmp/org-ci.asc

# 3. Set it as an ORGANIZATION secret named ORG_GPG_PRIVATE_KEY, scoped to an
#    explicit list of repos. Do NOT make it visible to all repositories.
#       gh CLI:
gh secret set ORG_GPG_PRIVATE_KEY \
  --org your-org \
  --repos repo-a,repo-b \
  < /tmp/org-ci.asc
#       Web UI equivalent:
#       Settings -> Secrets and variables -> Actions (at the ORG level)
#       -> New organization secret -> Repository access: "Selected repositories"
#       -> add repo-a and repo-b explicitly.

# 4. Wipe the file from disk.
shred -u /tmp/org-ci.asc

# 5. In EVERY repo's vault, share each secret CI needs with the org CI
#    fingerprint, from a developer machine that already has the secret stored:
dotsecenv secret share DATABASE_URL "$FP"
dotsecenv secret share DEPLOY_TOKEN "$FP"

# 6. Commit each updated vault file (.dotsecenv/vault) in its repo.
git add .dotsecenv/vault
git commit -m "ci: grant org CI identity access to deploy secrets"
git push
```

The org key is now provisioned. Drop `workflow.yml` into each participating
repo at `.github/workflows/deploy.yml`.

## Run it

This example is configuration, not a runnable script. To exercise the
workflow:

1. Copy `workflow.yml` to `.github/workflows/deploy.yml` in each application
   repo on the org secret's access list.
2. Make sure each repo has a vault at `.dotsecenv/vault` with `DATABASE_URL`
   and `DEPLOY_TOKEN` shared to the org CI identity (see bootstrap above), or
   change the secret names in the workflow to whatever the project uses.
3. Push to `main` (or trigger via `workflow_dispatch`) and watch the run.

## Files

- `workflow.yml` — the complete workflow. Copy to
  `.github/workflows/deploy.yml` in each participating project.
- `README.md` — this file.

## Threat model notes

- Large blast radius. A leak of `ORG_GPG_PRIVATE_KEY` compromises every vault
  the org key is a recipient of, across every repo on its access list. A
  repo-scoped key (example 03) confines a leak to one repo; prefer it unless
  the convenience of one shared key is worth the wider exposure.
- Keep the repo-access list minimal. Use "Selected repositories", never "All
  repositories". Every repo on the list can read the private key in CI.
- Rotation is fleet-wide. Re-keying means generating a new org key, replacing
  `ORG_GPG_PRIVATE_KEY`, and re-running `secret share` to the new fingerprint
  in every repo's vault — not a single-repo `secret store`.
- Grant the minimum recipient set. Only `secret share` to the org CI key for
  the secrets CI actually needs; everything else stays encrypted to humans
  only.

## Related

- Concept: [Key Scope](/concepts/key-scope/) — repo-scoped vs org-wide.
- Example 03 (the repo-scoped counterpart):
  [../03-ci-cd-github-action/](../03-ci-cd-github-action/)
- Tutorial: <https://dotsecenv.com/tutorials/org-wide-keypair/>
