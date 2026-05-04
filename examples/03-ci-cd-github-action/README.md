# Example 03 — CI/CD with the dotsecenv GitHub Action

A complete, production-shaped GitHub Actions workflow that installs
dotsecenv, imports a CI-only GPG key, decrypts secrets out of a checked-in
vault file, and hands them to a deploy step — all without storing plaintext
secrets in GitHub repository secrets.

## What this demonstrates

- Calling the `dotsecenv/dotsecenv@v0` composite action with provenance
  verification enabled (SHA-256 checksums, GPG signature on
  `checksums.txt`, and the Sigstore attestation on the archive).
- Importing a CI-only GPG private key from a sealed repo secret and using it
  as the dotsecenv identity for the job.
- Decrypting secrets out of a committed vault and exposing them as masked
  env vars to subsequent steps via `::add-mask::` and `$GITHUB_ENV`.

## Why a GPG key in a repo secret instead of just GitHub secrets?

Two reasons:

1. **One private key in GitHub, many secrets in your repo.** With dotsecenv,
   the private key is your CI identity; the actual secret values live in
   the encrypted vault file inside the repo. Adding a new secret is a
   developer-machine `secret store` + `secret share` + commit — no GitHub
   repo-secret edit needed. Rotation is a developer-machine `secret store`
   + commit. The list of secrets is visible to the team in the vault file.
2. **Provenance.** Vault writes are signed by the identity that produced
   them; you can audit who added or rotated each value.

If you need a single secret, use a GitHub repo secret directly. If you
already manage many secrets and want them version-controlled and
multi-recipient encrypted, dotsecenv is the right shape.

## Bootstrap procedure (do this once)

You need a CI identity, its private key as a repo secret, and the matching
public key on the vault's recipient list.

```bash
# 1. On a developer machine, generate a CI-only key (NO PASSPHRASE because
#    GitHub Actions cannot answer a pinentry prompt).
dotsecenv identity create \
  --algo RSA4096 \
  --name "CI ($GITHUB_REPOSITORY)" \
  --email "ci@your-org.example" \
  --no-passphrase

# 2. Capture the fingerprint and export the private key in ASCII-armored form.
FP=$(gpg --list-secret-keys --with-colons "ci@your-org.example" \
  | awk -F: '/^fpr:/ { print $10; exit }')
gpg --armor --export-secret-keys "$FP" > /tmp/dotsecenv-ci.asc

# 3. Add the contents of /tmp/dotsecenv-ci.asc as a GitHub repo secret named
#    DOTSECENV_GPG_PRIVATE_KEY. Two ways:
#       a. Settings -> Secrets and variables -> Actions -> New repository secret
#       b. gh CLI:  gh secret set DOTSECENV_GPG_PRIVATE_KEY < /tmp/dotsecenv-ci.asc

# 4. Wipe the file from disk.
shred -u /tmp/dotsecenv-ci.asc

# 5. Share each secret your CI needs with the CI fingerprint, from the
#    developer machine that already has the secret stored:
dotsecenv secret share DATABASE_URL "$FP"
dotsecenv secret share DEPLOY_TOKEN "$FP"

# 6. Commit the updated vault file (.dotsecenv/vault).
git add .dotsecenv/vault
git commit -m "ci: grant CI identity access to deploy secrets"
git push
```

The CI identity is now ready. Drop `workflow.yml` into your repo at
`.github/workflows/deploy.yml` and it will run on every push to `main`.

## Run it

This example is configuration, not a runnable script. To exercise the
workflow:

1. Copy `workflow.yml` to `.github/workflows/deploy.yml` in your application
   repo.
2. Make sure you have a vault at `.dotsecenv/vault` with `DATABASE_URL` and
   `DEPLOY_TOKEN` shared to your CI identity (see bootstrap above), or
   change the secret names in the workflow to whatever your project uses.
3. Push to `main` (or trigger via `workflow_dispatch`) and watch the run.

## Expected output

In the GitHub Actions log you should see:

```
Run dotsecenv/dotsecenv@v0
... Resolving latest released version ...
... Verifying GPG signature on checksums.txt ...
... Verifying SHA-256 checksum ...
... Verifying attestation ...
... dotsecenv version v0.X.Y installed at $RUNNER_TEMP/dotsecenv-bin/dotsecenv

Run dotsecenv init config -v .dotsecenv/vault
... Initialized config file ...
Run dotsecenv login <fingerprint>
... Login successful! ...

Run dotsecenv secret get DATABASE_URL
::add-mask::***
Run dotsecenv secret get DEPLOY_TOKEN
::add-mask::***

Run echo "DATABASE_URL is set: ${DATABASE_URL:+yes}"
DATABASE_URL is set: yes
DEPLOY_TOKEN is set: yes
```

Both env-var values appear as `***` in any subsequent log because they were
piped through `::add-mask::` before `$GITHUB_ENV`.

## Files

- `workflow.yml` — the complete workflow. Copy to
  `.github/workflows/deploy.yml` in your project.
- `README.md` — this file.

## Threat model notes

- **`--no-passphrase` keys are sensitive.** Anyone who can read the GitHub
  repo secret can decrypt every vault entry the key is a recipient of.
  Keep the secret tightly scoped (per repo, per environment), and rotate
  periodically.
- **Use environment-scoped secrets for production.** GitHub's "deployment
  environments" let you put `DOTSECENV_GPG_PRIVATE_KEY` behind a manual
  approval gate before it is exposed to the deploy job.
- **Grant minimum recipient set.** Only `secret share` to the CI key the
  secrets that CI actually needs. Everything else stays encrypted to humans
  only.
- **Verify provenance is on.** `verify-provenance: true` is the default and
  gates installation on a Sigstore attestation match. Don't turn it off.

## Related

- Action source and inputs reference: [`action.yml`](../../action.yml) at
  the repo root, plus
  <https://github.com/marketplace/actions/setup-dotsecenv>.
- CI/CD guide (full reference): <https://dotsecenv.com/guides/ci-cd/>
- Threat model: <https://dotsecenv.com/concepts/threat-model/>
- Example 02 (the `secret share` mechanics this relies on):
  [../02-team-share-revoke/](../02-team-share-revoke/)
