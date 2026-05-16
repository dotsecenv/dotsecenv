# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

Security updates are provided for the latest minor version. We recommend always running the latest release.

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Use GitHub Security Advisories (preferred):**

1. Go to [Security Advisories](https://github.com/dotsecenv/dotsecenv/security/advisories/new)
2. Click "Report a vulnerability"
3. Fill in the details

This ensures your report is private and only visible to maintainers.

### What to Include

Please provide:

- A description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Any suggested fixes (optional)
- Your dotsecenv version (`dotsecenv version`)
- Your operating system and architecture
- Your GPG version (`gpg --version`)

### Response Timeline

| Stage               | Timeline     |
| ------------------- | ------------ |
| Acknowledgment      | 48 hours     |
| Initial assessment  | 7 days       |
| Fix (critical)      | 7 days       |
| Fix (high)          | 14 days      |
| Fix (medium/low)    | 30 days      |

We will keep you informed of our progress throughout the process.

## Security Update Policy

Security fixes are released as patch versions (e.g., 0.1.1 → 0.1.2) and announced via:

- [GitHub Releases](https://github.com/dotsecenv/dotsecenv/releases)
- [GitHub Security Advisories](https://github.com/dotsecenv/dotsecenv/security/advisories)

Subscribe to releases to receive notifications.

## Out of Scope

The following are not considered vulnerabilities:

- Attacks requiring physical access to the machine
- Attacks requiring root/administrator privileges
- Social engineering attacks
- Denial of service attacks
- Issues in dependencies (report to the upstream project)
- Theoretical attacks without proof of concept

## Security Features

dotsecenv implements several security measures:

- **RFC 9580 OpenPGP compliance** with mandatory AEAD encryption
- **AES-256-GCM symmetric encryption** (NIST SP 800-38D)
- **FIPS 186-5 digital signatures** for vault entry authenticity
- **FIPS 140-3 cryptographic module** in release binaries
- **SLSA Build Level 3** with verifiable provenance attestations
- **Hermetic E2E testing** with network isolation verification

For more details, see our [Security Model](https://dotsecenv.com/concepts/security-model/) documentation.

## Recovering from a compromised GPG key

If a private GPG key in your team's keyring is suspected or known
to be compromised, work through the runbook in
[`recipes/rotate-compromised-key.md`](recipes/rotate-compromised-key.md).
For the related but distinct case of removing a departing
teammate's key (planned exit, no compromise assumed), use
[`recipes/team-member-offboarding.md`](recipes/team-member-offboarding.md).

The short version:

1. Generate or import a replacement identity.
2. `dotsecenv secret revoke <NAME> <COMPROMISED_FP> --all` per
   affected secret.
3. `dotsecenv secret share <NAME> <NEW_FP> --all` to add the
   replacement.
4. **Rotate each affected secret at its source** (new DB password,
   new API key, …) and re-store with `dotsecenv secret store`.
5. Verify with `dotsecenv vault doctor` and `vault describe`.
6. Commit and push.

### Limitations of the append-only design in this scenario

dotsecenv vaults are append-only: past entries are not mutated by
revoke or share. Two consequences follow that you must plan for:

- The leaked private key can still decrypt every entry that was
  ever written before the rotation, both in the current vault file
  and in the repository's git history. Revocation prevents
  *future* writes from being readable, not past ones.
- Therefore, revocation alone is not a mitigation. To make a leaked
  value safe, the only durable answer is to invalidate the value
  upstream (rotate the database password, reissue the API key,
  invalidate the session) and store the new value.

This is a deliberate trade-off: append-only preserves a verifiable
audit trail at the cost of being unable to "unsay" past
ciphertext. If you need ciphertext to be unrecoverable from the
vault file itself, the only option is to rewrite git history (e.g.
`git filter-repo`) and force every consumer to re-clone. Even
then, anyone who already cloned the old history retains the old
encrypted entries.

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers in our release notes (unless you prefer to remain anonymous).
