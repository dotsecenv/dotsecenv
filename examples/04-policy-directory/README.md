# Example 04 — System policy fragments

System administrators can constrain every dotsecenv user on a machine by
dropping YAML fragments into `/etc/dotsecenv/policy.d/`. This example ships
a two-file baseline showing the conventions: a `00-corp-baseline.yaml` with
org-wide constraints and a `99-team-overrides.yaml` showing how to override
scalar fields without touching the baseline.

## What this demonstrates

- Fragment-based policy composition (lexical-order load, with allow-lists
  merged by **union** and scalars merged by **last-fragment-wins**).
- All four supported policy fields:
  `approved_algorithms`, `approved_vault_paths`, `behavior.*`, `gpg.program`.
- The naming convention used by `sudoers.d`, `nginx conf.d`, etc. (`00-` for
  baselines, `99-` for overrides) and how it interacts with merge rules.
- The fail-closed posture: any error loading policy aborts startup. There is
  no "ignore broken fragment and continue".

## When to use the policy directory

Reach for `/etc/dotsecenv/policy.d/` when:

- You are a fleet admin (Mac DEP, MDM, configuration management) and want to
  enforce minimum crypto across every employee laptop.
- You need to constrain where vaults can live (`approved_vault_paths`) so
  developers cannot accidentally store a vault in a backed-up location.
- You want to pin `gpg.program` to a specific binary across the org (e.g. a
  patched build of GnuPG, or one specific install root on shared machines).

If you are a single-user developer the policy directory is unnecessary —
your user config already gives you full control. The policy directory exists
so admins can constrain users without rewriting the user config.

## Install the fragments

The directory and its files must be **owned by root** with permissions that
disallow non-root writes. dotsecenv enforces this at load time.

```bash
# Create the directory once.
sudo mkdir -p /etc/dotsecenv/policy.d
sudo chown root:root /etc/dotsecenv/policy.d
sudo chmod 0755 /etc/dotsecenv/policy.d

# Drop the baseline.
sudo install -m 0644 -o root -g root \
  00-corp-baseline.yaml /etc/dotsecenv/policy.d/00-corp-baseline.yaml

# Drop the team overrides.
sudo install -m 0644 -o root -g root \
  99-team-overrides.yaml /etc/dotsecenv/policy.d/99-team-overrides.yaml
```

Then verify both fragments parse and the merge result is what you expect:

```bash
dotsecenv policy validate
dotsecenv policy list
```

## Expected output

`dotsecenv policy validate` on a valid two-fragment install:

```
policy valid (2 fragment(s) in /etc/dotsecenv/policy.d)
```

`dotsecenv policy list` shows the merged effective policy with per-field
origin attribution (which fragment contributed each field):

```
Policy directory: /etc/dotsecenv/policy.d (2 fragment(s))
  approved_algorithms:
    - algo: ECC, curves: [P-384, P-521], min_bits: 384  [00-corp-baseline.yaml]
    - algo: EdDSA, curves: [Ed25519, Ed448], min_bits: 255  [00-corp-baseline.yaml]
    - algo: RSA, min_bits: 3072  [00-corp-baseline.yaml]
  approved_vault_paths:
    - ~/.local/share/dotsecenv/vault  [00-corp-baseline.yaml]
    - ~/work/*/.dotsecenv/vault  [00-corp-baseline.yaml]
    - ~/personal/dotsecenv/vault  [99-team-overrides.yaml]
  behavior:
    require_explicit_vault_upgrade: true  [00-corp-baseline.yaml]
    restrict_to_configured_vaults: true  [00-corp-baseline.yaml]
  gpg.program: /usr/bin/gpg  [99-team-overrides.yaml]
```

Notice:
- `approved_vault_paths` is a deduped union of both fragments.
- `gpg.program` came from `99-team-overrides.yaml` (last-set-wins for scalars).
- `behavior.*` came from `00-corp-baseline.yaml` because no later fragment
  set those sub-fields.

`dotsecenv policy list --json` returns the same data as a structured object
suitable for compliance tooling. The `--json` form is also available on
`policy validate`.

## Merge rules cheat sheet

| Field                   | Cross-fragment merge | User vs policy                     |
| ----------------------- | -------------------- | ---------------------------------- |
| `approved_algorithms`   | Union (per-algo collapse: curves union, min_bits min) | Intersection (user narrowed by policy) |
| `approved_vault_paths`  | Deduped union of patterns | Filter (user vault entries that match a pattern) |
| `behavior.*`            | Per-sub-field last-set-wins (lex order) | Policy overrides user; warning printed |
| `gpg.program`           | Last-set-wins (lex order) | Policy overrides user; warning printed |

Forbidden top-level keys (rejected at load time): `login:`, `vault:`. A
fragment that contains either fails the load with `forbidden policy key`.
`login` is per-user (cryptographically bound to the user's private key);
`vault` would erase user vaults wholesale, so admins use
`approved_vault_paths` instead.

## Files

- `00-corp-baseline.yaml` — org-wide baseline. Sets approved algorithms,
  approved vault paths, and two strict behavior flags.
- `99-team-overrides.yaml` — late-loading override. Pins `gpg.program` and
  appends one extra `approved_vault_paths` pattern.
- `README.md` — this file.

## Recovering from a broken policy

If you install a malformed fragment, `dotsecenv` will refuse to start with a
clear error message identifying the offending file. To recover:

```bash
# See exactly what is wrong:
sudo dotsecenv policy validate

# Remove or fix the offending fragment:
sudo rm /etc/dotsecenv/policy.d/<broken>.yaml

# Confirm the policy is healthy again:
sudo dotsecenv policy validate
```

Until policy parses cleanly, `dotsecenv` (including normal `secret get`
calls by every user on the machine) refuses to run. This is intentional:
a partially-readable policy directory is indistinguishable from tampering,
so the only safe behaviour is to fail closed.

## Related

- Concepts: <https://dotsecenv.com/concepts/policy-directory/>
- FIPS / compliance: <https://dotsecenv.com/concepts/compliance/>
- README "Policy Directory" section in this repo (the canonical reference).
