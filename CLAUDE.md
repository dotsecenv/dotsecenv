# Follow these rules

## Release new version

- When asked to release, use `rt git::release --major --sign --push vX.Y.Z` where X.Y.Z is the version to release
- Then push the tag to the origin

## Policy directory conventions

- Policy fragments live at `/etc/dotsecenv/policy.d/*.yaml`, owned `root:root`, mode `0644` or stricter
- Filename ordering matches Unix `*.d` convention (sudoers.d, systemd, nginx): files load lexically; for scalar policy fields in future phases, lexically-later fragments override earlier ones
- Naming convention: `00-base, 50-team, 99-overrides`
- For allow-list fields (Phase 1: `approved_algorithms`), filename order is irrelevant — fragments union
- `policy.DefaultDir` in `pkg/dotsecenv/policy/policy.go` is exposed as a `var` (not `const`) so tests can override; **production code MUST NOT reassign it**
- `policy validate` is meant to run in CI for ops repos shipping policy; exit codes are distinct per error category
