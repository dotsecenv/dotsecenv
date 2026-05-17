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

## Documentation hygiene

When writing or editing user-facing prose (READMEs, recipes, tutorials, runbooks, guides, concept pages, code comments, CLI help strings, error messages):

- Run the content through the `/humanizer` skill before committing. Scan for em-dash overuse, rule-of-three decoration, AI vocabulary (`delve`, `underscores`, `leverage`, `seamless`, `tapestry`, `robust`), copula avoidance, signposting ("Let me dive into…"), fragmented headers, and inline-header vertical lists (`**Bold:** restatement`).
- Keep the focus on the tool. Do not prescribe company policy, comms channels, escalation paths, or org-specific workflow (on-call channels, security logs, "loop in legal", HR procedures). Document what dotsecenv does and how to use it; leave the org-side wrapping to the reader.
- Match the terse, direct voice in `website/src/content/docs/tutorials/` and `website/src/content/docs/runbooks/`. The Tier-3 offboarding section in `skills/secrets/SKILL.md` is the compact-runbook reference: numbered steps, one-sentence explanations, single `<Aside>` for the append-only contract.
