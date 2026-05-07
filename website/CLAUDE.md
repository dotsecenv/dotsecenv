# Website Project Instructions

## Changelog Generation

When asked to update the changelog for a new release:

1. **Get version tags** from the dotsecenv repo:
   ```bash
   cd ../dotsecenv
   git fetch --tags
   LATEST=$(git describe --tags --abbrev=0)
   PREV=$(git tag -l "v*" --sort=-version:refname | sed -n '2p')
   ```

2. **Get commit logs** between tags from both repos:
   ```bash
   # dotsecenv commits
   cd ../dotsecenv
   git log $PREV..$LATEST --oneline

   # plugin commits (skip if tags don't exist in plugin for older releases)
   cd ../plugin
   git fetch --tags
   if git rev-parse "$PREV" >/dev/null 2>&1 && git rev-parse "$LATEST" >/dev/null 2>&1; then
     git log $PREV..$LATEST --oneline
   fi
   ```

3. **Get release date**:
   ```bash
   cd ../dotsecenv
   git log -1 --format='%B %d, %Y' $LATEST
   ```

4. **Group commits** by type:
   - `feat:` → **Features**
   - `fix:` → **Bug Fixes**
   - Everything else → **Other**
   - Commits from **dotsecenv** use `#N` for issue/PR references
   - Commits from **plugin** use `plugin#N` for issue/PR references

5. **Update changelog**: Add new version section at the top of `src/content/docs/changelog.mdx` (after the intro paragraph, before the first version entry)

### Changelog Entry Format

```mdx
---

## vX.Y.Z
*Month Day, Year*

### Features
- Feature description here

### Bug Fixes
- Fix description here

### Other
- Other changes here
```

### Commit Message Convention

Use Conventional Commits for changelog-friendly messages:

| Type | Category | Example |
|------|----------|---------|
| `feat:` | Features | `feat: add list mode to secret get` |
| `fix:` | Bug Fixes | `fix: remove extra newline from output` |
| `refactor:` | Other | `refactor: simplify error handling` |
| `chore:` | Other | `chore: update dependencies` |
| `docs:` | Other | `docs: update README` |
| `test:` | Other | `test: add e2e tests` |
| `ci:` | Other | `ci: add security review workflow` |

Use `feat!:` or `fix!:` suffix for breaking changes.

### Twitter/X Announcement Posts

After generating the changelog entry, output 1–3 Twitter/X announcement posts in the terminal. Do **not** commit these anywhere — they are for copy-pasting to X/Twitter only.

Guidelines:
- Keep each post under 280 characters
- Lead with the version number and the most notable change
- Use a direct, informative tone (no hype or excessive emojis)
- If the release has multiple highlights, use separate posts for each
- Format each post as a fenced code block for easy copy-paste

Example output:

```
dotsecenv v0.5.0 is out! New `dse up` command loads ancestor .secenv files when jumping into subdirectories. Plus fixes for zsh secret leaks and unnecessary vault calls.

https://dotsecenv.sh/changelog
```

```
dotsecenv v0.5.0 fixes a zsh bug where `local` declarations could leak secret values on directory re-entry. Upgrade recommended.
```
