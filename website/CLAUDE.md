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

2. **Get commit log** between tags:
   ```bash
   git log $PREV..$LATEST --oneline
   ```

3. **Get release date**:
   ```bash
   git log -1 --format='%B %d, %Y' $LATEST
   ```

4. **Group commits** by type:
   - `feat:` → **Features**
   - `fix:` → **Bug Fixes**
   - Everything else → **Other**

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
