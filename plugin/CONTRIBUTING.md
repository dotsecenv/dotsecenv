# Contributing to dotsecenv Shell Plugins

> **⚠️ Source has moved.** This repository is now an **artifact-only publish target**. The shell plugin source of truth lives in [`dotsecenv/dotsecenv`](https://github.com/dotsecenv/dotsecenv) at [`plugin/`](https://github.com/dotsecenv/dotsecenv/tree/main/plugin). **All issues and pull requests must be filed against `dotsecenv/dotsecenv`** — contributions opened here cannot be accepted.

Thank you for your interest in contributing to the dotsecenv shell plugins! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## Where to Contribute

All contribution happens on [`dotsecenv/dotsecenv`](https://github.com/dotsecenv/dotsecenv). This repository receives the published plugin source on each release and is not edited directly.

- **Report a bug** → [open an issue on `dotsecenv/dotsecenv`](https://github.com/dotsecenv/dotsecenv/issues/new/choose). CLI and plugin issues are tracked together.
- **Request a feature** → same — [`dotsecenv/dotsecenv` issues](https://github.com/dotsecenv/dotsecenv/issues/new/choose).
- **Fix a bug or add shell support** → open a pull request against [`dotsecenv/dotsecenv`](https://github.com/dotsecenv/dotsecenv) touching the [`plugin/`](https://github.com/dotsecenv/dotsecenv/tree/main/plugin) subdirectory.
- **Report a security vulnerability** → privately via [`dotsecenv/dotsecenv` security advisories](https://github.com/dotsecenv/dotsecenv/security/advisories/new).

## Development Setup

These instructions still apply when you've checked out [`dotsecenv/dotsecenv`](https://github.com/dotsecenv/dotsecenv) and want to iterate on plugin source under `plugin/`.

### Prerequisites

- **bash** (4.0+ for associative arrays)
- **zsh** (5.0+)
- **fish** (3.0+, optional)
- **dotsecenv** CLI installed
- **Make** (for running tests)

### Clone and Test

```bash
# Clone the monorepo (source of truth)
git clone https://github.com/dotsecenv/dotsecenv.git
cd dotsecenv/plugin

# Run tests
make test

# Run tests for a specific shell
make test-bash
make test-zsh
make test-fish
```

### Project Structure

```text
plugin/
├── _dotsecenv_core.sh      # Shared core functionality
├── dotsecenv.plugin.bash   # Bash plugin
├── dotsecenv.plugin.zsh    # Zsh plugin
├── conf.d/
│   └── dotsecenv.fish      # Fish plugin
├── install.sh              # Universal installer
└── tests/                  # Test suite
```

## Code Style

### Shell Scripts

- Use POSIX-compatible syntax where possible
- Quote all variables: `"$var"` not `$var`
- Use `[[ ]]` for tests in bash/zsh
- Add comments for non-obvious logic
- Follow existing code patterns

### Commit Messages

Use conventional commit format:

```text
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting, no code change
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**

```text
feat(zsh): add completion for secret names
fix(bash): handle spaces in directory names
docs(readme): clarify fish installation
```

## Submitting Changes

Pull requests against **this repository (`dotsecenv/plugin`) are not accepted** — it is an artifact-only publish target. Each release replays the latest `plugin/` source from [`dotsecenv/dotsecenv`](https://github.com/dotsecenv/dotsecenv), so any commits made here would be overwritten.

### Where to send your PR

1. **Fork** [`dotsecenv/dotsecenv`](https://github.com/dotsecenv/dotsecenv).
2. **Create a branch** from `main`.
3. **Make your changes** under [`plugin/`](https://github.com/dotsecenv/dotsecenv/tree/main/plugin).
4. **Run tests**: `cd plugin && make test`.
5. **Test manually** in your shell.
6. **Commit** with a [conventional message](#commit-messages).
7. **Open a pull request** against `dotsecenv/dotsecenv:main`.

### PR Requirements

- [ ] Tests pass (`cd plugin && make test`)
- [ ] Changes work in all supported shells (bash, zsh, fish)
- [ ] Commit messages follow conventions
- [ ] No security regressions

## Testing

### Running Tests

```bash
# All tests
make test

# Specific shell
make test-bash
make test-zsh
make test-fish
```

### Writing Tests

- Add tests in the `tests/` directory
- Test both success and failure cases
- Test edge cases (spaces in paths, special characters)

## Getting Help

- Check existing [issues on `dotsecenv/dotsecenv`](https://github.com/dotsecenv/dotsecenv/issues)
- Read the [main documentation](https://dotsecenv.com)
- Ask in issue comments on `dotsecenv/dotsecenv`

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
