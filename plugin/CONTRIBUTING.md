# Contributing to dotsecenv Shell Plugins

Thank you for your interest in contributing to the dotsecenv shell plugins! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## Ways to Contribute

- **Report bugs**: Open an issue using the bug report template
- **Suggest features**: Open an issue using the feature request template
- **Fix bugs**: Submit pull requests for open issues
- **Add shell support**: Help improve bash, zsh, or fish support

## Development Setup

### Prerequisites

- **bash** (4.0+ for associative arrays)
- **zsh** (5.0+)
- **fish** (3.0+, optional)
- **dotsecenv** CLI installed
- **Make** (for running tests)

### Clone and Test

```bash
# Clone the repository
git clone https://github.com/dotsecenv/plugin.git
cd plugin

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

## Pull Request Process

### Before Submitting

1. **Fork** the repository
2. **Create a branch** from `main`
3. **Make your changes**
4. **Run tests**: `make test`
5. **Test manually** in your shell
6. **Commit** with a descriptive message

### Submitting

1. Push your branch to your fork
2. Open a pull request against `main`
3. Fill in the PR template
4. Wait for review

### PR Requirements

- [ ] Tests pass (`make test`)
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

- Check existing [issues](https://github.com/dotsecenv/plugin/issues)
- Read the [main documentation](https://dotsecenv.com)
- Ask in issue comments

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
