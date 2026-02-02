# Contributing to dotsecenv

Thank you for your interest in contributing to dotsecenv! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## Ways to Contribute

- **Report bugs**: Open an issue using the bug report template
- **Suggest features**: Open an issue using the feature request template
- **Improve documentation**: Fix typos, clarify explanations, add examples
- **Submit code**: Fix bugs, implement features, improve tests

## Development Setup

### Prerequisites

- **Go 1.25+** (check with `go version`)
- **GPG** (check with `gpg --version`)
- **Make** (check with `make --version`)
- **mise** (optional, for tool management)

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/dotsecenv/dotsecenv.git
cd dotsecenv

# Install development tools
make install-tools

# Build the binary
make build

# Binary is at bin/dotsecenv
```

### Running Tests

```bash
# Run all tests
make test

# Run end-to-end tests
make build e2e
```

### Linting

```bash
# Run linting
make lint
```

## Code Style

### Go Formatting

- Use `gofmt` for formatting (enforced by CI)
- Follow [Effective Go](https://go.dev/doc/effective_go) guidelines
- Run `make lint` before committing

### Commit Messages

Use conventional commit format:

```
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

```
feat(vault): add secret rotation command
fix(gpg): handle missing pinentry gracefully
docs(readme): clarify installation steps
```

### Branch Naming

Use descriptive branch names:

```
feat/secret-rotation
fix/gpg-pinentry-error
docs/installation-guide
```

## Pull Request Process

### Before Submitting

1. **Fork** the repository
2. **Create a branch** from `main`
3. **Make your changes**
4. **Run tests**: `make test`
5. **Run linting**: `make lint`
6. **Commit** with a descriptive message

### Submitting

1. Push your branch to your fork
2. Open a pull request against `main`
3. Fill in the PR template
4. Wait for review

### PR Requirements

- [ ] Tests pass (`make test`)
- [ ] Linting passes (`make lint`)
- [ ] Documentation updated (if applicable)
- [ ] Commit messages follow conventions
- [ ] No secrets or credentials in code

### Review Process

- A maintainer will review your PR
- Address any requested changes
- Once approved, a maintainer will merge

## Issue Guidelines

### Bug Reports

A good bug report includes:

- Clear, descriptive title
- Steps to reproduce
- Expected vs actual behavior
- dotsecenv version (`dotsecenv version`)
- OS and architecture
- GPG version
- Relevant logs or error messages

### Feature Requests

A good feature request includes:

- Problem you're trying to solve
- Proposed solution
- Alternatives you've considered
- Additional context

## Testing Requirements

### For Bug Fixes

- Add a test that fails without your fix
- Ensure the test passes with your fix

### For New Features

- Add unit tests for new functions
- Add integration tests for new commands
- Update existing tests if behavior changes

### Test Coverage

We aim for meaningful test coverage. Focus on:

- Edge cases
- Error handling
- Security-sensitive code paths

## Signing Commits (Optional)

For a security-focused project, signed commits are appreciated:

```bash
# Configure GPG signing
git config --global commit.gpgsign true
git config --global user.signingkey YOUR_GPG_KEY_ID
```

## Getting Help

- Check existing [issues](https://github.com/dotsecenv/dotsecenv/issues)
- Read the [documentation](https://dotsecenv.com)
- Ask in issue comments

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
