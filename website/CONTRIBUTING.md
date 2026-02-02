# Contributing to dotsecenv Website

Thank you for your interest in contributing to the dotsecenv documentation website! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## Ways to Contribute

- **Report bugs**: Open an issue using the bug report template
- **Suggest improvements**: Open an issue using the feature request template
- **Improve documentation**: Fix typos, clarify explanations, add examples
- **Add guides**: Write tutorials or how-to guides

## Development Setup

### Prerequisites

- **Node.js 25+** (check with `node --version`)
- **pnpm** (check with `pnpm --version`)
- **Make** (check with `make --version`)

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/dotsecenv/website.git
cd website

# Install dependencies
pnpm install

# Start development server
pnpm dev

# Build for production
pnpm build
```

### Linting

```bash
# Run all linting
pnpm lint

# Lint markdown only
pnpm lint:md

# Lint TypeScript/ESLint only
pnpm lint:eslint
```

## Content Guidelines

### Documentation Structure

- **Tutorials**: Step-by-step learning guides in `src/content/docs/tutorials/`
- **How-To Guides**: Task-oriented recipes in `src/content/docs/how-to/`
- **Concepts**: Explanatory content in `src/content/docs/concepts/`
- **Reference**: Technical specifications in `src/content/docs/reference/`

### Writing Style

- Use clear, concise language
- Write in second person ("you" not "we")
- Include code examples where helpful
- Test all commands before documenting

### Markdown/MDX

- Use MDX for interactive components
- Follow markdownlint rules
- Use Starlight components (`Tabs`, `Steps`, `Aside`, etc.)

## Commit Messages

Use conventional commit format:

```text
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**

- `feat`: New content or feature
- `fix`: Fix errors or typos
- `docs`: Documentation structure changes
- `style`: Formatting, no content change
- `refactor`: Restructuring without content change
- `chore`: Maintenance tasks

**Examples:**

```text
docs(guides): add GitHub Action tutorial
fix(concepts): correct GPG configuration example
feat(tutorials): add multi-user vault guide
```

## Pull Request Process

### Before Submitting

1. **Fork** the repository
2. **Create a branch** from `main`
3. **Make your changes**
4. **Run linting**: `pnpm lint`
5. **Build locally**: `pnpm build`
6. **Commit** with a descriptive message

### Submitting

1. Push your branch to your fork
2. Open a pull request against `main`
3. Fill in the PR template
4. Wait for review

### PR Requirements

- [ ] Linting passes (`pnpm lint`)
- [ ] Build succeeds (`pnpm build`)
- [ ] Content is accurate and tested
- [ ] Commit messages follow conventions

## Getting Help

- Check existing [issues](https://github.com/dotsecenv/website/issues)
- Read the [main documentation](https://dotsecenv.com)
- Ask in issue comments

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
