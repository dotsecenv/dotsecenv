# Security Policy

## Reporting a Vulnerability

If you discover a security issue in the dotsecenv shell plugins, please report it responsibly.

### How to Report

**Use GitHub Security Advisories (preferred):**

1. Go to [Security Advisories](https://github.com/dotsecenv/plugin/security/advisories/new)
2. Click "Report a vulnerability"
3. Fill in the details

This ensures your report is private and only visible to maintainers.

### What to Include

Please provide:

- A description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Any suggested fixes (optional)
- Your shell and version (bash/zsh/fish)
- Your operating system

### Response Timeline

| Stage               | Timeline     |
| ------------------- | ------------ |
| Acknowledgment      | 48 hours     |
| Initial assessment  | 7 days       |
| Fix                 | 14 days      |

## Security Features

The shell plugins include several security measures:

- **File ownership checks**: Refuses to load files not owned by you
- **Permission checks**: Refuses to load world-writable files
- **Trust system**: Prompts before loading `.secenv` files from untrusted directories
- **No eval of untrusted content**: Values are not executed as shell commands

## Out of Scope

The following are not considered vulnerabilities:

- Issues in the main dotsecenv CLI (report to [dotsecenv/dotsecenv](https://github.com/dotsecenv/dotsecenv/security/advisories/new))
- Attacks requiring physical access to the machine
- Social engineering attacks

## Main Project Security

For security issues in the main dotsecenv CLI tool, please report to the [dotsecenv repository](https://github.com/dotsecenv/dotsecenv/security/advisories/new).
