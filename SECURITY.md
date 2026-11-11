# Security Policy

BlackBoxus is a password manager, so security reports are our highest priority.

## Project status

BlackBoxus is in early development and has **not** been independently audited. Until it has, it should not be used to store real credentials.

## Reporting a vulnerability

**Please do not report security issues in public GitHub issues, discussions or pull requests.**

Report them privately through GitHub:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the issue, the affected component and version or commit, and steps to reproduce.

You will receive an acknowledgement within 7 days. We will keep you informed while we work on a fix and will credit you in the advisory unless you prefer to remain anonymous.

## Scope

In scope:

- Cryptographic design and implementation (`vault-core`, protocol specification)
- Any way a compromised or malicious server could read, modify, roll back or delete vault data without detection
- Authentication, session handling and key management
- Server, desktop app, browser extension and mobile apps
- Build, release and supply-chain integrity

Out of scope:

- Attacks that require full control of an unlocked device
- Denial of service through excessive traffic
- Findings from automated scanners without a demonstrated impact

## Disclosure

We follow coordinated disclosure. We ask that you give us up to 90 days to release a fix before publishing details.
