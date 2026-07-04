# Security Policy

## Reporting a vulnerability

If you discover a security issue in this project, please report it privately by
email so it can be addressed before public disclosure:

- **Email:** faizan@kolega.ai

Please include steps to reproduce and the affected version. We aim to acknowledge
reports promptly and will coordinate a fix and disclosure timeline with you.

## Scope

- **In scope:** the scanner package, CLI, schemas, and ground-truth
  tooling in this repository.
- **Out of scope:** the cloned target repositories under `repos/` (third-party,
  intentionally vulnerable) and imported ground-truth fixtures.

Secrets must never be committed; `gitleaks` runs as a pre-merge gate.
