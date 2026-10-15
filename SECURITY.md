# Security Policy

## Important Notice

This project is a **cybersecurity research and simulation framework**.
It is NOT intended for deployment on real vehicle systems.

## Reporting Vulnerabilities

If you discover a security vulnerability in this research framework,
please report it responsibly:

1. Do NOT create a public GitHub issue for security vulnerabilities.
2. Email the maintainers with a detailed description.
3. Include steps to reproduce.
4. Allow reasonable time for a fix before public disclosure.

## Security Design Principles

- All cryptographic operations use the `cryptography` library — no custom primitives.
- Cryptographic keys are NEVER hardcoded in source code.
- All MAC comparisons use constant-time algorithms.
- Secrets are never logged.
- Attack simulation is restricted to controlled/simulation environments.
- No real vehicle systems should be connected to the attack simulator.

## Scope

This security policy applies to the research framework itself.
It does NOT make claims about automotive production security.
