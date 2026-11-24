# Security Policy

## Reporting a Vulnerability

Please report security issues responsibly via GitHub Security Advisories on this repository. Do not open public issues with exploit payloads against production systems.

## Design Properties

- Pure Python standard library only; no network calls, no subprocess shell execution, and no `eval`/`exec`.
- Deterministic verification outputs suitable for CI/CD gates and offline audit trails.
