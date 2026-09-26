# Security Policy

## Supported Versions

pqc-inventory is under active development. Security fixes are applied to the latest
release only.

| Version | Supported |
| ------- | --------- |
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

Report them privately through GitHub's vulnerability reporting:
https://github.com/Edward3113/pqc-inventory/security/advisories/new

Include as much of the following as you can:

- A description of the issue and its potential impact
- Steps to reproduce, or a proof of concept
- The affected version and your environment (OS, Python version)

## What to Expect

- Acknowledgment within 5 business days
- An initial assessment within 10 business days
- Credit in the release notes once a fix ships, unless you prefer to remain anonymous

## Scope

In scope: vulnerabilities in pqc-inventory itself, such as a malicious server response
that crashes the scanner, causes code execution, or produces falsified results, and
vulnerable dependencies that affect the tool.

Out of scope: cryptographic weaknesses the tool reports on third-party servers (those
are findings, not vulnerabilities in this project) and use of the tool against systems
without authorization.
