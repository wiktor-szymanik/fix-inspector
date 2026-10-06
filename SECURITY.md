# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in FIX Inspector, please report it privately to:

**security@lionsec.pl**

Please include enough information to reproduce and assess the issue, including the affected
version, relevant configuration, expected behavior, observed behavior, and reproduction
steps where possible.

Do not disclose a vulnerability publicly before it has been reviewed and addressed.
Do not include credentials, private keys, customer data, or other sensitive material unless
it is strictly necessary to reproduce the issue.

## Scope

This policy applies to security vulnerabilities in FIX Inspector itself.

Security issues discovered in external FIX systems while using FIX Inspector are not
FIX Inspector vulnerabilities. Report those findings to the owner of the affected system
through its authorized security or disclosure process.

## Public issues

Do not attach real FIX captures, credentials, API keys, private certificates, customer data,
or unreviewed diagnostic archives to public GitHub issues.

For non-sensitive bugs and feature requests, use the repository's normal public issue
workflow.

## Authorized use

FIX Inspector is intended for authorized security testing, research, and development.
Some features can intentionally modify, delay, drop, replay, or fuzz FIX traffic and may
disrupt a target session. Use them only where you have permission to test.
