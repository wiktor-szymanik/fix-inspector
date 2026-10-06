# Contributing

Contributions to FIX Inspector are welcome.

## Development setup

Use the Windows setup, test, and build commands documented in [README.md](README.md).
`-Dev` installs test dependencies and `-Build` installs the packaging dependencies used by
the existing PyInstaller workflow. No production FIX service is required for the automated
test suite.

## Change scope

Keep changes focused and preserve FIX Inspector's protocol invariants:

- ordered fields,
- duplicate tags,
- DATA bytes,
- original/effective message bytes,
- queue ordering,
- session injection/recovery behavior,
- sensitive-data redaction.

FIX Inspector is a testing proxy, not a second general-purpose FIX session engine. Changes
to protocol behavior should include regression tests covering the affected invariants.
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for module boundaries and design rules.

## Tests

Before opening a pull request, run:

```powershell
.\scripts\setup-windows.ps1 -Dev
.\scripts\test-windows.ps1
```

Add focused tests for behavior changes and regressions. Do not replace synthetic fixtures
with real captured messages, production credentials, or customer data.

TLS tests generate disposable keys/certificates in temporary directories and do not modify
system trust.

## Versioning and release notes

The authoritative application version is defined in `src/fixinspector/__init__.py`.
Setuptools and release scripts derive their version information from that value.

Update [CHANGELOG.md](CHANGELOG.md) when preparing a release or when a change is significant
enough to document for users.

## Repository hygiene

Do not commit:

- generated build/release output,
- virtual environments,
- local application settings,
- captured FIX traffic,
- logs or diagnostics,
- credentials or private keys,
- customer/client data,
- developer-specific configuration.

The source packager (`scripts/package-source.py`) uses an explicit allowlist for public
source releases. New public non-Python assets should be added deliberately and reviewed for
provenance and sensitive content.

## License

By contributing to this repository, you agree that your contribution will be licensed under
the project's [Apache License 2.0](LICENSE).
