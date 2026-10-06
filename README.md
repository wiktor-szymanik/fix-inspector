# FIX Inspector

[![Version](https://img.shields.io/badge/version-1.0.6-2563eb)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-Apache%202.0-4c1)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11--3.14-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D4?logo=windows&logoColor=white)](#platform-support)
[![Security](https://img.shields.io/badge/security-policy-2563eb)](SECURITY.md)

**FIX Inspector** is a desktop security testing and traffic inspection toolkit for the
Financial Information eXchange (FIX) protocol. It sits between an existing FIX client
and FIX endpoint, allowing an authorized tester to inspect, intercept, modify, replay,
compose, fuzz, and decode FIX traffic without replacing the application's FIX session
engine.

```text
FIX Client <-> FIX Inspector <-> FIX Endpoint
```

FIX Inspector is designed around FIX-specific behavior such as ordered fields,
duplicate tags, session state, raw framing, dictionaries, and message correlation.
Runtime use does not require Internet access.

## Features

- Plain TCP listener with Plain TCP or verified TLS upstream transport.
- Ordered interception with held/queued message handling.
- Searchable message History with filters, bookmarks, notes, and correlation.
- Lossless handling of ordered and duplicate FIX fields.
- Parsed, raw, diff, validation, and repeating-group inspection.
- **Sender** for controlled modification and retransmission of captured messages.
- Dictionary-driven **Composer** for building application messages.
- Finite, low-rate **Fuzzer** with explicit session-destructive mutation support.
- Offline **Decoder** for standalone FIX message analysis.
- Configurable proxy rules for controlled delay, drop, duplication, pause, and disconnect behavior.
- Optional transport/session and application FIX dictionaries.
- Session/admin visibility, sequence tracking, and active-session injection support.
- Local SQLite projects, redacted exports, presentation settings, and global sensitive-field masking.

## Main workspaces

| Workspace | Purpose |
| --- | --- |
| **Proxy** | Configure transport, intercept traffic, review History, and apply proxy rules. |
| **Sender** | Modify and resend captured FIX messages through the active session or supported isolated flow. |
| **Composer** | Build dictionary-backed application messages from structured fields. |
| **Fuzzer** | Run finite mutation campaigns against authorized FIX test targets. |
| **Decoder** | Decode and inspect FIX messages without an active connection. |
| **Dictionaries** | Load and inspect user-provided FIX transport/application dictionaries. |

## Platform support

| Platform | Run from source | Packaged build | Status |
| --- | --- | --- | --- |
| **Windows x64** | Supported | PyInstaller build workflow included | Source workflow tested; standalone binary should be validated before distribution |
| **Linux** | Not currently supported/tested | Not supported | Planned |
| **macOS** | Not currently supported/tested | Not supported | Planned |

The Python/Qt stack is cross-platform, but FIX Inspector currently documents and tests
Windows as the supported platform.

## Requirements

- Windows x64.
- PowerShell 5.1 or newer.
- 64-bit CPython 3.11-3.14 (`>=3.11,<3.15`).
- Initial setup access to a Python package index, or a prepared wheel directory.

Runtime dependencies are pinned in `requirements.txt`. Development and build dependencies
are kept separately in `requirements-dev.txt` and `requirements-build.txt`.

## Quick start - Windows

Clone or extract the repository, open PowerShell in the repository root, then run:

```powershell
.\scripts\setup-windows.ps1
.\scripts\run-windows.ps1
```

The setup script creates a local `.venv` and installs the required dependencies.
The run script uses that environment without reinstalling packages.

If Python is not available on `PATH`, pass the interpreter explicitly to setup using
the script's `-Python` option.

The equivalent source entry point after setup is:

```powershell
.\.venv\Scripts\python.exe -m fixinspector
```

## Basic usage

1. Open **Proxy -> Settings**.
2. Configure the local listener address and port.
3. Configure the upstream FIX endpoint and select **Plain TCP** or **TLS**.
4. Start the proxy.
5. Point the existing FIX client at the FIX Inspector listener.
6. Review traffic in **Proxy -> History** or enable **Intercept** for manual control.
7. Use **Open in Sender**, **Composer**, **Fuzzer**, or **Decoder** as needed for the authorized test.

FIX Inspector is a testing proxy, not a replacement FIX engine. Session-aware features
work with the observed/active FIX session rather than attempting to become a second
independent production session engine.

## TLS

The local listener is plaintext. The upstream connection can use Plain TCP or TLS.
For TLS, FIX Inspector supports certificate verification, SNI/hostname configuration,
and an optional custom CA file.

Transport selection does not change FIX payload semantics.

## FIX dictionaries

FIX dictionaries are optional for transparent proxying. Loading transport/session and
application XML dictionaries improves:

- field and message names,
- enum interpretation,
- repeating-group inspection,
- validation,
- Composer assistance,
- Fuzzer assistance.

FIX Inspector does not bundle official or vendor FIX dictionaries. Users should load
appropriately licensed dictionaries they are authorized to use. Files under
`tests/fixtures` are deliberately small synthetic parser inputs, not production dictionaries.

## Sensitive data handling

**Settings -> Privacy** controls global display masking. Sensitive FIX field values are
masked by default, with tag `553` always included in the sensitive set and additional
numeric tags configurable by the user.

Display masking does not modify the underlying FIX message bytes. Persistence, logging,
exports, and diagnostics apply their own redaction behavior. Projects, screenshots,
clipboard contents, and deliberately unmasked views can still contain sensitive business
data, so review them before sharing.

## Development and tests

Install development dependencies and run the test suite with:

```powershell
.\scripts\setup-windows.ps1 -Dev
.\scripts\test-windows.ps1
```

The test suite covers parsing, serialization, DATA fields, ordered queues, injection and
recovery, masking/redaction, persistence, mutation logic, UI behavior, and localhost
TCP/TLS integration. No production FIX service is required for the automated suite.

## Building on Windows

Install build dependencies and run the existing PyInstaller workflow:

```powershell
.\scripts\setup-windows.ps1 -Build
.\scripts\build-windows.ps1
```

The build script runs the repository's validation steps and produces a portable Windows
package under `release/`. Generated build output is intentionally excluded from source
control and from the GitHub source package.

Before publishing a standalone binary, perform an interactive Windows smoke test for the
window/taskbar icon, startup, proxy configuration, and normal desktop DPI behavior.

For offline dependency setup, use the setup script's `-Wheelhouse` option with a directory
containing compatible wheels for the selected Python/Windows architecture.

## Source package

A clean GitHub source archive can be produced from an initialized development environment:

```powershell
.\.venv\Scripts\python.exe scripts\package-source.py
```

The packager uses an explicit public-file allowlist and rejects common private/local
artifacts such as build output, virtual environments, logs, captures, private keys,
private infrastructure addresses, and previous release archives.

## Documentation

- [User guide](docs/USER_GUIDE.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Architecture and development boundaries](docs/ARCHITECTURE.md)
- [Display and presentation](docs/DISPLAY_PRESENTATION.md)
- [Contributing](CONTRIBUTING.md)

## Security

FIX Inspector is intended for authorized security testing, research, and development.

Security vulnerabilities in FIX Inspector itself should be reported privately to
**security@lionsec.pl**. See [SECURITY.md](SECURITY.md) for the reporting policy.

Security findings discovered in external FIX systems should be reported to the owner of
the affected system through its authorized disclosure process.

## License

FIX Inspector is licensed under the [Apache License 2.0](LICENSE).

Commercial use, modification, and redistribution are permitted subject to the license.
The Apache License does not grant permission to use the FIX Inspector name or logo as
branding for derivative products except as required for reasonable attribution.

Third-party dependencies remain subject to their respective licenses.
