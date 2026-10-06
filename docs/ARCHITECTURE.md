# Architecture

FIX Inspector is a Python/PySide6 desktop application. `run.py`, the installed
`fix-inspector` command and `python -m fixinspector` call `fixinspector.app.main`.
`packaging/entrypoint.py` is the existing PyInstaller launcher with explicit
frozen-process shutdown. The official `resources/app.ico` is the single icon asset;
no FIX XML is required. `app_resources.py` resolves it from the source root or
PyInstaller's resource directory and sets the Qt application-wide icon. The same
ICO is embedded in the Windows executable by the existing PyInstaller spec.

## Boundaries

- `transport`: plaintext listener, TCP/TLS upstream creation and connection lifecycle.
  Both upstream modes converge into the same FIX processing pipeline.
- `fix`: byte framing, ordered fields, parsing, serialization, dictionaries,
  validation and non-destructive repeating-group projections.
- `session`: observed state, ordered outbound queue, injection and substitution
  journal/recovery. The external FIX client still owns ordinary session lifecycle.
- `intercept`: hold/forward decisions and explicit proxy behaviour/fault rules.
- `repeater`, `composer`, `fuzzer`: tool models/controllers using shared injection.
  Sender's isolated Logon connection is not a second complete session engine.
  Internal `RepeaterController`/`RepeaterPanel` names, `repeater` project keys and
  `REPEATER` source IDs remain for compatibility; the UI displays Sender/SENDER.
- `history`, `correlation`, `records`: traffic metadata, retention and related messages.
- `project`: local SQLite history/state, exports and redaction.
- `gui`: Qt workspace, panels and shared widgets. Network processing is off the UI thread.
- `_legacy_v03`: **active compatibility UI shell and imported support code**, not an
  unused backup. `gui/main_window.py` subclasses it and binds modern backend classes.
  It must remain in the source package until a separately tested migration removes it.

## Invariants

Messages are ordered field sequences, never normalized into tag dictionaries.
Keep duplicates, unknown fields and length-delimited DATA intact. Managed edits
repair framing; explicit manual replay may deliberately retain malformed bytes.

Holding outbound sequence N queues subsequent traffic. Safe injection waits for
a replaceable plain outbound Heartbeat, never replaces genuine business traffic,
and journals original/effective bytes. Recovery consults this journal. Correlation
does not promise one synchronous response per request.

## Local state and privacy

Projects are user-selected `.fixproj` SQLite files (including WAL/SHM while open).
GUI settings use QSettings INI in Qt's writable application configuration location;
legacy settings can be migrated. Logs rotate under the user's local application
data directory. These files are runtime data, never distribution assets.
Tag 553 and configured secret tags are redacted in persistence/exports/logs.
Display masking is global, controlled only in Settings → Privacy. Its applied
boolean and additional tags persist in QSettings. Missing/invalid preferences
default to masked; obsolete per-tab flags are ignored. Projects may add secret
tags to the global set but cannot turn display masking off. Presentation changes
commit drafts without repairing framing, then reproject the real in-memory bytes.
The application has no telemetry or cloud synchronization.

## Verification

Tests cover protocol models, byte framing, queues, injection/recovery, persistence,
redaction, controlled mutations, GUI workflows and loopback fake endpoints.
Synthetic XML fixtures exercise minimal messages, custom groups and component
cycles, not full official FIX schemas. Tests generate temporary localhost TLS
material; no stored private key or OS trust installation is required.
