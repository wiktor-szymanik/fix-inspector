# FIX Inspector troubleshooting

Diagnostics is available under **Help → Troubleshooting**. Endpoint and
interception settings are under **Proxy → Settings**; policy rules and the
fault journal are under **Proxy → Rules**.

## Source application does not start

Run `.\scripts\setup-windows.ps1`, then
`.\.venv\Scripts\python.exe -m fixinspector --self-test`. A zero exit code proves
the packaged protocol core loads. For source development, Python must be 3.11
through 3.14; the acceptance build used Python 3.14 x64 and exact pins in
`requirements.txt`/`requirements-build.txt`.

## TLS connection fails

- Confirm **Transport = TLS** for a TLS upstream. Plain TCP services require
  **Transport = Plain TCP**; transport selection never falls back automatically.
- Keep verification enabled and make SNI match the certificate hostname.
- For a private PKI, select the issuing CA certificate, not a server private key.
- Confirm the CA file exists and is PEM/CRT encoded.
- Check Diagnostics for verification mode, negotiated TLS version/cipher, and
  the last network error.
- Verification-disabled mode is only for an authorized disposable harness. It
  does not fix protocol/cipher/firewall failures.

For Plain TCP failures, verify the configured host/port and server availability.
No certificate, SNI, CA file, or dictionary is needed. Diagnostics retains the
last connection error; the listener remains available for the next client and
can be stopped/restarted. Changing transport requires stopping the proxy first.

The upstream is TLS 1.3 only. The local listener is plaintext and should remain
bound to loopback unless the lab design explicitly requires otherwise.

## Client connects but traffic does not move

Look at Diagnostics and the Intercept queue. A HELD outbound sequence pauses all
later outbound traffic by design. Forward or Drop it; Drop creates a sequence gap.
Safe injected messages also wait for a plain outbound Heartbeat and do not replace
TestRequest heartbeats or genuine business messages.

## Malformed traffic is shown as Raw

This is expected fail-soft behavior. Framing and parsing warnings are displayed;
the original bytes are retained and forwarded according to intercept policy.
Buffers are bounded to avoid indefinite memory growth. Decoder can inspect the
same raw material offline and optionally repair only BodyLength/CheckSum.

## History appears to omit older rows

Diagnostics shows the live limit, evicted count, and SQLite durable count. With
an open project, older rows remain on disk. Increase **In-memory History limit**
and reopen the project. Without a project, evicted in-memory rows are intentionally
discarded.

## Project is locked or corrupt

Only open one writer for a `.fixproj` file. Stop proxy activity before switching
projects. SQLite uses WAL and full synchronous commits. Copy the project and its
`-wal`/`-shm` siblings before forensic recovery. A newer schema or corrupt JSON
state is reported instead of silently modifying traffic.

## Logs and secrets

The log location is shown in Diagnostics. Logs are bounded and local. Tag 553 is
always redacted. If a new vendor credential tag is discovered, add it in
Settings → Privacy immediately; applying the policy re-redacts durable project rows.
Do not attach unreviewed projects or raw captures to bug reports.

## Portable build is blocked by Windows

Extract the entire ZIP; do not move only the EXE away from its `_internal`
directory. Verify the published SHA-256. An unsigned internal build can trigger
SmartScreen; follow the organization’s code-signing and application-control
process rather than disabling endpoint protections globally.

## Rebuild completely offline

Prepare wheels matching the Python version and Windows architecture for all
dependencies in `requirements-dev.txt`, `requirements-build.txt` and the build
backend in `pyproject.toml`. Run `scripts\setup-windows.ps1 -Build -Wheelhouse`
with that directory as its argument, then `scripts\build-windows.ps1`.
The explicit wheelhouse option uses `--no-index`. Runtime performs no package
download, update check, telemetry, or cloud synchronization.
