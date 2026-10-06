# FIX Inspector user guide

## 1. Purpose and topology

Use FIX Inspector only for authorized manual security testing. The supported
topology is:

```text
external FIX client -> plaintext TCP listener -> FIX Inspector -> Plain TCP or TLS upstream
```

The external client owns Logon, Logout, sequence generation, heartbeat cadence,
and ordinary recovery. FIX Inspector observes session state and virtualizes only
safe outbound Heartbeat slots for Sender, Composer, and safe Fuzzer cases.

## 2. Start and configure

Open **Proxy → Settings → Proxy endpoints** and set the listener address,
upstream host/port, and **Transport**. The route summary updates as you edit.
**Plain TCP** creates no TLS context or handshake. SNI, certificate verification,
CA file, and CA Browse are hidden in this mode, but their saved values remain.
Traffic is unencrypted in Plain TCP mode.

**TLS** preserves the existing TLS 1.3 behavior. Certificate and hostname
verification is enabled by default and uses the Windows/system trust store.
To trust an internal test CA, leave verification enabled and select its PEM/CRT
file. Older settings without the transport key default to TLS.

Disabling verification is testing-only. The warning remains visible in
Proxy Settings, the status bar, and Help → Troubleshooting, and Start requires a second
confirmation. A configured CA path is rejected before the listener starts if the
file is missing in TLS mode; TLS fields are not validated in Plain TCP mode.

The **Dictionaries** workspace accepts optional XML metadata for field names,
message names, and schema-aware tools. Missing dictionaries never prevent
proxy startup or forwarding, including Logon, in either transport mode.
Session/admin traffic is not held by default. **Hide Heartbeats**
filters only `35=0`; **Hide other session/admin** independently filters
`A/1/2/3/4/5`. The master intercept switch, application direction policy, and
explicit session/admin opt-in are separate.

## 3. Intercept and History

For live presentations, **Settings → Display** provides interface zoom,
message/table font sizes and a temporary presentation preset. See
`DISPLAY_PRESENTATION.md` for shortcuts, persistence and the font/scale model.

If an outbound application SeqNum N is held, all later Client → Server wire
messages are queued. Nothing can send N+1 first. Resolve the blue **HELD** row;
gray **QUEUED** application messages are promoted in arrival order. Auto-forward
is an optional deadline policy. Structured Forward repairs BodyLength and
CheckSum; Raw mode retains intentional framing errors.

History preserves flat wire order and duplicate tags. Use Ctrl+C or the context
menu for value, tag, tag=value, raw, and readable copies. Use Search for simple
text; Filter opens Traffic, Fields/range and Advanced controls. Active filter
chips can be removed individually. Clear filters keeps the search text; Clear
history deletes captured records only after confirmation. Advanced expressions
support message properties and arbitrary tags, for example:

```text
msgtype=D AND direction="Client → Server" AND tag.54=1
(clordid~TEST OR orderid~TEST) AND NOT status=DROPPED
```

Bookmarks, notes, Original/Effective Diff, repeating-group projection, and
Related correlation are available in **Proxy → History**. Use the inspector's
**More** menu for Diff, Groups, Related and Notes; **Columns** shows optional metadata.
The History header has a separate Columns menu for message-list columns.
Secret-tag predicates remain usable for the current session but are omitted
from saved filters; their values are not displayed in chips.

History and Intercept share Open in Sender/Fuzzer/Composer/Decoder actions.
Fuzzer and Composer retain their application-only eligibility; Composer also
requires dictionary metadata. Decoder receives the currently masked display
copy unless secrets are revealed. Its input is offline, not a send operation.

### Proxy Rules

Rules is a UI projection of the existing proxy policy, not a new matcher.
Visible Order values describe fixed precedence: global override (1), next-N
one-shot (2), first matching ordered rule (3.n), category default (4), then
direction delay (5). Only tier 3 can be moved up/down. Disconnect rows are
independent event triggers, not message actions at another precedence level.

Add rule shows parameters appropriate to the applicability/action. Ordered
rules support category, MsgType and exact tag=value conditions joined by AND;
they do not support History's arbitrary boolean/range expressions. Next-N
applies to all messages in a direction. Presets display their resulting policy
rows immediately. Clean disables saved rules and clears active policies using
the existing reset API. If messages are pending, reset requires confirmation
because the existing reset contract discards them, rather than forwarding them.

Queue / journal retains forward/drop selected/all and manual disconnect actions.
An armed disconnect trigger has no individual edit/cancel API; use Reset.
Primary navigation is Proxy, Sender, Composer, Fuzzer, Decoder and Dictionaries.
File contains project operations and Export; View contains presentation mode,
Reset layout and global Settings. **Proxy → Rules** presents the existing
Proxy Behaviour API through fixed-precedence policy rows.

## 4. Long sessions and projects

The default live History/correlation window is 10,000 records and can be changed
from 100 to 1,000,000 in **Settings → Advanced**. Unresolved HELD/QUEUED records are never
evicted. With an open project, every record is first committed to SQLite;
eviction removes only the UI/in-memory copy. Save never deletes older durable
rows, and Save As copies the complete database.

Without an open project, evicted records cannot be recovered. Create a project
before a long capture. Opening a large project loads its newest configured live
window; increase the limit and reopen when a larger working set is needed.

**Settings → Privacy** is the only secret-display control. **Mask sensitive FIX
fields** defaults on; tag 553 is always sensitive. Enter additional numeric tags
(for example `554, 925`) and choose **Apply**. Invalid tags are reported inline.
The applied mask preference and tags persist. Old per-tab disclosure flags are
ignored. Turning masking off displays actual values globally, including in newly
opened Sender items; turn it back on before screen sharing. No per-tab reveal
controls remain. Display changes do not replace actual FIX values with masks.
To edit hidden secret values or use raw/manual editing with secrets, disable
masking here first. Tag 553 and additional tags remain redacted in logs, project
writes and readable/raw/JSON/Markdown exports regardless of the display setting.

## 5. Sender, Composer, and Fuzzer

**Sender** accepts every FIX History record, including Heartbeat, Logon,
TestRequest, ResendRequest, Reject, SequenceReset, and Logout from either
direction. Replays are emitted Client → Server. Business Replay preserves the
captured payload and Clone/Edit provides the ordered, duplicate-preserving
field editor.

The **Managed** Session fields mode enables automatic BodyLength (9), MsgSeqNum (34),
SendingTime (52), and CheckSum (10). Safe sends show “Queued - waiting for safe
active-session slot” until a plain outbound Heartbeat becomes available. The
**Framing only** mode updates 9/10 and preserves 34/52. It still uses the existing
Heartbeat slot and session-identity policy; it is not an independent session
engine or a guarantee of sequence safety when preserved values are stale.
**Manual** uses Exact Raw Replay, disables all four automatic
updates, and is visibly session-destructive; it preserves manual 9, 34, 43,
52, 122, 10 and malformed framing bytes.
Mode selection is non-modal. Existing send acknowledgements/confirmations remain.
**Advanced field overrides** retains custom checkbox combinations from old
projects. **Activity** shows execution state; **Responses** lists correlated
traffic and opens its History record on double-click. **Ctrl+R** sends the
current Sender item only while the Sender workspace is active.

For a `35=A` Sender item, **Send on new connection** opens an independent
upstream connection using the selected Plain TCP/TLS transport, sends the resulting Logon, and captures server traffic
in both Sender and History with Source `SENDER` (the persisted identifier remains
`REPEATER` for compatibility). It does not reuse or close
the main proxy connection. This isolated transport deliberately does not add a
second FIX session engine: it does not generate heartbeats, manage resend, or
perform automatic logout. Close it with **Close test connection**.

**Composer** creates application messages from dictionary metadata, separating
required/optional fields, enums, arbitrary invalid values, and repeating groups.
Templates are project-local. Composer uses the same injection controller.
It remains Managed-only; manual/framing-only replay belongs in Sender.

**Fuzzer** creates finite sequential campaigns from History, Sender, or
Composer. It has no high-rate mode. Session-destructive cases are disabled until
the single **Enable session-destructive cases** checkbox is enabled. Red rows
identify those mutations; the small legend explains the classification. There is
no second campaign authorization checkbox or enabling confirmation dialog.
Disconnect pauses the campaign and reconnect never silently
resumes it.
Advanced planner inputs are collapsible. Selecting a result shows its case
payload in the shared Parsed/Raw/Validation viewer. This is the draft before
session-field virtualization, not an assertion that those exact bytes were
sent. Double-click opens sent/correlated History. Its context menu sends the
draft to Sender/Decoder or copies redacted raw; it never starts another run.

## 6. Offline Decoder

Decoder has no transport/session dependency. Paste or load FIX using actual SOH,
`␁`, `|`, `^A`, `<SOH>`, or `\x01`; common timestamp/log prefixes are removed.
Multiple messages and duplicate fields remain separate. Malformed/truncated
bytes remain in Raw with framing and validation issues. **Repair selected
framing** recalculates BodyLength and CheckSum. Secrets start hidden here too.
After Decode, the input preview is masked while its original decoded bytes
remain in memory. Re-decoding an unchanged masked preview uses that original,
not the redaction placeholder. An unprocessed draft is not overwritten while
typing; Decode it before sharing the screen. Applying the global Privacy policy
also masks a pending input draft while retaining its original text in memory.
All decoded views use the same global policy as the other workspaces.

### Dictionary management

**Dictionaries** is the only dictionary-management surface. Transport and
application paths each have Loaded/Not loaded state and Load/Replace/Remove.
Load errors appear inline and retain the previously loaded metadata. Removing
the last dictionary leaves a valid dictionary-free proxy. Search covers fields,
messages, enum/type metadata and groups; the summary includes nested repeating
groups. Header context menus expose optional table columns.

## 7. Diagnostics and logs

**Help → Troubleshooting** reports listener/upstream state, TLS verification/protocol/cipher,
observed identities/sequences/HeartBtInt, ordered queues, injection and recovery
journal state, dictionaries, parser/malformed counts, last network error, live
and durable History counts, and the log path. **Copy diagnostics** and **Export
diagnostic bundle** produce an allowlisted metadata report; they deliberately
omit payloads, identities, endpoints, paths, logs and exception bodies, even
when the message viewer is revealing secrets.

Logs rotate at 2 MiB with four backups under
`%LOCALAPPDATA%\FIX Inspector\logs\fix-inspector.log` (falling back to APPDATA or
the current directory). Traffic bodies are not deliberately logged, and the
final formatter redacts tag 553 plus configured secret tags even if diagnostic
text contains `tag=value` or a bytes representation.

## 8. Keyboard shortcuts

- Ctrl+I: toggle intercept master switch.
- Ctrl+R: send the current Sender item while Sender is active.
- Ctrl+F: search Proxy History, Composer message types or Dictionaries.
- Ctrl+Enter: forward the selected HELD message.
- Ctrl+Shift+D: confirm Drop for the selected HELD message.
- Ctrl+L: focus History filter.
- Ctrl+C: copy selected cells.
- Ctrl+N/O/S/Shift+S: new/open/save/save-as project.
