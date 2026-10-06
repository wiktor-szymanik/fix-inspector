# Changelog

All notable public changes to FIX Inspector are documented here.

## 1.0.6

- Renamed the replay workspace to **Sender** and contextual actions to **Open in Sender**.
  Existing project keys, source identifiers, and internal controller names remain compatible.
- Simplified Fuzzer session-destructive controls to one **Enable session-destructive cases**
  option, while preserving red visual classification and the concise destructive-case legend.
- Centralized sensitive-field display policy under **Settings -> Privacy**. Masking is enabled
  by default, tag `553` remains sensitive, and additional numeric tags can be configured.
- Removed per-workspace secret-disclosure controls while preserving message bytes and unsent
  edits when display masking changes.
- Preserved independent redaction for storage, exports, logs, and diagnostics.
- Added the application icon to source and Windows packaging workflows.
- Standardized product prose on ASCII hyphens and completed public-source repository cleanup.
- No intentional changes to FIX parsing, serialization, proxy, session, or injection behavior.

## 1.0.5rc1

Release-candidate snapshot containing the completed product UI refactor:

- Proxy Intercept/History/Rules/Settings workflow and shared message inspection.
- Sender, Composer, controlled Fuzzer, Decoder, and optional dictionary management.
- Plain TCP/TLS upstream selection, session/admin inspection, and local projects.
- Exact version display and Windows setup/run/test/build scripts.
- Disposable TLS test certificates instead of a distributed test private key.
- Application icon support and standardized product punctuation.
