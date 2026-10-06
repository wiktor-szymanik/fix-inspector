# Test inputs

These tiny XML/JSON files are synthetic, test-specific inputs, not distributions of official
or vendor FIX dictionaries. They deliberately contain incomplete definitions, artificial
nested groups, and component cycles for regression tests.

They are retained only because automated tests use these paths; they are not production
examples.

No full third-party dictionaries, captured sessions, or project files are bundled. Users
load their own appropriately licensed dictionary files through the Dictionaries workspace.

TLS certificate/private-key material is generated per test process by
`tests/tls_fixture.py` in a temporary directory and cleaned up at process exit. Synthetic
secret marker strings in tests are redaction assertions, not credentials.
