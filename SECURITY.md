# Security policy

PurgeLog helps redact supported patterns. It is not a guarantee of anonymization, compliance, or complete secret detection. Always inspect the result before sharing it.

- Runtime processing is offline. No telemetry, remote APIs, external assets, update checks, or account registration are implemented.
- The pure core has no filesystem or networking access. CLI/GUI adapters perform only their documented local I/O.
- Input files are immutable by default. `-o` refuses existing destinations. Shell redirection has its own overwrite semantics.
- Private credential files are plaintext. Store them outside Git with restrictive permissions; PurgeLog does not encrypt them or securely erase process/browser memory.
- GUI logs and selected files stay in browser memory. CLI-provided rules are served over a random loopback session URL. This is not a security boundary against malicious local software, browser extensions, a compromised browser, or another process running as the same OS user.
- A browser may retain form/session data through features outside this app's control. Close the tab when done. Copied clipboard text, browser downloads, shell history, and external backups are outside PurgeLog's control.
- Do not paste real credentials into public issues. Use synthetic reproductions. For a vulnerability report, use GitHub private vulnerability reporting if enabled; otherwise ask the maintainer for a private reporting channel without posting exploit details or secrets.
- Supported structured input is valid JSON and valid object/array JSON Lines records. Plain text, malformed records, multiline unquoted values, unfamiliar token formats, encodings, and heavily escaped values may evade patterns. IPv6 and universal personal-data identification are not implemented.
- The 10 MiB input cap limits memory use but is not a guarantee of constant-time execution. Custom literal credentials are bounded; user-supplied executable rules and regex are not supported.

No real user credentials or transactions are needed to run tests.
