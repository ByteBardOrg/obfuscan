# Defanged Slack C2 Loader

This fixture is based on a real-world malicious npm package sample reported by a user.

The source has been defanged before inclusion:

- No live Slack token or channel id remains.
- The network client is a stub and never sends requests.
- The decrypt function is a stub and never returns payload content.
- File deletion, file writing, chmod, process spawning, and polling are removed.
- The initialization block only logs a disabled message.

This fixture verifies that a fully disabled/remediated copy of the loader does not produce a block finding.
