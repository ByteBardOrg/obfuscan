# Slack C2 Dropper

This fixture models a real-world malicious npm package sample reported by a user.

The fixture is defanged before inclusion:

- It imports no real Node modules.
- `https`, `fs`, `path`, `child`, and `crypto` are inert local shim objects.
- The Slack token, channel id, host, encrypted content, salt, and IV are redacted placeholders.
- `example.invalid` is used instead of the original C2 host.
- No function is invoked at module load time.
- Even if imported, the APIs called by exported functions are local no-op shims.

The retained static structure is intentional: Slack/C2 API markers, PBKDF2/AES-GCM decrypt-stage markers, write/chmod staging, child-process launch shape, and self-delete shape.
