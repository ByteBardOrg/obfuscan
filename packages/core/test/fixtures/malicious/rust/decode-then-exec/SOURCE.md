# rust decode-then-exec

Synthesized. Rust has limited dynamic-exec surface; the most common attack
shape is dynamic library loading via `libloading`. The base64 blob decodes to
the literal `/tmp/stub.so`.
