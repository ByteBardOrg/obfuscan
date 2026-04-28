# string-array decoder

Synthesized to match the canonical [obfuscator.io](https://obfuscator.io)
output shape: a long array of base64 strings + a decoder function +
`eval(decoder(i))`. Strings encode the literal text "payload-stub-N-..." —
no real payload.
