# rust build-rs-network

Canonical Rust supply-chain shape. `build.rs` runs on every cargo build; any
network access from it is virtually always malicious. C2 host replaced with
example.com. The Layer-C `obf.cargo-build-rs-network` rule keys off the
`build.rs` filename — the `as` field presents this file under that path.
