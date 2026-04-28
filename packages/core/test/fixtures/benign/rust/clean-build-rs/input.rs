// Pure cargo directives — no network, no filesystem writes outside OUT_DIR.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/proto");
    println!("cargo:rustc-link-lib=static=foo");
}
