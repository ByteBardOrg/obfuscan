// Defanged: base64 decode -> libloading::Library::new on the decoded path.
// libloading is in the Rust config's dynamic_exec_sinks AND library_load.
use base64::Engine;
use libloading::Library;

fn load_module(blob: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path_bytes = base64::engine::general_purpose::STANDARD.decode(blob)?;
    let path = String::from_utf8(path_bytes)?;
    unsafe {
        let _lib = Library::new(&path)?;
    }
    Ok(())
}

fn main() {
    let _ = load_module("L3RtcC9zdHViLnNv"); // "/tmp/stub.so"
}
