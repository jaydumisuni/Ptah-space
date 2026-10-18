#![forbid(unsafe_code)]
//! E01 executable boundary for `ptah-node`.

fn main() {
    eprintln!(
        "ptah-node: E01 secure-link client library is available; deployment connection configuration is required."
    );
    // No signed production enrollment or exact Node identity is configured:
    // an unprovisioned executable must never report a healthy runtime.
    std::process::exit(2);
}
