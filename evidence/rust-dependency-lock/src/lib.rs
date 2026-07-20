#![forbid(unsafe_code)]
//! Phase 0C dependency-resolution evidence only.
//!
//! This package forces Cargo to resolve the exact candidate direct dependency
//! graph. It implements no Ptah runtime behavior and must not be linked by a
//! production package.

/// Records that this package is evidence-only and cannot authorize runtime work.
pub const RUNTIME_IMPLEMENTATION_AUTHORIZED: bool = false;

#[cfg(test)]
mod tests {
    use super::RUNTIME_IMPLEMENTATION_AUTHORIZED;

    #[test]
    fn dependency_evidence_cannot_authorize_runtime() {
        assert!(!RUNTIME_IMPLEMENTATION_AUTHORIZED);
    }
}
