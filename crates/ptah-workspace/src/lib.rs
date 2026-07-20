#![forbid(unsafe_code)]
//! Non-claiming Phase 0C boundary for `ptah-workspace`.
//!
//! No runtime capability is implemented or authorized by this crate.

/// Records that this package is only a Phase 0C scaffold.
pub const PTAH_WORKSPACE_RUNTIME_AUTHORIZED: bool = false;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_cannot_claim_runtime_authorization() {
        assert!(!PTAH_WORKSPACE_RUNTIME_AUTHORIZED);
    }
}
