#![forbid(unsafe_code)]
//! Non-claiming Phase 0C boundary for `decomposition-libarchive`.
//!
//! No runtime capability is implemented or authorized by this crate.

/// Records that this package is only a Phase 0C scaffold.
pub const DECOMPOSITION_LIBARCHIVE_RUNTIME_AUTHORIZED: bool = false;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_cannot_claim_runtime_authorization() {
        assert!(!DECOMPOSITION_LIBARCHIVE_RUNTIME_AUTHORIZED);
    }
}
