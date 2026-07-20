#![forbid(unsafe_code)]
//! Phase 0C scaffold guards.
//!
//! This crate deliberately contains no Ptah runtime implementation. It records
//! the frozen planning checkpoints and fails closed on runtime authorization.

/// Phase 0B governance freeze accepted for Phase 0C entry.
pub const PHASE_0B_FREEZE_COMMIT: &str = "dc2db457f1705d0cba80f17ab76e5e93f808aee0";

/// Merge commit containing the frozen WP14 corpus and first-slice proof plan.
pub const WP14_FREEZE_COMMIT: &str = "fef387c4f074af7fcf86f2d99f7f9b7637e91f88";

/// The selected public implementation repository.
pub const IMPLEMENTATION_REPOSITORY: &str = "jaydumisuni/Ptah-space";

/// Runtime work remains blocked until ADR-0033 is accepted and the roadmap
/// control book explicitly changes this condition.
pub const RUNTIME_IMPLEMENTATION_AUTHORIZED: bool = false;

/// Returns an error when a caller attempts to treat this scaffold as an
/// authorized runtime repository.
///
/// # Errors
///
/// Always returns an error while Phase 0C authorization remains false.
pub const fn require_runtime_authorization() -> Result<(), &'static str> {
    if RUNTIME_IMPLEMENTATION_AUTHORIZED {
        Ok(())
    } else {
        Err("Ptah runtime implementation is not authorized; this branch is Phase 0C scaffold only")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_commits_are_full_sha1_values() {
        assert_eq!(PHASE_0B_FREEZE_COMMIT.len(), 40);
        assert_eq!(WP14_FREEZE_COMMIT.len(), 40);
        assert!(
            PHASE_0B_FREEZE_COMMIT
                .chars()
                .all(|item| item.is_ascii_hexdigit())
        );
        assert!(
            WP14_FREEZE_COMMIT
                .chars()
                .all(|item| item.is_ascii_hexdigit())
        );
    }

    #[test]
    fn runtime_remains_fail_closed() {
        let result = require_runtime_authorization();
        assert_eq!(
            result,
            Err("Ptah runtime implementation is not authorized; this branch is Phase 0C scaffold only")
        );
    }

    #[test]
    fn repository_identity_is_explicit() {
        assert_eq!(IMPLEMENTATION_REPOSITORY, "jaydumisuni/Ptah-space");
    }
}
