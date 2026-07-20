#![forbid(unsafe_code)]
//! Non-claiming Phase 0C boundary for `ptah-contracts`.
//!
//! The generated module binds frozen catalog, schema and lifecycle metadata.
//! JSON Schema and lifecycle JSON remain authoritative. No runtime capability
//! is implemented or authorized by this crate.

/// Deterministic metadata generated from the frozen Phase 0B contract set.
pub mod generated;

/// Records that this package is only a Phase 0C scaffold.
pub const PTAH_CONTRACTS_RUNTIME_AUTHORIZED: bool = false;

#[cfg(test)]
mod tests {
    use super::generated;

    #[test]
    fn generated_binding_counts_match_the_frozen_set() {
        assert_eq!(generated::CATALOG_COUNT, 14);
        assert_eq!(generated::SCHEMA_COUNT, 346);
        assert_eq!(generated::STATE_MACHINE_COUNT, 99);
        assert_eq!(generated::CATALOGS.len(), generated::CATALOG_COUNT);
        assert_eq!(generated::SCHEMAS.len(), generated::SCHEMA_COUNT);
        assert_eq!(
            generated::STATE_MACHINES.len(),
            generated::STATE_MACHINE_COUNT
        );
    }

    #[test]
    fn generated_bindings_preserve_the_frozen_catalog_digest() {
        assert_eq!(
            generated::CATALOG_SET_SHA256,
            "f0668a5f5d5c68cabf623176608c627a94482faa4f4460e4f0fe0f0969d7c64d"
        );
        assert_eq!(
            generated::PHASE_0B_FREEZE_COMMIT,
            "dc2db457f1705d0cba80f17ab76e5e93f808aee0"
        );
    }

    #[test]
    fn canonical_schema_identity_wins_over_a_legacy_catalog_alias() {
        assert!(
            generated::schema_by_id("urn:ptah:schema:conformance:definitions:0.1.0")
                .is_some()
        );
        assert!(
            generated::schema_by_id("urn:ptah:schema:conformance.definitions:0.1.0")
                .is_none()
        );
    }

    #[test]
    fn catalog_and_lifecycle_lookups_are_available() {
        assert!(
            generated::catalog_by_id("urn:ptah:schema-catalog:domain:0.1.2").is_some()
        );
        assert!(generated::state_machine("conformance.run.lifecycle", "0.1.0").is_some());
    }
}
