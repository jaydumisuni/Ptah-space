#![forbid(unsafe_code)]
#![doc = "D07 provider-neutral security evidence and reproduction composition."]

mod error;
mod store;

pub use error::D07Error;
pub use store::SecurityEvidenceStore;

#[cfg(test)]
mod tests {
    #[test]
    fn frozen_wp12_store_contains_exactly_eighteen_entity_pairs() {
        assert_eq!(super::store::wp12_schema_pairs().len(), 18);
    }
}
