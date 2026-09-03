#![forbid(unsafe_code)]
#![doc = "D07 provider-neutral security evidence and reproduction composition."]

mod assessment;
mod error;
mod evidence;
mod store;

pub use assessment::{
    AssessmentAdmission, AssessmentAdmissionRequest, AssessmentAuthorization, AssessmentPlan,
    AssessmentRunMapping, AssessmentTarget, CoverageProjection, RawReportAlias, ScannerRevision,
    SecurityTestClass,
};
pub use error::D07Error;
pub use evidence::{
    ClaimProjection, CorrelationRelation, EvidenceBundleProjection, EvidenceCoverage,
    EvidenceItemBinding, FindingDraft, ObservationCorrelation, ObservationProjection,
};
pub use store::SecurityEvidenceStore;

#[cfg(test)]
mod tests {
    #[test]
    fn frozen_wp12_store_contains_exactly_eighteen_entity_pairs() {
        assert_eq!(super::store::wp12_schema_pairs().len(), 18);
    }
}
