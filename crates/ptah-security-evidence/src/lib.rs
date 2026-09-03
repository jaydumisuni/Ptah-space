#![forbid(unsafe_code)]
#![doc = "D07 provider-neutral security evidence and reproduction composition."]

mod adapters;
mod assessment;
mod card;
mod disclosure;
mod error;
mod evidence;
mod remediation;
mod reproduction;
mod review;
mod store;

pub use adapters::{BackendReplacementProjection, SecurityAdapterObservation};
pub use assessment::{
    AssessmentAdmission, AssessmentAdmissionRequest, AssessmentAuthorization, AssessmentPlan,
    AssessmentRunMapping, AssessmentTarget, CoverageProjection, RawReportAlias, ScannerRevision,
    SecurityTestClass,
};
pub use card::EvidenceCardView;
pub use disclosure::DisclosurePolicy;
pub use error::D07Error;
pub use evidence::{
    ClaimProjection, CorrelationRelation, EvidenceBundleProjection, EvidenceCoverage,
    EvidenceItemBinding, FindingDraft, ObservationCorrelation, ObservationProjection,
};
pub use remediation::{
    PatchBinding, PostFixDecision, PostFixVerificationRequest, RemediationAcknowledgement,
    RemediationExecutionRequest,
};
pub use reproduction::{
    ReproductionComparisonDecision, ReproductionComparisonProjection, ReproductionIndependence,
    ReproductionOutcome, ReproductionProtocolProjection, ReproductionRequestProjection,
    ReproductionRunRequest,
};
pub use review::{
    AcceptedRiskProjection, DisputeProjection, ReviewDecisionProjection, ReviewOutcome,
    ValidationRequest,
};
pub use store::SecurityEvidenceStore;

#[cfg(test)]
mod tests {
    #[test]
    fn frozen_wp12_store_contains_exactly_eighteen_entity_pairs() {
        assert_eq!(super::store::wp12_schema_pairs().len(), 18);
    }
}
