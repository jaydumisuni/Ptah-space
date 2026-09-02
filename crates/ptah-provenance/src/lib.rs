#![forbid(unsafe_code)]
#![doc = "Provider-neutral D06 provenance, SBOM, signing and proof-bundle composition."]

mod attestation;
mod error;
mod oci;
mod proof_bundle;
mod reproduction;
mod sbom;
mod signature;
mod store;
mod subject;
mod trust;

pub use attestation::{AttestationProjection, BoundMaterial, EnvelopeType, MaterialOrigin};
pub use error::D06Error;
pub use oci::{DiscoveryMethod, OciDescriptor, OciReferrerProjection};
pub use proof_bundle::{BundleCoverage, ProofBundleManifest, ProofDomain, ProofEntry};
pub use reproduction::{
    BackendEvidence, CachePolicy, ComparisonClass, IndependenceRequirement,
    ReproductionComparisonProjection, ReproductionExecutionKind, ReproductionRequestProjection,
    ReproductionRunProjection,
};
pub use sbom::{
    CoverageState, PackageObservationProjection, SbomClaimScope, SbomConversion, SbomCoverage,
    SbomFormat, SbomProjection, SbomProjectionInput,
};
pub use signature::{
    DisclosureAcknowledgement, SignatureProjection, SignatureVerificationProjection, SigningMethod,
    TransparencyEvidenceProjection, TransparencyMode, VerificationDecision,
    verify_signature_binding,
};
pub use store::ProvenanceStore;
pub use subject::ExactSubject;
pub use trust::{OfflinePolicy, TransparencyPolicy, TrustMode, TrustPolicyProjection};
