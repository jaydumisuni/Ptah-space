use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};

use crate::{D06Error, ExactSubject};

/// Frozen mechanical SBOM coverage state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    /// Requested scope was scanned with no retained gaps.
    Complete,
    /// Some requested scope is retained as a gap.
    Partial,
    /// The scan failed.
    Failed,
    /// Evidence cannot establish a final coverage state.
    Inconclusive,
}

/// Explicit requested/scanned/gap accounting for one SBOM run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomCoverage {
    /// Caller-requested scan scopes.
    pub requested: Vec<String>,
    /// Scopes actually scanned.
    pub scanned: Vec<String>,
    /// Deliberately skipped scopes.
    pub skipped: Vec<String>,
    /// Unsupported scopes.
    pub unsupported: Vec<String>,
    /// Error descriptions by scope.
    pub errors: Vec<String>,
    /// Unknown/unclassified coverage gaps.
    pub unknown_gaps: Vec<String>,
    /// Mechanical coverage state.
    pub state: CoverageState,
}

impl SbomCoverage {
    /// Whether the evidence can mechanically claim complete coverage.
    #[must_use]
    pub fn claims_complete(&self) -> bool {
        self.state == CoverageState::Complete
            && !self.requested.is_empty()
            && self
                .requested
                .iter()
                .all(|scope| self.scanned.contains(scope))
            && self.skipped.is_empty()
            && self.unsupported.is_empty()
            && self.errors.is_empty()
            && self.unknown_gaps.is_empty()
    }

    /// Number of retained gap/error entries.
    #[must_use]
    pub fn gap_count(&self) -> usize {
        self.skipped.len() + self.unsupported.len() + self.errors.len() + self.unknown_gaps.len()
    }
}

/// Frozen/native or registered SBOM serialization format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SbomFormat {
    /// Syft JSON.
    SyftJson,
    /// SPDX JSON.
    SpdxJson,
    /// SPDX tag-value.
    SpdxTagValue,
    /// `CycloneDX` JSON.
    CycloneDxJson,
    /// `CycloneDX` XML.
    CycloneDxXml,
    /// Registered format outside the frozen native vocabulary.
    OtherRegistered(String),
}

/// A format conversion projection with explicit retained information loss.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomConversion {
    /// Source format.
    pub from: SbomFormat,
    /// Destination format.
    pub to: SbomFormat,
    /// Information that could not be represented exactly.
    pub information_loss: Vec<String>,
}

impl SbomConversion {
    /// Whether no information loss was observed during conversion.
    #[must_use]
    pub fn is_lossless(&self) -> bool {
        self.information_loss.is_empty()
    }
}

/// Scope of authority carried by an SBOM projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SbomClaimScope {
    /// Package/component inventory evidence only.
    InventoryOnly,
}

impl SbomClaimScope {
    /// SBOM inventory never proves vulnerability state.
    #[must_use]
    pub const fn proves_vulnerability_state(self) -> bool {
        false
    }
    /// SBOM inventory never approves licences.
    #[must_use]
    pub const fn proves_licence_acceptance(self) -> bool {
        false
    }
    /// SBOM inventory never grants release acceptance.
    #[must_use]
    pub const fn proves_release_acceptance(self) -> bool {
        false
    }
}

/// One exact package observation consumed by an SBOM, separate from the SBOM itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageObservationProjection {
    /// Exact scanned subject.
    pub subject: ExactSubject,
    /// Stable package identity.
    pub package_ref: EntityRef,
    /// Exact package revision.
    pub package_revision_ref: EntityRef,
}

/// Provider-neutral immutable SBOM evidence projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomProjection {
    /// Exact subject inventories apply to.
    pub subject: ExactSubject,
    /// Generator Facility revision.
    pub generator_facility_revision_ref: EntityRef,
    /// Generator Provider revision.
    pub generator_provider_revision_ref: EntityRef,
    /// Exact generator configuration revision.
    pub generator_configuration_ref: EntityRef,
    /// Native retained report artifact.
    pub native_report_artifact_ref: EntityRef,
    /// Native report format.
    pub format: SbomFormat,
    /// Declared format version.
    pub format_version: String,
    /// Separate package observations included in the report.
    pub package_observation_refs: Vec<EntityRef>,
    /// Mandatory separate SBOM coverage record.
    pub coverage_ref: EntityRef,
}

/// Inputs required to construct one exact SBOM evidence projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomProjectionInput {
    /// Exact subject inventories apply to.
    pub subject: ExactSubject,
    /// Generator Facility revision.
    pub generator_facility_revision_ref: EntityRef,
    /// Generator Provider revision.
    pub generator_provider_revision_ref: EntityRef,
    /// Exact generator configuration revision.
    pub generator_configuration_ref: EntityRef,
    /// Native retained report artifact.
    pub native_report_artifact_ref: EntityRef,
    /// Native report format.
    pub format: SbomFormat,
    /// Declared format version.
    pub format_version: String,
    /// Separate package observations included in the report.
    pub package_observation_refs: Vec<EntityRef>,
    /// Mandatory separate SBOM coverage record.
    pub coverage_ref: EntityRef,
}

impl SbomProjection {
    /// Construct one SBOM projection with mandatory exact coverage binding.
    ///
    /// # Errors
    /// Returns [`D06Error::InvalidCoverage`] if the coverage reference is not an SBOM Coverage entity,
    /// or [`D06Error::InexactSubject`] when the subject is not exact.
    pub fn new(input: SbomProjectionInput) -> Result<Self, D06Error> {
        input.subject.validate()?;
        if input.coverage_ref.entity_kind.as_str() != "provenance.sbom_coverage" {
            return Err(D06Error::InvalidCoverage);
        }
        Ok(Self {
            subject: input.subject,
            generator_facility_revision_ref: input.generator_facility_revision_ref,
            generator_provider_revision_ref: input.generator_provider_revision_ref,
            generator_configuration_ref: input.generator_configuration_ref,
            native_report_artifact_ref: input.native_report_artifact_ref,
            format: input.format,
            format_version: input.format_version,
            package_observation_refs: input.package_observation_refs,
            coverage_ref: input.coverage_ref,
        })
    }
}
