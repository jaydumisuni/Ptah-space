use crate::D04Error;
use ptah_activity_runtime::{IdempotencyClass, RetryClass, SideEffectClass};
use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Accepted D04 mechanical effect metadata from ADR-0037.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationEffectClass {
    /// Read/observe without requesting mutation.
    Observe,
    /// Produce caller-reviewable draft state without publication.
    Draft,
    /// Compute a hypothetical effect without requesting it externally.
    Simulate,
    /// Request an authorized state mutation.
    Mutate,
    /// Publish caller-owned state to an external boundary.
    Publish,
    /// Request a destructive mutation under separate authority.
    Destructive,
    /// Request an externally authoritative side effect.
    ExternalSideEffect,
}

impl OperationEffectClass {
    /// Exact accepted D04 effect vocabulary in canonical order.
    pub const ALL: [Self; 7] = [
        Self::Observe,
        Self::Draft,
        Self::Simulate,
        Self::Mutate,
        Self::Publish,
        Self::Destructive,
        Self::ExternalSideEffect,
    ];

    const fn canonical_name(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Draft => "draft",
            Self::Simulate => "simulate",
            Self::Mutate => "mutate",
            Self::Publish => "publish",
            Self::Destructive => "destructive",
            Self::ExternalSideEffect => "external_side_effect",
        }
    }
}

/// One versioned, provider-bound mechanical operation descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationDescriptorRevision {
    /// Stable namespaced operation key advertised to callers.
    pub operation_key: String,
    /// Semantic version of this descriptor revision.
    pub descriptor_version: String,
    /// Exact Facility Revision that exposes the operation.
    pub facility_revision_ref: EntityRef,
    /// Exact Provider Revision that exposes the operation.
    pub provider_revision_ref: EntityRef,
    /// Current Provider Instance when the descriptor is live-instance bound.
    pub provider_instance_ref: Option<EntityRef>,
    /// Exact current Provider generation when instance-bound.
    pub provider_generation: Option<u64>,
    /// Provider-defined freshness token retained as mechanical evidence.
    pub freshness_token: Option<String>,
    /// Exact Ptah Capability references advertised by the descriptor.
    pub capability_refs: Vec<EntityRef>,
    /// Frozen input schema references expected by the operation.
    pub input_schema_refs: Vec<String>,
    /// Frozen output schema references emitted by the operation.
    pub output_schema_refs: Vec<String>,
    /// D04 caller-visible mechanical effect metadata.
    pub effect: OperationEffectClass,
    /// Frozen A04 execution-side-effect classification.
    pub a04_side_effect: SideEffectClass,
    /// Frozen A04 retry classification.
    pub retry_class: RetryClass,
    /// Frozen A04 idempotency classification.
    pub idempotency_class: IdempotencyClass,
    /// Exact Grant references mechanically required by this descriptor.
    pub required_grant_refs: Vec<EntityRef>,
    /// Whether separate caller/application approval is mechanically required.
    pub caller_approval_required: bool,
    /// Whether local materialization is mechanically required before execution.
    pub materialization_required: bool,
    /// Exact precondition kinds supported by this descriptor.
    pub supported_preconditions: Vec<String>,
    /// Expected Receipt/proof state names exposed to callers.
    pub expected_receipt_states: Vec<String>,
    /// Explicit provider/facility limitations.
    pub limits: Vec<String>,
}

impl OperationDescriptorRevision {
    /// Validate descriptor structure and compatibility with frozen A04 semantics.
    ///
    /// # Errors
    /// Returns [`D04Error`] when required descriptor identity is absent, an
    /// instance/generation binding is incoherent, or effect metadata would
    /// weaken the frozen A04 execution classification.
    pub fn validate(&self) -> Result<(), D04Error> {
        if !valid_operation_key(&self.operation_key) {
            return Err(D04Error::InvalidOperationDescriptor("operation_key"));
        }
        if self.descriptor_version.trim().is_empty() {
            return Err(D04Error::InvalidOperationDescriptor("descriptor_version"));
        }
        match (&self.provider_instance_ref, self.provider_generation) {
            (Some(_), Some(0)) => {
                return Err(D04Error::InvalidOperationDescriptor("provider_generation"));
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(D04Error::InvalidOperationDescriptor(
                    "provider_instance_generation_binding",
                ));
            }
            _ => {}
        }
        if !effect_compatible(self.effect, self.a04_side_effect) {
            return Err(D04Error::EffectCompatibility {
                effect: self.effect.canonical_name().to_owned(),
                side_effect: format!("{:?}", self.a04_side_effect),
            });
        }
        Ok(())
    }

    /// Return the deterministic SHA-256 digest of this exact descriptor revision.
    ///
    /// # Errors
    /// Returns [`D04Error`] if canonical JSON serialization fails.
    pub fn digest(&self) -> Result<String, D04Error> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| D04Error::DescriptorSerialization(error.to_string()))?;
        let digest = Sha256::digest(bytes);
        Ok(hex_digest(&digest))
    }
}

/// Exact descriptor lookup result without semantic ranking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationResolution {
    candidates: Vec<OperationDescriptorRevision>,
}

impl OperationResolution {
    /// Return every exact candidate remaining after caller constraints.
    #[must_use]
    pub fn candidates(&self) -> &[OperationDescriptorRevision] {
        &self.candidates
    }

    /// Whether more than one exact candidate remains unresolved.
    #[must_use]
    pub fn is_ambiguous(&self) -> bool {
        self.candidates.len() > 1
    }
}

/// Derived operation descriptor catalog; it is not execution authority.
#[derive(Debug, Default)]
pub struct OperationCatalog {
    descriptors: Vec<OperationDescriptorRevision>,
}

impl OperationCatalog {
    /// Register one exact descriptor revision without collapsing providers.
    ///
    /// # Errors
    /// Returns [`D04Error`] if validation fails or the exact descriptor digest
    /// is already retained.
    pub fn register(&mut self, descriptor: OperationDescriptorRevision) -> Result<(), D04Error> {
        descriptor.validate()?;
        let digest = descriptor.digest()?;
        if self
            .descriptors
            .iter()
            .any(|existing| existing.digest().is_ok_and(|value| value == digest))
        {
            return Err(D04Error::DescriptorDuplicate(digest));
        }
        self.descriptors.push(descriptor);
        Ok(())
    }

    /// Resolve descriptors only by exact caller-supplied mechanical constraints.
    ///
    /// # Errors
    /// Returns [`D04Error::OperationUnavailable`] when no descriptor matches.
    pub fn resolve(
        &self,
        operation_key: &str,
        facility_revision_ref: Option<&EntityRef>,
        provider_revision_ref: Option<&EntityRef>,
    ) -> Result<OperationResolution, D04Error> {
        let candidates: Vec<_> = self
            .descriptors
            .iter()
            .filter(|descriptor| descriptor.operation_key == operation_key)
            .filter(|descriptor| {
                facility_revision_ref
                    .is_none_or(|required| &descriptor.facility_revision_ref == required)
            })
            .filter(|descriptor| {
                provider_revision_ref
                    .is_none_or(|required| &descriptor.provider_revision_ref == required)
            })
            .cloned()
            .collect();
        if candidates.is_empty() {
            return Err(D04Error::OperationUnavailable(operation_key.to_owned()));
        }
        Ok(OperationResolution { candidates })
    }
}

fn valid_operation_key(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-')
        })
        && value.contains('.')
}

const fn effect_compatible(effect: OperationEffectClass, side_effect: SideEffectClass) -> bool {
    match effect {
        OperationEffectClass::Observe | OperationEffectClass::Simulate => {
            matches!(side_effect, SideEffectClass::ObservationOnly)
        }
        OperationEffectClass::Draft => matches!(
            side_effect,
            SideEffectClass::ObservationOnly | SideEffectClass::Reversible
        ),
        OperationEffectClass::Mutate => matches!(
            side_effect,
            SideEffectClass::Reversible
                | SideEffectClass::IdempotentMutation
                | SideEffectClass::NonIdempotentMutation
        ),
        OperationEffectClass::Publish | OperationEffectClass::ExternalSideEffect => matches!(
            side_effect,
            SideEffectClass::ExternalAuthoritative | SideEffectClass::NonIdempotentMutation
        ),
        OperationEffectClass::Destructive => matches!(side_effect, SideEffectClass::Destructive),
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
