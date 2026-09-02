use crate::{D04Error, ExactPrecondition};
use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Accepted D04 staged Recipe lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStage {
    /// Observe current state without mutation.
    Observe,
    /// Produce caller-reviewable draft state.
    Draft,
    /// Simulate the intended effect.
    Simulate,
    /// Execute the separately authorized effect.
    Execute,
    /// Verify postconditions separately from execution acknowledgement.
    Verify,
}

impl ExecutionStage {
    const fn rank(self) -> u8 {
        match self {
            Self::Observe => 0,
            Self::Draft => 1,
            Self::Simulate => 2,
            Self::Execute => 3,
            Self::Verify => 4,
        }
    }
}

/// Non-secret parameter values allowed in D04 Plan manifests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum ParameterValue {
    /// UTF-8 caller value.
    String(String),
    /// Boolean caller value.
    Bool(bool),
    /// Signed integral caller value.
    Integer(i64),
    /// Ordered caller list.
    List(Vec<ParameterValue>),
    /// Deterministically ordered caller object.
    Object(BTreeMap<String, ParameterValue>),
    /// Exact canonical Ptah reference instead of embedded bytes.
    EntityRef(EntityRef),
}

/// One declared ordinary non-secret parameter binding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParameterBinding {
    /// Stable declared parameter key.
    pub key: String,
    /// Non-secret bounded value.
    pub value: ParameterValue,
}

/// One opaque credential-reference binding; no raw credential value exists here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialBinding {
    /// Stable credential requirement key.
    pub requirement_key: String,
    /// Exact opaque credential reference.
    pub credential_ref: EntityRef,
    /// Optional exact Provider/service scope.
    pub provider_or_service_scope_ref: Option<EntityRef>,
}

/// One mechanically planned operation in an immutable D04 execution manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannedOperation {
    /// Exact immutable Recipe step key.
    pub recipe_step_key: String,
    /// Staged lifecycle position.
    pub stage: ExecutionStage,
    /// Exact caller-selected operation key.
    pub operation_key: String,
    /// Immutable Recipe step dependencies that must complete before this operation becomes ready.
    pub dependency_step_keys: Vec<String>,
    /// Exact descriptor digest resolved before planning.
    pub descriptor_digest: String,
    /// Exact logical targets.
    pub logical_target_refs: Vec<EntityRef>,
    /// Ordinary non-secret parameters.
    pub parameters: Vec<ParameterBinding>,
    /// Opaque credential-reference bindings.
    pub credentials: Vec<CredentialBinding>,
    /// Exact required service registrations.
    pub service_refs: Vec<EntityRef>,
    /// Exact required Grants.
    pub required_grant_refs: Vec<EntityRef>,
    /// Exact per-operation preconditions frozen by the plan.
    pub preconditions: Vec<ExactPrecondition>,
    /// Optional separate caller/application approval reference.
    pub caller_approval_ref: Option<EntityRef>,
    /// Exact expected output declarations.
    pub expected_output_refs: Vec<EntityRef>,
    /// Explicit operation limitations.
    pub limitations: Vec<String>,
}

/// Deterministic D04 staged execution-plan manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionPlanManifest {
    /// Exact immutable Recipe Revision.
    pub recipe_revision_ref: EntityRef,
    /// Exact separate Acceptance.
    pub acceptance_ref: EntityRef,
    /// Ordered staged operations.
    pub operations: Vec<PlannedOperation>,
    /// Caller/Recipe-declared ordinary parameter keys.
    pub declared_parameter_keys: Vec<String>,
    /// Caller/Recipe-declared credential requirement keys.
    pub declared_credential_keys: Vec<String>,
    /// Caller/Recipe-declared exact service refs.
    pub declared_service_refs: Vec<EntityRef>,
}

impl ExecutionPlanManifest {
    /// Validate monotonic stages and exact declaration boundaries.
    ///
    /// # Errors
    /// Returns [`D04Error`] for backwards stages or undeclared Plan inputs.
    pub fn validate(&self) -> Result<(), D04Error> {
        let mut previous = None;
        for operation in &self.operations {
            if let Some(rank) = previous
                && operation.stage.rank() < rank
            {
                return Err(D04Error::InvalidStageOrder);
            }
            previous = Some(operation.stage.rank());
            for parameter in &operation.parameters {
                if !self.declared_parameter_keys.contains(&parameter.key) {
                    return Err(D04Error::UndeclaredPlanInput {
                        kind: "parameter".to_owned(),
                        key: parameter.key.clone(),
                    });
                }
            }
            for credential in &operation.credentials {
                if !self
                    .declared_credential_keys
                    .contains(&credential.requirement_key)
                {
                    return Err(D04Error::UndeclaredPlanInput {
                        kind: "credential".to_owned(),
                        key: credential.requirement_key.clone(),
                    });
                }
            }
            for service in &operation.service_refs {
                if !self.declared_service_refs.contains(service) {
                    return Err(D04Error::UndeclaredPlanInput {
                        kind: "service".to_owned(),
                        key: service.entity_id.to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Return a deterministic SHA-256 digest of the exact ordered manifest.
    ///
    /// # Errors
    /// Returns [`D04Error`] when JSON serialization fails.
    pub fn digest(&self) -> Result<String, D04Error> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| D04Error::PlanSerialization(error.to_string()))?;
        Ok(hex_digest(&Sha256::digest(bytes)))
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
