use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};

/// Exact mechanical precondition classes supported by D04.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconditionKind {
    /// Exact A07 Object Revision digest.
    ObjectRevisionDigest,
    /// Exact canonical A03 record revision.
    CanonicalRecordRevision,
    /// Exact Git branch head commit.
    GitBranchHead,
    /// Exact caller-owned Draft revision.
    DraftRevision,
    /// Exact state-machine state token.
    StateMachineState,
    /// Exact Provider generation/freshness token.
    ProviderFreshness,
}

/// Caller-required exact precondition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactPrecondition {
    /// Mechanical precondition class.
    pub kind: PreconditionKind,
    /// Exact target identity.
    pub target_ref: EntityRef,
    /// Optional exact caller selector.
    pub selector: Option<String>,
    /// Expected exact value/revision/generation token.
    pub expected: String,
    /// Evidence supporting the expected value.
    pub evidence_refs: Vec<EntityRef>,
}

/// Explicitly observed value for one precondition target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedPrecondition {
    /// Mechanical precondition class.
    pub kind: PreconditionKind,
    /// Exact target identity.
    pub target_ref: EntityRef,
    /// Optional exact selector.
    pub selector: Option<String>,
    /// Observed exact value/revision/generation token.
    pub observed: String,
    /// Evidence supporting the observation.
    pub evidence_refs: Vec<EntityRef>,
}

/// Exact expected-versus-observed precondition conflict evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreconditionConflict {
    /// Conflicting mechanical precondition class.
    pub kind: PreconditionKind,
    /// Exact target identity.
    pub target_ref: EntityRef,
    /// Optional exact selector.
    pub selector: Option<String>,
    /// Caller-required exact value.
    pub expected: String,
    /// Exact observed value, or `None` when no matching observation exists.
    pub observed: Option<String>,
    /// Evidence retained with the expectation.
    pub expected_evidence_refs: Vec<EntityRef>,
    /// Evidence retained with the observation.
    pub observed_evidence_refs: Vec<EntityRef>,
}

/// Compare expected and observed preconditions using exact mechanical identity only.
///
/// # Errors
/// Returns the first [`PreconditionConflict`] when a matching observation is
/// missing or its exact value differs. No refresh, fuzzy match, or reconciliation
/// is attempted.
pub fn evaluate_preconditions(
    expected: &[ExactPrecondition],
    observed: &[ObservedPrecondition],
) -> Result<(), Box<PreconditionConflict>> {
    for requirement in expected {
        let observation = observed.iter().find(|candidate| {
            candidate.kind == requirement.kind
                && candidate.target_ref == requirement.target_ref
                && candidate.selector == requirement.selector
        });
        match observation {
            Some(observation) if observation.observed == requirement.expected => {}
            Some(observation) => {
                return Err(Box::new(PreconditionConflict {
                    kind: requirement.kind,
                    target_ref: requirement.target_ref.clone(),
                    selector: requirement.selector.clone(),
                    expected: requirement.expected.clone(),
                    observed: Some(observation.observed.clone()),
                    expected_evidence_refs: requirement.evidence_refs.clone(),
                    observed_evidence_refs: observation.evidence_refs.clone(),
                }));
            }
            None => {
                return Err(Box::new(PreconditionConflict {
                    kind: requirement.kind,
                    target_ref: requirement.target_ref.clone(),
                    selector: requirement.selector.clone(),
                    expected: requirement.expected.clone(),
                    observed: None,
                    expected_evidence_refs: requirement.evidence_refs.clone(),
                    observed_evidence_refs: Vec::new(),
                }));
            }
        }
    }
    Ok(())
}
