//! Independent signed external-effect evidence for uncertain E02/A05 attempts.
//! Verification is read-only: a valid witness cannot mint fresh dispatch
//! authority, replay an Attempt, or bypass separate release acceptance.
use crate::gateway_control_journal::DispatchObservation;
use ring::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The witness message binds the external observation to one immutable Attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectObservation {
    /// Schema version for canonical signed receipt.
    pub schema: String,
    /// Identity of the separately trusted observer.
    pub witness_id: String,
    /// Serialized canonical Dispatch identity.
    pub dispatch: String,
    /// Serialized canonical Attempt identity.
    pub attempt: String,
    /// Exact original request digest.
    pub request_digest: String,
    /// Originating Node identity.
    pub node: String,
    /// Node Generation at execution.
    pub generation: u64,
    /// Authenticated E01 connection epoch.
    pub connection_epoch: u64,
    /// Control-issued E02 fence.
    pub fence: u64,
    /// A05 Provider Generation.
    pub provider_generation: u64,
    /// Externally observed process identity.
    pub process_identity: String,
    /// Observed host boot identity.
    pub boot_identity: String,
    /// Externally observed process exit code.
    pub observed_exit_code: i32,
    /// SHA-256 digest of independently observed process output.
    pub observed_stdout_digest: String,
    /// Independent observer's evidence source.
    pub observation_source: String,
}

/// Signature and exact pinned public-key identity supplied by an independent
/// witness service. The verifier does NOT trust a public key from the message.
#[derive(Debug, Clone)]
pub struct SignedEffectObservation {
    /// Immutable signed external-effect observation.
    pub observation: EffectObservation,
    /// Detached Ed25519 signature over canonical observation.
    pub signature: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
/// Verification failures that always retain an uncertain Attempt.
pub enum EffectVerificationError {
    /// Unrecognized observation schema.
    InvalidSchema,
    /// Missing or invalid required identity.
    InvalidIdentity,
    /// Noncanonical request or output digest.
    InvalidDigest,
    /// Control, Node, and witness Attempt identities disagree.
    IncorrectAttempt,
    /// Witness identity does not match pinned authority.
    UntrustedWitness,
    /// Detached signature fails against the pinned key.
    InvalidSignature,
    /// Node did not record a complete process exit.
    MissingNodeEvidence,
    /// Node and witness disagree on observed process effect.
    MismatchedNodeEvidence,
}

/// Exact authorized independent witness configuration, provisioned separately
/// from Node and Control certificates and not accepted from the wire.
pub struct TrustedWitness<'a> {
    /// Identity of the separately trusted observer.
    pub witness_id: &'a str,
    /// Pinned verification key supplied by the independent trust configuration.
    pub ed25519_public_key: &'a [u8; 32],
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
/// Canonical serialization of signed proof: domain-separated fixed-field order.
///
/// # Errors
/// Rejects empty identities, zero generations, or invalid content digests.
pub fn canonical_message(
    observation: &EffectObservation,
) -> Result<Vec<u8>, EffectVerificationError> {
    if observation.schema != "ptah.external-effect-witness.v1" {
        return Err(EffectVerificationError::InvalidSchema);
    }
    if [
        &observation.witness_id,
        &observation.dispatch,
        &observation.attempt,
        &observation.node,
        &observation.process_identity,
        &observation.boot_identity,
        &observation.observation_source,
    ]
    .iter()
    .any(|s| s.is_empty())
        || observation.generation == 0
        || observation.connection_epoch == 0
        || observation.fence == 0
        || observation.provider_generation == 0
    {
        return Err(EffectVerificationError::InvalidIdentity);
    }
    if !valid_sha256(&observation.request_digest)
        || !valid_sha256(&observation.observed_stdout_digest)
    {
        return Err(EffectVerificationError::InvalidDigest);
    }
    let body =
        serde_json::to_vec(observation).map_err(|_| EffectVerificationError::InvalidSchema)?;
    let mut message = b"PTAH/E07/INDEPENDENT-A05-EFFECT/V1\0".to_vec();
    message.extend_from_slice(&(body.len() as u64).to_be_bytes());
    message.extend_from_slice(&body);
    Ok(message)
}

/// Actual Node journal result supplied separately from the independent witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCompletion {
    /// Immutable canonical Attempt.
    pub attempt: String,
    /// Immutable canonical Node identity.
    pub node: String,
    /// Exact Node Generation.
    pub generation: u64,
    /// Exact E01 connection epoch.
    pub connection_epoch: u64,
    /// Exact original request digest.
    pub request_digest: String,
    /// Persisted Node attempt phase.
    pub phase: String,
    /// Control-issued E02 fence.
    pub fence: u64,
    /// Persisted A05 process exit code, if observed.
    pub exit_code: Option<i32>,
    /// Persisted A05 stdout digest, if complete.
    pub stdout_digest: Option<String>,
}

/// Verified receipt metadata remains *evidence*, never new execution authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEffectEvidence {
    /// SHA-256 of the independently verified canonical witness message.
    pub canonical_sha256: String,
    /// Identity of the separately trusted observer.
    pub witness_id: String,
}

/// Verify an independently signed observation against the Control journal and
/// actual Node-side completion fields. No persistent state is modified.
///
/// The caller must independently authorize and pin the witness public key.
/// A missing or ambiguous Node process result remains unresolved.
///
/// # Errors
/// Rejects forged, conflicting, stale, or incomplete evidence.
pub fn verify_effect(
    control: &DispatchObservation,
    node: &NodeCompletion,
    signed: &SignedEffectObservation,
    trusted: &TrustedWitness<'_>,
) -> Result<VerifiedEffectEvidence, EffectVerificationError> {
    let obs = &signed.observation;
    let canonical = canonical_message(obs)?;
    if obs.witness_id != trusted.witness_id {
        return Err(EffectVerificationError::UntrustedWitness);
    }
    if obs.attempt != node.attempt
        || obs.node != node.node
        || obs.generation != node.generation
        || obs.connection_epoch != node.connection_epoch
    {
        return Err(EffectVerificationError::IncorrectAttempt);
    }
    if obs.dispatch != control.dispatch
        || obs.attempt != control.attempt
        || obs.request_digest != control.request_digest
        || obs.fence != control.fence
        || obs.request_digest != node.request_digest
        || obs.fence != node.fence
    {
        return Err(EffectVerificationError::IncorrectAttempt);
    }
    if node.phase != "completed" || node.exit_code.is_none() || node.stdout_digest.is_none() {
        return Err(EffectVerificationError::MissingNodeEvidence);
    }
    if node.exit_code != Some(obs.observed_exit_code)
        || node.stdout_digest.as_deref() != Some(obs.observed_stdout_digest.as_str())
    {
        return Err(EffectVerificationError::MismatchedNodeEvidence);
    }
    UnparsedPublicKey::new(&signature::ED25519, trusted.ed25519_public_key)
        .verify(&canonical, &signed.signature)
        .map_err(|_| EffectVerificationError::InvalidSignature)?;
    Ok(VerifiedEffectEvidence {
        canonical_sha256: format!("sha256:{:x}", Sha256::digest(&canonical)),
        witness_id: obs.witness_id.clone(),
    })
}
