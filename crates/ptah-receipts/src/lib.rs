#![forbid(unsafe_code)]
//! Immutable A04 Receipt evidence.
//!
//! A Receipt is append-only evidence for one exact Activity/Operation/Attempt
//! execution context. An acknowledgement Receipt never becomes completion proof
//! merely because it was delivered.

use ptah_identifiers::{EntityId, EntityRef};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use thiserror::Error;

/// Frozen Receipt schema identifier.
pub const RECEIPT_SCHEMA_ID: &str = "urn:ptah:schema:activity:receipt:0.1.0";
/// Frozen Receipt schema version.
pub const RECEIPT_SCHEMA_VERSION: &str = "0.1.0";
/// Frozen Receipt entity kind.
pub const RECEIPT_ENTITY_KIND: &str = "proof.receipt";

/// Receipt kind from the frozen Activity proof contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    RequestAcknowledgement,
    Routing,
    WorkDispatch,
    ProcessObservation,
    RuntimeObservation,
    OperationObservation,
    ProgressCheckpoint,
    OutputObservation,
    Readback,
    HashVerification,
    ExternalResult,
    Review,
    Correction,
}

/// Receipt outcome from the frozen Activity proof contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOutcome {
    Positive,
    Negative,
    Partial,
    Inconclusive,
    Corrected,
    Superseded,
}

/// Evidence authority class from the frozen Receipt contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityClass {
    CallerClaim,
    PtahControlPlane,
    PtahNode,
    WorkspaceProvider,
    FacilityRuntime,
    OperatingSystem,
    PhysicalDevice,
    ExternalProvider,
    HumanConfirmation,
    IndependentReviewer,
    AuthoritativeExternalSystem,
}

/// Bounded proof levels evaluated by A04.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofLevel {
    Requested,
    Accepted,
    Routed,
    Dispatched,
    ProcessStarted,
    InterfaceLaunched,
    RuntimeReady,
    OperationArmed,
    ProgressObserved,
    OperationCompleted,
    OutputCreated,
    OutputReadBack,
    OutputHashVerified,
    ExternalResultRecorded,
    AuthoritativeExternalResult,
    IndependentlyReviewed,
}

/// Exact physical execution context bound into every Receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptContext {
    pub activity_ref: EntityRef,
    pub operation_ref: EntityRef,
    pub attempt_ref: EntityRef,
    pub idempotency_key: Option<String>,
    pub correlation_nonce: String,
    pub node_ref: EntityRef,
    pub node_generation: u64,
    pub provider_ref: EntityRef,
    pub provider_generation: u64,
    pub workload_generation: u64,
    pub connection_epoch: u64,
    pub facility_ref: EntityRef,
    pub producer_instance_ref: EntityRef,
    pub producer_version: String,
}

/// Input for one immutable Receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptSpec {
    pub kind: ReceiptKind,
    pub outcome: ReceiptOutcome,
    pub authority_class: AuthorityClass,
    pub context: ReceiptContext,
    pub producer_identity_evidence_refs: Vec<EntityRef>,
    pub proof_claim_refs: Vec<EntityRef>,
    /// A04's evaluated bounded proof-level projection. Durable claim identities
    /// remain `proof_claim_refs`; this set is not a substitute for those claims.
    pub proof_levels: Vec<ProofLevel>,
    pub previous_or_superseded_receipt_refs: Vec<EntityRef>,
    pub summary: String,
    pub limitations: Vec<String>,
    pub occurred_at: String,
}

/// One immutable Receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    id: EntityId,
    spec: ReceiptSpec,
}

impl Receipt {
    /// Validate and construct a Receipt without publishing it to a repository.
    /// This lets callers persist canonical truth before exposing the projection.
    pub fn prepare(spec: ReceiptSpec) -> Result<Self, ReceiptError> {
        Self::prepare_with_id(EntityId::new_v7(), spec)
    }

    /// Validate and construct a Receipt with an explicit canonical identity.
    pub fn prepare_with_id(id: EntityId, spec: ReceiptSpec) -> Result<Self, ReceiptError> {
        validate_spec(&spec)?;
        Ok(Self { id, spec })
    }

    /// Canonical Receipt identity.
    #[must_use]
    pub const fn id(&self) -> EntityId {
        self.id
    }

    /// Exact execution context.
    #[must_use]
    pub const fn context(&self) -> &ReceiptContext {
        &self.spec.context
    }

    /// Receipt kind.
    #[must_use]
    pub const fn kind(&self) -> ReceiptKind {
        self.spec.kind
    }

    /// Receipt outcome.
    #[must_use]
    pub const fn outcome(&self) -> ReceiptOutcome {
        self.spec.outcome
    }

    /// Whether this positive Receipt explicitly represents `level`.
    #[must_use]
    pub fn proves(&self, level: ProofLevel) -> bool {
        self.spec.outcome == ReceiptOutcome::Positive && self.spec.proof_levels.contains(&level)
    }

    /// Render the frozen canonical Receipt document for A03 journaling.
    #[must_use]
    pub fn canonical_document(&self) -> Value {
        let context = &self.spec.context;
        json!({
            "envelope": entity_envelope(self.id, &self.spec.occurred_at, &context.producer_instance_ref),
            "receipt_contract_version": RECEIPT_SCHEMA_VERSION,
            "receipt_kind": self.spec.kind,
            "receipt_outcome": self.spec.outcome,
            "authority_class": self.spec.authority_class,
            "activity_ref": context.activity_ref,
            "operation_ref": context.operation_ref,
            "attempt_ref": context.attempt_ref,
            "idempotency_key": context.idempotency_key,
            "correlation_nonce": context.correlation_nonce,
            "node_ref": context.node_ref,
            "node_generation": context.node_generation,
            "provider_ref": context.provider_ref,
            "provider_generation": context.provider_generation,
            "workload_generation": context.workload_generation,
            "connection_epoch": context.connection_epoch,
            "facility_ref": context.facility_ref,
            "producer_instance_ref": context.producer_instance_ref,
            "producer_version": context.producer_version,
            "producer_identity_evidence_refs": self.spec.producer_identity_evidence_refs,
            "proof_claim_refs": self.spec.proof_claim_refs,
            "occurred_at": self.spec.occurred_at,
            "observed_at": self.spec.occurred_at,
            "received_at": self.spec.occurred_at,
            "summary": self.spec.summary,
            "input_refs": [],
            "output_refs": [],
            "artifact_refs": [],
            "checkpoint_refs": [],
            "content_hashes": [],
            "event_refs": [],
            "previous_or_superseded_receipt_refs": self.spec.previous_or_superseded_receipt_refs,
            "signature_or_attestation_refs": [],
            "limitations": self.spec.limitations,
            "payload_class": "none",
            "extensions": {}
        })
    }

    /// Consume the immutable Receipt back into its validated specification.
    #[must_use]
    pub fn into_spec(self) -> ReceiptSpec {
        self.spec
    }
}

/// Append-only in-memory Receipt repository used by the A04 runtime projection.
#[derive(Debug, Clone, Default)]
pub struct ReceiptStore {
    inner: Arc<RwLock<HashMap<EntityId, Receipt>>>,
}

impl ReceiptStore {
    /// Append a newly allocated Receipt.
    pub fn append(&self, spec: ReceiptSpec) -> Result<Receipt, ReceiptError> {
        let receipt = Receipt::prepare(spec)?;
        self.publish(receipt)
    }

    /// Append with an explicit identity for replay/recovery collision detection.
    pub fn append_with_id(&self, id: EntityId, spec: ReceiptSpec) -> Result<Receipt, ReceiptError> {
        let receipt = Receipt::prepare_with_id(id, spec)?;
        self.publish(receipt)
    }

    /// Publish an already validated Receipt into the append-only repository.
    pub fn publish(&self, receipt: Receipt) -> Result<Receipt, ReceiptError> {
        let mut receipts = self.inner.write().map_err(|_| ReceiptError::Poisoned)?;
        if receipts.contains_key(&receipt.id) {
            return Err(ReceiptError::DuplicateIdentity(receipt.id));
        }
        receipts.insert(receipt.id, receipt.clone());
        Ok(receipt)
    }

    /// Read one Receipt by canonical identity.
    pub fn get(&self, id: EntityId) -> Result<Option<Receipt>, ReceiptError> {
        Ok(self
            .inner
            .read()
            .map_err(|_| ReceiptError::Poisoned)?
            .get(&id)
            .cloned())
    }

    /// Read Receipts bound to one exact Attempt.
    pub fn for_attempt(&self, attempt_id: EntityId) -> Result<Vec<Receipt>, ReceiptError> {
        Ok(self
            .inner
            .read()
            .map_err(|_| ReceiptError::Poisoned)?
            .values()
            .filter(|receipt| receipt.spec.context.attempt_ref.entity_id == attempt_id)
            .cloned()
            .collect())
    }

    /// Number of retained immutable Receipts.
    pub fn len(&self) -> Result<usize, ReceiptError> {
        Ok(self
            .inner
            .read()
            .map_err(|_| ReceiptError::Poisoned)?
            .len())
    }

    /// Whether no Receipt has been retained.
    pub fn is_empty(&self) -> Result<bool, ReceiptError> {
        Ok(self.len()? == 0)
    }
}

/// Receipt validation/storage failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReceiptError {
    #[error("Receipt identity already exists: {0}")]
    DuplicateIdentity(EntityId),
    #[error("correlation nonce must contain 8..=512 characters")]
    InvalidCorrelationNonce,
    #[error("idempotency key must contain 8..=512 characters when present")]
    InvalidIdempotencyKey,
    #[error("Receipt must carry at least one durable proof-claim reference")]
    MissingProofClaims,
    #[error("correction/corrected/superseded Receipt requires a prior Receipt reference")]
    MissingSupersededReceipt,
    #[error("Receipt reference arrays must not contain duplicates")]
    DuplicateReferences,
    #[error("Receipt summary must contain 1..=8192 characters")]
    EmptySummary,
    #[error("Receipt producer version must contain 1..=256 characters")]
    EmptyProducerVersion,
    #[error("Receipt limitation must contain 1..=4096 characters")]
    InvalidLimitation,
    #[error("Receipt store state is unavailable")]
    Poisoned,
}

fn validate_spec(spec: &ReceiptSpec) -> Result<(), ReceiptError> {
    let nonce_len = spec.context.correlation_nonce.len();
    if !(8..=512).contains(&nonce_len) {
        return Err(ReceiptError::InvalidCorrelationNonce);
    }
    if let Some(key) = &spec.context.idempotency_key {
        if !(8..=512).contains(&key.len()) {
            return Err(ReceiptError::InvalidIdempotencyKey);
        }
    }
    if spec.proof_claim_refs.is_empty() {
        return Err(ReceiptError::MissingProofClaims);
    }
    if matches!(spec.kind, ReceiptKind::Correction)
        || matches!(
            spec.outcome,
            ReceiptOutcome::Corrected | ReceiptOutcome::Superseded
        )
    {
        if spec.previous_or_superseded_receipt_refs.is_empty() {
            return Err(ReceiptError::MissingSupersededReceipt);
        }
    }
    if has_duplicates(&spec.producer_identity_evidence_refs)
        || has_duplicates(&spec.proof_claim_refs)
        || has_duplicates(&spec.previous_or_superseded_receipt_refs)
    {
        return Err(ReceiptError::DuplicateReferences);
    }
    if spec.summary.trim().is_empty() || spec.summary.len() > 8192 {
        return Err(ReceiptError::EmptySummary);
    }
    if spec.context.producer_version.trim().is_empty() || spec.context.producer_version.len() > 256 {
        return Err(ReceiptError::EmptyProducerVersion);
    }
    if spec
        .limitations
        .iter()
        .any(|item| item.trim().is_empty() || item.len() > 4096)
    {
        return Err(ReceiptError::InvalidLimitation);
    }
    Ok(())
}

fn has_duplicates(refs: &[EntityRef]) -> bool {
    refs.iter()
        .enumerate()
        .any(|(index, item)| refs[index + 1..].contains(item))
}

fn entity_envelope(id: EntityId, timestamp: &str, authority_ref: &EntityRef) -> Value {
    json!({
        "entity_id": id,
        "entity_kind": RECEIPT_ENTITY_KIND,
        "schema_id": RECEIPT_SCHEMA_ID,
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "record_revision": 1,
        "created_at": timestamp,
        "updated_at": timestamp,
        "global_scope": "ptah_global",
        "authority_ref": authority_ref,
        "privacy_class": "internal",
        "audience": "organization",
        "redaction_policy": "none",
        "retention_policy": {
            "policy_id": "ptah.a04.receipt",
            "policy_version": "0.1.0",
            "retention_class": "historical"
        },
        "extensions": {}
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(kind: &str) -> EntityRef {
        EntityRef::new(kind).expect("valid reference")
    }

    fn spec() -> ReceiptSpec {
        ReceiptSpec {
            kind: ReceiptKind::RequestAcknowledgement,
            outcome: ReceiptOutcome::Positive,
            authority_class: AuthorityClass::PtahNode,
            context: ReceiptContext {
                activity_ref: reference("core.activity"),
                operation_ref: reference("core.operation"),
                attempt_ref: reference("core.attempt"),
                idempotency_key: Some("operation-key-0001".to_owned()),
                correlation_nonce: "nonce-0001".to_owned(),
                node_ref: reference("core.node"),
                node_generation: 7,
                provider_ref: reference("runtime.provider"),
                provider_generation: 3,
                workload_generation: 11,
                connection_epoch: 5,
                facility_ref: reference("runtime.facility"),
                producer_instance_ref: reference("runtime.provider_instance"),
                producer_version: "1.0.0".to_owned(),
            },
            producer_identity_evidence_refs: vec![reference("proof.evidence")],
            proof_claim_refs: vec![reference("proof.claim")],
            proof_levels: vec![ProofLevel::Accepted],
            previous_or_superseded_receipt_refs: Vec::new(),
            summary: "producer acknowledged the request".to_owned(),
            limitations: vec!["acknowledgement is not completion proof".to_owned()],
            occurred_at: "2026-08-16T16:00:00Z".to_owned(),
        }
    }

    #[test]
    fn duplicate_receipt_identity_fails_closed() {
        let store = ReceiptStore::default();
        let id = EntityId::new_v7();
        store.append_with_id(id, spec()).expect("first append");
        assert_eq!(
            store.append_with_id(id, spec()),
            Err(ReceiptError::DuplicateIdentity(id))
        );
    }

    #[test]
    fn acknowledgement_does_not_prove_operation_completed() {
        let receipt = ReceiptStore::default().append(spec()).expect("Receipt");
        assert!(receipt.proves(ProofLevel::Accepted));
        assert!(!receipt.proves(ProofLevel::OperationCompleted));
    }

    #[test]
    fn exact_context_is_retained() {
        let receipt = ReceiptStore::default().append(spec()).expect("Receipt");
        assert_eq!(receipt.context().correlation_nonce, "nonce-0001");
        assert_eq!(receipt.context().node_generation, 7);
        assert_eq!(receipt.context().provider_generation, 3);
        assert_eq!(receipt.context().workload_generation, 11);
        assert_eq!(receipt.context().connection_epoch, 5);
    }

    #[test]
    fn prepared_receipt_is_not_published_until_explicitly_committed() {
        let store = ReceiptStore::default();
        let receipt = Receipt::prepare(spec()).expect("prepare");
        assert!(store.is_empty().expect("empty"));
        store.publish(receipt).expect("publish");
        assert_eq!(store.len().expect("count"), 1);
    }

    #[test]
    fn correction_requires_prior_receipt_reference() {
        let mut corrected = spec();
        corrected.kind = ReceiptKind::Correction;
        corrected.outcome = ReceiptOutcome::Corrected;
        assert_eq!(
            Receipt::prepare(corrected),
            Err(ReceiptError::MissingSupersededReceipt)
        );
    }
}
