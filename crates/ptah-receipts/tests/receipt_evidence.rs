use ptah_identifiers::{EntityId, EntityRef};
use ptah_receipts::{
    AuthorityClass, ProofLevel, Receipt, ReceiptContext, ReceiptError, ReceiptKind, ReceiptOutcome,
    ReceiptSpec, ReceiptStore,
};

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
        occurred_at: "2026-08-16T16:45:00Z".to_owned(),
    }
}

#[test]
fn prepared_receipt_is_not_visible_before_explicit_publish() {
    let store = ReceiptStore::default();
    let receipt = Receipt::prepare(spec()).expect("prepare");
    assert!(store.is_empty().expect("empty"));
    store.publish(receipt).expect("publish");
    assert_eq!(store.len().expect("count"), 1);
}

#[test]
fn acknowledgement_is_not_operation_completion_proof() {
    let receipt = Receipt::prepare(spec()).expect("Receipt");
    assert!(receipt.proves(ProofLevel::Accepted));
    assert!(!receipt.proves(ProofLevel::OperationCompleted));
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
fn correction_requires_superseded_receipt_reference() {
    let mut corrected = spec();
    corrected.kind = ReceiptKind::Correction;
    corrected.outcome = ReceiptOutcome::Corrected;
    assert_eq!(
        Receipt::prepare(corrected),
        Err(ReceiptError::MissingSupersededReceipt)
    );
}
