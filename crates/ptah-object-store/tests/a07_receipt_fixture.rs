#[allow(clippy::too_many_arguments)]
fn append_receipt(
    runtime: &ActivityRuntime,
    activity_id: EntityId,
    operation_id: EntityId,
    attempt_id: EntityId,
    nonce: &str,
    context: &AttemptContext,
    kind: ReceiptKind,
    proof_levels: Vec<ProofLevel>,
    summary: &str,
) -> EntityId {
    runtime
        .append_receipt(ReceiptSpec {
            kind,
            outcome: ReceiptOutcome::Positive,
            authority_class: AuthorityClass::FacilityRuntime,
            context: ReceiptContext {
                activity_ref: EntityRef::from_id(activity_id, "core.activity").expect("Activity"),
                operation_ref: EntityRef::from_id(operation_id, "core.operation")
                    .expect("Operation"),
                attempt_ref: EntityRef::from_id(attempt_id, "core.attempt").expect("Attempt"),
                idempotency_key: None,
                correlation_nonce: nonce.to_owned(),
                node_ref: context.node_ref.clone(),
                node_generation: context.node_generation,
                provider_ref: context.provider_ref.clone(),
                provider_generation: context.provider_generation,
                workload_generation: context.workload_generation,
                connection_epoch: context.connection_epoch,
                facility_ref: context.facility_ref.clone(),
                producer_instance_ref: context.producer_instance_ref.clone(),
                producer_version: context.producer_version.clone(),
            },
            producer_identity_evidence_refs: vec![reference("proof.evidence")],
            proof_claim_refs: vec![reference("proof.claim")],
            proof_levels,
            previous_or_superseded_receipt_refs: Vec::new(),
            summary: summary.to_owned(),
            limitations: Vec::new(),
            occurred_at: NOW.to_owned(),
        })
        .expect("append Receipt")
}
