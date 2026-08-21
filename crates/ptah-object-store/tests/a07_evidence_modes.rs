fn create_evidence(
    runtime: &ActivityRuntime,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    mode: EvidenceMode,
) -> EvidenceBundle {
    create_evidence_for_target(
        runtime,
        workspace_ref,
        authority_ref,
        mode,
        reference("object.object"),
    )
}

fn create_evidence_for_target(
    runtime: &ActivityRuntime,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    mode: EvidenceMode,
    logical_target_ref: EntityRef,
) -> EvidenceBundle {
    let (activity_id, operation_id, attempt_id, context, nonce) =
        create_attempt_fixture(runtime, workspace_ref, authority_ref, logical_target_ref);
    let (receipt_ids, completion_receipt_id) = match mode {
        EvidenceMode::Register => {
            let output = append_receipt(
                runtime,
                activity_id,
                operation_id,
                attempt_id,
                &nonce,
                &context,
                ReceiptKind::OutputObservation,
                vec![ProofLevel::OutputCreated, ProofLevel::OperationCompleted],
                "output bytes observed for A07 registration",
            );
            let hash = append_receipt(
                runtime,
                activity_id,
                operation_id,
                attempt_id,
                &nonce,
                &context,
                ReceiptKind::HashVerification,
                vec![ProofLevel::OutputHashVerified],
                "SHA-256 independently verified before A07 registration",
            );
            (vec![output, hash], output)
        }
        EvidenceMode::Readback => {
            let readback = append_receipt(
                runtime,
                activity_id,
                operation_id,
                attempt_id,
                &nonce,
                &context,
                ReceiptKind::Readback,
                vec![ProofLevel::OutputReadBack, ProofLevel::OperationCompleted],
                "local CAS bytes independently read back",
            );
            (vec![readback], readback)
        }
        EvidenceMode::OutputOnly => {
            let output = append_receipt(
                runtime,
                activity_id,
                operation_id,
                attempt_id,
                &nonce,
                &context,
                ReceiptKind::OutputObservation,
                vec![ProofLevel::OutputCreated, ProofLevel::OperationCompleted],
                "A07 metadata output independently observed",
            );
            (vec![output], output)
        }
    };
    let receipt_refs = receipt_ids
        .iter()
        .map(|id| EntityRef::from_id(*id, "proof.receipt").expect("Receipt ref"))
        .collect();
    EvidenceBundle {
        production: ProductionEvidence {
            activity_ref: EntityRef::from_id(activity_id, "core.activity").expect("Activity ref"),
            operation_ref: EntityRef::from_id(operation_id, "core.operation")
                .expect("Operation ref"),
            attempt_ref: EntityRef::from_id(attempt_id, "core.attempt").expect("Attempt ref"),
            receipt_refs,
        },
        completion_receipt_id,
        activity_id,
        operation_id,
        attempt_id,
    }
}
