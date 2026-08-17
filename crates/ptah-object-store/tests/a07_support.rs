fn complete_evidence(runtime: &ActivityRuntime, evidence: &EvidenceBundle, result_ref: EntityRef) {
    runtime
        .complete_attempt(evidence.attempt_id, evidence.completion_receipt_id)
        .expect("complete Attempt");
    runtime
        .prove_operation_succeeded(
            evidence.operation_id,
            evidence.completion_receipt_id,
            vec![result_ref.clone()],
        )
        .expect("prove Operation");
    runtime
        .complete_activity(evidence.activity_id, vec![result_ref])
        .expect("complete Activity");
}

fn register_spec(
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    production: ProductionEvidence,
) -> RegisterObjectSpec {
    RegisterObjectSpec {
        workspace_ref: workspace_ref.clone(),
        authority_ref: authority_ref.clone(),
        object_class: "binary_blob".to_owned(),
        declared_name: Some("candidate.bin".to_owned()),
        source_refs: vec![reference("proof.evidence")],
        revision_role: RevisionRole::Generated,
        origin_class: OriginClass::Generated,
        created_reason: "A07 conformance candidate".to_owned(),
        production,
        expected_sha256: None,
    }
}

fn contains_ref(document: &serde_json::Value, field: &str, expected: &EntityRef) -> bool {
    document
        .get(field)
        .and_then(serde_json::Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|item| {
                serde_json::from_value::<EntityRef>(item.clone()).is_ok_and(|reference| {
                    reference.entity_id == expected.entity_id
                        && reference.entity_kind == expected.entity_kind
                })
            })
        })
}
