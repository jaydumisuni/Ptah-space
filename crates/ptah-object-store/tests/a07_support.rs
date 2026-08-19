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

fn ledger_document(ledger_path: &Path, entity_id: EntityId) -> serde_json::Value {
    let ledger = Ledger::open(ledger_path).expect("open A03 ledger for test inspection");
    ledger
        .latest_record(entity_id)
        .expect("read A03 record")
        .expect("canonical record retained")
        .document()
        .clone()
}

fn ledger_record_count(ledger_path: &Path) -> u64 {
    let connection = rusqlite::Connection::open(ledger_path).expect("open ledger for record count");
    connection
        .query_row("SELECT COUNT(*) FROM ptah_entity_records", [], |row| row.get(0))
        .expect("count canonical records")
}

fn mutate_latest_document(
    ledger_path: &Path,
    entity_id: EntityId,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let connection = rusqlite::Connection::open(ledger_path).expect("open ledger for tamper fixture");
    let (revision, document_json): (u64, String) = connection
        .query_row(
            "SELECT record_revision, document_json FROM ptah_entity_records WHERE entity_id = ?1 ORDER BY record_revision DESC LIMIT 1",
            [entity_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read latest canonical JSON for tamper fixture");
    let mut document: serde_json::Value =
        serde_json::from_str(&document_json).expect("decode canonical JSON for tamper fixture");
    mutate(&mut document);
    connection
        .execute(
            "UPDATE ptah_entity_records SET document_json = ?1 WHERE entity_id = ?2 AND record_revision = ?3",
            rusqlite::params![
                serde_json::to_string(&document).expect("encode tampered canonical JSON"),
                entity_id.to_string(),
                revision,
            ],
        )
        .expect("apply tamper fixture");
}

fn cas_object_path(cas_root: &Path, digest: &str) -> PathBuf {
    cas_root.join("sha256").join(&digest[..2]).join(digest)
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
