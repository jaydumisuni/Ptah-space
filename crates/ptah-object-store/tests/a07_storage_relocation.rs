#[test]
fn moved_cas_root_preserves_artifact_and_revision_identity() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let registration_evidence =
        create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let artifact_ref;
    let registration;
    {
        let mut store = ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock())
            .expect("open A07");
        registration = store
            .register_bytes(
                b"relocatable artifact bytes",
                register_spec(
                    &workspace,
                    &authority,
                    registration_evidence.production.clone(),
                ),
            )
            .expect("register");
        artifact_ref = store
            .promote_artifact(
                registration.revision_ref.entity_id,
                ArtifactPromotionSpec {
                    workspace_ref: workspace.clone(),
                    authority_ref: authority.clone(),
                    artifact_type: "relocatable_output".to_owned(),
                    artifact_version: "1.0.0".to_owned(),
                    purpose: "prove backend path is not Artifact identity".to_owned(),
                    subject_refs: Vec::new(),
                    production: registration_evidence.production.clone(),
                },
            )
            .expect("promote");
    }

    fs::rename(temp.cas(), temp.moved_cas()).expect("move local CAS root");
    let store = ObjectStore::open(temp.ledger(), temp.moved_cas(), config(), fixed_clock())
        .expect("reopen moved CAS");
    assert_eq!(
        store
            .read_revision(registration.revision_ref.entity_id)
            .expect("read relocated bytes"),
        b"relocatable artifact bytes"
    );
    let artifact = store.latest(artifact_ref.entity_id).expect("same Artifact");
    let artifact_id_text = artifact_ref.entity_id.to_string();
    let revision_id_text = registration.revision_ref.entity_id.to_string();
    assert_eq!(
        artifact
            .get("envelope")
            .and_then(|value| value.get("entity_id"))
            .and_then(serde_json::Value::as_str),
        Some(artifact_id_text.as_str())
    );
    assert_eq!(
        artifact
            .get("promoted_revision_refs")
            .and_then(serde_json::Value::as_array)
            .and_then(|items| items.first())
            .and_then(|value| value.get("entity_id"))
            .and_then(serde_json::Value::as_str),
        Some(revision_id_text.as_str())
    );
}
