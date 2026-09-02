#![allow(missing_docs)]
use ptah_activity_runtime::{IdempotencyClass, RetryClass, SideEffectClass};
use ptah_identifiers::EntityRef;
use ptah_recipe_registry::{
    D04Error, OperationCatalog, OperationDescriptorRevision, OperationEffectClass,
};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid reference")
}

fn descriptor(key: &str, provider_generation: u64) -> OperationDescriptorRevision {
    OperationDescriptorRevision {
        operation_key: key.to_owned(),
        descriptor_version: "1.0.0".to_owned(),
        facility_revision_ref: reference("runtime.facility_revision"),
        provider_revision_ref: reference("runtime.provider_revision"),
        provider_instance_ref: Some(reference("runtime.provider_instance")),
        provider_generation: Some(provider_generation),
        freshness_token: Some(format!("generation-{provider_generation}")),
        capability_refs: vec![reference("core.capability")],
        input_schema_refs: Vec::new(),
        output_schema_refs: Vec::new(),
        effect: OperationEffectClass::Observe,
        a04_side_effect: SideEffectClass::ObservationOnly,
        retry_class: RetryClass::RetrySafe,
        idempotency_class: IdempotencyClass::NoneRequired,
        required_grant_refs: Vec::new(),
        caller_approval_required: false,
        materialization_required: false,
        supported_preconditions: Vec::new(),
        expected_receipt_states: vec!["operation_completed".to_owned()],
        limits: Vec::new(),
    }
}

#[test]
fn exposes_exact_adr0037_effect_vocabulary() {
    assert_eq!(OperationEffectClass::ALL.len(), 7);
    assert_eq!(
        serde_json::to_value(OperationEffectClass::ALL).expect("serialize"),
        serde_json::json!([
            "observe",
            "draft",
            "simulate",
            "mutate",
            "publish",
            "destructive",
            "external_side_effect"
        ])
    );
}

#[test]
fn incompatible_effect_and_a04_side_effect_fails_closed() {
    let mut value = descriptor("workspace.delete", 4);
    value.effect = OperationEffectClass::Destructive;
    value.a04_side_effect = SideEffectClass::ObservationOnly;
    assert!(matches!(
        value.validate(),
        Err(D04Error::EffectCompatibility { .. })
    ));
}

#[test]
fn descriptor_digest_is_deterministic_and_revision_bound() {
    let first = descriptor("source.search", 2);
    let same = first.clone();
    let mut changed_generation = first.clone();
    changed_generation.provider_generation = Some(3);
    changed_generation.freshness_token = Some("generation-3".to_owned());
    assert_eq!(first.digest().expect("digest"), same.digest().expect("digest"));
    assert_ne!(
        first.digest().expect("digest"),
        changed_generation.digest().expect("digest")
    );
}

#[test]
fn catalog_retains_ambiguity_instead_of_selecting_provider() {
    let mut catalog = OperationCatalog::default();
    catalog
        .register(descriptor("source.search", 2))
        .expect("first");
    catalog
        .register(descriptor("source.search", 3))
        .expect("second");
    let result = catalog
        .resolve("source.search", None, None)
        .expect("lookup");
    assert!(result.is_ambiguous());
    assert_eq!(result.candidates().len(), 2);
}
