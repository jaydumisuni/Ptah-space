//! E02 Task 2 deterministic placement eligibility and scoring tests.

use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_agent::{
    Architecture, NodeCapabilitySnapshot, NodeResourceSnapshot, OsFamily, PlatformFacts,
    ResourcePressure, ResourceQuantity, ResourceUnit, SnapshotOutcome,
};
use ptah_node_link::{CredentialFingerprint, ProtocolVersion, SessionBinding};
use ptah_placement_runtime::{
    CandidateRejection, PlacementPolicy, PlacementRequirement, ResourceRequirement,
    evaluate_candidate, select_candidate,
};

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid test entity kind")
}

fn make_session() -> SessionBinding {
    SessionBinding {
        node_id: NodeId::new(),
        node_generation: NodeGeneration::new(7),
        connection_epoch: ConnectionEpoch::new(11),
        enrollment_ref: entity("security.node-enrollment"),
        credential_fingerprint: CredentialFingerprint::from_der(b"e02-test-credential"),
        negotiated_protocol: ProtocolVersion { major: 1, minor: 0 },
    }
}

fn capability_snapshot(
    session: &SessionBinding,
    capabilities: Vec<EntityRef>,
    providers: Vec<EntityRef>,
) -> NodeCapabilitySnapshot {
    let verification_refs = if capabilities.is_empty() {
        Vec::new()
    } else {
        vec![entity("runtime.capability-verification")]
    };
    NodeCapabilitySnapshot::new(
        session
            .node_id
            .entity_ref(session.node_generation, session.connection_epoch),
        session.node_generation,
        session.connection_epoch,
        SnapshotOutcome::Complete,
        "e02-test-agent",
        PlatformFacts {
            os_family: OsFamily::Linux,
            os_name: Some("Test Linux".to_owned()),
            os_version: Some("1".to_owned()),
            kernel_name: Some("test".to_owned()),
            kernel_version: Some("1".to_owned()),
            architecture: Architecture::X86_64,
            architecture_detail: None,
        },
        capabilities,
        verification_refs,
        providers,
        vec![entity("runtime.node-observation")],
        vec![entity("proof.receipt")],
        Vec::new(),
    )
    .expect("valid capability snapshot")
}

fn resource_snapshot(
    session: &SessionBinding,
    available: f64,
    pressure: ResourcePressure,
) -> NodeResourceSnapshot {
    NodeResourceSnapshot::new(
        session
            .node_id
            .entity_ref(session.node_generation, session.connection_epoch),
        session.node_generation,
        session.connection_epoch,
        SnapshotOutcome::Complete,
        vec![ResourceQuantity {
            resource_key: "cpu".to_owned(),
            unit: ResourceUnit::Cores,
            observed_total: 8.0,
            administratively_allocatable: 8.0,
            reserved: 0.0,
            consumed: 8.0 - available,
            currently_available: available,
            pressure,
            observation_refs: vec![entity("runtime.node-observation")],
        }],
        vec![entity("runtime.node-observation")],
        vec![entity("proof.receipt")],
        Vec::new(),
    )
    .expect("valid resource snapshot")
}

fn requirement(capability: EntityRef, provider: EntityRef) -> PlacementRequirement {
    PlacementRequirement::new(
        entity("activity.attempt"),
        vec![capability],
        vec![provider],
        vec![
            ResourceRequirement::new("cpu", ResourceUnit::Cores, 2.0)
                .expect("resource requirement"),
        ],
        Some(OsFamily::Linux),
    )
}

#[test]
fn exact_current_session_and_snapshots_are_eligible() {
    let session = make_session();
    let capability = entity("runtime.capability");
    let provider = entity("runtime.provider-revision");
    let capabilities =
        capability_snapshot(&session, vec![capability.clone()], vec![provider.clone()]);
    let resources = resource_snapshot(&session, 6.0, ResourcePressure::Normal);

    let candidate = evaluate_candidate(
        &session,
        &capabilities,
        &resources,
        &requirement(capability, provider),
        PlacementPolicy::strict(),
    )
    .expect("eligible candidate");

    assert_eq!(candidate.node_id(), session.node_id);
    assert_eq!(candidate.node_generation(), session.node_generation);
    assert_eq!(candidate.connection_epoch(), session.connection_epoch);
}

#[test]
fn snapshot_node_identity_generation_and_epoch_mismatches_fail_closed() {
    let session = make_session();
    let capability = entity("runtime.capability");
    let provider = entity("runtime.provider-revision");
    let requirement = requirement(capability.clone(), provider.clone());
    let resources = resource_snapshot(&session, 6.0, ResourcePressure::Normal);

    let other_session = make_session();
    let wrong_node = capability_snapshot(
        &other_session,
        vec![capability.clone()],
        vec![provider.clone()],
    );
    assert_eq!(
        evaluate_candidate(
            &session,
            &wrong_node,
            &resources,
            &requirement,
            PlacementPolicy::strict()
        ),
        Err(CandidateRejection::NodeIdentityMismatch)
    );

    let mut wrong_generation =
        capability_snapshot(&session, vec![capability.clone()], vec![provider.clone()]);
    wrong_generation.node_generation = NodeGeneration::new(session.node_generation.value() + 1);
    assert_eq!(
        evaluate_candidate(
            &session,
            &wrong_generation,
            &resources,
            &requirement,
            PlacementPolicy::strict()
        ),
        Err(CandidateRejection::NodeGenerationMismatch)
    );

    let mut wrong_epoch = capability_snapshot(&session, vec![capability], vec![provider]);
    wrong_epoch.connection_epoch = ConnectionEpoch::new(session.connection_epoch.value() + 1);
    assert_eq!(
        evaluate_candidate(
            &session,
            &wrong_epoch,
            &resources,
            &requirement,
            PlacementPolicy::strict()
        ),
        Err(CandidateRejection::ConnectionEpochMismatch)
    );
}

#[test]
fn missing_required_capability_is_ineligible() {
    let session = make_session();
    let required = entity("runtime.capability");
    let provider = entity("runtime.provider-revision");
    let capabilities = capability_snapshot(&session, Vec::new(), vec![provider.clone()]);
    let resources = resource_snapshot(&session, 6.0, ResourcePressure::Normal);

    assert_eq!(
        evaluate_candidate(
            &session,
            &capabilities,
            &resources,
            &requirement(required, provider),
            PlacementPolicy::strict(),
        ),
        Err(CandidateRejection::MissingCapability)
    );
}

#[test]
fn missing_required_provider_revision_is_ineligible() {
    let session = make_session();
    let capability = entity("runtime.capability");
    let required_provider = entity("runtime.provider-revision");
    let capabilities = capability_snapshot(&session, vec![capability.clone()], Vec::new());
    let resources = resource_snapshot(&session, 6.0, ResourcePressure::Normal);

    assert_eq!(
        evaluate_candidate(
            &session,
            &capabilities,
            &resources,
            &requirement(capability, required_provider),
            PlacementPolicy::strict(),
        ),
        Err(CandidateRejection::MissingProviderRevision)
    );
}

#[test]
fn insufficient_requested_resource_is_ineligible() {
    let session = make_session();
    let capability = entity("runtime.capability");
    let provider = entity("runtime.provider-revision");
    let capabilities =
        capability_snapshot(&session, vec![capability.clone()], vec![provider.clone()]);
    let resources = resource_snapshot(&session, 1.0, ResourcePressure::Normal);

    assert_eq!(
        evaluate_candidate(
            &session,
            &capabilities,
            &resources,
            &requirement(capability, provider),
            PlacementPolicy::strict(),
        ),
        Err(CandidateRejection::InsufficientResource)
    );
}

#[test]
fn strict_policy_rejects_critical_and_unavailable_resource_pressure() {
    let session = make_session();
    let capability = entity("runtime.capability");
    let provider = entity("runtime.provider-revision");
    let capabilities =
        capability_snapshot(&session, vec![capability.clone()], vec![provider.clone()]);
    let requirement = requirement(capability, provider);

    for (pressure, expected) in [
        (
            ResourcePressure::Critical,
            CandidateRejection::CriticalResourcePressure,
        ),
        (
            ResourcePressure::Unavailable,
            CandidateRejection::UnavailableResource,
        ),
    ] {
        let resources = resource_snapshot(&session, 6.0, pressure);
        assert_eq!(
            evaluate_candidate(
                &session,
                &capabilities,
                &resources,
                &requirement,
                PlacementPolicy::strict(),
            ),
            Err(expected)
        );
    }
}

#[test]
fn deterministic_scoring_prefers_lower_pressure_for_identical_requirements() {
    let first = make_session();
    let second = make_session();
    let capability = entity("runtime.capability");
    let provider = entity("runtime.provider-revision");
    let requirement = requirement(capability.clone(), provider.clone());

    let first_candidate = evaluate_candidate(
        &first,
        &capability_snapshot(&first, vec![capability.clone()], vec![provider.clone()]),
        &resource_snapshot(&first, 6.0, ResourcePressure::Normal),
        &requirement,
        PlacementPolicy::strict(),
    )
    .expect("first eligible");
    let second_candidate = evaluate_candidate(
        &second,
        &capability_snapshot(&second, vec![capability], vec![provider]),
        &resource_snapshot(&second, 6.0, ResourcePressure::Elevated),
        &requirement,
        PlacementPolicy::strict(),
    )
    .expect("second eligible");

    for _ in 0..8 {
        let selected =
            select_candidate([second_candidate.clone(), first_candidate.clone()]).expect("winner");
        assert_eq!(selected.node_id(), first.node_id);
    }
}

#[test]
fn canonical_node_identity_is_final_stable_tie_break() {
    let first = make_session();
    let second = make_session();
    let capability = entity("runtime.capability");
    let provider = entity("runtime.provider-revision");
    let requirement = requirement(capability.clone(), provider.clone());

    let first_candidate = evaluate_candidate(
        &first,
        &capability_snapshot(&first, vec![capability.clone()], vec![provider.clone()]),
        &resource_snapshot(&first, 6.0, ResourcePressure::Normal),
        &requirement,
        PlacementPolicy::strict(),
    )
    .expect("first eligible");
    let second_candidate = evaluate_candidate(
        &second,
        &capability_snapshot(&second, vec![capability], vec![provider]),
        &resource_snapshot(&second, 6.0, ResourcePressure::Normal),
        &requirement,
        PlacementPolicy::strict(),
    )
    .expect("second eligible");

    let expected = first.node_id.min(second.node_id);
    let forward = select_candidate([first_candidate.clone(), second_candidate.clone()])
        .expect("forward winner");
    let reverse = select_candidate([second_candidate, first_candidate]).expect("reverse winner");
    assert_eq!(forward.node_id(), expected);
    assert_eq!(reverse.node_id(), expected);
}
