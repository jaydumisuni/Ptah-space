//! E02 Task 3 advisory Node-offer tests.

use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_agent::{
    Architecture, NodeCapabilitySnapshot, NodeResourceSnapshot, OsFamily, PlatformFacts,
    ResourcePressure, ResourceQuantity, ResourceUnit, SnapshotOutcome,
};
use ptah_node_link::{
    CredentialFingerprint, NodeOfferFrame, OfferedResource, ProtocolVersion, SessionBinding,
};
use ptah_placement_runtime::{OfferError, validate_offer};

const NOW: u64 = 1_800_000_000;
const FUTURE: u64 = NOW + 30;

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid entity kind")
}

fn make_session() -> SessionBinding {
    SessionBinding {
        node_id: NodeId::new(),
        node_generation: NodeGeneration::new(7),
        connection_epoch: ConnectionEpoch::new(11),
        enrollment_ref: entity("security.node-enrollment"),
        credential_fingerprint: CredentialFingerprint::from_der(b"e02-offer-credential"),
        negotiated_protocol: ProtocolVersion { major: 1, minor: 0 },
    }
}

fn capability_snapshot(session: &SessionBinding) -> NodeCapabilitySnapshot {
    NodeCapabilitySnapshot::new(
        session
            .node_id
            .entity_ref(session.node_generation, session.connection_epoch),
        session.node_generation,
        session.connection_epoch,
        SnapshotOutcome::Complete,
        "e02-offer-agent",
        PlatformFacts {
            os_family: OsFamily::Linux,
            os_name: Some("Test Linux".to_owned()),
            os_version: Some("1".to_owned()),
            kernel_name: Some("test".to_owned()),
            kernel_version: Some("1".to_owned()),
            architecture: Architecture::X86_64,
            architecture_detail: None,
        },
        vec![entity("runtime.capability")],
        vec![entity("runtime.capability-verification")],
        vec![entity("runtime.provider-revision")],
        vec![entity("runtime.node-observation")],
        vec![entity("proof.receipt")],
        Vec::new(),
    )
    .expect("capability snapshot")
}

fn resource_snapshot(session: &SessionBinding) -> NodeResourceSnapshot {
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
            consumed: 2.0,
            currently_available: 6.0,
            pressure: ResourcePressure::Normal,
            observation_refs: vec![entity("runtime.node-observation")],
        }],
        vec![entity("runtime.node-observation")],
        vec![entity("proof.receipt")],
        Vec::new(),
    )
    .expect("resource snapshot")
}

fn offer(
    session: &SessionBinding,
    capabilities: &NodeCapabilitySnapshot,
    resources: &NodeResourceSnapshot,
) -> NodeOfferFrame {
    NodeOfferFrame {
        offer_ref: entity("placement.node-offer"),
        node_id: session.node_id,
        node_generation: session.node_generation,
        connection_epoch: session.connection_epoch,
        capability_snapshot_ref: capabilities.snapshot_ref.clone(),
        resource_snapshot_ref: resources.snapshot_ref.clone(),
        offered_resources: vec![OfferedResource {
            resource_key: "cpu".to_owned(),
            unit: ResourceUnit::Cores,
            quantity: 4.0,
        }],
        load_score: Some(20),
        locality: Some("local".to_owned()),
        valid_until_unix_seconds: FUTURE,
        nonce: 1,
    }
}

#[test]
fn offer_is_bound_to_exact_session_and_current_evidence_refs() {
    let session = make_session();
    let capabilities = capability_snapshot(&session);
    let resources = resource_snapshot(&session);
    let wire = offer(&session, &capabilities, &resources);

    let validated = validate_offer(&session, &wire, &capabilities, &resources, NOW)
        .expect("current advisory offer");

    assert_eq!(validated.node_id(), session.node_id);
    assert_eq!(validated.node_generation(), session.node_generation);
    assert_eq!(validated.connection_epoch(), session.connection_epoch);
    assert_eq!(validated.capability_snapshot_ref(), &capabilities.snapshot_ref);
    assert_eq!(validated.resource_snapshot_ref(), &resources.snapshot_ref);
    assert!(!validated.authorizes_dispatch());
}

#[test]
fn expired_offer_is_ineligible() {
    let session = make_session();
    let capabilities = capability_snapshot(&session);
    let resources = resource_snapshot(&session);
    let mut wire = offer(&session, &capabilities, &resources);
    wire.valid_until_unix_seconds = NOW;

    assert_eq!(
        validate_offer(&session, &wire, &capabilities, &resources, NOW),
        Err(OfferError::Expired)
    );
}

#[test]
fn cross_node_offer_fails_closed() {
    let current = make_session();
    let other = make_session();
    let capabilities = capability_snapshot(&current);
    let resources = resource_snapshot(&current);
    let wire = offer(&other, &capabilities, &resources);

    assert_eq!(
        validate_offer(&current, &wire, &capabilities, &resources, NOW),
        Err(OfferError::NodeIdentityMismatch)
    );
}

#[test]
fn stale_or_wrong_evidence_refs_fail_closed() {
    let session = make_session();
    let capabilities = capability_snapshot(&session);
    let resources = resource_snapshot(&session);

    let mut wrong_capability = offer(&session, &capabilities, &resources);
    wrong_capability.capability_snapshot_ref = entity("runtime.node-capability-snapshot");
    assert_eq!(
        validate_offer(&session, &wrong_capability, &capabilities, &resources, NOW),
        Err(OfferError::CapabilityEvidenceMismatch)
    );

    let mut wrong_resource = offer(&session, &capabilities, &resources);
    wrong_resource.resource_snapshot_ref = entity("runtime.node-resource-snapshot");
    assert_eq!(
        validate_offer(&session, &wrong_resource, &capabilities, &resources, NOW),
        Err(OfferError::ResourceEvidenceMismatch)
    );
}

#[test]
fn malformed_offer_nonce_and_capacity_fail_closed() {
    let session = make_session();
    let capabilities = capability_snapshot(&session);
    let resources = resource_snapshot(&session);

    let mut zero_nonce = offer(&session, &capabilities, &resources);
    zero_nonce.nonce = 0;
    assert_eq!(
        validate_offer(&session, &zero_nonce, &capabilities, &resources, NOW),
        Err(OfferError::InvalidNonce)
    );

    let mut invalid_capacity = offer(&session, &capabilities, &resources);
    invalid_capacity.offered_resources[0].quantity = 0.0;
    assert_eq!(
        validate_offer(&session, &invalid_capacity, &capabilities, &resources, NOW),
        Err(OfferError::InvalidOfferedResource)
    );
}
