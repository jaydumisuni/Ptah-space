use ptah_application_runtime::{
    ApplicationOperation, CompatibilityDecision, CompatibilityRequirement, D08Error,
    ExecutionDisposition, NodeLocalCompatibility, PlatformClass, RemoteNodeExecution,
    RemoteNodeRequirement, RequirementOutcome, require_remote_display,
};
use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_placement_runtime::{
    AuthorityBinding, FenceToken, Lease, PlacementMetadata, Reservation, authorize_dispatch,
};
use ptah_provider_api::ProviderGeneration;

const AUTH_NOW: u64 = 1_800_000_000;
const D08_NOW: &str = "2026-09-03T12:00:00Z";

fn evidence() -> EntityRef {
    EntityRef::new("proof.evidence").expect("valid evidence kind")
}

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid entity kind")
}

fn dispatch_authority(
    node_id: NodeId,
    generation: NodeGeneration,
    epoch: ConnectionEpoch,
) -> ptah_placement_runtime::DispatchAuthority {
    let binding = AuthorityBinding::new(entity("activity.attempt"), node_id, generation, epoch);
    let placement = PlacementMetadata::new(binding.clone());
    let reservation = Reservation::new(
        entity("resource.reservation"),
        binding.clone(),
        AUTH_NOW + 120,
    );
    let fence = FenceToken::new(1).expect("Fence");
    let lease = Lease::new(
        entity("isolation.lease"),
        reservation.reservation_ref().clone(),
        binding.clone(),
        fence,
        AUTH_NOW + 90,
    );
    authorize_dispatch(
        &placement,
        &reservation,
        Some(&lease),
        &binding,
        fence,
        AUTH_NOW,
    )
    .expect("validated E02 dispatch authority")
}

fn compatible_remote_node(
    node_id: NodeId,
    generation: NodeGeneration,
    epoch: ConnectionEpoch,
    operation: ApplicationOperation,
) -> NodeLocalCompatibility {
    NodeLocalCompatibility {
        compatibility_ref: entity("application.compatibility"),
        application_revision_ref: entity("application.application_revision"),
        operation,
        provider_revision_ref: entity("runtime.provider_revision"),
        provider_instance_ref: entity("runtime.provider_instance"),
        provider_generation: ProviderGeneration::new(1).expect("provider generation"),
        node_ref: node_id.entity_ref(generation, epoch),
        node_generation: generation.value(),
        node_capability_snapshot_ref: entity("runtime.node-capability-snapshot"),
        node_resource_snapshot_ref: entity("runtime.node-resource-snapshot"),
        requirements: vec![CompatibilityRequirement {
            key: "remote_platform_current".to_owned(),
            mandatory: true,
            outcome: RequirementOutcome::Satisfied,
            condition_refs: Vec::new(),
            evidence_refs: vec![evidence()],
            reason: None,
        }],
        decision: CompatibilityDecision::Compatible,
        condition_refs: Vec::new(),
        evaluated_at: "2026-09-03T11:00:00Z".to_owned(),
        valid_until: "2026-09-03T13:00:00Z".to_owned(),
        evidence_refs: vec![evidence()],
        limitations: Vec::new(),
    }
}

#[test]
fn d08_25_remote_display_requirement_remains_a_non_executing_programme_e_blocker() {
    let disposition = ExecutionDisposition::for_platform(
        PlatformClass::WindowsNode,
        ApplicationOperation::RemoteDisplay,
        None,
        vec![evidence()],
        D08_NOW,
    )
    .expect("remote platform should retain a Programme E blocker");
    let ExecutionDisposition::RequiresRemoteNode(requirement) = disposition else {
        panic!("remote display must not become an executable D08 session");
    };

    let retained: RemoteNodeRequirement =
        require_remote_display(&requirement).expect("blocker should remain mechanically visible");
    assert_eq!(retained, requirement);
    assert_eq!(retained.operation, ApplicationOperation::RemoteDisplay);
    assert_eq!(retained.roadmap_dependency, "Programme E");
    assert!(!retained.evidence_refs.is_empty());
}

#[test]
fn e02_current_remote_node_satisfies_only_the_programme_e_placement_authority_blocker() {
    let node_id = NodeId::new();
    let generation = NodeGeneration::new(7);
    let epoch = ConnectionEpoch::new(11);
    let authority = dispatch_authority(node_id, generation, epoch);
    let compatibility = compatible_remote_node(
        node_id,
        generation,
        epoch,
        ApplicationOperation::LaunchGraphical,
    );

    let disposition = ExecutionDisposition::for_remote_platform_with_authority(
        PlatformClass::WindowsNode,
        ApplicationOperation::LaunchGraphical,
        compatibility.clone(),
        authority.clone(),
        D08_NOW,
    )
    .expect("E02 authority should satisfy the placement blocker");
    let ExecutionDisposition::RemoteNodeReady(ready) = disposition else {
        panic!("validated E02 remote authority should be retained explicitly");
    };
    let ready: RemoteNodeExecution = *ready;
    assert_eq!(ready.platform(), PlatformClass::WindowsNode);
    assert_eq!(ready.compatibility(), &compatibility);
    assert_eq!(
        ready.dispatch_authority().binding().node_id(),
        node_id
    );
    assert_eq!(
        ready.dispatch_authority().binding().node_generation(),
        generation
    );
}

#[test]
fn mismatched_remote_node_authority_fails_closed_without_synthetic_session() {
    let authority_node = NodeId::new();
    let compatibility_node = NodeId::new();
    let generation = NodeGeneration::new(7);
    let epoch = ConnectionEpoch::new(11);
    let authority = dispatch_authority(authority_node, generation, epoch);
    let compatibility = compatible_remote_node(
        compatibility_node,
        generation,
        epoch,
        ApplicationOperation::LaunchGraphical,
    );

    assert!(matches!(
        ExecutionDisposition::for_remote_platform_with_authority(
            PlatformClass::WindowsNode,
            ApplicationOperation::LaunchGraphical,
            compatibility,
            authority,
            D08_NOW,
        ),
        Err(D08Error::RemoteNodeAuthorityMismatch)
    ));
}
