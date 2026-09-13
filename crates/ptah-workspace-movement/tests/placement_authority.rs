//! E04 exact E02 target authority composition.

use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_placement_runtime::{
    AuthorityBinding, AuthorityError, FenceToken, Lease, PlacementMetadata, Reservation,
};
use ptah_workspace_movement::{
    PreparedWorkspaceMove, WorkspaceMoveError, WorkspaceMoveEvidence, WorkspaceMovePhase,
    WorkspaceMover,
};

const NOW: u64 = 1_800_000_000;
const FUTURE: u64 = NOW + 60;

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid entity kind")
}

fn binding() -> AuthorityBinding {
    AuthorityBinding::new(
        entity("activity.attempt"),
        NodeId::new(),
        NodeGeneration::new(7),
        ConnectionEpoch::new(11),
    )
}

fn prepared() -> PreparedWorkspaceMove {
    PreparedWorkspaceMove {
        phase: WorkspaceMovePhase::AwaitingPlacement,
        evidence: WorkspaceMoveEvidence {
            source_archive_sha256: "a".repeat(64),
            checkpoint_bundle_ref: "checkpoint:e04".to_owned(),
            workspace_ref: "workspace:e04".to_owned(),
            workspace_revision_ref: "workspace-revision:e04".to_owned(),
        },
    }
}

fn reservation(binding: &AuthorityBinding) -> Reservation {
    Reservation::new(entity("resource.reservation"), binding.clone(), FUTURE)
}

fn lease(binding: &AuthorityBinding, reservation: &Reservation, fence: FenceToken) -> Lease {
    Lease::new(
        entity("isolation.lease"),
        reservation.reservation_ref().clone(),
        binding.clone(),
        fence,
        FUTURE,
    )
}

#[test]
fn target_admission_requires_a_current_exact_e02_lease_and_fence() {
    let expected = binding();
    let placement = PlacementMetadata::new(expected.clone());
    let reservation = reservation(&expected);
    let fence = FenceToken::new(4).expect("positive fence");

    let missing = WorkspaceMover::admit_target(
        prepared(),
        &placement,
        &reservation,
        None,
        &expected,
        fence,
        NOW,
    );
    assert_eq!(
        missing,
        Err(WorkspaceMoveError::Placement(AuthorityError::MissingLease))
    );

    let stale_lease = lease(
        &expected,
        &reservation,
        FenceToken::new(3).expect("positive fence"),
    );
    let stale = WorkspaceMover::admit_target(
        prepared(),
        &placement,
        &reservation,
        Some(&stale_lease),
        &expected,
        fence,
        NOW,
    );
    assert_eq!(
        stale,
        Err(WorkspaceMoveError::Placement(AuthorityError::StaleFence))
    );

    let current_lease = lease(&expected, &reservation, fence);
    let admitted = WorkspaceMover::admit_target(
        prepared(),
        &placement,
        &reservation,
        Some(&current_lease),
        &expected,
        fence,
        NOW,
    )
    .expect("current E02 authority");

    assert_eq!(admitted.phase, WorkspaceMovePhase::Transferring);
    assert_eq!(admitted.target.binding, expected);
    assert_eq!(
        admitted.target.reservation_ref,
        reservation.reservation_ref().clone()
    );
    assert_eq!(admitted.target.lease_ref, current_lease.lease_ref().clone());
    assert_eq!(admitted.target.fence, fence);
    assert_eq!(admitted.source.workspace_ref, "workspace:e04");
}

#[test]
fn target_admission_rejects_a_different_node_generation() {
    let expected = binding();
    let wrong = AuthorityBinding::new(
        expected.attempt_ref().clone(),
        expected.node_id(),
        NodeGeneration::new(expected.node_generation().value() + 1),
        expected.connection_epoch(),
    );
    let placement = PlacementMetadata::new(wrong);
    let reservation = reservation(&expected);
    let fence = FenceToken::new(4).expect("positive fence");
    let current_lease = lease(&expected, &reservation, fence);

    let result = WorkspaceMover::admit_target(
        prepared(),
        &placement,
        &reservation,
        Some(&current_lease),
        &expected,
        fence,
        NOW,
    );

    assert_eq!(
        result,
        Err(WorkspaceMoveError::Placement(
            AuthorityError::NodeGenerationMismatch
        ))
    );
}
