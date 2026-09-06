use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_placement_runtime::{
    AuthorityBinding, AuthorityError, FenceToken, Lease, PlacementMetadata, Reservation,
    authorize_dispatch,
};

const NOW: u64 = 1_800_000_000;
const FUTURE: u64 = NOW + 60;

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid test entity kind")
}

fn binding() -> AuthorityBinding {
    AuthorityBinding::new(
        entity("activity.attempt"),
        NodeId::new(),
        NodeGeneration::new(7),
        ConnectionEpoch::new(11),
    )
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
fn fence_token_is_positive_and_monotonic() {
    assert_eq!(FenceToken::new(0), Err(AuthorityError::InvalidFenceToken));

    let one = FenceToken::new(1).expect("positive fence");
    let two = FenceToken::new(2).expect("positive fence");
    assert_eq!(two.require_newer_than(one), Ok(()));
    assert_eq!(one.require_newer_than(one), Err(AuthorityError::StaleFence));
    assert_eq!(one.require_newer_than(two), Err(AuthorityError::StaleFence));
}

#[test]
fn reservation_is_bound_to_exact_attempt_node_generation_and_epoch() {
    let expected = binding();
    let reservation = reservation(&expected);

    assert_eq!(reservation.binding(), &expected);
    assert_eq!(reservation.binding().attempt_ref(), expected.attempt_ref());
    assert_eq!(reservation.binding().node_id(), expected.node_id());
    assert_eq!(reservation.binding().node_generation(), expected.node_generation());
    assert_eq!(reservation.binding().connection_epoch(), expected.connection_epoch());
}

#[test]
fn lease_is_bound_to_reservation_attempt_node_and_fence() {
    let expected = binding();
    let reservation = reservation(&expected);
    let fence = FenceToken::new(3).expect("fence");
    let lease = lease(&expected, &reservation, fence);

    assert_eq!(lease.reservation_ref(), reservation.reservation_ref());
    assert_eq!(lease.binding(), &expected);
    assert_eq!(lease.fence(), fence);
}

#[test]
fn placement_metadata_without_lease_cannot_authorize_dispatch() {
    let expected = binding();
    let placement = PlacementMetadata::new(expected.clone());
    let reservation = reservation(&expected);
    let fence = FenceToken::new(1).expect("fence");

    let result = authorize_dispatch(&placement, &reservation, None, &expected, fence, NOW);
    assert_eq!(result, Err(AuthorityError::MissingLease));
}

#[test]
fn matching_unexpired_reservation_and_lease_authorize_dispatch() {
    let expected = binding();
    let placement = PlacementMetadata::new(expected.clone());
    let reservation = reservation(&expected);
    let fence = FenceToken::new(4).expect("fence");
    let lease = lease(&expected, &reservation, fence);

    let authority = authorize_dispatch(
        &placement,
        &reservation,
        Some(&lease),
        &expected,
        fence,
        NOW,
    )
    .expect("matching current authority");

    assert_eq!(authority.binding(), &expected);
    assert_eq!(authority.reservation_ref(), reservation.reservation_ref());
    assert_eq!(authority.lease_ref(), lease.lease_ref());
    assert_eq!(authority.fence(), fence);
}

#[test]
fn stale_fence_fails_closed() {
    let expected = binding();
    let placement = PlacementMetadata::new(expected.clone());
    let reservation = reservation(&expected);
    let stale = FenceToken::new(4).expect("fence");
    let current = FenceToken::new(5).expect("fence");
    let lease = lease(&expected, &reservation, stale);

    assert_eq!(
        authorize_dispatch(
            &placement,
            &reservation,
            Some(&lease),
            &expected,
            current,
            NOW,
        ),
        Err(AuthorityError::StaleFence)
    );
}

#[test]
fn expired_reservation_and_lease_fail_closed() {
    let expected = binding();
    let placement = PlacementMetadata::new(expected.clone());
    let fence = FenceToken::new(1).expect("fence");

    let expired_reservation = Reservation::new(
        entity("resource.reservation"),
        expected.clone(),
        NOW,
    );
    let lease_for_expired_reservation = lease(&expected, &expired_reservation, fence);
    assert_eq!(
        authorize_dispatch(
            &placement,
            &expired_reservation,
            Some(&lease_for_expired_reservation),
            &expected,
            fence,
            NOW,
        ),
        Err(AuthorityError::ExpiredReservation)
    );

    let current_reservation = reservation(&expected);
    let expired_lease = Lease::new(
        entity("isolation.lease"),
        current_reservation.reservation_ref().clone(),
        expected.clone(),
        fence,
        NOW,
    );
    assert_eq!(
        authorize_dispatch(
            &placement,
            &current_reservation,
            Some(&expired_lease),
            &expected,
            fence,
            NOW,
        ),
        Err(AuthorityError::ExpiredLease)
    );
}

#[test]
fn wrong_attempt_fails_closed() {
    let expected = binding();
    let placement = PlacementMetadata::new(expected.clone());
    let reservation = reservation(&expected);
    let fence = FenceToken::new(1).expect("fence");
    let wrong = AuthorityBinding::new(
        entity("activity.attempt"),
        expected.node_id(),
        expected.node_generation(),
        expected.connection_epoch(),
    );
    let lease = lease(&wrong, &reservation, fence);

    assert_eq!(
        authorize_dispatch(
            &placement,
            &reservation,
            Some(&lease),
            &expected,
            fence,
            NOW,
        ),
        Err(AuthorityError::AttemptMismatch)
    );
}

#[test]
fn wrong_node_generation_fails_closed() {
    let expected = binding();
    let placement = PlacementMetadata::new(expected.clone());
    let reservation = reservation(&expected);
    let fence = FenceToken::new(1).expect("fence");
    let wrong = AuthorityBinding::new(
        expected.attempt_ref().clone(),
        expected.node_id(),
        NodeGeneration::new(expected.node_generation().value() + 1),
        expected.connection_epoch(),
    );
    let lease = lease(&wrong, &reservation, fence);

    assert_eq!(
        authorize_dispatch(
            &placement,
            &reservation,
            Some(&lease),
            &expected,
            fence,
            NOW,
        ),
        Err(AuthorityError::NodeGenerationMismatch)
    );
}

#[test]
fn wrong_connection_epoch_fails_closed() {
    let expected = binding();
    let placement = PlacementMetadata::new(expected.clone());
    let reservation = reservation(&expected);
    let fence = FenceToken::new(1).expect("fence");
    let wrong = AuthorityBinding::new(
        expected.attempt_ref().clone(),
        expected.node_id(),
        expected.node_generation(),
        ConnectionEpoch::new(expected.connection_epoch().value() + 1),
    );
    let lease = lease(&wrong, &reservation, fence);

    assert_eq!(
        authorize_dispatch(
            &placement,
            &reservation,
            Some(&lease),
            &expected,
            fence,
            NOW,
        ),
        Err(AuthorityError::ConnectionEpochMismatch)
    );
}
