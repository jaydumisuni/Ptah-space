//! Control-owned E02 issuance over the authenticated current E01 Node connection.
//! No arbitrary external caller can supply a Reservation, Lease or Fence.
use crate::gateway_control_journal::{ControlDispatchJournal, ControlJournalError};
use crate::{
    node_link::{DispatchAuthorityFrames, build_dispatch_frames},
    placement::{PlacementAuthorityOwner, PlacementAuthorityTiming, PlacementControlError},
};
use ptah_identifiers::EntityRef;
use ptah_node_link::{
    AuthenticatedServerStream, LinkError, LinkMessage, SessionBinding, write_frame,
};
use ptah_placement_runtime::{PlacementPolicy, PlacementRequirement, ReservedResource};
use ptah_platform_admission::PlatformNodeClass;
use std::time::Duration;

const E02_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// Control dispatch denied; the caller must preserve the grant as uncertain
/// after any partial wire write. Never silently re-issue the same Attempt.
#[derive(Debug)]
pub enum ControlDispatchError {
    /// The Control's E01 enrollment no longer matches the active TLS peer.
    PeerBinding,
    /// No longer the canonical current session.
    StaleSession,
    /// Original E02 placement authority owner refused issuance.
    Placement(PlacementControlError),
    /// Selected Node/Generation/Epoch differs from the active TLS peer.
    WrongNode,
    /// A bounded E02 frame write failed; completion is now uncertain.
    Transport(LinkError),
    /// Durable Control attempt ownership could not be committed.
    Journal(ControlJournalError),
    /// A bounded E02 frame write timed out; completion is now uncertain.
    Timeout,
}
/// Mint placement authority exclusively through Ptah Control and transmit its
/// exact Reservation → Lease/Fence → Dispatch frames on the matched TLS link.
/// This does not create an executor, accept caller-issued leases, or claim
/// an execution receipt. On any transport failure, do not replay the Attempt.
///
/// # Errors
///
/// Rejects mismatched authenticated peer, stale session, unavailable E05
/// platform admission, invalid E02 placement or any bounded wire failure.
#[allow(clippy::too_many_arguments)]
pub async fn issue_and_send(
    owner: &mut PlacementAuthorityOwner,
    binding: &SessionBinding,
    stream: &mut AuthenticatedServerStream,
    platform: PlatformNodeClass,
    requirement: &PlacementRequirement,
    policy: PlacementPolicy,
    reserved: Vec<ReservedResource>,
    timing: PlacementAuthorityTiming,
    dispatch_ref: EntityRef,
    operation_ref: EntityRef,
    journal: &mut ControlDispatchJournal,
    request_digest: &str,
) -> Result<DispatchAuthorityFrames, ControlDispatchError> {
    if binding.credential_fingerprint != stream.peer_fingerprint() {
        return Err(ControlDispatchError::PeerBinding);
    }
    if !owner.is_current_session(binding) {
        return Err(ControlDispatchError::StaleSession);
    }
    let grant = owner
        .place_admitted_and_issue(platform, requirement, policy, reserved, timing)
        .map_err(ControlDispatchError::Placement)?;
    let frames = build_dispatch_frames(&grant, dispatch_ref, operation_ref);
    if frames.request.node_id != binding.node_id
        || frames.request.node_generation != binding.node_generation
        || frames.request.connection_epoch != binding.connection_epoch
    {
        return Err(ControlDispatchError::WrongNode);
    }
    journal
        .stage_issued(&frames, request_digest)
        .map_err(ControlDispatchError::Journal)?;
    // The grant has been issued; every subsequent failure is uncertain,
    // not an instruction to mint or send new authority.
    for frame in [
        LinkMessage::DispatchReservation(Box::new(frames.reservation.clone())),
        LinkMessage::DispatchLease(Box::new(frames.lease.clone())),
        LinkMessage::DispatchRequest(Box::new(frames.request.clone())),
    ] {
        tokio::time::timeout(E02_SEND_TIMEOUT, write_frame(stream.stream_mut(), &frame))
            .await
            .map_err(|_| ControlDispatchError::Timeout)?
            .map_err(ControlDispatchError::Transport)?;
    }
    journal
        .mark_sent(&frames)
        .map_err(ControlDispatchError::Journal)?;
    Ok(frames)
}
