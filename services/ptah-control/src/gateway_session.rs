//! Retained mutual-TLS E01 enrollment sessions. No dispatch authority.
use crate::placement::PlacementAuthorityOwner;
use ptah_node_link::{
    AuthenticatedServerStream, Heartbeat, HelloAck, LinkError, LinkMessage, SessionBinding,
    TlsServerConfig, accept_tls, read_frame, write_frame,
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpStream, sync::Mutex};

const HANDSHAKE_LIMIT: Duration = Duration::from_secs(5);

/// Establish an authenticated session without holding the owner lock while
/// awaiting unauthenticated network input.
///
/// # Errors
/// Invalid TLS, Hello, enrollment, protocol or expired handshake.
pub async fn establish(
    socket: TcpStream,
    tls: &TlsServerConfig,
    owner: &Arc<Mutex<PlacementAuthorityOwner>>,
    now: u64,
) -> Result<(SessionBinding, AuthenticatedServerStream), LinkError> {
    establish_with_timeout(socket, tls, owner, now, HANDSHAKE_LIMIT).await
}

/// E01 session with a bounded, caller-selected *transport* timeout.
/// Only callers using slow external byte-pumps should override the default.
/// Peer certificate, enrollment and generation checks remain unchanged.
///
/// # Errors
/// Rejects failed TLS, invalid peer identity, expired enrollment, stale
/// session generation or bounded handshake transport timeouts.
pub async fn establish_with_timeout(
    socket: TcpStream,
    tls: &TlsServerConfig,
    owner: &Arc<Mutex<PlacementAuthorityOwner>>,
    now: u64,
    handshake_timeout: Duration,
) -> Result<(SessionBinding, AuthenticatedServerStream), LinkError> {
    let mut stream = tokio::time::timeout(handshake_timeout, accept_tls(socket, tls))
        .await
        .map_err(|_| LinkError::Io("E01 TLS timeout".into()))??;
    if !stream.is_tls13() {
        return Err(LinkError::TlsHandshake("TLS 1.3 required".into()));
    }
    let hello = tokio::time::timeout(handshake_timeout, read_frame(stream.stream_mut()))
        .await
        .map_err(|_| LinkError::Io("E01 Hello timeout".into()))??;
    let LinkMessage::Hello(hello) = hello else {
        return Err(LinkError::MalformedFrame("E01 expects Hello".into()));
    };
    // Re-evaluate time *after* TLS, Hello and waiting for the owner lock.
    // A client whose enrollment expires during negotiation is not admitted.
    let mut current = owner.lock().await;
    let actual_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LinkError::Io("invalid system time".into()))?
        .as_secs();
    let binding = current.accept_hello(&hello, stream.peer_fingerprint(), now.max(actual_now))?;
    drop(current);
    let ack = LinkMessage::HelloAck(HelloAck {
        selected_version: binding.negotiated_protocol,
        node_id: binding.node_id,
        node_generation: binding.node_generation,
        connection_epoch: binding.connection_epoch,
    });
    let sent = tokio::time::timeout(handshake_timeout, write_frame(stream.stream_mut(), &ack))
        .await
        .map_err(|_| LinkError::Io("E01 Ack timeout".into()));
    match sent {
        Ok(Ok(())) => Ok((binding, stream)),
        other => {
            owner.lock().await.end_session_if_current(&binding);
            other??;
            Err(LinkError::Io("E01 unexpected Ack state".into()))
        }
    }
}

/// Reject heartbeat replay, incorrect Node identity, generation or epoch.
///
/// # Errors
/// Wrong authority binding or non-increasing sequence.
pub fn validate_heartbeat(
    binding: &SessionBinding,
    beat: &Heartbeat,
    previous: u64,
) -> Result<(), LinkError> {
    if beat.node_id != binding.node_id {
        return Err(LinkError::NodeIdentityMismatch);
    }
    if beat.node_generation != binding.node_generation {
        return Err(LinkError::StaleNodeGeneration {
            current: binding.node_generation.value(),
            requested: beat.node_generation.value(),
        });
    }
    if beat.connection_epoch != binding.connection_epoch {
        return Err(LinkError::StaleConnectionEpoch {
            current: binding.connection_epoch.value(),
            requested: beat.connection_epoch.value(),
        });
    }
    if beat.sequence == 0 || beat.sequence <= previous {
        return Err(LinkError::MalformedFrame("replayed E01 heartbeat".into()));
    }
    Ok(())
}

/// Retain only a live authenticated E01 heartbeat channel. Any message that
/// could alter execution or capability authority is rejected.
///
/// # Errors
/// Stale/superseded session, replay, unexpected message or idle timeout.
pub async fn retain(
    mut stream: AuthenticatedServerStream,
    binding: &SessionBinding,
    owner: &Arc<Mutex<PlacementAuthorityOwner>>,
    idle: Duration,
) -> Result<(), LinkError> {
    let mut sequence = 0_u64;
    loop {
        let message = tokio::time::timeout(idle, read_frame(stream.stream_mut()))
            .await
            .map_err(|_| LinkError::Io("E01 idle timeout".into()))??;
        if !owner.lock().await.is_current_session(binding) {
            return Err(LinkError::SupersededConnection);
        }
        match message {
            LinkMessage::Heartbeat(beat) => {
                validate_heartbeat(binding, &beat, sequence)?;
                sequence = beat.sequence;
            }
            LinkMessage::Close => return Ok(()),
            _ => {
                return Err(LinkError::MalformedFrame(
                    "enrollment channel cannot accept dispatch or evidence".into(),
                ));
            }
        }
    }
}

/// Authenticate, retain, and revoke on disconnect, but never revoke a
/// superseding E01 session.
///
/// # Errors
/// Transport, authority, liveness, replay and malformed-frame failures.
pub async fn handle(
    socket: TcpStream,
    tls: &TlsServerConfig,
    owner: &Arc<Mutex<PlacementAuthorityOwner>>,
    now: u64,
    idle: Duration,
) -> Result<(), LinkError> {
    let (binding, stream) = establish(socket, tls, owner, now).await?;
    let result = retain(stream, &binding, owner, idle).await;
    owner.lock().await.end_session_if_current(&binding);
    result
}
