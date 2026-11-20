//! Production-oriented E01 Node gateway admission.
//! Certificate fingerprints come ONLY from the authenticated TLS 1.3 peer.
//! The existing canonical Ptah enrollment owner decides approval and session
//! freshness; neither a claimed Hello ID nor a local fixture grants authority.
use crate::placement::PlacementAuthorityOwner;
use ptah_node_link::{
    HelloAck, LinkError, LinkMessage, SessionBinding, TlsServerConfig, accept_tls, read_frame,
    write_frame,
};
use std::time::Duration;
use tokio::net::TcpStream;

/// Admit one mutually authenticated Node and send an exact E01 acknowledgement.
/// Returns no placement/dispatch rights; E05 and E02 remain separate owners.
///
/// # Errors
///
/// Rejects missing/invalid client certificates, unapproved or stale E01 Hello
/// bindings, invalid message framing, and unresponsive peers.
pub async fn admit_authenticated_node(
    socket: TcpStream,
    tls: &TlsServerConfig,
    owner: &mut PlacementAuthorityOwner,
    now_epoch_seconds: u64,
) -> Result<SessionBinding, LinkError> {
    let timeout = Duration::from_secs(5);
    let mut connection = tokio::time::timeout(timeout, accept_tls(socket, tls))
        .await
        .map_err(|_| LinkError::Io("TLS handshake timeout".into()))??;
    if !connection.is_tls13() {
        return Err(LinkError::TlsHandshake(String::from("TLS 1.3 is required")));
    }
    let message = tokio::time::timeout(timeout, read_frame(connection.stream_mut()))
        .await
        .map_err(|_| LinkError::Io("E01 Hello timeout".into()))??;
    let LinkMessage::Hello(hello) = message else {
        return Err(LinkError::MalformedFrame(String::from(
            "expected NodeHello",
        )));
    };
    let authenticated_fingerprint = connection.peer_fingerprint();
    let binding = owner.accept_hello(&hello, authenticated_fingerprint, now_epoch_seconds)?;
    let ack = HelloAck {
        selected_version: binding.negotiated_protocol,
        node_id: binding.node_id,
        node_generation: binding.node_generation,
        connection_epoch: binding.connection_epoch,
    };
    tokio::time::timeout(
        timeout,
        write_frame(connection.stream_mut(), &LinkMessage::HelloAck(ack)),
    )
    .await
    .map_err(|_| LinkError::Io("E01 acknowledgement timeout".into()))??;
    Ok(binding)
}
