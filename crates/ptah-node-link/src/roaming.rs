//! Optional outbound E07 rendezvous transport. Relay forwards opaque bytes;
//! E01 end-to-end mutual TLS still authenticates the actual peer.
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
/// Initial relay preface; intentionally not an authentication protocol.
pub const RELAY_PREFIX: &str = "PTAH-E07-RELAY-V1";
/// Ready message before the first opaque TLS byte.
pub const RELAY_READY: &[u8] = b"PTAH-E07-RELAY-READY\n";
/// Maximum wire preface size.
pub const MAX_HELLO: usize = 96;

/// Endpoint role for relay pairing (not a security authority).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayRole {
    /// Control presents its existing E01 TLS server.
    Control,
    /// Node presents its existing E01 TLS client.
    Node,
}
impl RelayRole {
    /// Single-byte wire role.
    #[must_use]
    pub fn code(self) -> char {
        match self {
            Self::Control => 'C',
            Self::Node => 'N',
        }
    }
}
/// Only bounded lower-case hexadecimal routing identifiers are accepted.
/// A route ID is NOT a credential and never admits a Ptah task.
#[must_use]
pub fn valid_route_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
}
/// Build a relay preface. No certificate/private key crosses the relay.
///
/// # Errors
/// Rejects malformed route identifiers rather than silently normalizing them.
pub fn hello(role: RelayRole, route: &str) -> Result<String, &'static str> {
    if !valid_route_id(route) {
        return Err("relay route ID must be 64 lower-case hex digits");
    }
    Ok(format!("{RELAY_PREFIX} {} {route}\n", role.code()))
}
/// Connect outbound to an internet reachable relay, pair, then hand the
/// resulting opaque stream to the existing E01 TLS code unchanged.
/// Does NOT issue permissions or perform a second workspace approval.
///
/// # Errors
/// Invalid local route ID, transport failure, pair timeout or invalid relay.
pub async fn connect(
    address: SocketAddr,
    role: RelayRole,
    route: &str,
) -> Result<TcpStream, String> {
    let preface = hello(role, route)?;
    let mut stream = tokio::time::timeout(Duration::from_secs(12), TcpStream::connect(address))
        .await
        .map_err(|_| "relay TCP connection timeout")?
        .map_err(|e| format!("relay TCP: {e}"))?;
    stream
        .write_all(preface.as_bytes())
        .await
        .map_err(|e| format!("relay preface: {e}"))?;
    let mut ready = [0_u8; RELAY_READY.len()];
    tokio::time::timeout(Duration::from_secs(190), stream.read_exact(&mut ready))
        .await
        .map_err(|_| "relay peer pairing timeout")?
        .map_err(|e| format!("relay pairing: {e}"))?;
    if ready != RELAY_READY {
        return Err("relay returned invalid READY response".into());
    }
    Ok(stream)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn route_is_not_a_permission_and_is_strictly_bounded() {
        let v = "0123456789abcdef".repeat(4);
        assert!(valid_route_id(&v));
        assert!(!valid_route_id(&v.to_uppercase()));
        assert!(!valid_route_id(&v[..63]));
        assert!(!valid_route_id(&format!("{v}\n")));
        assert!(
            hello(RelayRole::Node, &v)
                .unwrap()
                .starts_with("PTAH-E07-RELAY-V1 N ")
        );
        assert!(
            hello(RelayRole::Control, &v)
                .unwrap()
                .starts_with("PTAH-E07-RELAY-V1 C ")
        );
    }
}
