//! Opaque E07 roaming rendezvous. Does not interpret Ptah workspace requests,
//! issue E02 fences, authenticate users or decrypt end-to-end E01 mutual TLS.
//! Both Control and Node dial OUTBOUND, so neither needs an inbound NAT port.
#![forbid(unsafe_code)]
use ptah_node_link::roaming::{RELAY_PREFIX, RELAY_READY, valid_route_id};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore},
};
const MAX_WAITING: usize = 64;
const WAIT: Duration = Duration::from_mins(3);
const MAX_ACTIVE: usize = 64;
struct Waiting {
    role: u8,
    stream: TcpStream,
    id: u64,
}
struct State {
    pending: Mutex<HashMap<String, Waiting>>,
    ids: AtomicU64,
    active: Arc<Semaphore>,
}
async fn receive_hello(stream: &mut TcpStream) -> Result<(u8, String), String> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        tokio::time::timeout(Duration::from_secs(8), stream.read_exact(&mut byte))
            .await
            .map_err(|_| "relay preface timeout")?
            .map_err(|e| format!("relay preface: {e}"))?;
        if byte[0] == b'\n' {
            break;
        }
        if line.len() >= 95 {
            return Err("relay preface too long".into());
        }
        line.push(byte[0]);
    }
    let text = std::str::from_utf8(&line).map_err(|_| "bad relay preface")?;
    let mut words = text.split_ascii_whitespace();
    if words.next() != Some(RELAY_PREFIX) {
        return Err("wrong relay protocol".into());
    }
    let role = match words.next() {
        Some("C") => b'C',
        Some("N") => b'N',
        _ => return Err("invalid relay role".into()),
    };
    let route = words.next().ok_or("missing relay route")?;
    if words.next().is_some() || !valid_route_id(route) {
        return Err("invalid relay route".into());
    }
    Ok((role, route.into()))
}
async fn handle(mut stream: TcpStream, state: Arc<State>) -> Result<(), String> {
    let (role, route) = receive_hello(&mut stream).await?;
    let id = state.ids.fetch_add(1, Ordering::Relaxed);
    let mut pending = state.pending.lock().await;
    if let Some(waiting) = pending.get(&route) {
        if waiting.role == role {
            return Err("same-role relay pair rejected".into());
        }
        let peer = pending.remove(&route).ok_or("relay pair removed")?;
        drop(pending);
        let permit = state
            .active
            .clone()
            .try_acquire_owned()
            .map_err(|_| "relay active-pair capacity reached")?;
        let mut first = peer.stream;
        first
            .write_all(RELAY_READY)
            .await
            .map_err(|e| e.to_string())?;
        stream
            .write_all(RELAY_READY)
            .await
            .map_err(|e| e.to_string())?;
        // After READY no relay framing exists. All forwarded application
        // data is end-to-end E01 mutual TLS ciphertext.
        let _permit = permit;
        let _ = tokio::time::timeout(
            Duration::from_mins(10),
            tokio::io::copy_bidirectional(&mut first, &mut stream),
        )
        .await;
        return Ok(());
    }
    if pending.len() >= MAX_WAITING {
        return Err("relay pending-pair capacity reached".into());
    }
    pending.insert(route.clone(), Waiting { role, stream, id });
    drop(pending);
    let expiry = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(WAIT).await;
        let mut cache = expiry.pending.lock().await;
        if cache.get(&route).is_some_and(|entry| entry.id == id) {
            cache.remove(&route);
        }
    });
    Ok(())
}
async fn serve(listener: TcpListener) -> std::io::Result<()> {
    let state = Arc::new(State {
        pending: Mutex::new(HashMap::new()),
        ids: AtomicU64::new(1),
        active: Arc::new(Semaphore::new(MAX_ACTIVE)),
    });
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = handle(stream, state).await {
                eprintln!("ptah-e07-relay: transport condition: {error}");
            }
        });
    }
}
#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args().collect();
    let result = async {
        if args.len() != 3 || args[1] != "--listen" {
            return Err("usage: ptah-e07-relay --listen <relay-public-listener-ip:port>");
        }
        let addr: SocketAddr = args[2].parse().map_err(|_| "invalid relay bind")?;
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|_| "cannot bind relay")?;
        eprintln!(
            "ptah-e07-relay: listening on {}",
            listener.local_addr().map_err(|_| "listener addr")?
        );
        serve(listener).await.map_err(|_| "relay accept failed")
    }
    .await;
    if let Err(msg) = result {
        eprintln!("ptah-e07-relay: {msg}");
        std::process::exit(2);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ptah_node_link::roaming::{self, RelayRole};
    #[tokio::test]
    async fn opaque_dual_outbound_pipe_preserves_binary_and_rejects_duplicate_role() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve(listener));
        let key = "ab".repeat(32);
        let control = tokio::spawn({
            let key = key.clone();
            async move {
                roaming::connect(addr, RelayRole::Control, &key)
                    .await
                    .unwrap()
            }
        });
        let mut node = roaming::connect(addr, RelayRole::Node, &key).await.unwrap();
        let mut c = control.await.unwrap();
        c.write_all(&[0, 1, 2, 0xfe, 0xff]).await.unwrap();
        let mut buffer = [0; 5];
        node.read_exact(&mut buffer).await.unwrap();
        assert_eq!(buffer, [0, 1, 2, 0xfe, 0xff]);
        node.write_all(&[40, 0, 33]).await.unwrap();
        let mut out = [0; 3];
        c.read_exact(&mut out).await.unwrap();
        assert_eq!(out, [40, 0, 33]);
        task.abort();
    }

    #[tokio::test]
    async fn existing_e01_mutual_tls_and_binary_frames_survive_untrusted_relay() {
        use ptah_node_link::{
            CredentialFingerprint, LinkMessage, TlsClientConfig, TlsIdentity, TlsServerConfig,
            TlsTrustRoots, accept_tls, connect_tls, read_frame, write_frame,
        };
        const CA: &[u8] =
            include_bytes!("../../../../crates/ptah-node-link/tests/fixtures/ca.cert.der");
        const SERVER: &[u8] =
            include_bytes!("../../../../crates/ptah-node-link/tests/fixtures/server.cert.der");
        const SERVER_KEY: &[u8] =
            include_bytes!("../../../../crates/ptah-node-link/tests/fixtures/server.key.der");
        const CLIENT: &[u8] =
            include_bytes!("../../../../crates/ptah-node-link/tests/fixtures/client.cert.der");
        const CLIENT_KEY: &[u8] =
            include_bytes!("../../../../crates/ptah-node-link/tests/fixtures/client.key.der");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let relay = tokio::spawn(serve(listener));
        let route = "19".repeat(32);
        let control = tokio::spawn({
            let route = route.clone();
            async move {
                let tcp = roaming::connect(address, RelayRole::Control, &route)
                    .await
                    .unwrap();
                let server = TlsServerConfig::new(
                    TlsIdentity::from_der(vec![SERVER.to_vec()], SERVER_KEY.to_vec()).unwrap(),
                    TlsTrustRoots::from_der(vec![CA.to_vec()]).unwrap(),
                )
                .unwrap();
                let mut tls = accept_tls(tcp, &server).await.unwrap();
                assert!(tls.is_tls13());
                assert_eq!(
                    tls.peer_fingerprint(),
                    CredentialFingerprint::from_der(CLIENT)
                );
                assert_eq!(
                    read_frame(tls.stream_mut()).await.unwrap(),
                    LinkMessage::Close
                );
                write_frame(tls.stream_mut(), &LinkMessage::Close)
                    .await
                    .unwrap();
            }
        });
        let tcp = roaming::connect(address, RelayRole::Node, &route)
            .await
            .unwrap();
        let client = TlsClientConfig::new(
            TlsIdentity::from_der(vec![CLIENT.to_vec()], CLIENT_KEY.to_vec()).unwrap(),
            TlsTrustRoots::from_der(vec![CA.to_vec()]).unwrap(),
        )
        .unwrap();
        let mut tls = connect_tls(tcp, "localhost", &client).await.unwrap();
        assert!(tls.is_tls13());
        write_frame(tls.stream_mut(), &LinkMessage::Close)
            .await
            .unwrap();
        assert_eq!(
            read_frame(tls.stream_mut()).await.unwrap(),
            LinkMessage::Close
        );
        control.await.unwrap();
        relay.abort();
    }
    #[tokio::test]
    async fn bad_protocol_and_oversize_are_closed_without_touching_other_routes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve(listener));
        let mut bad = TcpStream::connect(addr).await.unwrap();
        bad.write_all(b"INVALID C 123\n").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), bad.read_u8())
                .await
                .unwrap()
                .is_err()
        );
        task.abort();
    }
}
