//! Real E03 TLS byte transfer connected to Ptah E07 signed candidate readback.
//! Hermetic, temporary keys and loopback only: NOT physical two-Node approval.
use ptah_control::formula_readback::witness_candidate;
use ptah_control::gateway_control_journal::DispatchObservation;
use ptah_control::gateway_witness::{
    EffectObservation, NodeCompletion, SignedEffectObservation, TrustedWitness, canonical_message,
};
use ptah_formula_work_cells::{FormulaDispatchCustody, preflight_with_custody};
use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_link::{
    CredentialFingerprint, TlsClientConfig, TlsIdentity, TlsServerConfig, TlsTrustRoots,
    accept_tls, connect_tls,
};
use ptah_node_transfer::{
    DirectSourceSession, DirectTargetSession, ExactRangeSource, MAX_RANGE_BYTES,
};
use ptah_transfer::{
    DownloadCursor, TransferPeerBinding, TransferRouteCandidate, TransferRouteKind, TransferTicket,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::{TcpListener, TcpStream};

const CA: &[u8] = include_bytes!("../../../crates/ptah-node-link/tests/fixtures/ca.cert.der");
const SERVER: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.cert.der");
const SERVER_KEY: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.key.der");
const CLIENT: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.cert.der");
const CLIENT_KEY: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.key.der");
const FORMULA: &[u8] = include_bytes!(
    "../../../adapters/formula-workcells/tests/fixtures/formula-generated-handoff.json"
);

fn roots() -> TlsTrustRoots {
    TlsTrustRoots::from_der(vec![CA.to_vec()]).unwrap()
}
fn server_config() -> TlsServerConfig {
    TlsServerConfig::new(
        TlsIdentity::from_der(vec![SERVER.to_vec()], SERVER_KEY.to_vec()).unwrap(),
        roots(),
    )
    .unwrap()
}
fn client_config() -> TlsClientConfig {
    TlsClientConfig::new(
        TlsIdentity::from_der(vec![CLIENT.to_vec()], CLIENT_KEY.to_vec()).unwrap(),
        roots(),
    )
    .unwrap()
}
fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).unwrap()
}
fn peer(fp: CredentialFingerprint) -> TransferPeerBinding {
    TransferPeerBinding {
        node_id: NodeId::new(),
        node_generation: NodeGeneration::INITIAL,
        connection_epoch: ConnectionEpoch::INITIAL,
        credential_fingerprint: *fp.as_bytes(),
    }
}
fn ticket(bytes: &[u8]) -> TransferTicket {
    let source_fp = CredentialFingerprint::from_der(SERVER);
    TransferTicket::new(
        reference("transfer.ticket"),
        reference("transfer.request"),
        reference("transfer.run"),
        reference("activity.attempt"),
        peer(source_fp),
        peer(CredentialFingerprint::from_der(CLIENT)),
        Some(reference("storage.content")),
        None,
        bytes.len() as u64,
        format!("{:x}", Sha256::digest(bytes)),
        1024,
        vec![TransferRouteCandidate {
            kind: TransferRouteKind::Direct,
            endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7443),
            server_name: "localhost".into(),
            expected_peer_fingerprint: *source_fp.as_bytes(),
            relay_ref: None,
        }],
        1,
        100,
        1,
    )
    .unwrap()
}
struct Source {
    bytes: Vec<u8>,
    digest: String,
}
impl ExactRangeSource for Source {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn canonical_sha256(&self) -> &str {
        &self.digest
    }
    fn read_exact_range(&mut self, start: u64, len: u64) -> Result<Vec<u8>, String> {
        let a = usize::try_from(start).map_err(|e| e.to_string())?;
        let b = usize::try_from(len).map_err(|e| e.to_string())?;
        self.bytes
            .get(a..a + b)
            .map(ToOwned::to_owned)
            .ok_or_else(|| "outside source".into())
    }
}
fn signer() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[42_u8; 32]).unwrap()
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn native_tls_e03_bytes_reach_independently_witnessed_formula_candidate() {
    let payload = b"9\n".to_vec();
    let t = ticket(&payload);
    let listen = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listen.local_addr().unwrap();
    let source_ticket = t.clone();
    let server_payload = payload.clone();
    let server = tokio::spawn(async move {
        let (tcp, _) = listen.accept().await.unwrap();
        let mut tls = accept_tls(tcp, &server_config()).await.unwrap();
        assert!(tls.is_tls13());
        let fp = tls.peer_fingerprint();
        let mut source = Source {
            digest: format!("{:x}", Sha256::digest(&server_payload)),
            bytes: server_payload,
        };
        DirectSourceSession::serve(
            tls.stream_mut(),
            &source_ticket,
            fp,
            &mut source,
            1,
            Some(1),
        )
        .await
        .unwrap();
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = connect_tls(tcp, "localhost", &client_config())
        .await
        .unwrap();
    assert!(tls.is_tls13());
    let fp = tls.peer_fingerprint();
    let mut cursor = DownloadCursor::default();
    let tmp = std::env::temp_dir().join(format!(
        "ptah-formula-e03-readback-{}.part",
        t.ticket_ref().entity_id
    ));
    let _ = std::fs::remove_file(&tmp);
    let transfer = DirectTargetSession::pull_missing_ranges(
        tls.stream_mut(),
        &t,
        fp,
        &tmp,
        &mut cursor,
        1,
        Some(1),
    )
    .await
    .unwrap();
    server.await.unwrap();
    assert_eq!(transfer.network_bytes, 2);
    assert_eq!(transfer.requested_ranges, 1);
    assert_eq!(transfer.accepted_ranges, 1);
    let readback = std::fs::read(&tmp).unwrap();
    std::fs::remove_file(&tmp).unwrap();
    let transferred = format!("sha256:{}", transfer.whole_sha256.unwrap());
    assert_eq!(readback, payload);

    let wire: serde_json::Value = serde_json::from_slice(FORMULA).unwrap();
    let custody = FormulaDispatchCustody {
        manifest_digest: wire["manifest_digest"].as_str().unwrap().into(),
        work_cell_digest: wire["work_cell_digest"].as_str().unwrap().into(),
        required_authority: wire["required_authority"].as_str().unwrap().into(),
    };
    let work = preflight_with_custody(FORMULA, &custody).unwrap();
    let sha = format!("sha256:{:x}", Sha256::digest(&readback));
    let observation = EffectObservation {
        schema: "ptah.external-effect-witness.v1".into(),
        witness_id: "test-only-independent-observer".into(),
        dispatch: "dispatch-e03-test".into(),
        attempt: "attempt-e03-test".into(),
        request_digest: work.manifest_digest.clone(),
        node: "source-test-node".into(),
        generation: 2,
        connection_epoch: 3,
        fence: 4,
        provider_generation: 1,
        process_identity: "test-provider:102".into(),
        boot_identity: "test-boot".into(),
        observed_exit_code: 0,
        observed_stdout_digest: sha.clone(),
        observation_source: "test-harness-independent-observation".into(),
    };
    let signed = SignedEffectObservation {
        signature: signer()
            .sign(&canonical_message(&observation).unwrap())
            .as_ref()
            .to_vec(),
        observation: observation.clone(),
    };
    let trust_key: [u8; 32] = signer().public_key().as_ref().try_into().unwrap();
    let trust = TrustedWitness {
        witness_id: &observation.witness_id,
        ed25519_public_key: &trust_key,
    };
    let control = DispatchObservation {
        dispatch: observation.dispatch.clone(),
        attempt: observation.attempt.clone(),
        request_digest: observation.request_digest.clone(),
        phase: "needs_reconciliation".into(),
        fence: observation.fence,
    };
    let node = NodeCompletion {
        attempt: observation.attempt.clone(),
        node: observation.node.clone(),
        generation: observation.generation,
        connection_epoch: observation.connection_epoch,
        request_digest: observation.request_digest,
        phase: "completed".into(),
        fence: observation.fence,
        exit_code: Some(0),
        stdout_digest: Some(sha),
    };
    let bound = witness_candidate(
        &work,
        &control,
        &node,
        &signed,
        &trust,
        &transferred,
        2,
        readback.clone(),
    )
    .unwrap();
    assert_eq!(bound.candidate.bytes, readback);
    assert_eq!(bound.candidate.claimed_digest, transferred);
    assert_eq!(bound.candidate.work_cell_digest, custody.work_cell_digest);
    assert_eq!(bound.attempt, node.attempt);

    let mut corrupt = signed;
    corrupt.observation.observation_source.push_str("-tampered");
    assert!(
        witness_candidate(
            &work,
            &control,
            &node,
            &corrupt,
            &trust,
            &transferred,
            2,
            readback.clone()
        )
        .is_err()
    );
    assert!(
        witness_candidate(
            &work,
            &control,
            &node,
            &corrupt,
            &trust,
            &transferred,
            2,
            b"8\n".to_vec()
        )
        .is_err()
    );
}

/// One TCP/TLS channel goes away after one retained range. A new channel
/// must resume from the exact verified partial bytes; signed readback is
/// only possible after the full candidate artifact is byte-complete.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn e03_interrupted_then_resumed_candidate_is_complete_before_witness_readback() {
    let mut payload = vec![b'7'; MAX_RANGE_BYTES];
    payload.extend_from_slice(b"9\n");
    let t = ticket(&payload);
    let partial = std::env::temp_dir().join(format!(
        "ptah-formula-e03-recovery-{}.part",
        t.ticket_ref().entity_id
    ));
    let _ = std::fs::remove_file(&partial);
    let mut cursor = DownloadCursor::default();
    let mut last = None;
    for pass in 0..2 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let source_ticket = t.clone();
        let source_bytes = payload.clone();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = accept_tls(tcp, &server_config()).await.unwrap();
            let fp = tls.peer_fingerprint();
            let mut src = Source {
                digest: format!("{:x}", Sha256::digest(&source_bytes)),
                bytes: source_bytes,
            };
            DirectSourceSession::serve(tls.stream_mut(), &source_ticket, fp, &mut src, 1, Some(1))
                .await
                .unwrap();
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = connect_tls(tcp, "localhost", &client_config())
            .await
            .unwrap();
        let fp = tls.peer_fingerprint();
        let report = DirectTargetSession::pull_missing_ranges(
            tls.stream_mut(),
            &t,
            fp,
            &partial,
            &mut cursor,
            1,
            Some(1),
        )
        .await
        .unwrap();
        server.await.unwrap();
        if pass == 0 {
            assert_eq!(report.network_bytes, MAX_RANGE_BYTES as u64);
            assert!(report.whole_sha256.is_none());
        } else {
            assert_eq!(report.network_bytes, 2);
            assert_eq!(report.resumed_ranges, 1);
            assert_eq!(report.whole_sha256.as_deref(), Some(t.canonical_sha256()));
        }
        last = Some(report);
    }
    let bytes = std::fs::read(&partial).unwrap();
    std::fs::remove_file(&partial).unwrap();
    assert_eq!(bytes, payload);
    let complete = last.unwrap();
    let completed_hash = format!("sha256:{}", complete.whole_sha256.unwrap());
    let wire: serde_json::Value = serde_json::from_slice(FORMULA).unwrap();
    let custody = FormulaDispatchCustody {
        manifest_digest: wire["manifest_digest"].as_str().unwrap().into(),
        work_cell_digest: wire["work_cell_digest"].as_str().unwrap().into(),
        required_authority: wire["required_authority"].as_str().unwrap().into(),
    };
    let work = preflight_with_custody(FORMULA, &custody).unwrap();
    let obs = EffectObservation {
        schema: "ptah.external-effect-witness.v1".into(),
        witness_id: "test-only-independent-observer".into(),
        dispatch: "dispatch-resumed-test".into(),
        attempt: "attempt-resumed-test".into(),
        request_digest: work.manifest_digest.clone(),
        node: "source-resumed-node".into(),
        generation: 2,
        connection_epoch: 3,
        fence: 5,
        provider_generation: 1,
        process_identity: "test-provider:102".into(),
        boot_identity: "test-boot".into(),
        observed_exit_code: 0,
        observed_stdout_digest: completed_hash.clone(),
        observation_source: "test-harness-independent-observation".into(),
    };
    let signed = SignedEffectObservation {
        signature: signer()
            .sign(&canonical_message(&obs).unwrap())
            .as_ref()
            .to_vec(),
        observation: obs.clone(),
    };
    let public: [u8; 32] = signer().public_key().as_ref().try_into().unwrap();
    let trust = TrustedWitness {
        witness_id: &obs.witness_id,
        ed25519_public_key: &public,
    };
    let control = DispatchObservation {
        dispatch: obs.dispatch.clone(),
        attempt: obs.attempt.clone(),
        request_digest: obs.request_digest.clone(),
        phase: "needs_reconciliation".into(),
        fence: obs.fence,
    };
    let node = NodeCompletion {
        attempt: obs.attempt.clone(),
        node: obs.node.clone(),
        generation: obs.generation,
        connection_epoch: obs.connection_epoch,
        request_digest: obs.request_digest,
        phase: "completed".into(),
        fence: obs.fence,
        exit_code: Some(0),
        stdout_digest: Some(completed_hash.clone()),
    };
    let accepted = witness_candidate(
        &work,
        &control,
        &node,
        &signed,
        &trust,
        &completed_hash,
        payload.len() as u64,
        bytes,
    )
    .unwrap();
    assert_eq!(accepted.candidate.claimed_digest, completed_hash);
    assert_eq!(accepted.candidate.bytes, payload);
}
