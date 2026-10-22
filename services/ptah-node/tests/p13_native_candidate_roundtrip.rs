//! An integrated *hermetic* P13 regression: genuine Ptah E01 identity,
//! Control-issued E03 ticket, durable A05 candidate file, authenticated TLS
//! transport and interrupted range resume, plus the existing signed readback
//! verifier. Test-owned witness key is NOT a deployed independent witness.
// Existing Node-local candidate module also carries its own unit tests.
// Preserve its production code while importing it into this integration test.
#[allow(clippy::items_after_statements)]
#[path = "../src/e07_candidate.rs"]
mod e07_candidate;

use e07_candidate::{DurableCandidateSource, persist_candidate_once};
use ptah_control::{
    formula_readback::witness_candidate,
    gateway_control_journal::DispatchObservation,
    gateway_witness::{
        EffectObservation, NodeCompletion, SignedEffectObservation, TrustedWitness,
        canonical_message,
    },
    node_link::NodeLinkControl,
    transfer::{TransferAuthorityOwner, TransferTicketSpec},
};
use ptah_formula_work_cells::{
    FormulaDispatchCustody, ValidatedFormulaWorkCell, preflight_with_custody,
};
use ptah_identifiers::EntityRef;
use ptah_node::transfer::NodeTransferGuard;
use ptah_node_agent::NodeAgent;
use ptah_node_link::{
    ApprovedNodeEnrollment, CredentialFingerprint, EnrollmentLifecycle, NodeHello, ProtocolVersion,
    TlsClientConfig, TlsIdentity, TlsServerConfig, TlsTrustRoots, accept_tls, connect_tls,
};
use ptah_node_transfer::{DirectSourceSession, DirectTargetSession, ExactRangeSource};
use ptah_transfer::{DownloadCursor, TransferPeerRole, TransferRouteCandidate, TransferRouteKind};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
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

fn reference(name: &str) -> EntityRef {
    EntityRef::new(name).unwrap()
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "ptah-p13-native-candidate-{}",
        ptah_identifiers::EntityId::new_v7()
    ));
    fs::create_dir(&path).unwrap();
    path
}
fn server_config() -> TlsServerConfig {
    TlsServerConfig::new(
        TlsIdentity::from_der(vec![SERVER.to_vec()], SERVER_KEY.to_vec()).unwrap(),
        TlsTrustRoots::from_der(vec![CA.to_vec()]).unwrap(),
    )
    .unwrap()
}
fn client_config() -> TlsClientConfig {
    TlsClientConfig::new(
        TlsIdentity::from_der(vec![CLIENT.to_vec()], CLIENT_KEY.to_vec()).unwrap(),
        TlsTrustRoots::from_der(vec![CA.to_vec()]).unwrap(),
    )
    .unwrap()
}
fn enrollment(agent: &NodeAgent, cert: &[u8]) -> ApprovedNodeEnrollment {
    ApprovedNodeEnrollment::new(
        reference("core.node_enrollment"),
        agent.node_id(),
        EnrollmentLifecycle::Approved,
        vec!["node.connect".to_owned()],
        vec![CredentialFingerprint::from_der(cert)],
        None,
    )
    .unwrap()
}
fn hello(agent: &NodeAgent, enrollment_ref: EntityRef) -> NodeHello {
    NodeHello {
        supported_major: 1,
        minimum_minor: 0,
        maximum_minor: 0,
        node_id: agent.node_id(),
        node_generation: agent.generation(),
        connection_epoch: agent.connection_epoch(),
        enrollment_ref,
        agent_revision: "p13-native-integrated-regression".into(),
        capability_snapshot_ref: None,
    }
}

fn formula_work() -> ValidatedFormulaWorkCell {
    let wire = include_bytes!(
        "../../../adapters/formula-workcells/tests/fixtures/formula-generated-handoff.json"
    );
    let inspected: serde_json::Value = serde_json::from_slice(wire).unwrap();
    let custody = FormulaDispatchCustody {
        manifest_digest: inspected["manifest_digest"].as_str().unwrap().into(),
        work_cell_digest: inspected["work_cell_digest"].as_str().unwrap().into(),
        required_authority: inspected["required_authority"].as_str().unwrap().into(),
    };
    preflight_with_custody(wire, &custody).unwrap()
}

async fn pull_pass(
    ticket: &ptah_transfer::TransferTicket,
    persisted: &Path,
    expected_sha: &str,
    partial: &Path,
    cursor: &mut DownloadCursor,
    ranges: usize,
) -> ptah_node_transfer::DirectTransferReport {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_ticket = ticket.clone();
    let server_path = persisted.to_path_buf();
    let expected = expected_sha.to_owned();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = accept_tls(tcp, &server_config()).await.unwrap();
        assert!(tls.is_tls13());
        assert_eq!(
            tls.peer_fingerprint(),
            CredentialFingerprint::from_der(CLIENT)
        );
        let peer = tls.peer_fingerprint();
        let mut source = DurableCandidateSource::open(&server_path, &expected).unwrap();
        DirectSourceSession::serve(
            tls.stream_mut(),
            &server_ticket,
            peer,
            &mut source,
            1,
            Some(ranges),
        )
        .await
        .unwrap();
    });
    let tcp = TcpStream::connect(address).await.unwrap();
    let mut tls = connect_tls(tcp, "localhost", &client_config())
        .await
        .unwrap();
    assert!(tls.is_tls13());
    assert_eq!(
        tls.peer_fingerprint(),
        CredentialFingerprint::from_der(SERVER)
    );
    let peer = tls.peer_fingerprint();
    let report = DirectTargetSession::pull_missing_ranges(
        tls.stream_mut(),
        ticket,
        peer,
        partial,
        cursor,
        1,
        Some(ranges),
    )
    .await
    .unwrap();
    server.await.unwrap();
    report
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Deliberate single full-chain native integration proof.
async fn control_issued_candidate_bytes_resume_then_signed_readback_is_candidate_only() {
    let dir = directory();
    let candidate = b"9\n";
    let (source_path, prefixed_sha) = persist_candidate_once(&dir, "attempt-1", candidate).unwrap();
    assert_eq!(
        DurableCandidateSource::open(&source_path, &prefixed_sha)
            .unwrap()
            .canonical_sha256(),
        &prefixed_sha[7..]
    );
    let work = formula_work();
    let source_agent = NodeAgent::bootstrap().unwrap();
    let target_agent = NodeAgent::bootstrap().unwrap();
    let source_enroll = enrollment(&source_agent, SERVER);
    let target_enroll = enrollment(&target_agent, CLIENT);
    let source_enroll_ref = source_enroll.enrollment_ref().clone();
    let target_enroll_ref = target_enroll.enrollment_ref().clone();
    let e01 = NodeLinkControl::new(
        ProtocolVersion { major: 1, minor: 0 },
        vec![source_enroll, target_enroll],
    );
    let mut control = TransferAuthorityOwner::new(e01);
    let now = now();
    control
        .accept_hello(
            &hello(&source_agent, source_enroll_ref),
            CredentialFingerprint::from_der(SERVER),
            now,
        )
        .unwrap();
    control
        .accept_hello(
            &hello(&target_agent, target_enroll_ref),
            CredentialFingerprint::from_der(CLIENT),
            now,
        )
        .unwrap();
    let ticket = control
        .issue_ticket(
            TransferTicketSpec {
                request_ref: reference("transfer.request"),
                run_ref: reference("transfer.run"),
                attempt_ref: reference("activity.attempt"),
                source_node_id: source_agent.node_id(),
                target_node_id: target_agent.node_id(),
                content_ref: Some(reference("storage.content")),
                artifact_ref: None,
                expected_size: candidate.len() as u64,
                canonical_sha256: prefixed_sha[7..].to_owned(),
                range_size: 1,
                routes: vec![TransferRouteCandidate {
                    kind: TransferRouteKind::Direct,
                    endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7443),
                    server_name: "localhost".into(),
                    expected_peer_fingerprint: *CredentialFingerprint::from_der(SERVER).as_bytes(),
                    relay_ref: None,
                }],
                expires_at_unix_seconds: now + 120,
            },
            now,
        )
        .unwrap();
    control.assert_current(&ticket).unwrap();
    let mut source_guard = NodeTransferGuard::for_agent(&source_agent);
    let mut target_guard = NodeTransferGuard::for_agent(&target_agent);
    source_guard
        .accept_ticket(&source_agent, TransferPeerRole::Source, &ticket, now)
        .unwrap();
    target_guard
        .accept_ticket(&target_agent, TransferPeerRole::Target, &ticket, now)
        .unwrap();
    source_guard
        .authorize_peer(
            &source_agent,
            &ticket,
            CredentialFingerprint::from_der(CLIENT),
            now,
        )
        .unwrap();
    target_guard
        .authorize_peer(
            &target_agent,
            &ticket,
            CredentialFingerprint::from_der(SERVER),
            now,
        )
        .unwrap();

    let partial = dir.join("candidate-return.part");
    let mut cursor = DownloadCursor::default();
    let first = pull_pass(
        &ticket,
        &source_path,
        &prefixed_sha,
        &partial,
        &mut cursor,
        1,
    )
    .await;
    assert_eq!(first.network_bytes, 1);
    assert!(first.whole_sha256.is_none());
    // A legitimate interrupted range cannot confer completed result authority.
    let second = pull_pass(
        &ticket,
        &source_path,
        &prefixed_sha,
        &partial,
        &mut cursor,
        2,
    )
    .await;
    assert_eq!(second.resumed_ranges, 1);
    assert_eq!(second.network_bytes, 1);
    assert_eq!(
        second.whole_sha256.as_deref(),
        Some(ticket.canonical_sha256())
    );
    assert_eq!(fs::read(&partial).unwrap(), candidate);

    let (observation, completion, signed) = witness_for_test(&work, &prefixed_sha);
    let key = witness_key();
    let public_key: [u8; 32] = key.public_key().as_ref().try_into().unwrap();
    let pinned = TrustedWitness {
        witness_id: "test-controlled-not-deployed-witness",
        ed25519_public_key: &public_key,
    };
    let witnessed = witness_candidate(
        &work,
        &observation,
        &completion,
        &signed,
        &pinned,
        second.whole_sha256.as_ref().unwrap(),
        candidate.len() as u64,
        fs::read(&partial).unwrap(),
    )
    .unwrap();
    assert_eq!(witnessed.candidate.bytes, candidate);
    assert_eq!(witnessed.candidate.manifest_digest, work.manifest_digest);
    assert_eq!(witnessed.witness_id, pinned.witness_id);
    assert_eq!(witnessed.attempt, completion.attempt);

    let mut tampered = signed.clone();
    tampered.observation.process_identity.push_str("-forged");
    assert!(
        witness_candidate(
            &work,
            &observation,
            &completion,
            &tampered,
            &pinned,
            second.whole_sha256.as_ref().unwrap(),
            candidate.len() as u64,
            fs::read(&partial).unwrap()
        )
        .is_err()
    );
    control.revoke_ticket(ticket.ticket_ref());
    assert!(control.assert_current(&ticket).is_err());
    fs::remove_dir_all(dir).unwrap();
}

fn witness_key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[57_u8; 32]).unwrap()
}
fn witness_for_test(
    work: &ValidatedFormulaWorkCell,
    stdout: &str,
) -> (DispatchObservation, NodeCompletion, SignedEffectObservation) {
    let effect = EffectObservation {
        schema: "ptah.external-effect-witness.v1".into(),
        witness_id: "test-controlled-not-deployed-witness".into(),
        dispatch: "fixture-dispatch".into(),
        attempt: "fixture-attempt".into(),
        request_digest: work.manifest_digest.clone(),
        node: "node-fixture-source".into(),
        generation: 1,
        connection_epoch: 1,
        fence: 1,
        provider_generation: 1,
        process_identity: "pid=fixture-not-physical".into(),
        boot_identity: "fixture-boot".into(),
        observed_exit_code: 0,
        observed_stdout_digest: stdout.into(),
        observation_source: "test-generated-signature-not-externally-verified".into(),
    };
    let signed = SignedEffectObservation {
        signature: witness_key()
            .sign(&canonical_message(&effect).unwrap())
            .as_ref()
            .to_vec(),
        observation: effect.clone(),
    };
    let control = DispatchObservation {
        dispatch: effect.dispatch.clone(),
        attempt: effect.attempt.clone(),
        request_digest: effect.request_digest.clone(),
        phase: "needs_reconciliation".into(),
        fence: effect.fence,
    };
    let node = NodeCompletion {
        attempt: effect.attempt,
        node: effect.node,
        generation: effect.generation,
        connection_epoch: effect.connection_epoch,
        request_digest: effect.request_digest,
        phase: "completed".into(),
        fence: effect.fence,
        exit_code: Some(0),
        stdout_digest: Some(stdout.into()),
    };
    (control, node, signed)
}
