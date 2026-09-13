//! E03 verified-cache and B01 resume-integrity contract tests.

use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_transfer::{
    CacheDecision, DownloadCursor, E03TransferError, TransferCachePolicy, TransferPeerBinding,
    TransferRouteCandidate, TransferRouteKind, TransferTicket, VerifiedCacheEvidence,
    VerifiedRange, decide_cache, validate_resume_cursor,
};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

const MIB: usize = 1024 * 1024;

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid Ptah entity kind")
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn peer(seed: u8, generation: u64, epoch: u64) -> TransferPeerBinding {
    TransferPeerBinding {
        node_id: NodeId::new(),
        node_generation: NodeGeneration::new(generation),
        connection_epoch: ConnectionEpoch::new(epoch),
        credential_fingerprint: [seed; 32],
    }
}

fn ticket_for(bytes: &[u8]) -> (TransferTicket, EntityRef) {
    let content_ref = reference("storage.content");
    let route = TransferRouteCandidate {
        kind: TransferRouteKind::Direct,
        endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 44103),
        server_name: "target.e03.test".to_owned(),
        expected_peer_fingerprint: [0x22; 32],
        relay_ref: None,
    };
    let ticket = TransferTicket::new(
        reference("transfer.ticket"),
        reference("transfer.request"),
        reference("transfer.run"),
        reference("activity.attempt"),
        peer(0x11, 1, 1),
        peer(0x22, 2, 3),
        Some(content_ref.clone()),
        None,
        u64::try_from(bytes.len()).expect("test size fits u64"),
        sha256(bytes),
        MIB as u64,
        vec![route],
        100,
        200,
        17,
    )
    .expect("valid E03 ticket");
    (ticket, content_ref)
}

fn temp_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ptah-e03-{label}-{}-{}.partial",
        std::process::id(),
        NodeId::new()
    ))
}

#[test]
fn verified_exact_cache_can_be_reused_but_policy_can_force_network() {
    let bytes = vec![0x5a; 2 * MIB];
    let (ticket, content_ref) = ticket_for(&bytes);
    let location_ref = reference("storage.location");
    let evidence = VerifiedCacheEvidence {
        content_ref: content_ref.clone(),
        location_ref: location_ref.clone(),
        size: bytes.len() as u64,
        canonical_sha256: sha256(&bytes),
        verified: true,
    };

    assert_eq!(
        decide_cache(
            &ticket,
            TransferCachePolicy::ReuseVerifiedLocalContent,
            Some(&evidence)
        ),
        Ok(CacheDecision::ReuseVerified {
            content_ref: Box::new(content_ref),
            location_ref: Box::new(location_ref),
        })
    );
    assert_eq!(
        decide_cache(
            &ticket,
            TransferCachePolicy::RequireNetworkTransfer,
            Some(&evidence)
        ),
        Ok(CacheDecision::NetworkTransfer)
    );
}

#[test]
fn cache_reuse_rejects_unverified_or_identity_mismatched_bytes() {
    let bytes = vec![0x6b; 2 * MIB];
    let (ticket, content_ref) = ticket_for(&bytes);
    let base = VerifiedCacheEvidence {
        content_ref,
        location_ref: reference("storage.location"),
        size: bytes.len() as u64,
        canonical_sha256: sha256(&bytes),
        verified: true,
    };

    let unverified = VerifiedCacheEvidence {
        verified: false,
        ..base.clone()
    };
    assert_eq!(
        decide_cache(
            &ticket,
            TransferCachePolicy::ReuseVerifiedLocalContent,
            Some(&unverified)
        ),
        Err(E03TransferError::UnverifiedCacheEvidence)
    );

    let mismatched = VerifiedCacheEvidence {
        canonical_sha256: "cd".repeat(32),
        ..base
    };
    assert_eq!(
        decide_cache(
            &ticket,
            TransferCachePolicy::ReuseVerifiedLocalContent,
            Some(&mismatched)
        ),
        Err(E03TransferError::CacheIdentityMismatch)
    );
}

#[test]
fn retained_verified_ranges_are_reread_before_resume() {
    let mut bytes = vec![0_u8; 2 * MIB];
    bytes[..MIB].fill(0x41);
    bytes[MIB..].fill(0x42);
    let (ticket, _) = ticket_for(&bytes);
    let path = temp_path("resume");
    fs::write(&path, &bytes).expect("write partial test file");

    let mut cursor = DownloadCursor::default();
    cursor.mark_verified(VerifiedRange {
        start: 0,
        len: MIB as u64,
        sha256: sha256(&bytes[..MIB]),
    });

    assert_eq!(validate_resume_cursor(&ticket, &cursor, &path), Ok(()));

    let mut file = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("reopen partial test file");
    file.seek(SeekFrom::Start(7))
        .expect("seek into retained range");
    file.write_all(&[0xff]).expect("mutate retained byte");
    file.flush().expect("flush retained-byte mutation");

    assert_eq!(
        validate_resume_cursor(&ticket, &cursor, &path),
        Err(E03TransferError::RetainedRangeDigestMismatch)
    );

    fs::remove_file(path).expect("remove partial test file");
}
