//! Optional, physically observed ATHENA -> KRATOS independent signature
//! acceptance for the candidate that travelled through native E03 TLS.
//! This checks a separate observer process and pinned test public key.
//! E01 identity/lease/fence in the fixture are NOT production-issued.

use ptah_control::{
    formula_readback::{FormulaReadbackError, witness_candidate},
    gateway_control_journal::DispatchObservation,
    gateway_witness::{
        EffectObservation, EffectVerificationError, NodeCompletion, SignedEffectObservation,
        TrustedWitness,
    },
};
use ptah_formula_work_cells::{FormulaDispatchCustody, preflight_with_custody};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};

fn as_str<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for part in path {
        cur = if cur.is_array() {
            &cur[part.parse::<usize>().unwrap()]
        } else {
            &cur[*part]
        };
    }
    cur.as_str().unwrap()
}
fn number(v: &Value, path: &[&str]) -> u64 {
    let mut cur = v;
    for part in path {
        cur = if cur.is_array() {
            &cur[part.parse::<usize>().unwrap()]
        } else {
            &cur[*part]
        };
    }
    cur.as_u64().unwrap()
}
fn bytes(v: &Value, key: &str) -> Vec<u8> {
    v[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| u8::try_from(n.as_u64().unwrap()).unwrap())
        .collect()
}
fn pinned_public_key(path: &Path) -> [u8; 32] {
    let text = fs::read_to_string(path).unwrap();
    let hex = text.trim();
    assert_eq!(hex.len(), 64, "32-byte test witness public key");
    let data = (0..32)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect::<Vec<_>>();
    data.try_into().unwrap()
}
fn work() -> ptah_formula_work_cells::ValidatedFormulaWorkCell {
    let wire = include_bytes!(
        "../../../adapters/formula-workcells/tests/fixtures/formula-generated-handoff.json"
    );
    let facts: Value = serde_json::from_slice(wire).unwrap();
    let custody = FormulaDispatchCustody {
        manifest_digest: as_str(&facts, &["manifest_digest"]).into(),
        work_cell_digest: as_str(&facts, &["work_cell_digest"]).into(),
        required_authority: as_str(&facts, &["required_authority"]).into(),
    };
    preflight_with_custody(wire, &custody).unwrap()
}

#[test]
#[ignore = "requires real ATHENA signed evidence, separately pinned key and KRATOS E03 logs"]
#[allow(clippy::too_many_lines)] // One opt-in physical proof with explicit evidence sources.
fn verify_athena_independent_signature_against_real_native_e03_readback() {
    let path = env::var("P13_PHYSICAL_EVIDENCE_DIR")
        .expect("physical evidence directory must be selected explicitly");
    let dir = Path::new(&path);
    let read =
        |name: &str| serde_json::from_slice::<Value>(&fs::read(dir.join(name)).unwrap()).unwrap();
    let plan_path = env::var("P13_PHYSICAL_PLAN").expect("Control-issued plan path required");
    let plan: Value = serde_json::from_slice(&fs::read(plan_path).unwrap()).unwrap();
    let bundle = read("p13-physical-signed-witness-20261023.json");
    let target = read("p13-physical-athena-target-20261023.json");
    let source_path = env::var("P13_PHYSICAL_SOURCE_EVIDENCE")
        .expect("source-process completion evidence path required");
    let source = serde_json::from_slice::<Value>(&fs::read(source_path).unwrap()).unwrap();
    let pubkey = pinned_public_key(&dir.join("p13-test-witness-public-20261023.hex"));
    let candidate = b"9\n".to_vec();
    let sha = format!("{:x}", Sha256::digest(&candidate));
    assert_eq!(source["role"], "source");
    assert_eq!(source["passes"], 2);
    assert_eq!(as_str(&source, &["sha256"]), sha);
    assert_eq!(target["host"], "ATHENA");
    assert_eq!(target["native_e03"], true);
    assert_eq!(target["test_fixture_pki"], true);
    assert_eq!(number(&target, &["size"]), candidate.len() as u64);
    assert_eq!(as_str(&target, &["sha256"]), sha);
    assert_eq!(number(&target, &["passes", "0", "network_bytes"]), 1);
    assert_eq!(number(&target, &["passes", "1", "network_bytes"]), 1);
    assert_eq!(number(&target, &["passes", "1", "resumed_ranges"]), 1);
    assert_eq!(as_str(&target, &["passes", "1", "whole_sha256"]), sha);
    assert_eq!(as_str(&plan, &["ticket", "canonical_sha256"]), sha);
    assert_eq!(number(&plan, &["ticket", "expected_size"]), 2);

    let obj: EffectObservation = serde_json::from_value(bundle["observation"].clone()).unwrap();
    let signed = SignedEffectObservation {
        observation: obj.clone(),
        signature: bytes(&bundle, "signature"),
    };
    assert_eq!(bytes(&bundle, "public_key"), pubkey);
    assert_eq!(bundle["observed_size"], candidate.len() as u64);
    assert_eq!(
        as_str(&bundle, &["observed_candidate_sha256"]),
        format!("sha256:{sha}")
    );
    let actual_attempt = format!(
        "{}:{}",
        as_str(&plan, &["ticket", "attempt_ref", "entity_kind"]),
        as_str(&plan, &["ticket", "attempt_ref", "entity_id"])
    );
    let actual_dispatch = format!(
        "e03.ticket:{}",
        as_str(&plan, &["ticket", "ticket_ref", "entity_id"])
    );
    let actual_node = as_str(&plan, &["ticket", "target", "node_id"]);
    assert_eq!(obj.attempt, actual_attempt);
    assert_eq!(obj.dispatch, actual_dispatch);
    assert_eq!(obj.node, actual_node);
    assert_eq!(
        obj.observation_source,
        "ATHENA independent process reread native E03 candidate and resumed-range evidence"
    );
    assert_eq!(obj.observed_stdout_digest, format!("sha256:{sha}"));
    let work = work();
    assert_eq!(obj.request_digest, work.manifest_digest);

    // Control/Node test-owned completion facts are rebuilt from a separate
    // Oracle-retrieved target result and the immutable test ticket, rather
    // than copied from the witness's signed observations.
    let control = DispatchObservation {
        dispatch: actual_dispatch,
        attempt: actual_attempt.clone(),
        request_digest: work.manifest_digest.clone(),
        phase: "needs_reconciliation".into(),
        fence: 1,
    };
    let node = NodeCompletion {
        attempt: actual_attempt,
        node: actual_node.into(),
        generation: 1,
        connection_epoch: 1,
        request_digest: work.manifest_digest.clone(),
        phase: "completed".into(),
        fence: 1,
        exit_code: Some(0),
        stdout_digest: Some(format!("sha256:{sha}")),
    };
    let trust = TrustedWitness {
        witness_id: "athena-separate-process-p13-20261023",
        ed25519_public_key: &pubkey,
    };
    let verified = witness_candidate(
        &work,
        &control,
        &node,
        &signed,
        &trust,
        &sha,
        candidate.len() as u64,
        candidate.clone(),
    )
    .unwrap();
    assert_eq!(verified.candidate.bytes, candidate);
    assert_eq!(verified.witness_id, trust.witness_id);
    assert_eq!(verified.attempt, node.attempt);
    assert!(verified.witness_message_digest.starts_with("sha256:"));
    println!(
        "PHYSICAL_P13_SIGNED_TEST_WITNESS_PASS node=ATHENA digest={}",
        verified.witness_message_digest
    );

    let mut altered = signed.clone();
    altered.signature[0] ^= 1;
    assert!(matches!(
        witness_candidate(
            &work,
            &control,
            &node,
            &altered,
            &trust,
            &sha,
            candidate.len() as u64,
            candidate.clone(),
        ),
        Err(FormulaReadbackError::Witness(
            EffectVerificationError::InvalidSignature
        ))
    ));
    assert!(matches!(
        witness_candidate(
            &work,
            &control,
            &node,
            &signed,
            &trust,
            &sha,
            candidate.len() as u64,
            b"8\n".to_vec(),
        ),
        Err(FormulaReadbackError::IncorrectTransferDigest)
    ));
    let mut failed = node.clone();
    failed.phase = "needs_reconciliation".into();
    assert_eq!(
        witness_candidate(
            &work,
            &control,
            &failed,
            &signed,
            &trust,
            &sha,
            candidate.len() as u64,
            candidate.clone(),
        )
        .err(),
        Some(FormulaReadbackError::IncompleteExecution)
    );
}
