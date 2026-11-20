//! Hermetic E07 independent external-effect witness negative tests.
use ptah_control::gateway_control_journal::DispatchObservation;
use ptah_control::gateway_witness::{
    EffectObservation, EffectVerificationError, NodeCompletion, SignedEffectObservation,
    TrustedWitness, canonical_message, verify_effect,
};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn observation() -> EffectObservation {
    EffectObservation {
        schema: "ptah.external-effect-witness.v1".into(),
        witness_id: "isolated-test-observer".into(),
        dispatch: "{\"entity_kind\":\"runtime.dispatch\",\"id\":\"d1\"}".into(),
        attempt: "{\"entity_kind\":\"activity.attempt\",\"id\":\"a1\"}".into(),
        request_digest: format!("sha256:{}", "a".repeat(64)),
        node: "node-a".into(),
        generation: 4,
        connection_epoch: 6,
        fence: 12,
        provider_generation: 2,
        process_identity: "pid:1234:boot:unique".into(),
        boot_identity: "boot-1".into(),
        observed_exit_code: 0,
        observed_stdout_digest: format!("sha256:{}", "b".repeat(64)),
        observation_source: "external readback process completion".into(),
    }
}
fn control(obs: &EffectObservation) -> DispatchObservation {
    DispatchObservation {
        dispatch: obs.dispatch.clone(),
        attempt: obs.attempt.clone(),
        request_digest: obs.request_digest.clone(),
        phase: "needs_reconciliation".into(),
        fence: obs.fence,
    }
}
fn node(obs: &EffectObservation) -> NodeCompletion {
    NodeCompletion {
        attempt: obs.attempt.clone(),
        node: obs.node.clone(),
        generation: obs.generation,
        connection_epoch: obs.connection_epoch,
        request_digest: obs.request_digest.clone(),
        phase: "completed".into(),
        fence: obs.fence,
        exit_code: Some(obs.observed_exit_code),
        stdout_digest: Some(obs.observed_stdout_digest.clone()),
    }
}
fn signer() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[11_u8; 32]).expect("test fixture key")
}
fn signed(obs: EffectObservation) -> SignedEffectObservation {
    let bytes = canonical_message(&obs).expect("valid canonical bytes");
    SignedEffectObservation {
        observation: obs,
        signature: signer().sign(&bytes).as_ref().to_vec(),
    }
}
#[test]
fn independent_signature_matches_exact_control_and_node_result() {
    let obs = observation();
    let public: [u8; 32] = signer().public_key().as_ref().try_into().unwrap();
    let trusted = TrustedWitness {
        witness_id: &obs.witness_id,
        ed25519_public_key: &public,
    };
    let result =
        verify_effect(&control(&obs), &node(&obs), &signed(obs.clone()), &trusted).unwrap();
    assert_eq!(result.witness_id, obs.witness_id);
    assert!(result.canonical_sha256.starts_with("sha256:"));
}
#[test]
fn forged_or_altered_signature_and_untrusted_key_cannot_reconcile() {
    let obs = observation();
    let public: [u8; 32] = signer().public_key().as_ref().try_into().unwrap();
    let trusted = TrustedWitness {
        witness_id: &obs.witness_id,
        ed25519_public_key: &public,
    };
    let mut artifact = signed(obs.clone());
    artifact.observation.process_identity = "changed-after-sign".into();
    assert_eq!(
        verify_effect(&control(&obs), &node(&obs), &artifact, &trusted),
        Err(EffectVerificationError::InvalidSignature)
    );
    let wrong_key = [99_u8; 32];
    let wrong_trust = TrustedWitness {
        witness_id: &obs.witness_id,
        ed25519_public_key: &wrong_key,
    };
    assert_eq!(
        verify_effect(
            &control(&obs),
            &node(&obs),
            &signed(obs.clone()),
            &wrong_trust
        ),
        Err(EffectVerificationError::InvalidSignature)
    );
    let wrong_id = TrustedWitness {
        witness_id: "unknown",
        ed25519_public_key: &public,
    };
    assert_eq!(
        verify_effect(&control(&obs), &node(&obs), &signed(obs.clone()), &wrong_id),
        Err(EffectVerificationError::UntrustedWitness)
    );
}
#[test]
fn incomplete_or_conflicting_node_result_never_becomes_completed() {
    let obs = observation();
    let public: [u8; 32] = signer().public_key().as_ref().try_into().unwrap();
    let trusted = TrustedWitness {
        witness_id: &obs.witness_id,
        ed25519_public_key: &public,
    };
    let artifact = signed(obs.clone());
    let mut unknown = node(&obs);
    unknown.phase = "needs_reconciliation".into();
    assert_eq!(
        verify_effect(&control(&obs), &unknown, &artifact, &trusted),
        Err(EffectVerificationError::MissingNodeEvidence)
    );
    let mut conflict = node(&obs);
    conflict.stdout_digest = Some(format!("sha256:{}", "c".repeat(64)));
    assert_eq!(
        verify_effect(&control(&obs), &conflict, &artifact, &trusted),
        Err(EffectVerificationError::MismatchedNodeEvidence)
    );
    let mut swapped_node = node(&obs);
    swapped_node.node = "another-node".into();
    assert_eq!(
        verify_effect(&control(&obs), &swapped_node, &artifact, &trusted),
        Err(EffectVerificationError::IncorrectAttempt)
    );
    let mut old_generation = node(&obs);
    old_generation.generation -= 1;
    assert_eq!(
        verify_effect(&control(&obs), &old_generation, &artifact, &trusted),
        Err(EffectVerificationError::IncorrectAttempt)
    );
    let mut old_epoch = node(&obs);
    old_epoch.connection_epoch -= 1;
    assert_eq!(
        verify_effect(&control(&obs), &old_epoch, &artifact, &trusted),
        Err(EffectVerificationError::IncorrectAttempt)
    );
    let mut previous = control(&obs);
    previous.attempt.push('x');
    assert_eq!(
        verify_effect(&previous, &node(&obs), &artifact, &trusted),
        Err(EffectVerificationError::IncorrectAttempt)
    );
}
