//! Formula candidate readback after native E03 and independent E07 evidence.
//! Existing Ptah verifier supplies cryptographic effect witness checks;
//! this boundary does not authorize execution or certify mathematics.
use crate::{
    gateway_control_journal::DispatchObservation,
    gateway_witness::{
        EffectVerificationError, NodeCompletion, SignedEffectObservation, TrustedWitness,
        verify_effect,
    },
};
use ptah_formula_work_cells::{
    CandidateOnlyReceipt, ValidatedFormulaWorkCell, candidate_only_receipt,
};
use sha2::{Digest, Sha256};

/// Fail-closed independent effect and returned-byte verification outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormulaReadbackError {
    /// Original Control request does not name this Formula manifest.
    WrongRequest,
    /// Node has not durably completed with exit zero.
    IncompleteExecution,
    /// Readback byte count differs from the transfer claim.
    IncorrectByteLength,
    /// Full byte SHA-256 differs from E03 completed-file claim.
    IncorrectTransferDigest,
    /// Original Node output digest does not match readback.
    IncorrectOutputDigest,
    /// Independently pinned Ed25519 witness validation failed.
    Witness(EffectVerificationError),
    /// Empty candidate is not an observed execution output.
    EmptyCandidate,
}

/// Hashed byte readback plus the independently validated witness identity.
/// The candidate is still UNTRUSTED as mathematics; Formula must check it.
#[derive(Debug, Clone)]
pub struct WitnessedFormulaCandidate {
    /// Exact bytes and work identities, still not a math certificate.
    pub candidate: CandidateOnlyReceipt,
    /// Externally configured trusted observer identity.
    pub witness_id: String,
    /// SHA-256 of the cryptographically verified message.
    pub witness_message_digest: String,
    /// Original immutable Attempt identity.
    pub attempt: String,
    /// Node that performed the recorded attempt.
    pub node: String,
}

/// Called after E03 has completed an exact-byte destination readback.
/// The whole SHA-256 is the E03 completed-file digest, not a wire ack.
/// Validity of E03 route/ticket/lease remains the transport owner's duty.
///
/// # Errors
/// Rejects missing completed process evidence, changed bytes or unsigned and
/// mismatched external effect observations; never authorizes a retry.
#[allow(clippy::too_many_arguments)]
pub fn witness_candidate(
    work: &ValidatedFormulaWorkCell,
    control: &DispatchObservation,
    node: &NodeCompletion,
    signed: &SignedEffectObservation,
    trusted: &TrustedWitness<'_>,
    e03_whole_sha256: &str,
    e03_expected_size: u64,
    returned_bytes: Vec<u8>,
) -> Result<WitnessedFormulaCandidate, FormulaReadbackError> {
    if control.request_digest != work.manifest_digest {
        return Err(FormulaReadbackError::WrongRequest);
    }
    if node.exit_code != Some(0) || node.phase != "completed" {
        return Err(FormulaReadbackError::IncompleteExecution);
    }
    if returned_bytes.is_empty() {
        return Err(FormulaReadbackError::EmptyCandidate);
    }
    if returned_bytes.len() as u64 != e03_expected_size {
        return Err(FormulaReadbackError::IncorrectByteLength);
    }
    let sha = format!("sha256:{:x}", Sha256::digest(&returned_bytes));
    if e03_whole_sha256 != sha {
        return Err(FormulaReadbackError::IncorrectTransferDigest);
    }
    if node.stdout_digest.as_deref() != Some(sha.as_str()) {
        return Err(FormulaReadbackError::IncorrectOutputDigest);
    }
    let verified =
        verify_effect(control, node, signed, trusted).map_err(FormulaReadbackError::Witness)?;
    let candidate = candidate_only_receipt(work, returned_bytes)
        .map_err(|_| FormulaReadbackError::EmptyCandidate)?;
    Ok(WitnessedFormulaCandidate {
        candidate,
        witness_id: verified.witness_id,
        witness_message_digest: verified.canonical_sha256,
        attempt: node.attempt.clone(),
        node: node.node.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_witness::{EffectObservation, canonical_message};
    use ptah_formula_work_cells::{FormulaDispatchCustody, preflight_with_custody};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn eligible() -> ValidatedFormulaWorkCell {
        let bytes = include_bytes!(
            "../../../adapters/formula-workcells/tests/fixtures/formula-generated-handoff.json"
        );
        let wire: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let expected = FormulaDispatchCustody {
            manifest_digest: wire["manifest_digest"].as_str().unwrap().into(),
            work_cell_digest: wire["work_cell_digest"].as_str().unwrap().into(),
            required_authority: wire["required_authority"].as_str().unwrap().into(),
        };
        preflight_with_custody(bytes, &expected).unwrap()
    }
    fn key() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[41_u8; 32]).unwrap()
    }
    fn proof(
        work: &ValidatedFormulaWorkCell,
    ) -> (DispatchObservation, NodeCompletion, SignedEffectObservation) {
        let sha = format!("sha256:{:x}", Sha256::digest(b"9\n"));
        let obs = EffectObservation {
            schema: "ptah.external-effect-witness.v1".into(),
            witness_id: "separately-provisioned-test-witness".into(),
            dispatch: "exact-dispatch-1".into(),
            attempt: "exact-attempt-1".into(),
            request_digest: work.manifest_digest.clone(),
            node: "physical-node-1".into(),
            generation: 2,
            connection_epoch: 3,
            fence: 4,
            provider_generation: 1,
            process_identity: "pid=101@boot1".into(),
            boot_identity: "boot1".into(),
            observed_exit_code: 0,
            observed_stdout_digest: sha.clone(),
            observation_source: "independent-observer-test-harness".into(),
        };
        let signed = SignedEffectObservation {
            signature: key()
                .sign(&canonical_message(&obs).unwrap())
                .as_ref()
                .into(),
            observation: obs.clone(),
        };
        let control = DispatchObservation {
            dispatch: obs.dispatch,
            attempt: obs.attempt.clone(),
            request_digest: obs.request_digest.clone(),
            phase: "needs_reconciliation".into(),
            fence: obs.fence,
        };
        let node = NodeCompletion {
            attempt: obs.attempt,
            node: obs.node,
            generation: obs.generation,
            connection_epoch: obs.connection_epoch,
            request_digest: obs.request_digest,
            phase: "completed".into(),
            fence: obs.fence,
            exit_code: Some(0),
            stdout_digest: Some(sha),
        };
        (control, node, signed)
    }

    #[test]
    fn signed_e03_readback_is_still_candidate_only() {
        let work = eligible();
        let (control, node, signed) = proof(&work);
        let pubkey: [u8; 32] = key().public_key().as_ref().try_into().unwrap();
        let trust = TrustedWitness {
            witness_id: "separately-provisioned-test-witness",
            ed25519_public_key: &pubkey,
        };
        let sha = format!("sha256:{:x}", Sha256::digest(b"9\n"));
        let result = witness_candidate(
            &work,
            &control,
            &node,
            &signed,
            &trust,
            &sha,
            2,
            b"9\n".to_vec(),
        )
        .unwrap();
        assert_eq!(result.candidate.bytes, b"9\n");
        assert_eq!(result.candidate.manifest_digest, work.manifest_digest);
        assert_eq!(result.witness_id, trust.witness_id);
        assert_eq!(result.attempt, node.attempt);
        assert!(result.witness_message_digest.starts_with("sha256:"));
    }
    #[test]
    fn forged_changed_or_unfinished_effect_cannot_be_read_back_as_completed() {
        let work = eligible();
        let (control, node, signed) = proof(&work);
        let pubkey: [u8; 32] = key().public_key().as_ref().try_into().unwrap();
        let trust = TrustedWitness {
            witness_id: "separately-provisioned-test-witness",
            ed25519_public_key: &pubkey,
        };
        let sha = format!("sha256:{:x}", Sha256::digest(b"9\n"));
        assert_eq!(
            witness_candidate(
                &work,
                &control,
                &node,
                &signed,
                &trust,
                &sha,
                3,
                b"9\n".to_vec()
            )
            .unwrap_err(),
            FormulaReadbackError::IncorrectByteLength
        );
        assert_eq!(
            witness_candidate(
                &work,
                &control,
                &node,
                &signed,
                &trust,
                &sha,
                2,
                b"8\n".to_vec()
            )
            .unwrap_err(),
            FormulaReadbackError::IncorrectTransferDigest
        );
        let mut corrupt = signed.clone();
        corrupt.observation.process_identity.push('x');
        assert_eq!(
            witness_candidate(
                &work,
                &control,
                &node,
                &corrupt,
                &trust,
                &sha,
                2,
                b"9\n".to_vec()
            )
            .unwrap_err(),
            FormulaReadbackError::Witness(EffectVerificationError::InvalidSignature)
        );
        let mut no_exit = node.clone();
        no_exit.phase = "needs_reconciliation".into();
        assert_eq!(
            witness_candidate(
                &work,
                &control,
                &no_exit,
                &signed,
                &trust,
                &sha,
                2,
                b"9\n".to_vec()
            )
            .unwrap_err(),
            FormulaReadbackError::IncompleteExecution
        );
        let mut other = control.clone();
        other.request_digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            witness_candidate(
                &work,
                &other,
                &node,
                &signed,
                &trust,
                &sha,
                2,
                b"9\n".to_vec()
            )
            .unwrap_err(),
            FormulaReadbackError::WrongRequest
        );
        let mut different = node.clone();
        different.node = "different-node".into();
        assert_eq!(
            witness_candidate(
                &work,
                &control,
                &different,
                &signed,
                &trust,
                &sha,
                2,
                b"9\n".to_vec()
            )
            .unwrap_err(),
            FormulaReadbackError::Witness(EffectVerificationError::IncorrectAttempt)
        );
    }
}
