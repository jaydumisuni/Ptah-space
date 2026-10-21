//! Formula-generated cross-repository Ptah work-cell contract regression tests.
use ptah_formula_work_cells::{
    FormulaDispatchCustody, FormulaWorkCellError, candidate_only_receipt, preflight_with_custody,
    validate_handoff,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fixture() -> Vec<u8> {
    include_bytes!("fixtures/formula-generated-handoff.json")
        .trim_ascii_end()
        .to_vec()
}
fn approved_fixture() -> ptah_formula_work_cells::ValidatedFormulaWorkCell {
    let expected = FormulaDispatchCustody {
        manifest_digest: "sha256:778e11206defae987198ad7174606ab063a64855a4d0775a10bce66087e2ec07"
            .into(),
        work_cell_digest: "sha256:d156d75e30f1da5b7fc32e1a5f55fec0f126c0b11ae0cd361ea1b925071a8d09"
            .into(),
        required_authority:
            "sha256:f849d67325facf04177bc663b2dc544051831c589ef581d412f2eba44834e77c".into(),
    };
    preflight_with_custody(&fixture(), &expected).unwrap()
}
fn digest(v: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(v))
}
fn encode(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}
fn fully_bound_mutation(field: &str, value: &str) -> Vec<u8> {
    let mut wire: Value = serde_json::from_slice(&fixture()).unwrap();
    let mut cell: Value = serde_json::from_str(wire["work_cell_json"].as_str().unwrap()).unwrap();
    cell[field] = Value::String(value.into());
    let cell_json = String::from_utf8(encode(&cell)).unwrap();
    let cell_digest = digest(cell_json.as_bytes());

    let mut manifest: Value =
        serde_json::from_str(wire["manifest_json"].as_str().unwrap()).unwrap();
    manifest["work_cells"] = serde_json::json!([cell_digest.clone()]);
    let manifest_json = String::from_utf8(encode(&manifest)).unwrap();

    wire["manifest_digest"] = Value::String(digest(manifest_json.as_bytes()));
    wire["manifest_json"] = Value::String(manifest_json);
    wire["work_cell_digest"] = Value::String(cell_digest);
    wire["work_cell_json"] = Value::String(cell_json);
    encode(&wire)
}

#[test]
fn real_formula_generated_packet_is_accepted_structurally() {
    let data = validate_handoff(&fixture()).unwrap();
    assert_eq!(
        data.work_cell_digest,
        "sha256:d156d75e30f1da5b7fc32e1a5f55fec0f126c0b11ae0cd361ea1b925071a8d09"
    );
    assert_eq!(data.requested_result_class, "COUNT");
    assert_eq!(data.known_input_digests.len(), 1);
    assert_eq!(data.max_work_units, 100);
    assert_eq!(data.max_memory_bytes, 1024);
    assert_eq!(data.wall_clock_millis, 50);
    let approved = approved_fixture();
    let candidate = candidate_only_receipt(&approved, b"candidate-only".to_vec()).unwrap();
    assert_eq!(candidate.claimed_digest, digest(&candidate.bytes));
    assert_eq!(candidate.work_cell_digest, data.work_cell_digest);
    assert_eq!(candidate.manifest_digest, data.manifest_digest);
}

#[test]
fn mismatched_manifest_or_work_cell_digest_fails_closed() {
    let mut wire: Value = serde_json::from_slice(&fixture()).unwrap();
    wire["manifest_digest"] = Value::String(digest(b"wrong"));
    assert_eq!(
        validate_handoff(&encode(&wire)),
        Err(FormulaWorkCellError::DigestMismatch)
    );
    let mut wire: Value = serde_json::from_slice(&fixture()).unwrap();
    wire["work_cell_digest"] = Value::String(digest(b"wrong"));
    assert_eq!(
        validate_handoff(&encode(&wire)),
        Err(FormulaWorkCellError::DigestMismatch)
    );
}

#[test]
fn forged_outer_authority_and_noncanonical_wire_fail_closed() {
    let mut wire: Value = serde_json::from_slice(&fixture()).unwrap();
    wire["required_authority"] = Value::String(digest(b"different-authority"));
    assert_eq!(
        validate_handoff(&encode(&wire)),
        Err(FormulaWorkCellError::IdentityMismatch)
    );
    let mut padded = fixture();
    padded.push(b' ');
    assert_eq!(
        validate_handoff(&padded),
        Err(FormulaWorkCellError::Noncanonical)
    );
}

#[test]
fn even_internally_consistent_rehashed_authority_write_is_rejected() {
    let poisoned = fully_bound_mutation(
        "side_effect_limits",
        "SideEffectPolicy { allow_local_process: true, allow_network: true, allow_authority_write: true }",
    );
    assert_eq!(
        validate_handoff(&poisoned),
        Err(FormulaWorkCellError::ForbiddenSideEffects)
    );
}

#[test]
fn unbounded_or_missing_work_does_not_claim_success() {
    let missing_budget = fully_bound_mutation(
        "resource_budget",
        "ResourceContract { max_work_units: 0, max_memory_bytes: 1024, wall_clock_millis: 50 }",
    );
    assert_eq!(
        validate_handoff(&missing_budget),
        Err(FormulaWorkCellError::InvalidResourceContract)
    );
    let work = approved_fixture();
    assert_eq!(
        candidate_only_receipt(&work, vec![]),
        Err(FormulaWorkCellError::EmptyCandidate)
    );
}

#[test]
fn custody_binds_formula_origin_outside_self_consistent_packet() {
    let valid = validate_handoff(&fixture()).unwrap();
    let expected = FormulaDispatchCustody {
        manifest_digest: valid.manifest_digest.clone(),
        work_cell_digest: valid.work_cell_digest.clone(),
        required_authority: valid.required_authority.clone(),
    };
    let approved = preflight_with_custody(&fixture(), &expected).unwrap();
    assert_eq!(&*approved, &valid);
    let stale = FormulaDispatchCustody {
        manifest_digest: digest(b"earlier-campaign"),
        ..expected.clone()
    };
    assert_eq!(
        preflight_with_custody(&fixture(), &stale),
        Err(FormulaWorkCellError::IdentityMismatch)
    );
    let wrong_authority = FormulaDispatchCustody {
        required_authority: digest(b"foreign-authority"),
        ..expected
    };
    assert_eq!(
        preflight_with_custody(&fixture(), &wrong_authority),
        Err(FormulaWorkCellError::IdentityMismatch)
    );
}
