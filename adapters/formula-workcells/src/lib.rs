#![forbid(unsafe_code)]
//! Formula `WorkCell` transport validation. This is a Ptah adapter, NOT a
//! mathematical Director, checker, promoter, or execution provider.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

const WIRE_SCHEMA: &str = "formula-ptah-handoff-v1";
const MANIFEST_SCHEMA: &str = "formula-director-manifest-v1";
const CELL_SCHEMA: &str = "formula-work-cell-plan-v1";
const NO_SIDE_EFFECTS: &str = "SideEffectPolicy { allow_local_process: false, allow_network: false, allow_authority_write: false }";

/// Transport-boundary validation errors. None is a mathematical verdict.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FormulaWorkCellError {
    /// JSON is malformed or its declared fields do not match this exact schema.
    #[error("invalid handoff schema or JSON")]
    InvalidJson,
    /// Serialized object is not the canonical sender representation.
    #[error("noncanonical envelope or nested payload")]
    Noncanonical,
    /// One SHA-256 claim is malformed or not matched by its exact bytes.
    #[error("digest does not bind exact bytes")]
    DigestMismatch,
    /// A packet's object identities, schema, or obligation do not match.
    #[error("work cell identity, authority, or manifest mismatch")]
    IdentityMismatch,
    /// The work cell requests side effects incompatible with this adapter.
    #[error("work cell attempts forbidden side effects")]
    ForbiddenSideEffects,
    /// Work cell checkpoint, resources, or stop policy cannot be admitted.
    #[error("invalid work cell execution limits")]
    InvalidResourceContract,
    /// No candidate bytes were returned.
    #[error("empty candidate is not execution evidence")]
    EmptyCandidate,
}

/// Formula-owned canonical packet consumed by Ptah without reinterpretation.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema: String,
    manifest_digest: String,
    manifest_json: String,
    query_digest: String,
    query_json: String,
    work_cell_digest: String,
    work_cell_json: String,
    obligation_digest: String,
    required_authority: String,
    result_policy: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FormulaManifest {
    schema: String,
    campaign: String,
    query: String,
    replay_manifest: String,
    work_cells: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FormulaCell {
    schema: String,
    allowed_capabilities: Vec<String>,
    allowed_packages: Vec<String>,
    checkpoint_policy: String,
    deterministic_replay_key: String,
    evidence_requirement: String,
    obligation_digest: String,
    required_authority: String,
    resource_budget: String,
    semantic_inputs: Vec<String>,
    side_effect_limits: String,
    stop_conditions: Vec<String>,
}

/// Inspected, untrusted Formula work cell; structural integrity alone is not
/// authorization to dispatch, stage or issue a candidate receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedFormulaWorkCell {
    /// Exact Formula Director manifest identity.
    pub manifest_digest: String,
    /// Exact Formula `QueryIR` digest.
    pub query_digest: String,
    /// Formula requested result class.
    pub requested_result_class: String,
    /// Bound source input artifact digests.
    pub known_input_digests: Vec<String>,
    /// Exact Formula `WorkCellPlan` digest.
    pub work_cell_digest: String,
    /// Formula obligation identity; not mutable by Ptah.
    pub obligation_digest: String,
    /// Required Formula mathematical authority identity.
    pub required_authority: String,
    /// Resource ceiling.
    pub max_work_units: u64,
    /// Memory ceiling in bytes.
    pub max_memory_bytes: u64,
    /// Wall-clock ceiling in milliseconds.
    pub wall_clock_millis: u64,
}

/// Dispatch-capable work: obtainable ONLY after independent A04 custody
/// preflight. Unlike syntax inspection this type cannot be assembled by callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedFormulaWorkCell {
    inspected: InspectedFormulaWorkCell,
}
impl std::ops::Deref for ValidatedFormulaWorkCell {
    type Target = InspectedFormulaWorkCell;
    fn deref(&self) -> &Self::Target {
        &self.inspected
    }
}

/// Caller-owned expected Formula identities from the admitted A04 operation
/// custody context. These MUST be provided independently of the wire payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormulaDispatchCustody {
    /// Expected Formula Director manifest.
    pub manifest_digest: String,
    /// Expected exact Formula work-cell identity.
    pub work_cell_digest: String,
    /// Expected admitted mathematical authority.
    pub required_authority: String,
}

/// Untrusted candidate receipt, *never* a Formula mathematical certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateOnlyReceipt {
    /// Exact source manifest.
    pub manifest_digest: String,
    /// Exact executed work-cell identity.
    pub work_cell_digest: String,
    /// Digest of the returned candidate bytes.
    pub claimed_digest: String,
    /// Bytes requiring independent Formula semantic verification.
    pub bytes: Vec<u8>,
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}

fn check_digest(value: &str, bytes: &[u8]) -> Result<(), FormulaWorkCellError> {
    if !is_digest(value) || hash_bytes(bytes) != value {
        return Err(FormulaWorkCellError::DigestMismatch);
    }
    Ok(())
}

fn canonical_json(raw: &[u8]) -> Result<serde_json::Value, FormulaWorkCellError> {
    let parsed: serde_json::Value =
        serde_json::from_slice(raw).map_err(|_| FormulaWorkCellError::InvalidJson)?;
    let canonical = serde_json::to_vec(&parsed).map_err(|_| FormulaWorkCellError::InvalidJson)?;
    if canonical != raw {
        return Err(FormulaWorkCellError::Noncanonical);
    }
    Ok(parsed)
}

fn ensure_digest_list(values: &[String]) -> Result<(), FormulaWorkCellError> {
    if values.iter().any(|x| !is_digest(x)) {
        return Err(FormulaWorkCellError::IdentityMismatch);
    }
    Ok(())
}

fn parse_budget(input: &str) -> Result<(u64, u64, u64), FormulaWorkCellError> {
    let raw = input
        .strip_prefix("ResourceContract { ")
        .and_then(|v| v.strip_suffix(" }"))
        .ok_or(FormulaWorkCellError::InvalidResourceContract)?;
    let fields: Vec<_> = raw.split(", ").collect();
    if fields.len() != 3 {
        return Err(FormulaWorkCellError::InvalidResourceContract);
    }
    let work = fields[0]
        .strip_prefix("max_work_units: ")
        .ok_or(FormulaWorkCellError::InvalidResourceContract)?
        .parse::<u64>()
        .map_err(|_| FormulaWorkCellError::InvalidResourceContract)?;
    let memory = fields[1]
        .strip_prefix("max_memory_bytes: ")
        .ok_or(FormulaWorkCellError::InvalidResourceContract)?
        .parse::<u64>()
        .map_err(|_| FormulaWorkCellError::InvalidResourceContract)?;
    let time = fields[2]
        .strip_prefix("wall_clock_millis: ")
        .ok_or(FormulaWorkCellError::InvalidResourceContract)?
        .parse::<u64>()
        .map_err(|_| FormulaWorkCellError::InvalidResourceContract)?;
    if work == 0 || memory == 0 || time == 0 {
        return Err(FormulaWorkCellError::InvalidResourceContract);
    }
    Ok((work, memory, time))
}

/// Validate an exact canonical Formula packet before handing it to the
/// existing Ptah Activity/placement/provider infrastructure.
/// No Activity, Attempt, process or mathematical authority is created here.
///
/// # Errors
/// Rejects malformed identity, noncanonical bytes, unsafe effect policies and
/// invalid budget/stop contract. Failing validation cannot start execution.
#[allow(clippy::too_many_lines)]
pub fn validate_handoff(bytes: &[u8]) -> Result<InspectedFormulaWorkCell, FormulaWorkCellError> {
    canonical_json(bytes)?;
    let wire: Wire =
        serde_json::from_slice(bytes).map_err(|_| FormulaWorkCellError::InvalidJson)?;
    if wire.schema != WIRE_SCHEMA || wire.result_policy != "CANDIDATE_ONLY" {
        return Err(FormulaWorkCellError::IdentityMismatch);
    }
    check_digest(&wire.manifest_digest, wire.manifest_json.as_bytes())?;
    check_digest(&wire.query_digest, wire.query_json.as_bytes())?;
    check_digest(&wire.work_cell_digest, wire.work_cell_json.as_bytes())?;
    canonical_json(wire.manifest_json.as_bytes())?;
    let query = canonical_json(wire.query_json.as_bytes())?;
    canonical_json(wire.work_cell_json.as_bytes())?;
    let manifest: FormulaManifest =
        serde_json::from_str(&wire.manifest_json).map_err(|_| FormulaWorkCellError::InvalidJson)?;
    let cell: FormulaCell = serde_json::from_str(&wire.work_cell_json)
        .map_err(|_| FormulaWorkCellError::InvalidJson)?;
    if manifest.query != wire.query_digest
        || query["schema"] != "formula-query-ir-v1"
        || query["authority_contract"] != wire.required_authority
        || query["side_effect_policy"]["allow_authority_write"] != false
        || query["side_effect_policy"]["allow_local_process"] != false
        || query["side_effect_policy"]["allow_network"] != false
    {
        return Err(FormulaWorkCellError::IdentityMismatch);
    }
    if manifest.schema != MANIFEST_SCHEMA || cell.schema != CELL_SCHEMA {
        return Err(FormulaWorkCellError::IdentityMismatch);
    }
    ensure_digest_list(&[
        manifest.campaign,
        manifest.query,
        manifest.replay_manifest,
        cell.deterministic_replay_key,
        cell.evidence_requirement,
    ])?;
    ensure_digest_list(&manifest.work_cells)?;
    ensure_digest_list(&cell.allowed_capabilities)?;
    ensure_digest_list(&cell.allowed_packages)?;
    ensure_digest_list(&cell.semantic_inputs)?;
    if !is_digest(&wire.obligation_digest)
        || !is_digest(&wire.required_authority)
        || cell.obligation_digest != wire.obligation_digest
        || cell.required_authority != wire.required_authority
        || !manifest.work_cells.contains(&wire.work_cell_digest)
    {
        return Err(FormulaWorkCellError::IdentityMismatch);
    }
    if cell.side_effect_limits != NO_SIDE_EFFECTS {
        return Err(FormulaWorkCellError::ForbiddenSideEffects);
    }
    if cell.checkpoint_policy != "AT_STOP_BOUNDARY"
        || cell.stop_conditions.is_empty()
        || cell.stop_conditions.iter().any(|x| {
            !matches!(
                x.as_str(),
                "SATISFIED"
                    | "REFUTED"
                    | "CERTIFIED_BOUND"
                    | "SEMANTIC_UNKNOWN"
                    | "RESOURCE_BOUNDED_UNKNOWN"
                    | "BLOCKED_BY_AUTHORITY"
            )
        })
    {
        return Err(FormulaWorkCellError::InvalidResourceContract);
    }
    let (work, memory, time) = parse_budget(&cell.resource_budget)?;
    let requested = query["targets"]
        .as_array()
        .and_then(|t| t.first())
        .and_then(|t| t["result_class"].as_str())
        .ok_or(FormulaWorkCellError::IdentityMismatch)?;
    if !["COUNT", "WITNESS", "DECISION", "OPTIMUM", "BOUND"].contains(&requested) {
        return Err(FormulaWorkCellError::IdentityMismatch);
    }
    let inputs = query["known_bindings"]
        .as_array()
        .ok_or(FormulaWorkCellError::IdentityMismatch)?
        .iter()
        .map(|entry| entry["artifact"].as_str().unwrap_or("").to_string())
        .collect::<Vec<_>>();
    ensure_digest_list(&inputs)?;
    let limits = &query["resource_contract"];
    if limits["max_work_units"].as_str() != Some(work.to_string().as_str())
        || limits["max_memory_bytes"].as_str() != Some(memory.to_string().as_str())
        || limits["wall_clock_millis"].as_str() != Some(time.to_string().as_str())
    {
        return Err(FormulaWorkCellError::InvalidResourceContract);
    }
    Ok(InspectedFormulaWorkCell {
        manifest_digest: wire.manifest_digest,
        query_digest: wire.query_digest,
        requested_result_class: requested.to_string(),
        known_input_digests: inputs,
        work_cell_digest: wire.work_cell_digest,
        obligation_digest: wire.obligation_digest,
        required_authority: wire.required_authority,
        max_work_units: work,
        max_memory_bytes: memory,
        wall_clock_millis: time,
    })
}

/// Package candidate bytes with exact Formula provenance for independent
/// verification by Formula. Neither Ptah nor this receipt admits the candidate.
///
/// # Errors
/// Empty output is not evidence.
pub fn candidate_only_receipt(
    work: &ValidatedFormulaWorkCell,
    bytes: Vec<u8>,
) -> Result<CandidateOnlyReceipt, FormulaWorkCellError> {
    if bytes.is_empty() {
        return Err(FormulaWorkCellError::EmptyCandidate);
    }
    Ok(CandidateOnlyReceipt {
        manifest_digest: work.manifest_digest.clone(),
        work_cell_digest: work.work_cell_digest.clone(),
        claimed_digest: hash_bytes(&bytes),
        bytes,
    })
}

/// Check the Formula packet against caller-supplied A04 custody identities
/// before any Ptah placement or execution action. Self-consistent hashes alone
/// are not dispatch authorization.
///
/// # Errors
/// Rejects forged, stale, swapped, or otherwise unbound Formula work.
pub fn preflight_with_custody(
    bytes: &[u8],
    expected: &FormulaDispatchCustody,
) -> Result<ValidatedFormulaWorkCell, FormulaWorkCellError> {
    if !is_digest(&expected.manifest_digest)
        || !is_digest(&expected.work_cell_digest)
        || !is_digest(&expected.required_authority)
    {
        return Err(FormulaWorkCellError::IdentityMismatch);
    }
    let work = validate_handoff(bytes)?;
    if work.manifest_digest != expected.manifest_digest
        || work.work_cell_digest != expected.work_cell_digest
        || work.required_authority != expected.required_authority
    {
        return Err(FormulaWorkCellError::IdentityMismatch);
    }
    Ok(ValidatedFormulaWorkCell { inspected: work })
}
