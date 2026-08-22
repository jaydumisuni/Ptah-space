#!/usr/bin/env python3
from pathlib import Path

p = Path('crates/ptah-checkpoint/src/lib.rs')
s = p.read_text()

def replace(old, new):
    global s
    if old not in s:
        raise SystemExit(f'missing transform anchor: {old[:120]!r}')
    s = s.replace(old, new, 1)

replace(
'''/// Independent recovery-verification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOutcome {''',
'''/// Target-specific restore-compatibility outcome. Integrity verification is separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityOutcome {
    /// Target satisfies the declared requirements without conversion.
    Compatible,
    /// Target is compatible only through an explicitly authorized conversion path.
    CompatibleWithConversion,
    /// Target can satisfy only a reduced scope and cannot authorize this full restore.
    PartiallyCompatible,
    /// Target conflicts with one or more declared requirements.
    Incompatible,
    /// Evidence is insufficient to decide compatibility.
    Unknown,
}

/// Immutable, target-specific and time-bounded restore compatibility decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreCompatibilityDecision {
    /// Stable decision identifier.
    pub decision_id: String,
    /// Exact checkpoint bundle evaluated.
    pub checkpoint_bundle_ref: String,
    /// SHA-256 binding of the exact restore target evaluated.
    pub target_fingerprint_sha256: String,
    /// Compatibility outcome, distinct from checkpoint integrity verification.
    pub outcome: CompatibilityOutcome,
    /// Decision evaluation time in Unix milliseconds.
    pub evaluated_at_unix_ms: u64,
    /// Expiry time in Unix milliseconds.
    pub valid_until_unix_ms: u64,
    /// Evidence supporting the target-specific decision.
    pub evidence_refs: Vec<String>,
    /// Explicit incompatibilities, conversions or unknowns.
    pub limitations: Vec<String>,
}

/// Independent recovery-verification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOutcome {''')

replace(
'''    /// Recovery-target compatibility requirements were satisfied.
    pub compatibility_verified: bool,
''',
''' ''')

replace(
'''pub struct RestoreTarget {
    /// New Workspace materialization generation.
    pub target_materialization_generation: u64,''',
'''pub struct RestoreTarget {
    /// Canonical target Workspace reference.
    pub workspace_ref: String,
    /// Exact target Workspace Revision reference.
    pub workspace_revision_ref: String,
    /// New Workspace materialization generation.
    pub target_materialization_generation: u64,''')

replace(
'''    /// Evidence that the Node/runtime restart or replacement actually occurred.
    pub restart_evidence_refs: Vec<String>,
    /// Exact executor identity for independence checks.
    pub executor_ref: String,
}''',
'''    /// Evidence that the Node/runtime restart or replacement actually occurred.
    pub restart_evidence_refs: Vec<String>,
    /// Credential, network, device, storage or isolation authorization references.
    pub authorization_refs: Vec<String>,
    /// Exact executor identity for independence checks.
    pub executor_ref: String,
}''')

replace(
'''    /// Target compatibility requirement is not satisfied.
    #[error("target compatibility requirement is unsatisfied: {0}")]
    CompatibilityUnsatisfied(String),
    /// Checkpoint has not passed independent verification.''',
'''    /// Target compatibility requirement is not satisfied.
    #[error("target compatibility requirement is unsatisfied: {0}")]
    CompatibilityUnsatisfied(String),
    /// Compatibility decision does not bind this bundle and exact target.
    #[error("restore compatibility decision does not match the requested restore")]
    CompatibilityDecisionMismatch,
    /// Compatibility decision does not authorize a full restore.
    #[error("restore target is not compatibly authorized")]
    IncompatibleRestoreTarget,
    /// Compatibility decision expired before restore execution.
    #[error("restore compatibility decision has expired")]
    ExpiredCompatibilityDecision,
    /// Checkpoint has not passed independent verification.''')

replace(
'''        required_classes: &[CheckpointClass],
        available_compatibility_refs: &[String],
        backend: &B,''',
'''        required_classes: &[CheckpointClass],
        backend: &B,''')

replace(
'''        let available: BTreeSet<_> = available_compatibility_refs.iter().cloned().collect();
''',
''' ''')

replace(
'''            let compatibility_verified = component
                .compatibility_requirement_refs
                .iter()
                .all(|requirement| available.contains(requirement));
            explicit_failure |= !compatibility_verified;

''',
''' ''')

replace(
'''            if !compatibility_verified {
                limitations.push("target_compatibility_unsatisfied".to_owned());
            }
''',
''' ''')

replace(
'''                readback_verified,
                compatibility_verified,
                evidence_refs,''',
'''                readback_verified,
                evidence_refs,''')

anchor = '''    /// Restore a verified bundle into exact newer Provider/materialization generations.
'''
insert = '''    /// Evaluate restore compatibility independently from checkpoint integrity verification.
    ///
    /// The decision is exact-target bound and time-bounded. A full restore accepts only
    /// `Compatible` or `CompatibleWithConversion`; reduced/unknown/incompatible decisions
    /// remain visible but cannot authorize mutation.
    ///
    /// # Errors
    /// Fails when the bundle is unknown, the target is structurally invalid, or the
    /// compatibility decision time window itself is invalid.
    pub fn evaluate_restore_compatibility(
        &self,
        bundle_id: &str,
        target: &RestoreTarget,
        evidence_refs: Vec<String>,
        evaluated_at_unix_ms: u64,
        valid_until_unix_ms: u64,
    ) -> Result<RestoreCompatibilityDecision, CheckpointError> {
        let stored = self
            .bundles
            .get(bundle_id)
            .ok_or(CheckpointError::BundleNotFound)?;
        validate_restore_target(stored, target)?;
        if valid_until_unix_ms <= evaluated_at_unix_ms {
            return Err(CheckpointError::InvalidRestoreTarget(
                "compatibility validity window",
            ));
        }
        let mut limitations = Vec::new();
        if target.workspace_ref != stored.bundle.manifest.workspace_ref {
            limitations.push("target_workspace_mismatch".to_owned());
        }
        if target.workspace_revision_ref != stored.bundle.manifest.workspace_revision_ref {
            limitations.push("target_workspace_revision_mismatch".to_owned());
        }
        let available: BTreeSet<_> = target.compatibility_refs.iter().cloned().collect();
        let target_map: BTreeMap<_, _> = target
            .provider_targets
            .iter()
            .map(|item| (item.source_provider_instance_ref.clone(), item))
            .collect();
        for component in &stored.bundle.manifest.components {
            for requirement in &component.compatibility_requirement_refs {
                if !available.contains(requirement) {
                    limitations.push(format!("missing_compatibility:{requirement}"));
                }
            }
            match target_map.get(&component.producer_provider_instance_ref) {
                Some(provider_target)
                    if provider_target.target_provider_generation > component.provider_generation => {}
                Some(_) => limitations.push(format!(
                    "stale_provider_generation:{}",
                    component.producer_provider_instance_ref
                )),
                None => limitations.push(format!(
                    "missing_provider_target:{}",
                    component.producer_provider_instance_ref
                )),
            }
        }
        let outcome = if evidence_refs.is_empty() {
            CompatibilityOutcome::Unknown
        } else if limitations.is_empty() {
            CompatibilityOutcome::Compatible
        } else {
            CompatibilityOutcome::Incompatible
        };
        Ok(RestoreCompatibilityDecision {
            decision_id: new_id(),
            checkpoint_bundle_ref: bundle_id.to_owned(),
            target_fingerprint_sha256: target_fingerprint(target)?,
            outcome,
            evaluated_at_unix_ms,
            valid_until_unix_ms,
            evidence_refs,
            limitations,
        })
    }

'''
if anchor not in s:
    raise SystemExit('missing compatibility insertion anchor')
s = s.replace(anchor, insert + anchor, 1)

replace(
'''        attempt_ref: impl Into<String>,
        target: RestoreTarget,
        backend: &mut B,
    ) -> Result<RestoreRun, CheckpointError> {''',
'''        attempt_ref: impl Into<String>,
        target: RestoreTarget,
        compatibility_decision: &RestoreCompatibilityDecision,
        now_unix_ms: u64,
        backend: &mut B,
    ) -> Result<RestoreRun, CheckpointError> {''')

replace(
'''        validate_restore_target(&stored, &target)?;
        let attempt_ref = attempt_ref.into();''',
'''        validate_restore_target(&stored, &target)?;
        validate_compatibility_decision(
            bundle_id,
            &target,
            compatibility_decision,
            now_unix_ms,
        )?;
        let attempt_ref = attempt_ref.into();''')

replace(
'''    if target.target_materialization_generation
        <= stored.bundle.manifest.source_materialization_generation
    {''',
'''    if target.workspace_ref.trim().is_empty() || target.workspace_revision_ref.trim().is_empty() {
        return Err(CheckpointError::InvalidRestoreTarget(
            "workspace target identity",
        ));
    }
    if target.target_materialization_generation
        <= stored.bundle.manifest.source_materialization_generation
    {''')

replace(
'''    if target.restart_evidence_refs.is_empty()
        || target
            .restart_evidence_refs
            .iter()
            .any(|item| item.trim().is_empty())
    {
        return Err(CheckpointError::MissingRestartEvidence);
    }
''',
'''    if target.restart_evidence_refs.is_empty()
        || target
            .restart_evidence_refs
            .iter()
            .any(|item| item.trim().is_empty())
    {
        return Err(CheckpointError::MissingRestartEvidence);
    }
    if target.authorization_refs.is_empty()
        || target.authorization_refs.iter().any(|item| item.trim().is_empty())
    {
        return Err(CheckpointError::InvalidRestoreTarget("authorization_refs"));
    }
''')

marker = '''fn restore_evidence_mismatch(
'''
helpers = '''fn validate_compatibility_decision(
    bundle_id: &str,
    target: &RestoreTarget,
    decision: &RestoreCompatibilityDecision,
    now_unix_ms: u64,
) -> Result<(), CheckpointError> {
    if decision.checkpoint_bundle_ref != bundle_id
        || decision.target_fingerprint_sha256 != target_fingerprint(target)?
    {
        return Err(CheckpointError::CompatibilityDecisionMismatch);
    }
    if now_unix_ms > decision.valid_until_unix_ms {
        return Err(CheckpointError::ExpiredCompatibilityDecision);
    }
    if !matches!(
        decision.outcome,
        CompatibilityOutcome::Compatible | CompatibilityOutcome::CompatibleWithConversion
    ) || decision.evidence_refs.is_empty()
    {
        return Err(CheckpointError::IncompatibleRestoreTarget);
    }
    Ok(())
}

fn target_fingerprint(target: &RestoreTarget) -> Result<String, CheckpointError> {
    sha256_json(target)
}

'''
if marker not in s:
    raise SystemExit('missing helper insertion anchor')
s = s.replace(marker, helpers + marker, 1)

p.write_text(s)
