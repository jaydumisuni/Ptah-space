#!/usr/bin/env python3
from pathlib import Path

p = Path('crates/ptah-checkpoint/src/lib.rs')
s = p.read_text()

start = s.index('    /// Restore a verified bundle into exact newer Provider/materialization generations.')
end = s.index('    /// Produce independent recovery proof from explicit postconditions.', start)

replacement = r'''    /// Restore a verified bundle into an exact target after a separately proven,
    /// target-bound compatibility decision.
    ///
    /// Every validation runs before the first backend side effect. Restore progress is
    /// accumulated explicitly so a later failure cannot erase earlier outputs/evidence.
    ///
    /// # Errors
    /// Fails closed for stale evidence, incompatible targets, reused Attempts, integrity
    /// drift, or backend/observation failure.
    pub fn restore<B: CheckpointBackend>(
        &mut self,
        bundle_id: &str,
        attempt_ref: impl Into<String>,
        target: RestoreTarget,
        compatibility_decision: &RestoreCompatibilityDecision,
        now_unix_ms: u64,
        backend: &mut B,
    ) -> Result<RestoreRun, CheckpointError> {
        if !self.verified_bundles.contains(bundle_id) {
            return Err(CheckpointError::UnverifiedBundle);
        }
        let stored = self
            .bundles
            .get(bundle_id)
            .ok_or(CheckpointError::BundleNotFound)?
            .clone();
        if sha256_json(&stored.bundle.manifest)? != stored.bundle.manifest_sha256 {
            self.verified_bundles.remove(bundle_id);
            return Err(CheckpointError::ManifestMismatch);
        }
        validate_restore_target(&stored, &target)?;
        validate_compatibility_decision(
            bundle_id,
            &target,
            compatibility_decision,
            now_unix_ms,
        )?;
        preflight_restore(&stored, &target)?;

        let attempt_ref = attempt_ref.into();
        if attempt_ref.trim().is_empty() {
            return Err(CheckpointError::InvalidRestoreTarget("attempt_ref"));
        }
        if !self.used_attempts.insert(attempt_ref.clone()) {
            return Err(CheckpointError::ReusedAttempt);
        }

        let progress = execute_restore_components(&stored, &attempt_ref, &target, backend)?;
        Ok(build_restore_run(
            &stored,
            bundle_id,
            attempt_ref,
            target,
            progress,
        ))
    }

'''
s = s[:start] + replacement + s[end:]

insert_at = s.index('fn validate_request(')
helpers = r'''#[derive(Default)]
struct RestoreProgress {
    restored_output_refs: Vec<String>,
    evidence_refs: Vec<String>,
    limitations: Vec<String>,
}

fn preflight_restore(stored: &StoredBundle, target: &RestoreTarget) -> Result<(), CheckpointError> {
    let compatibility: BTreeSet<_> = target.compatibility_refs.iter().cloned().collect();
    for component in &stored.bundle.manifest.components {
        let bytes = stored
            .bytes_by_component
            .get(&component.component_id)
            .ok_or(CheckpointError::VerificationFailed)?;
        if bytes.len() != component.byte_len || sha256_hex(bytes) != component.content_sha256 {
            return Err(CheckpointError::VerificationFailed);
        }
        if let Some(requirement) = component
            .compatibility_requirement_refs
            .iter()
            .find(|requirement| !compatibility.contains(*requirement))
        {
            return Err(CheckpointError::CompatibilityUnsatisfied(requirement.clone()));
        }
        let provider_target = provider_target_for(target, component)?;
        if provider_target.target_provider_generation <= component.provider_generation {
            return Err(CheckpointError::StaleProviderGeneration(
                component.producer_provider_instance_ref.clone(),
            ));
        }
    }
    Ok(())
}

fn provider_target_for<'a>(
    target: &'a RestoreTarget,
    component: &CheckpointComponent,
) -> Result<&'a ProviderRecoveryTarget, CheckpointError> {
    target
        .provider_targets
        .iter()
        .find(|candidate| {
            candidate.source_provider_instance_ref == component.producer_provider_instance_ref
        })
        .ok_or_else(|| {
            CheckpointError::MissingProviderTarget(
                component.producer_provider_instance_ref.clone(),
            )
        })
}

fn execute_restore_components<B: CheckpointBackend>(
    stored: &StoredBundle,
    attempt_ref: &str,
    target: &RestoreTarget,
    backend: &mut B,
) -> Result<RestoreProgress, CheckpointError> {
    let mut progress = RestoreProgress {
        evidence_refs: target.restart_evidence_refs.clone(),
        ..RestoreProgress::default()
    };
    for component in &stored.bundle.manifest.components {
        let provider_target = provider_target_for(target, component)?;
        let request = ComponentRestoreRequest {
            checkpoint_component_ref: component.component_id.clone(),
            bytes: stored.bytes_by_component[&component.component_id].clone(),
            target_provider_instance_ref: provider_target.target_provider_instance_ref.clone(),
            target_provider_generation: provider_target.target_provider_generation,
            target_connection_epoch: provider_target.target_connection_epoch,
            target_materialization_generation: target.target_materialization_generation,
        };
        let restored = backend.restore(&request).map_err(|error| {
            partial_restore_error(
                stored,
                attempt_ref,
                &component.component_id,
                error.to_string(),
                &progress,
                target.target_materialization_generation,
            )
        })?;
        if let Some(reason) = restore_evidence_mismatch(&request, &restored) {
            return Err(partial_restore_error(
                stored,
                attempt_ref,
                &component.component_id,
                format!("restore_evidence_mismatch:{reason}"),
                &progress,
                target.target_materialization_generation,
            ));
        }
        append_unique(&mut progress.restored_output_refs, &restored.output_refs);
        append_unique(&mut progress.evidence_refs, &restored.evidence_refs);
        append_unique(&mut progress.limitations, &restored.limitations);
    }
    Ok(progress)
}

fn build_restore_run(
    stored: &StoredBundle,
    bundle_id: &str,
    attempt_ref: String,
    target: RestoreTarget,
    progress: RestoreProgress,
) -> RestoreRun {
    let snap = &stored.bundle.manifest.snapshot;
    let evidence = progress.evidence_refs.clone();
    RestoreRun {
        restore_run_id: new_id(),
        checkpoint_bundle_ref: bundle_id.to_owned(),
        attempt_ref,
        executor_ref: target.executor_ref,
        target_materialization_generation: target.target_materialization_generation,
        provider_targets: target.provider_targets,
        restart_evidence_refs: target.restart_evidence_refs,
        restored_output_refs: progress.restored_output_refs,
        activities: reconcile(&snap.activity_refs, ReconciliationState::Recovered, &evidence),
        attachments: reconcile(&snap.attachment_refs, ReconciliationState::Detached, &evidence),
        leases: reconcile(&snap.lease_refs, ReconciliationState::Fenced, &evidence),
        partial_artifacts: reconcile(
            &snap.partial_artifact_refs,
            ReconciliationState::Partial,
            &evidence,
        ),
        result_handles: reconcile(
            &snap
                .result_handles
                .iter()
                .map(|handle| handle.handle_ref.clone())
                .collect::<Vec<_>>(),
            ReconciliationState::Retained,
            &evidence,
        ),
        schedules: reconcile(
            &snap
                .schedules
                .iter()
                .map(|schedule| schedule.schedule_ref.clone())
                .collect::<Vec<_>>(),
            ReconciliationState::Retained,
            &evidence,
        ),
        conflict_receipts: reconcile(
            &snap.conflict_receipt_refs,
            ReconciliationState::Conflict,
            &evidence,
        ),
        uncertain_external_effects: reconcile(
            &snap.uncertain_external_effect_refs,
            ReconciliationState::Unknown,
            &evidence,
        ),
        evidence_refs: progress.evidence_refs,
        limitations: progress.limitations,
    }
}

'''
s = s[:insert_at] + helpers + s[insert_at:]

old_start = s.index('fn partial_restore_error(')
old_end = s.index('\nfn reconcile(', old_start)
new_partial = r'''fn partial_restore_error(
    stored: &StoredBundle,
    attempt_ref: &str,
    failed_component_ref: &str,
    message: String,
    progress: &RestoreProgress,
    target_materialization_generation: u64,
) -> CheckpointError {
    let mut uncertain = stored
        .bundle
        .manifest
        .snapshot
        .uncertain_external_effect_refs
        .clone();
    if !uncertain.iter().any(|item| item == failed_component_ref) {
        uncertain.push(failed_component_ref.to_owned());
    }
    CheckpointError::RestoreFailed(Box::new(PartialRestoreFailure {
        checkpoint_bundle_ref: stored.bundle.bundle_id.clone(),
        attempt_ref: attempt_ref.to_owned(),
        failed_component_ref: failed_component_ref.to_owned(),
        message,
        restored_output_refs: progress.restored_output_refs.clone(),
        evidence_refs: progress.evidence_refs.clone(),
        limitations: progress.limitations.clone(),
        uncertain_external_effect_refs: uncertain,
        target_materialization_generation,
    }))
}
'''
s = s[:old_start] + new_partial + s[old_end:]

s = s.replace('.map_err(serialization_error)', '.map_err(|error| serialization_error(&error))')
s = s.replace(
    'fn serialization_error(error: serde_json::Error) -> CheckpointError {',
    'fn serialization_error(error: &serde_json::Error) -> CheckpointError {',
)

p.write_text(s)
