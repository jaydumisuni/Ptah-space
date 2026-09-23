//! E04 Task 7 stateless restart, retry and concurrency evidence.

use ptah_checkpoint::{RecoveryOutcome, RecoveryVerification, RestoreRun};
use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_placement_runtime::{AuthorityBinding, FenceToken};
use ptah_transfer::TransferRouteKind;
use ptah_workspace_movement::{
    TargetAuthorityEvidence, VaultTransferEvidence, WorkspaceMoveError, WorkspaceMoveEvidence,
    WorkspaceMovePhase, WorkspaceMover,
};

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid entity kind")
}

fn source(seed: char) -> WorkspaceMoveEvidence {
    WorkspaceMoveEvidence {
        source_archive_sha256: seed.to_string().repeat(64),
        checkpoint_bundle_ref: format!("checkpoint:{seed}"),
        workspace_ref: "workspace:shared".to_owned(),
        workspace_revision_ref: "workspace-revision:shared".to_owned(),
    }
}

fn target(attempt_ref: EntityRef, generation: u64, fence: u64) -> TargetAuthorityEvidence {
    TargetAuthorityEvidence {
        binding: AuthorityBinding::new(
            attempt_ref,
            NodeId::new(),
            NodeGeneration::new(generation),
            ConnectionEpoch::new(11),
        ),
        reservation_ref: entity("resource.reservation"),
        lease_ref: entity("isolation.lease"),
        fence: FenceToken::new(fence).expect("positive fence"),
    }
}

fn transfer(source: &WorkspaceMoveEvidence, route: TransferRouteKind) -> VaultTransferEvidence {
    VaultTransferEvidence {
        ticket_ref: entity("transfer.ticket"),
        run_ref: entity("transfer.run"),
        verification_ref: entity("transfer.verification"),
        route_kind: route,
        destination_sha256: source.source_archive_sha256.clone(),
        observed_size: 4096,
    }
}

fn restore(
    source: &WorkspaceMoveEvidence,
    target: &TargetAuthorityEvidence,
    run_id: &str,
) -> RestoreRun {
    RestoreRun {
        restore_run_id: run_id.to_owned(),
        checkpoint_bundle_ref: source.checkpoint_bundle_ref.clone(),
        attempt_ref: target.binding.attempt_ref().entity_id.to_string(),
        executor_ref: "executor:e04".to_owned(),
        target_materialization_generation: 10,
        provider_targets: Vec::new(),
        restart_evidence_refs: vec!["evidence:restart".to_owned()],
        restored_output_refs: vec!["output:workspace".to_owned()],
        activities: Vec::new(),
        attachments: Vec::new(),
        leases: Vec::new(),
        partial_artifacts: Vec::new(),
        result_handles: Vec::new(),
        schedules: Vec::new(),
        conflict_receipts: Vec::new(),
        uncertain_external_effects: Vec::new(),
        evidence_refs: vec!["evidence:restore".to_owned()],
        limitations: Vec::new(),
    }
}

fn recovery(restore: &RestoreRun, outcome: RecoveryOutcome) -> RecoveryVerification {
    RecoveryVerification {
        verification_id: format!("recovery:{}", restore.restore_run_id),
        restore_run_ref: restore.restore_run_id.clone(),
        verifier_ref: "verifier:independent".to_owned(),
        verifier_independent: true,
        target_materialization_generation: restore.target_materialization_generation,
        outcome,
        postconditions: Vec::new(),
        unresolved_operation_refs: Vec::new(),
        evidence_refs: vec!["evidence:recovery".to_owned()],
        limitations: Vec::new(),
    }
}

#[test]
fn coordinator_restart_reconstructs_terminal_phase_only_from_bound_owner_evidence() {
    let source = source('a');
    let target = target(entity("activity.attempt"), 7, 1);
    let transfer = transfer(&source, TransferRouteKind::Direct);
    let restore = restore(&source, &target, "restore:restart");
    let failed = recovery(&restore, RecoveryOutcome::Failed);

    let reconstructed = WorkspaceMover::reconstruct_terminal_evidence(
        source.clone(),
        target.clone(),
        transfer.clone(),
        restore.clone(),
        failed.clone(),
    )
    .expect("exact owner evidence reconstructs after coordinator restart");

    assert_eq!(reconstructed.phase, WorkspaceMovePhase::Failed);
    assert_eq!(reconstructed.restore_run, restore);
    assert_eq!(reconstructed.recovery_verification, failed);

    let mut wrong_restore_link = recovery(&restore, RecoveryOutcome::Recovered);
    wrong_restore_link.restore_run_ref = "restore:other".to_owned();
    assert!(matches!(
        WorkspaceMover::reconstruct_terminal_evidence(
            source,
            target,
            transfer,
            restore,
            wrong_restore_link,
        ),
        Err(WorkspaceMoveError::OwnerEvidenceMismatch(
            "recovery restore_run_ref"
        ))
    ));
}

#[test]
fn retry_requires_failed_prior_evidence_and_a_distinct_fresh_attempt() {
    let source = source('b');
    let attempt_a = entity("activity.attempt");
    let target_a = target(attempt_a.clone(), 7, 1);
    let transfer_a = transfer(&source, TransferRouteKind::Direct);
    let restore_a = restore(&source, &target_a, "restore:prior");
    let prior = WorkspaceMover::reconstruct_terminal_evidence(
        source.clone(),
        target_a.clone(),
        transfer_a,
        restore_a.clone(),
        recovery(&restore_a, RecoveryOutcome::Failed),
    )
    .expect("prior failure evidence");

    let same_target = target(attempt_a, 7, 2);
    let same_restore = restore(&source, &same_target, "restore:same-attempt");
    let same_attempt = WorkspaceMover::reconstruct_terminal_evidence(
        source.clone(),
        same_target,
        transfer(&source, TransferRouteKind::Direct),
        same_restore.clone(),
        recovery(&same_restore, RecoveryOutcome::Recovered),
    )
    .expect("mechanically valid fresh owner records with reused attempt");

    assert!(matches!(
        WorkspaceMover::record_retry(&prior, &same_attempt),
        Err(WorkspaceMoveError::RetryAttemptReused)
    ));

    let target_b = target(entity("activity.attempt"), 7, 1);
    let restore_b = restore(&source, &target_b, "restore:fresh");
    let fresh = WorkspaceMover::reconstruct_terminal_evidence(
        source.clone(),
        target_b,
        transfer(&source, TransferRouteKind::Direct),
        restore_b.clone(),
        recovery(&restore_b, RecoveryOutcome::Recovered),
    )
    .expect("fresh attempt owner evidence");

    let retry = WorkspaceMover::record_retry(&prior, &fresh).expect("fresh retry evidence");
    assert_eq!(
        retry.prior_recovery_verification,
        prior.recovery_verification
    );
    assert_eq!(
        retry.fresh_recovery_verification,
        fresh.recovery_verification
    );
    assert_ne!(retry.prior_attempt_ref, retry.fresh_attempt_ref);

    let recovered_prior_restore = restore(&source, &target_a, "restore:recovered-prior");
    let recovered_prior = WorkspaceMover::reconstruct_terminal_evidence(
        source.clone(),
        target_a,
        transfer(&source, TransferRouteKind::Direct),
        recovered_prior_restore.clone(),
        recovery(&recovered_prior_restore, RecoveryOutcome::Recovered),
    )
    .expect("recovered prior");
    assert!(matches!(
        WorkspaceMover::record_retry(&recovered_prior, &fresh),
        Err(WorkspaceMoveError::RetryRequiresPriorFailure)
    ));
}

#[test]
fn retry_cannot_change_the_source_vault_identity() {
    let source_a = source('c');
    let target_a = target(entity("activity.attempt"), 7, 1);
    let restore_a = restore(&source_a, &target_a, "restore:source-a");
    let prior = WorkspaceMover::reconstruct_terminal_evidence(
        source_a.clone(),
        target_a,
        transfer(&source_a, TransferRouteKind::Direct),
        restore_a.clone(),
        recovery(&restore_a, RecoveryOutcome::Failed),
    )
    .expect("prior");

    let source_b = source('d');
    let target_b = target(entity("activity.attempt"), 7, 1);
    let restore_b = restore(&source_b, &target_b, "restore:source-b");
    let fresh = WorkspaceMover::reconstruct_terminal_evidence(
        source_b.clone(),
        target_b,
        transfer(&source_b, TransferRouteKind::Direct),
        restore_b.clone(),
        recovery(&restore_b, RecoveryOutcome::Recovered),
    )
    .expect("fresh");

    assert!(matches!(
        WorkspaceMover::record_retry(&prior, &fresh),
        Err(WorkspaceMoveError::RetrySourceMismatch)
    ));
}

#[test]
fn target_generation_change_and_concurrent_attempts_do_not_alias_isolation_evidence() {
    let source = source('e');
    let attempt_a = entity("activity.attempt");
    let old_target = target(attempt_a, 7, 1);
    let old_transfer = transfer(&source, TransferRouteKind::Direct);
    let old = WorkspaceMover::isolation_evidence(&source, &old_target, &old_transfer);

    let new_generation_target = target(entity("activity.attempt"), 8, 1);
    let new_generation_transfer = transfer(&source, TransferRouteKind::Direct);
    let new_generation = WorkspaceMover::isolation_evidence(
        &source,
        &new_generation_target,
        &new_generation_transfer,
    );

    assert_ne!(old, new_generation);
    assert_ne!(
        old.target_binding.node_generation(),
        new_generation.target_binding.node_generation()
    );

    let concurrent_target = target(entity("activity.attempt"), 7, 1);
    let concurrent_transfer = transfer(&source, TransferRouteKind::Relay);
    let concurrent =
        WorkspaceMover::isolation_evidence(&source, &concurrent_target, &concurrent_transfer);

    assert_ne!(old, concurrent);
    assert_ne!(
        old.target_binding.attempt_ref(),
        concurrent.target_binding.attempt_ref()
    );
    assert_ne!(old.ticket_ref, concurrent.ticket_ref);
    assert_ne!(old.run_ref, concurrent.run_ref);
}

#[test]
fn reconstruction_rejects_restore_attempt_or_checkpoint_rebinding() {
    let source = source('f');
    let target = target(entity("activity.attempt"), 7, 1);
    let transfer = transfer(&source, TransferRouteKind::Direct);

    let mut wrong_attempt = restore(&source, &target, "restore:wrong-attempt");
    wrong_attempt.attempt_ref = "attempt:foreign".to_owned();
    let proof = recovery(&wrong_attempt, RecoveryOutcome::Failed);
    assert!(matches!(
        WorkspaceMover::reconstruct_terminal_evidence(
            source.clone(),
            target.clone(),
            transfer.clone(),
            wrong_attempt,
            proof,
        ),
        Err(WorkspaceMoveError::OwnerEvidenceMismatch(
            "restore attempt_ref"
        ))
    ));

    let mut wrong_checkpoint = restore(&source, &target, "restore:wrong-checkpoint");
    wrong_checkpoint.checkpoint_bundle_ref = "checkpoint:foreign".to_owned();
    let proof = recovery(&wrong_checkpoint, RecoveryOutcome::Failed);
    assert!(matches!(
        WorkspaceMover::reconstruct_terminal_evidence(
            source,
            target,
            transfer,
            wrong_checkpoint,
            proof,
        ),
        Err(WorkspaceMoveError::OwnerEvidenceMismatch(
            "restore checkpoint_bundle_ref"
        ))
    ));
}
