//! C11 acceptance corpus for Device Manager and MIBU workload admissions.

use ptah_android_runtime::{
    ApplicationSession, ApplicationSessionState, DeviceSession, DeviceSessionState,
};
use ptah_identifiers::EntityRef;
use ptah_provider_api::ProviderGeneration;
use ttg_device_workload_admissions::*;
use ttg_device_xray_admission::{
    AdmittedXrayWorkload, XrayAuthority, XrayCertificationVerdict, XrayEvidenceDisposition,
    XrayEvidenceFreshness, XrayProfileStatus, XraySignatureObservation,
};

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("entity")
}

fn generation(value: u64) -> ProviderGeneration {
    ProviderGeneration::new(value).expect("generation")
}

fn device_session(provider_generation: u64, connection_epoch: u64) -> DeviceSession {
    DeviceSession {
        session_ref: entity("device.session"),
        workspace_ref: entity("workspace.workspace"),
        device_ref: entity("device.device"),
        device_profile_revision_ref: entity("device.profile_revision"),
        interface_ref: entity("device.interface"),
        connection_ref: entity("device.connection"),
        provider_instance_ref: entity("runtime.provider_instance"),
        provider_generation: generation(provider_generation),
        connection_epoch,
        lease_ref: entity("isolation.lease"),
        capability_snapshot_ref: entity("runtime.capability_snapshot"),
        privacy_policy_refs: vec![entity("policy.privacy")],
        evidence_refs: vec![entity("proof.evidence")],
        recovery_generation: 0,
        started_at: "2026-08-31T08:00:00Z".into(),
        state: DeviceSessionState::Connected,
    }
}

fn application_session(session: &DeviceSession, version: &str) -> ApplicationSession {
    ApplicationSession {
        session_ref: entity("application.session"),
        device_session_ref: session.session_ref.clone(),
        installation_ref: entity("application.installation"),
        application_ref: entity("application.application"),
        application_revision_ref: entity("application.revision"),
        package_id: MIBU_PACKAGE_ID.into(),
        installed_version: version.into(),
        verified_signer: "sha256:verified-mibu-signer".into(),
        provider_instance_ref: session.provider_instance_ref.clone(),
        provider_generation: session.provider_generation,
        connection_epoch: session.connection_epoch,
        process_aliases: vec!["pid:1200".into()],
        activity_or_context: "com.thetechguy.mibu/.MainActivity".into(),
        visible_frame_ref: entity("proof.evidence"),
        semantic_context_ref: entity("application.semantic_context"),
        evidence_refs: vec![entity("proof.evidence")],
        started_at: "2026-08-31T08:01:00Z".into(),
        state: ApplicationSessionState::Visible,
    }
}

fn device_manager_application_session(session: &DeviceSession) -> ApplicationSession {
    let mut app = application_session(session, DEVICE_MANAGER_APP_VERSION);
    app.package_id = DEVICE_MANAGER_PACKAGE_ID.into();
    app.verified_signer = "sha256:verified-device-manager-signer".into();
    app.activity_or_context = "com.thetechguy.ttgdevicemanager/.MainActivity".into();
    app
}

fn dpc_authorization(session: &DeviceSession) -> ReversibleDpcAuthorization {
    ReversibleDpcAuthorization {
        authorization_ref: entity("policy.authorization"),
        device_session_ref: session.session_ref.clone(),
        scope: ReversibleDpcScope::ApplicationVisibility,
        approved: true,
        provider_generation: session.provider_generation,
        connection_epoch: session.connection_epoch,
        evidence_refs: vec![entity("proof.evidence")],
        approved_at: "2026-08-31T08:03:30Z".into(),
    }
}

fn xray(session: &DeviceSession) -> AdmittedXrayWorkload {
    AdmittedXrayWorkload {
        source_commit_sha: "ad4ae832ed994944a5d8e99bc3a0785e257826ff".into(),
        scanner_version: "0.4.3.dev2".into(),
        device_ref: session.device_ref.clone(),
        interface_ref: session.interface_ref.clone(),
        connection_ref: session.connection_ref.clone(),
        connection_epoch: session.connection_epoch,
        provider_instance_ref: session.provider_instance_ref.clone(),
        provider_generation: session.provider_generation,
        bundle_ref: entity("object.artifact"),
        scan_id: "scan-c11".into(),
        manifest_sha256: "a".repeat(64),
        disposition: XrayEvidenceDisposition::Correlated,
        freshness: XrayEvidenceFreshness::Current,
        certification: XrayCertificationVerdict::Certified,
        profile_status: XrayProfileStatus::Matched,
        profile_id: Some("profile-c11".into()),
        signature: XraySignatureObservation::SignedClaimUnverifiedPublicly,
        c08_protocol_operation_refs: vec![entity("device.protocol_operation")],
        evidence_refs: vec![entity("proof.evidence")],
        disagreement_refs: vec![],
        authority: XrayAuthority::EvidenceOnlyReadOnly,
    }
}

fn owner(session: &DeviceSession, is_device_owner: bool) -> DeviceOwnerObservation {
    DeviceOwnerObservation {
        package_id: DEVICE_MANAGER_PACKAGE_ID.into(),
        component_name: "com.thetechguy.ttgdevicemanager/.TTGDeviceAdminReceiver".into(),
        is_device_owner,
        provider_generation: session.provider_generation,
        connection_epoch: session.connection_epoch,
        evidence_refs: vec![entity("proof.evidence")],
        observed_at: "2026-08-31T08:02:00Z".into(),
    }
}

fn visibility(
    session: &DeviceSession,
    package_id: &str,
    hidden: bool,
) -> ApplicationVisibilityObservation {
    ApplicationVisibilityObservation {
        package_id: package_id.into(),
        hidden,
        provider_generation: session.provider_generation,
        connection_epoch: session.connection_epoch,
        evidence_refs: vec![entity("proof.evidence")],
        observed_at: "2026-08-31T08:03:00Z".into(),
    }
}

fn policy_request<'a>(
    source: &'a DeviceManagerSourceLock,
    session: &'a DeviceSession,
    xray: &'a AdmittedXrayWorkload,
    owner: &'a DeviceOwnerObservation,
    before: &'a ApplicationVisibilityObservation,
    intent: DeviceManagerPolicyIntent,
) -> DeviceManagerPolicyRequest<'a> {
    DeviceManagerPolicyRequest {
        source,
        session,
        application_session: device_manager_application_session(session),
        xray,
        device_owner: owner,
        authorization: dpc_authorization(session),
        before,
        intent,
        evidence_refs: vec![entity("proof.evidence")],
        requested_at: "2026-08-31T08:04:00Z".into(),
    }
}

#[test]
fn device_manager_frozen_private_source_admits_metadata_only() {
    let session = device_session(4, 9);
    let xray = xray(&session);
    let owner = owner(&session, true);
    let before = visibility(&session, "com.example.app", false);
    let source = DeviceManagerSourceLock::frozen();
    let admitted = admit_device_manager_policy(policy_request(
        &source,
        &session,
        &xray,
        &owner,
        &before,
        DeviceManagerPolicyIntent::ApplicationVisibility {
            package_id: "com.example.app".into(),
            hidden: true,
        },
    ))
    .expect("admit reversible policy");
    assert_eq!(
        admitted.authority,
        DeviceManagerAuthority::ReversibleDpcPolicyOnly
    );
    assert!(!admitted.source_extraction_allowed);
    assert!(!source.public_reuse_grant);
    assert_eq!(source.application_version, DEVICE_MANAGER_APP_VERSION);
}

#[test]
fn device_manager_requires_exact_c10_package_version_and_verified_signer() {
    let session = device_session(4, 9);
    let xray = xray(&session);
    let owner = owner(&session, true);
    let before = visibility(&session, "com.example.app", false);
    let source = DeviceManagerSourceLock::frozen();

    let mut wrong_version = policy_request(
        &source,
        &session,
        &xray,
        &owner,
        &before,
        DeviceManagerPolicyIntent::ApplicationVisibility {
            package_id: "com.example.app".into(),
            hidden: true,
        },
    );
    wrong_version.application_session.installed_version = "wrong-version".into();
    assert_eq!(
        admit_device_manager_policy(wrong_version).unwrap_err(),
        C11AdmissionError::DeviceManagerApplicationMismatch
    );

    let mut missing_signer = policy_request(
        &source,
        &session,
        &xray,
        &owner,
        &before,
        DeviceManagerPolicyIntent::ApplicationVisibility {
            package_id: "com.example.app".into(),
            hidden: true,
        },
    );
    missing_signer.application_session.verified_signer.clear();
    assert_eq!(
        admit_device_manager_policy(missing_signer).unwrap_err(),
        C11AdmissionError::DeviceManagerApplicationMismatch
    );
}

#[test]
fn device_manager_requires_current_explicit_reversible_policy_authorization() {
    let session = device_session(4, 9);
    let xray = xray(&session);
    let owner = owner(&session, true);
    let before = visibility(&session, "com.example.app", false);
    let source = DeviceManagerSourceLock::frozen();

    let mut denied = policy_request(
        &source,
        &session,
        &xray,
        &owner,
        &before,
        DeviceManagerPolicyIntent::ApplicationVisibility {
            package_id: "com.example.app".into(),
            hidden: true,
        },
    );
    denied.authorization.approved = false;
    assert_eq!(
        admit_device_manager_policy(denied).unwrap_err(),
        C11AdmissionError::DpcAuthorizationMismatch
    );

    let mut stale = policy_request(
        &source,
        &session,
        &xray,
        &owner,
        &before,
        DeviceManagerPolicyIntent::ApplicationVisibility {
            package_id: "com.example.app".into(),
            hidden: true,
        },
    );
    stale.authorization.connection_epoch = 8;
    assert_eq!(
        admit_device_manager_policy(stale).unwrap_err(),
        C11AdmissionError::DpcAuthorizationMismatch
    );
}

#[test]
fn device_manager_source_or_private_blob_drift_fails_closed() {
    let session = device_session(4, 9);
    let xray = xray(&session);
    let owner = owner(&session, true);
    let before = visibility(&session, "com.example.app", false);
    let mut source = DeviceManagerSourceLock::frozen();
    source.admin_receiver_blob_sha1 = "0".repeat(40);
    let err = admit_device_manager_policy(policy_request(
        &source,
        &session,
        &xray,
        &owner,
        &before,
        DeviceManagerPolicyIntent::ApplicationVisibility {
            package_id: "com.example.app".into(),
            hidden: true,
        },
    ))
    .unwrap_err();
    assert_eq!(err, C11AdmissionError::DeviceManagerSourceLockMismatch);
}

#[test]
fn device_manager_requires_current_correlated_c09_evidence() {
    let session = device_session(4, 9);
    let mut xray = xray(&session);
    xray.disposition = XrayEvidenceDisposition::Investigate;
    let owner = owner(&session, true);
    let before = visibility(&session, "com.example.app", false);
    let source = DeviceManagerSourceLock::frozen();
    let err = admit_device_manager_policy(policy_request(
        &source,
        &session,
        &xray,
        &owner,
        &before,
        DeviceManagerPolicyIntent::ApplicationVisibility {
            package_id: "com.example.app".into(),
            hidden: true,
        },
    ))
    .unwrap_err();
    assert_eq!(err, C11AdmissionError::XrayNotCurrentCorrelated);
}

#[test]
fn device_manager_rejects_stale_xray_or_device_owner_epoch() {
    let session = device_session(4, 9);
    let mut stale_xray = xray(&session);
    stale_xray.connection_epoch = 8;
    let current_owner = owner(&session, true);
    let before = visibility(&session, "com.example.app", false);
    let source = DeviceManagerSourceLock::frozen();
    let err = admit_device_manager_policy(policy_request(
        &source,
        &session,
        &stale_xray,
        &current_owner,
        &before,
        DeviceManagerPolicyIntent::ApplicationVisibility {
            package_id: "com.example.app".into(),
            hidden: true,
        },
    ))
    .unwrap_err();
    assert_eq!(err, C11AdmissionError::DeviceContextMismatch);

    let xray = xray(&session);
    let mut stale_owner = owner(&session, true);
    stale_owner.connection_epoch = 8;
    let err = admit_device_manager_policy(policy_request(
        &source,
        &session,
        &xray,
        &stale_owner,
        &before,
        DeviceManagerPolicyIntent::ApplicationVisibility {
            package_id: "com.example.app".into(),
            hidden: true,
        },
    ))
    .unwrap_err();
    assert_eq!(err, C11AdmissionError::DeviceContextMismatch);
}

#[test]
fn device_manager_requires_independently_observed_device_owner() {
    let session = device_session(4, 9);
    let xray = xray(&session);
    let owner = owner(&session, false);
    let before = visibility(&session, "com.example.app", false);
    let source = DeviceManagerSourceLock::frozen();
    let err = admit_device_manager_policy(policy_request(
        &source,
        &session,
        &xray,
        &owner,
        &before,
        DeviceManagerPolicyIntent::ApplicationVisibility {
            package_id: "com.example.app".into(),
            hidden: true,
        },
    ))
    .unwrap_err();
    assert_eq!(err, C11AdmissionError::DeviceOwnerNotObserved);
}

#[test]
fn device_manager_restricted_or_ownership_changing_intents_never_admit() {
    let session = device_session(4, 9);
    let xray = xray(&session);
    let owner = owner(&session, true);
    let before = visibility(&session, "com.example.app", false);
    let source = DeviceManagerSourceLock::frozen();
    for intent in [
        DeviceManagerPolicyIntent::DeviceOwnerEnrollment,
        DeviceManagerPolicyIntent::FactoryReset,
        DeviceManagerPolicyIntent::FrpRemoval,
        DeviceManagerPolicyIntent::MdmRemoval,
        DeviceManagerPolicyIntent::RawPartitionWrite,
        DeviceManagerPolicyIntent::OtaPolicyChange,
    ] {
        let err = admit_device_manager_policy(policy_request(
            &source, &session, &xray, &owner, &before, intent,
        ))
        .unwrap_err();
        assert_eq!(err, C11AdmissionError::RestrictedDeviceManagerIntent);
    }
}

#[test]
fn device_manager_policy_ack_is_not_success_until_exact_readback() {
    let session = device_session(4, 9);
    let xray = xray(&session);
    let owner = owner(&session, true);
    let before = visibility(&session, "com.example.app", false);
    let source = DeviceManagerSourceLock::frozen();
    let attempt = admit_device_manager_policy(policy_request(
        &source,
        &session,
        &xray,
        &owner,
        &before,
        DeviceManagerPolicyIntent::ApplicationVisibility {
            package_id: "com.example.app".into(),
            hidden: true,
        },
    ))
    .expect("attempt");
    assert_eq!(
        attempt.proof_state,
        DeviceManagerPolicyProofState::AwaitingReadback
    );
    let wrong = visibility(&session, "com.example.app", false);
    assert_eq!(
        verify_device_manager_policy(&attempt, &wrong).unwrap_err(),
        C11AdmissionError::PolicyPostconditionMismatch
    );
    let correct = visibility(&session, "com.example.app", true);
    let verified = verify_device_manager_policy(&attempt, &correct).expect("verified");
    assert!(verified.verified);
}

#[test]
fn device_manager_stale_policy_readback_is_rejected() {
    let session = device_session(4, 9);
    let xray = xray(&session);
    let owner = owner(&session, true);
    let before = visibility(&session, "com.example.app", false);
    let source = DeviceManagerSourceLock::frozen();
    let attempt = admit_device_manager_policy(policy_request(
        &source,
        &session,
        &xray,
        &owner,
        &before,
        DeviceManagerPolicyIntent::ApplicationVisibility {
            package_id: "com.example.app".into(),
            hidden: true,
        },
    ))
    .expect("attempt");
    let mut stale = visibility(&session, "com.example.app", true);
    stale.connection_epoch = 8;
    assert_eq!(
        verify_device_manager_policy(&attempt, &stale).unwrap_err(),
        C11AdmissionError::StalePolicyReadback
    );
}

#[test]
fn device_manager_rollback_must_restore_the_independent_pre_state() {
    let session = device_session(4, 9);
    let xray = xray(&session);
    let owner = owner(&session, true);
    let before = visibility(&session, "com.example.app", false);
    let source = DeviceManagerSourceLock::frozen();
    let attempt = admit_device_manager_policy(policy_request(
        &source,
        &session,
        &xray,
        &owner,
        &before,
        DeviceManagerPolicyIntent::ApplicationVisibility {
            package_id: "com.example.app".into(),
            hidden: true,
        },
    ))
    .expect("attempt");
    let verified =
        verify_device_manager_policy(&attempt, &visibility(&session, "com.example.app", true))
            .expect("verified");
    let wrong = visibility(&session, "com.example.app", true);
    assert_eq!(
        verify_device_manager_policy_rollback(&verified, &wrong).unwrap_err(),
        C11AdmissionError::RollbackPostconditionMismatch
    );
    let restored = visibility(&session, "com.example.app", false);
    let receipt = verify_device_manager_policy_rollback(&verified, &restored).expect("rollback");
    assert!(receipt.restored_original_state);
}

fn workflow_request<'a>(
    source: &'a MibuSourceLock,
    session: &'a DeviceSession,
    app: &'a ApplicationSession,
    xray: &'a AdmittedXrayWorkload,
    nonce: &'a str,
) -> MibuWorkflowRequest<'a> {
    MibuWorkflowRequest {
        source,
        device_session: session,
        application_session: app,
        xray,
        operation_ref: entity("operation.device_workflow"),
        nonce,
        evidence_refs: vec![entity("proof.evidence")],
        requested_at: "2026-08-31T08:10:00Z".into(),
    }
}

#[test]
fn mibu_frozen_source_protocol_and_version_are_mechanically_locked() {
    let session = device_session(7, 12);
    let app = application_session(&session, MIBU_APP_VERSION);
    let xray = xray(&session);
    let source = MibuSourceLock::frozen();
    let admission = admit_mibu_workflow(workflow_request(
        &source,
        &session,
        &app,
        &xray,
        "Abcd_1234-XYZ",
    ))
    .expect("admit");
    assert_eq!(
        admission.proof_protocol_version,
        MIBU_PROOF_PROTOCOL_VERSION
    );
    assert_eq!(admission.application_version, MIBU_APP_VERSION);
    assert_eq!(
        admission.authority,
        MibuAuthority::CorrelationAndEvidenceOnly
    );
    assert!(!admission.automatic_replay_allowed);
}

#[test]
fn mibu_source_lock_drift_fails_closed() {
    let session = device_session(7, 12);
    let app = application_session(&session, MIBU_APP_VERSION);
    let xray = xray(&session);
    let mut source = MibuSourceLock::frozen();
    source.proof_nonce_blob_sha1 = "0".repeat(40);
    assert_eq!(
        admit_mibu_workflow(workflow_request(
            &source,
            &session,
            &app,
            &xray,
            "Abcd_1234-XYZ"
        ))
        .unwrap_err(),
        C11AdmissionError::MibuSourceLockMismatch
    );
}

#[test]
fn mibu_nonce_syntax_is_exactly_bounded() {
    let session = device_session(7, 12);
    let app = application_session(&session, MIBU_APP_VERSION);
    let xray = xray(&session);
    let source = MibuSourceLock::frozen();
    for bad in [
        "short",
        "contains space",
        "bad!chars",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert_eq!(
            admit_mibu_workflow(workflow_request(&source, &session, &app, &xray, bad)).unwrap_err(),
            C11AdmissionError::InvalidMibuNonce
        );
    }
}

#[test]
fn mibu_requires_exact_c10_application_version_and_current_c09_context() {
    let session = device_session(7, 12);
    let wrong_app = application_session(&session, "0.2.0-dev");
    let current_xray = xray(&session);
    let source = MibuSourceLock::frozen();
    assert_eq!(
        admit_mibu_workflow(workflow_request(
            &source,
            &session,
            &wrong_app,
            &current_xray,
            "Abcd_1234-XYZ"
        ))
        .unwrap_err(),
        C11AdmissionError::MibuApplicationMismatch
    );

    let app = application_session(&session, MIBU_APP_VERSION);
    let mut stale_xray = xray(&session);
    stale_xray.connection_epoch = 11;
    assert_eq!(
        admit_mibu_workflow(workflow_request(
            &source,
            &session,
            &app,
            &stale_xray,
            "Abcd_1234-XYZ"
        ))
        .unwrap_err(),
        C11AdmissionError::DeviceContextMismatch
    );
}

fn proof(admission: &MibuWorkflowAdmission, level: MibuProofLevel) -> MibuProofEnvelope {
    MibuProofEnvelope {
        operation_ref: admission.operation_ref.clone(),
        application_session_ref: admission.application_session_ref.clone(),
        nonce: "Abcd_1234-XYZ".into(),
        proof_protocol_version: MIBU_PROOF_PROTOCOL_VERSION,
        producer_application_version: MIBU_APP_VERSION.into(),
        producer_authenticated: true,
        producer_auth_evidence_refs: vec![entity("proof.evidence")],
        provider_generation: admission.provider_generation,
        connection_epoch: admission.connection_epoch,
        level,
        external_authority: None,
        external_result_ref: None,
        evidence_refs: vec![entity("proof.evidence")],
        observed_at: "2026-08-31T08:11:00Z".into(),
    }
}

#[test]
fn mibu_correct_nonce_is_not_authentication() {
    let session = device_session(7, 12);
    let app = application_session(&session, MIBU_APP_VERSION);
    let xray = xray(&session);
    let source = MibuSourceLock::frozen();
    let admission = admit_mibu_workflow(workflow_request(
        &source,
        &session,
        &app,
        &xray,
        "Abcd_1234-XYZ",
    ))
    .expect("admit");
    let mut envelope = proof(&admission, MibuProofLevel::RuntimeArmed);
    envelope.producer_authenticated = false;
    envelope.producer_auth_evidence_refs.clear();
    assert_eq!(
        reconcile_mibu_proof(&admission, &envelope, None).unwrap_err(),
        C11AdmissionError::UnauthenticatedMibuProducer
    );
}

#[test]
fn mibu_wrong_nonce_protocol_version_or_epoch_is_stale_not_success() {
    let session = device_session(7, 12);
    let app = application_session(&session, MIBU_APP_VERSION);
    let xray = xray(&session);
    let source = MibuSourceLock::frozen();
    let admission = admit_mibu_workflow(workflow_request(
        &source,
        &session,
        &app,
        &xray,
        "Abcd_1234-XYZ",
    ))
    .expect("admit");

    let mut envelope = proof(&admission, MibuProofLevel::RuntimeArmed);
    envelope.nonce = "Other_1234".into();
    assert_eq!(
        reconcile_mibu_proof(&admission, &envelope, None).unwrap_err(),
        C11AdmissionError::MibuCorrelationMismatch
    );

    let mut envelope = proof(&admission, MibuProofLevel::RuntimeArmed);
    envelope.proof_protocol_version = 2;
    assert_eq!(
        reconcile_mibu_proof(&admission, &envelope, None).unwrap_err(),
        C11AdmissionError::MibuProofProtocolMismatch
    );

    let mut envelope = proof(&admission, MibuProofLevel::RuntimeArmed);
    envelope.producer_application_version = "0.2.0-dev".into();
    assert_eq!(
        reconcile_mibu_proof(&admission, &envelope, None).unwrap_err(),
        C11AdmissionError::MibuProofApplicationVersionMismatch
    );

    let mut envelope = proof(&admission, MibuProofLevel::RuntimeArmed);
    envelope.connection_epoch = 11;
    assert_eq!(
        reconcile_mibu_proof(&admission, &envelope, None).unwrap_err(),
        C11AdmissionError::StaleMibuProof
    );
}

#[test]
fn mibu_launch_or_runtime_ack_never_becomes_operation_or_external_success() {
    let session = device_session(7, 12);
    let app = application_session(&session, MIBU_APP_VERSION);
    let xray = xray(&session);
    let source = MibuSourceLock::frozen();
    let admission = admit_mibu_workflow(workflow_request(
        &source,
        &session,
        &app,
        &xray,
        "Abcd_1234-XYZ",
    ))
    .expect("admit");
    for level in [
        MibuProofLevel::ActivityLaunched,
        MibuProofLevel::RuntimeArmed,
    ] {
        let receipt =
            reconcile_mibu_proof(&admission, &proof(&admission, level), None).expect("receipt");
        assert!(!receipt.operation_complete);
        assert!(!receipt.external_authoritative_result);
    }
}

#[test]
fn mibu_external_result_requires_explicit_external_authority_and_reference() {
    let session = device_session(7, 12);
    let app = application_session(&session, MIBU_APP_VERSION);
    let xray = xray(&session);
    let source = MibuSourceLock::frozen();
    let admission = admit_mibu_workflow(workflow_request(
        &source,
        &session,
        &app,
        &xray,
        "Abcd_1234-XYZ",
    ))
    .expect("admit");
    let envelope = proof(&admission, MibuProofLevel::ExternalAuthoritativeResult);
    assert_eq!(
        reconcile_mibu_proof(&admission, &envelope, None).unwrap_err(),
        C11AdmissionError::MissingExternalAuthority
    );

    let mut envelope = proof(&admission, MibuProofLevel::ExternalAuthoritativeResult);
    envelope.external_authority = Some(MibuExternalAuthority::OfficialExternalService);
    envelope.external_result_ref = Some(entity("proof.evidence"));
    let receipt = reconcile_mibu_proof(&admission, &envelope, None).expect("external result");
    assert!(receipt.operation_complete);
    assert!(receipt.external_authoritative_result);
}

#[test]
fn mibu_authoritative_external_result_prevents_lower_or_conflicting_replay() {
    let session = device_session(7, 12);
    let app = application_session(&session, MIBU_APP_VERSION);
    let xray = xray(&session);
    let source = MibuSourceLock::frozen();
    let admission = admit_mibu_workflow(workflow_request(
        &source,
        &session,
        &app,
        &xray,
        "Abcd_1234-XYZ",
    ))
    .expect("admit");
    let mut final_envelope = proof(&admission, MibuProofLevel::ExternalAuthoritativeResult);
    final_envelope.external_authority = Some(MibuExternalAuthority::OfficialExternalService);
    final_envelope.external_result_ref = Some(entity("proof.evidence"));
    let final_receipt = reconcile_mibu_proof(&admission, &final_envelope, None).expect("final");
    assert_eq!(
        reconcile_mibu_proof(
            &admission,
            &proof(&admission, MibuProofLevel::RuntimeArmed),
            Some(&final_receipt)
        )
        .unwrap_err(),
        C11AdmissionError::AuthoritativeResultAlreadyRecorded
    );
}

#[test]
fn mibu_reconnect_rebinds_context_without_enabling_automatic_replay() {
    let session = device_session(7, 12);
    let app = application_session(&session, MIBU_APP_VERSION);
    let current_xray = xray(&session);
    let source = MibuSourceLock::frozen();
    let admission = admit_mibu_workflow(workflow_request(
        &source,
        &session,
        &app,
        &current_xray,
        "Abcd_1234-XYZ",
    ))
    .expect("admit");

    let mut recovered_session = session.clone();
    recovered_session.provider_generation = generation(8);
    recovered_session.connection_epoch = 13;
    recovered_session.recovery_generation = 1;
    let mut recovered_app = application_session(&recovered_session, MIBU_APP_VERSION);
    recovered_app.session_ref = app.session_ref.clone();
    let recovered_xray = xray(&recovered_session);
    let rebound = rebind_mibu_workflow(
        &admission,
        &recovered_session,
        &recovered_app,
        &recovered_xray,
        vec![entity("proof.evidence")],
    )
    .expect("rebind");
    assert_eq!(rebound.operation_ref, admission.operation_ref);
    assert_eq!(rebound.nonce_sha256, admission.nonce_sha256);
    assert_eq!(rebound.connection_epoch, 13);
    assert_eq!(rebound.rebind_generation, admission.rebind_generation + 1);
    assert!(!rebound.automatic_replay_allowed);

    let old_proof = proof(&admission, MibuProofLevel::OperationComplete);
    assert_eq!(
        reconcile_mibu_proof(&rebound, &old_proof, None).unwrap_err(),
        C11AdmissionError::StaleMibuProof
    );
}

fn release_artifact(role: MibuReleaseArtifactRole, byte: char) -> MibuReleaseArtifact {
    MibuReleaseArtifact {
        role,
        artifact_ref: entity("object.artifact"),
        sha256: byte.to_string().repeat(64),
    }
}

fn complete_release() -> MibuReleaseManifest {
    MibuReleaseManifest {
        source_commit_sha: MIBU_COMMIT_SHA.into(),
        application_version: MIBU_APP_VERSION.into(),
        proof_protocol_version: MIBU_PROOF_PROTOCOL_VERSION,
        artifacts: vec![
            release_artifact(MibuReleaseArtifactRole::AndroidApk, 'a'),
            release_artifact(MibuReleaseArtifactRole::WindowsHelper, 'b'),
            release_artifact(MibuReleaseArtifactRole::PlatformTools, 'c'),
            release_artifact(MibuReleaseArtifactRole::ExpectedUiEvidence, 'd'),
            release_artifact(MibuReleaseArtifactRole::ChecksumManifest, 'e'),
        ],
        evidence_refs: vec![entity("proof.evidence")],
    }
}

#[test]
fn mibu_complete_release_manifest_is_required_and_digest_bound() {
    let verified =
        validate_mibu_release(&MibuSourceLock::frozen(), &complete_release()).expect("release");
    assert_eq!(verified.artifact_count, 5);

    let mut incomplete = complete_release();
    incomplete.artifacts.pop();
    assert_eq!(
        validate_mibu_release(&MibuSourceLock::frozen(), &incomplete).unwrap_err(),
        C11AdmissionError::IncompleteMibuRelease
    );

    let mut bad_digest = complete_release();
    bad_digest.artifacts[0].sha256 = "NOT-A-DIGEST".into();
    assert_eq!(
        validate_mibu_release(&MibuSourceLock::frozen(), &bad_digest).unwrap_err(),
        C11AdmissionError::InvalidReleaseDigest
    );
}
