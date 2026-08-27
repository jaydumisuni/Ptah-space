//! C09 acceptance corpus for TTG Device X-Ray read-only workload admission.

use ptah_device_runtime::{
    AdbObservationProvider, AdmittedProtocolOperation, DeviceKind, DeviceLease, DeviceLeaseRequest,
    DeviceProviderBinding, DeviceRegistry, InterfaceTransport, MutationClass, ObservationSeed,
    ProtocolClass, ProtocolOperationRequest, Reachability, admit_protocol_operation,
};
use ptah_identifiers::EntityRef;
use ptah_provider_api::{
    ProviderGeneration, ProviderHealth, ProviderInstance, ProviderKind, ProviderReachability,
    ProviderReadiness, ProviderRevision,
};
use ttg_device_xray_admission::{
    AdmittedXrayWorkload, XrayAdmissionError, XrayAdmissionRequest, XrayAuthority,
    XrayCertificationVerdict, XrayEvidenceDisposition, XrayEvidenceFreshness, XrayEvidenceSummary,
    XrayProfileStatus, XrayPublicAssetEvidence, XraySignatureObservation, XraySourceLock,
    admit_xray_workload, frozen_public_assets,
};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid fixture reference")
}

fn provider_revision() -> ProviderRevision {
    ProviderRevision {
        revision_ref: reference("runtime.provider_revision"),
        provider_ref: reference("runtime.provider"),
        provider_kind: ProviderKind::Device,
        implementation_name: "fixture-device-provider".to_owned(),
        implementation_version: "0.1.0".to_owned(),
        build_or_package_digest: "sha256:fixture".to_owned(),
        configuration_digest: "sha256:configuration".to_owned(),
        supported_facility_refs: vec![reference("runtime.facility")],
        capability_claim_refs: vec![reference("proof.evidence")],
        dependency_refs: Vec::new(),
        node_requirements: Vec::new(),
        security_requirements: Vec::new(),
        known_limitations: Vec::new(),
    }
}

fn provider_instance(
    revision_ref: EntityRef,
    generation: u64,
    connection_epoch: u64,
) -> ProviderInstance {
    ProviderInstance {
        instance_ref: reference("runtime.provider_instance"),
        provider_revision_ref: revision_ref,
        node_ref: reference("core.node"),
        node_generation: 1,
        provider_generation: ProviderGeneration::new(generation).expect("provider generation"),
        connection_epoch,
        reachability: ProviderReachability::Reachable,
        readiness: ProviderReadiness::Ready,
        health: ProviderHealth::Healthy,
        endpoint_aliases: Vec::new(),
        process_or_service_refs: Vec::new(),
        observation_refs: vec![reference("proof.evidence")],
        started_at: "2026-08-27T00:00:00Z".to_owned(),
        limitations: Vec::new(),
    }
}

fn current_context() -> (
    ptah_device_runtime::DeviceInterfaceRecord,
    DeviceProviderBinding,
    AdmittedProtocolOperation,
) {
    let revision = provider_revision();
    let instance = provider_instance(revision.revision_ref.clone(), 1, 1);
    let binding = DeviceProviderBinding::bind(&revision, &instance).expect("device binding");
    let observation = AdbObservationProvider::new(binding.clone())
        .observe(
            InterfaceTransport::AdbUsb,
            ObservationSeed {
                profile_revision_ref: reference("device.profile_revision"),
                identity_basis_refs: vec![reference("proof.evidence")],
                continuity_basis_refs: vec![reference("proof.evidence")],
                evidence_refs: vec![reference("proof.evidence")],
                backend_alias: "DONOR-ALIAS".to_owned(),
                topology_or_address: Some("usb:1-2".to_owned()),
                endpoint_claims: vec!["18d1:4ee7".to_owned()],
                reachability: Reachability::Reachable,
                observed_at: "2026-08-27T00:00:01Z".to_owned(),
            },
            Some("1.0.41".to_owned()),
        )
        .expect("ADB observation");

    assert_eq!(observation.device_kind, DeviceKind::PhysicalAndroid);

    let mut registry = DeviceRegistry::default();
    let current = registry.reconcile(&observation).expect("reconcile");
    let lease = DeviceLease::issue(DeviceLeaseRequest {
        device_ref: current.device.device_ref.clone(),
        holder_ref: reference("core.activity"),
        scope: vec!["protocol.observe".to_owned()],
        fence_token: 9,
        provider_generation: current.interface.provider_generation,
        connection_epoch: current.interface.connection_epoch,
        issued_at: "2026-08-27T00:00:01Z".to_owned(),
        expires_at: "2026-08-27T01:00:01Z".to_owned(),
    })
    .expect("lease");

    let admitted = admit_protocol_operation(ProtocolOperationRequest {
        device_ref: current.device.device_ref.clone(),
        device_profile_revision_ref: current.device.current_profile_revision_ref.clone(),
        device_session_ref: reference("device.session"),
        interface: &current.interface,
        provider: &binding,
        lease: &lease,
        observed_fence_token: 9,
        protocol_class: ProtocolClass::Adb,
        protocol_operation_key: "ttg_xray.observe".to_owned(),
        mutation_class: MutationClass::DeviceRead,
        activity_ref: reference("core.activity"),
        operation_ref: reference("core.operation"),
        attempt_refs: vec![reference("core.attempt")],
        evidence_refs: vec![reference("proof.evidence")],
        started_at: "2026-08-27T00:00:02Z".to_owned(),
        physical_authority_ref: None,
    })
    .expect("C08 protocol admission");

    (current.interface, binding, admitted)
}

fn evidence() -> XrayEvidenceSummary {
    XrayEvidenceSummary {
        bundle_ref: reference("object.artifact"),
        scan_id: "scan-fixture".to_owned(),
        manifest_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .to_owned(),
        candidate_count: 1,
        selected_candidate_id: Some("candidate-1".to_owned()),
        certification: XrayCertificationVerdict::Certified,
        profile_status: XrayProfileStatus::Matched,
        profile_id: Some("android:tecno:km7:mt6765".to_owned()),
        freshness: XrayEvidenceFreshness::Current,
        bundle_write_allowed: false,
        certification_write_allowed: false,
        profile_write_allowed: false,
        signature: XraySignatureObservation::Unsigned,
        evidence_refs: vec![reference("proof.evidence")],
        disagreement_refs: Vec::new(),
    }
}

fn admit(
    source: &XraySourceLock,
    assets: &[XrayPublicAssetEvidence],
    interface: &ptah_device_runtime::DeviceInterfaceRecord,
    operations: &[AdmittedProtocolOperation],
    evidence: &XrayEvidenceSummary,
) -> Result<AdmittedXrayWorkload, XrayAdmissionError> {
    admit_xray_workload(XrayAdmissionRequest {
        source,
        public_assets: assets,
        current_interface: interface,
        c08_operations: operations,
        evidence,
    })
}

/* 1 */
#[test]
fn exact_donor_assets_and_current_c08_operation_admit_read_only() {
    let source = XraySourceLock::frozen();
    let assets = frozen_public_assets();
    let (interface, _binding, operation) = current_context();
    let result = admit(&source, &assets, &interface, &[operation], &evidence()).expect("C09 admit");
    assert_eq!(result.disposition, XrayEvidenceDisposition::Correlated);
    assert_eq!(result.authority, XrayAuthority::EvidenceOnlyReadOnly);
    assert_eq!(result.c08_protocol_operation_refs.len(), 1);
}

/* 2 */
#[test]
fn repository_drift_fails_closed() {
    let mut source = XraySourceLock::frozen();
    source.repository_url.push_str("-other");
    let assets = frozen_public_assets();
    let (interface, _binding, operation) = current_context();
    assert!(matches!(
        admit(&source, &assets, &interface, &[operation], &evidence()),
        Err(XrayAdmissionError::SourceLockMismatch("repository_url"))
    ));
}

/* 3 */
#[test]
fn donor_commit_drift_fails_closed() {
    let mut source = XraySourceLock::frozen();
    source.commit_sha = "0000000000000000000000000000000000000000".to_owned();
    let assets = frozen_public_assets();
    let (interface, _binding, operation) = current_context();
    assert!(matches!(
        admit(&source, &assets, &interface, &[operation], &evidence()),
        Err(XrayAdmissionError::SourceLockMismatch("commit_sha"))
    ));
}

/* 4 */
#[test]
fn donor_version_or_ci_drift_fails_closed() {
    let assets = frozen_public_assets();
    let (interface, _binding, operation) = current_context();

    let mut version = XraySourceLock::frozen();
    version.scanner_version = "0.4.3.dev3".to_owned();
    assert!(matches!(
        admit(
            &version,
            &assets,
            &interface,
            &[operation.clone()],
            &evidence()
        ),
        Err(XrayAdmissionError::SourceLockMismatch("scanner_version"))
    ));

    let mut ci = XraySourceLock::frozen();
    ci.ci_run_id += 1;
    assert!(matches!(
        admit(&ci, &assets, &interface, &[operation], &evidence()),
        Err(XrayAdmissionError::SourceLockMismatch("ci_run_id"))
    ));
}

/* 5 */
#[test]
fn donor_read_only_checker_drift_fails_closed() {
    let mut source = XraySourceLock::frozen();
    source.read_only_check_blob_sha1 = "0000000000000000000000000000000000000000".to_owned();
    let assets = frozen_public_assets();
    let (interface, _binding, operation) = current_context();
    assert!(matches!(
        admit(&source, &assets, &interface, &[operation], &evidence()),
        Err(XrayAdmissionError::SourceLockMismatch(
            "read_only_check_blob_sha1"
        ))
    ));
}

/* 6 */
#[test]
fn donor_bundle_seal_drift_fails_closed() {
    let mut source = XraySourceLock::frozen();
    source.bundle_seal_blob_sha1 = "0000000000000000000000000000000000000000".to_owned();
    let assets = frozen_public_assets();
    let (interface, _binding, operation) = current_context();
    assert!(matches!(
        admit(&source, &assets, &interface, &[operation], &evidence()),
        Err(XrayAdmissionError::SourceLockMismatch(
            "bundle_seal_blob_sha1"
        ))
    ));
}

/* 7 */
#[test]
fn incomplete_profile_fixture_set_fails_closed() {
    let source = XraySourceLock::frozen();
    let mut assets = frozen_public_assets();
    assets.pop();
    let (interface, _binding, operation) = current_context();
    assert!(matches!(
        admit(&source, &assets, &interface, &[operation], &evidence()),
        Err(XrayAdmissionError::PublicAssetLockMismatch)
    ));
}

/* 8 */
#[test]
fn profile_or_fixture_blob_drift_fails_closed() {
    let source = XraySourceLock::frozen();
    let mut assets = frozen_public_assets();
    assets[0].git_blob_sha1 = "0000000000000000000000000000000000000000".to_owned();
    let (interface, _binding, operation) = current_context();
    assert!(matches!(
        admit(&source, &assets, &interface, &[operation], &evidence()),
        Err(XrayAdmissionError::PublicAssetLockMismatch)
    ));
}

/* 9 */
#[test]
fn duplicate_public_asset_path_fails_closed() {
    let source = XraySourceLock::frozen();
    let mut assets = frozen_public_assets();
    assets[1] = assets[0].clone();
    let (interface, _binding, operation) = current_context();
    assert!(matches!(
        admit(&source, &assets, &interface, &[operation], &evidence()),
        Err(XrayAdmissionError::DuplicatePublicAsset)
    ));
}

/* 10 */
#[test]
fn every_donor_write_allowed_surface_is_rejected() {
    let source = XraySourceLock::frozen();
    let assets = frozen_public_assets();
    let (interface, _binding, operation) = current_context();

    for selector in 0..3 {
        let mut observed = evidence();
        match selector {
            0 => observed.bundle_write_allowed = true,
            1 => observed.certification_write_allowed = true,
            2 => observed.profile_write_allowed = true,
            _ => unreachable!(),
        }
        assert!(matches!(
            admit(
                &source,
                &assets,
                &interface,
                &[operation.clone()],
                &observed
            ),
            Err(XrayAdmissionError::WriteAuthorityClaim)
        ));
    }
}

/* 11 */
#[test]
fn malformed_manifest_digest_fails_closed() {
    let source = XraySourceLock::frozen();
    let assets = frozen_public_assets();
    let (interface, _binding, operation) = current_context();
    let mut observed = evidence();
    observed.manifest_sha256 =
        "ABCDEF6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned();
    assert!(matches!(
        admit(&source, &assets, &interface, &[operation], &observed),
        Err(XrayAdmissionError::InvalidManifestDigest)
    ));
}

/* 12 */
#[test]
fn missing_c08_operation_fails_closed() {
    let source = XraySourceLock::frozen();
    let assets = frozen_public_assets();
    let (interface, _binding, _operation) = current_context();
    assert!(matches!(
        admit(&source, &assets, &interface, &[], &evidence()),
        Err(XrayAdmissionError::MissingC08Operation)
    ));
}

/* 13 */
#[test]
fn stale_c08_provider_generation_fails_closed() {
    let source = XraySourceLock::frozen();
    let assets = frozen_public_assets();
    let (interface, _binding, mut operation) = current_context();
    operation.provider_generation = ProviderGeneration::new(2).expect("generation");
    assert!(matches!(
        admit(&source, &assets, &interface, &[operation], &evidence()),
        Err(XrayAdmissionError::C08ContextMismatch)
    ));
}

/* 14 */
#[test]
fn stale_c08_connection_epoch_fails_closed() {
    let source = XraySourceLock::frozen();
    let assets = frozen_public_assets();
    let (interface, _binding, mut operation) = current_context();
    operation.connection_epoch += 1;
    assert!(matches!(
        admit(&source, &assets, &interface, &[operation], &evidence()),
        Err(XrayAdmissionError::C08ContextMismatch)
    ));
}

/* 15 */
#[test]
fn multiple_device_candidates_remain_unsafe_evidence() {
    let source = XraySourceLock::frozen();
    let assets = frozen_public_assets();
    let (interface, _binding, operation) = current_context();
    let mut observed = evidence();
    observed.candidate_count = 2;
    observed.selected_candidate_id = None;
    observed.certification = XrayCertificationVerdict::Unsafe;
    observed.profile_status = XrayProfileStatus::NoSelection;
    observed.profile_id = None;

    let result =
        admit(&source, &assets, &interface, &[operation], &observed).expect("retain unsafe");
    assert_eq!(result.disposition, XrayEvidenceDisposition::Unsafe);
    assert_eq!(result.authority, XrayAuthority::EvidenceOnlyReadOnly);
}

/* 16 */
#[test]
fn stale_xray_evidence_remains_visible_and_investigate() {
    let source = XraySourceLock::frozen();
    let assets = frozen_public_assets();
    let (interface, _binding, operation) = current_context();
    let mut observed = evidence();
    observed.freshness = XrayEvidenceFreshness::Stale;

    let result =
        admit(&source, &assets, &interface, &[operation], &observed).expect("retain stale");
    assert_eq!(result.freshness, XrayEvidenceFreshness::Stale);
    assert_eq!(result.disposition, XrayEvidenceDisposition::Investigate);
}

/* 17 */
#[test]
fn disagreement_evidence_is_retained_without_forced_resolution() {
    let source = XraySourceLock::frozen();
    let assets = frozen_public_assets();
    let (interface, _binding, operation) = current_context();
    let mut observed = evidence();
    observed.disagreement_refs = vec![reference("proof.evidence")];

    let result =
        admit(&source, &assets, &interface, &[operation], &observed).expect("retain dispute");
    assert_eq!(result.disagreement_refs, observed.disagreement_refs);
    assert_eq!(result.disposition, XrayEvidenceDisposition::Investigate);
}

/* 18 */
#[test]
fn candidate_profile_remains_investigate_even_with_concrete_profile_id() {
    let source = XraySourceLock::frozen();
    let assets = frozen_public_assets();
    let (interface, _binding, operation) = current_context();
    let mut observed = evidence();
    observed.profile_status = XrayProfileStatus::CandidateProfile;
    observed.profile_id = Some("android:tecno:km7:mt6765".to_owned());

    let result =
        admit(&source, &assets, &interface, &[operation], &observed).expect("retain candidate");
    assert_eq!(result.certification, XrayCertificationVerdict::Certified);
    assert_eq!(result.disposition, XrayEvidenceDisposition::Investigate);
    assert_eq!(result.authority, XrayAuthority::EvidenceOnlyReadOnly);
}

/* 19 */
#[test]
fn signed_bundle_claim_is_not_private_key_verification() {
    let source = XraySourceLock::frozen();
    let assets = frozen_public_assets();
    let (interface, _binding, operation) = current_context();
    let mut observed = evidence();
    observed.signature = XraySignatureObservation::SignedClaimUnverifiedPublicly;

    let result =
        admit(&source, &assets, &interface, &[operation], &observed).expect("retain signature");
    assert_eq!(
        result.signature,
        XraySignatureObservation::SignedClaimUnverifiedPublicly
    );
    assert_eq!(result.authority, XrayAuthority::EvidenceOnlyReadOnly);
}

/* 20 */
#[test]
fn current_single_device_matched_profile_correlates_but_never_authorizes_mutation() {
    let source = XraySourceLock::frozen();
    let assets = frozen_public_assets();
    let (interface, _binding, operation) = current_context();
    let observed = evidence();

    let result =
        admit(&source, &assets, &interface, &[operation], &observed).expect("clean correlation");
    assert_eq!(result.disposition, XrayEvidenceDisposition::Correlated);
    assert_eq!(result.profile_status, XrayProfileStatus::Matched);
    assert_eq!(
        result.profile_id.as_deref(),
        Some("android:tecno:km7:mt6765")
    );
    assert_eq!(result.authority, XrayAuthority::EvidenceOnlyReadOnly);
}
