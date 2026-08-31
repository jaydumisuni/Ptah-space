//! C10 acceptance corpus for Android Device/Application Session v1.

use ptah_android_runtime::{
    AndroidRuntimeError, ApplicationLaunchReadBack, ApplicationLaunchRequest, ApplicationSession,
    ApplicationSessionState, DeviceSessionRecoveryRequest, DeviceSessionRequest,
    DeviceSessionState, InputAction, InputActionRequest, InputReadBack, PackageInstallRequest,
    PackageReadBack, ScreenContextRequest, SemanticNode, SemanticSelector,
    VerifiedPackageInstallation, admit_application_launch, admit_input_action,
    admit_package_install, capture_screen_context, open_device_session, reacquire_semantic_target,
    recover_device_session, resolve_semantic_target, verify_application_launch,
    verify_input_action, verify_package_install,
};
use ptah_archive_decomposition::{SignatureObservation, SignatureStatus};
use ptah_device_runtime::{
    DeviceInterfaceRecord, DeviceKind, DeviceLease, DeviceLeaseRequest, DeviceRecord,
    InterfaceLocality, InterfaceTransport, Reachability,
};
use ptah_identifiers::EntityRef;
use ptah_provider_api::ProviderGeneration;

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid reference")
}

fn android_device(kind: DeviceKind) -> DeviceRecord {
    DeviceRecord {
        device_ref: reference("device.device"),
        device_kind: kind,
        identity_basis_refs: vec![reference("proof.evidence")],
        current_profile_revision_ref: reference("device.profile_revision"),
        profile_revision_refs: vec![reference("device.profile_revision")],
        limitations: Vec::new(),
    }
}

fn interface(device_ref: EntityRef, generation: u64, epoch: u64) -> DeviceInterfaceRecord {
    DeviceInterfaceRecord {
        interface_ref: reference("device.interface"),
        device_ref,
        transport: InterfaceTransport::AdbUsb,
        mode_or_protocol: "adb".to_owned(),
        protocol_version: Some("1.0.41".to_owned()),
        observed_aliases: vec!["SERIAL-FIXTURE".to_owned()],
        topology_or_address: Some("usb:fixture".to_owned()),
        endpoint_claims: vec!["18d1:4ee7".to_owned()],
        provider_instance_ref: reference("runtime.provider_instance"),
        provider_generation: ProviderGeneration::new(generation).expect("generation"),
        locality: InterfaceLocality::NodeLocal,
        node_ref: reference("core.node"),
        node_generation: 1,
        provider_connection_epoch: epoch,
        connection_epoch: epoch,
        connection_ref: reference("device.connection"),
        continuity_basis_refs: vec![reference("proof.evidence")],
        capability_claim_refs: vec![reference("proof.evidence")],
        reachability: Reachability::Reachable,
        evidence_refs: vec![reference("proof.evidence")],
        first_observed_at: "2026-08-30T00:00:00Z".to_owned(),
        last_observed_at: "2026-08-30T00:00:01Z".to_owned(),
    }
}

fn lease(device_ref: EntityRef, generation: u64, epoch: u64) -> DeviceLease {
    DeviceLease::issue(DeviceLeaseRequest {
        device_ref,
        holder_ref: reference("workspace.workspace"),
        scope: vec![
            "android.session.control".to_owned(),
            "android.package.install".to_owned(),
            "android.application.launch".to_owned(),
            "android.application.stop".to_owned(),
            "android.semantic.read".to_owned(),
            "android.input".to_owned(),
            "android.clipboard".to_owned(),
            "android.evidence.capture".to_owned(),
            "android.session.cleanup".to_owned(),
        ],
        fence_token: 9,
        provider_generation: ProviderGeneration::new(generation).expect("generation"),
        connection_epoch: epoch,
        issued_at: "2026-08-30T00:00:01Z".to_owned(),
        expires_at: "2026-08-30T01:00:01Z".to_owned(),
    })
    .expect("lease")
}

#[test]
fn physical_android_session_opens_only_under_current_c08_lease_and_fence() {
    let device = android_device(DeviceKind::PhysicalAndroid);
    let interface = interface(device.device_ref.clone(), 4, 7);
    let lease = lease(device.device_ref.clone(), 4, 7);

    let session = open_device_session(DeviceSessionRequest {
        workspace_ref: reference("workspace.workspace"),
        device: &device,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        capability_snapshot_ref: reference("runtime.capability_snapshot"),
        privacy_policy_refs: vec![reference("policy.privacy")],
        evidence_refs: vec![reference("proof.evidence")],
        started_at: "2026-08-30T00:00:02Z".to_owned(),
    })
    .expect("current Android session");

    assert_eq!(session.device_ref, device.device_ref);
    assert_eq!(session.interface_ref, interface.interface_ref);
    assert_eq!(session.connection_ref, interface.connection_ref);
    assert_eq!(session.provider_generation, interface.provider_generation);
    assert_eq!(session.connection_epoch, 7);
    assert_eq!(session.lease_ref, lease.lease_ref);
    assert_eq!(session.state, DeviceSessionState::Connected);
}

#[test]
fn non_android_device_cannot_open_c10_session() {
    let device = android_device(DeviceKind::PhysicalIos);
    let interface = interface(device.device_ref.clone(), 4, 7);
    let lease = lease(device.device_ref.clone(), 4, 7);
    let error = open_device_session(DeviceSessionRequest {
        workspace_ref: reference("workspace.workspace"),
        device: &device,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        capability_snapshot_ref: reference("runtime.capability_snapshot"),
        privacy_policy_refs: vec![reference("policy.privacy")],
        evidence_refs: vec![reference("proof.evidence")],
        started_at: "2026-08-30T00:00:02Z".to_owned(),
    })
    .expect_err("non-Android device must fail closed");
    assert_eq!(error, AndroidRuntimeError::UnsupportedDeviceKind);
}

#[test]
fn stale_provider_generation_cannot_open_c10_session() {
    let device = android_device(DeviceKind::PhysicalAndroid);
    let interface = interface(device.device_ref.clone(), 5, 7);
    let lease = lease(device.device_ref.clone(), 4, 7);
    let error = open_device_session(DeviceSessionRequest {
        workspace_ref: reference("workspace.workspace"),
        device: &device,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        capability_snapshot_ref: reference("runtime.capability_snapshot"),
        privacy_policy_refs: vec![reference("policy.privacy")],
        evidence_refs: vec![reference("proof.evidence")],
        started_at: "2026-08-30T00:00:02Z".to_owned(),
    })
    .expect_err("stale Provider generation must fail closed");
    assert!(matches!(
        error,
        AndroidRuntimeError::Device(ptah_device_runtime::DeviceError::StaleLeaseProviderGeneration)
    ));
}

#[test]
fn stale_connection_epoch_cannot_open_c10_session() {
    let device = android_device(DeviceKind::PhysicalAndroid);
    let interface = interface(device.device_ref.clone(), 4, 8);
    let lease = lease(device.device_ref.clone(), 4, 7);
    let error = open_device_session(DeviceSessionRequest {
        workspace_ref: reference("workspace.workspace"),
        device: &device,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        capability_snapshot_ref: reference("runtime.capability_snapshot"),
        privacy_policy_refs: vec![reference("policy.privacy")],
        evidence_refs: vec![reference("proof.evidence")],
        started_at: "2026-08-30T00:00:02Z".to_owned(),
    })
    .expect_err("stale connection epoch must fail closed");
    assert!(matches!(
        error,
        AndroidRuntimeError::Device(ptah_device_runtime::DeviceError::StaleConnectionEpoch)
    ));
}

#[test]
fn stale_fence_cannot_open_c10_session() {
    let device = android_device(DeviceKind::AndroidEmulator);
    let interface = interface(device.device_ref.clone(), 4, 7);
    let lease = lease(device.device_ref.clone(), 4, 7);
    let error = open_device_session(DeviceSessionRequest {
        workspace_ref: reference("workspace.workspace"),
        device: &device,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 8,
        capability_snapshot_ref: reference("runtime.capability_snapshot"),
        privacy_policy_refs: vec![reference("policy.privacy")],
        evidence_refs: vec![reference("proof.evidence")],
        started_at: "2026-08-30T00:00:02Z".to_owned(),
    })
    .expect_err("stale fence must fail closed");
    assert!(matches!(
        error,
        AndroidRuntimeError::Device(ptah_device_runtime::DeviceError::StaleFence)
    ));
}

#[test]
fn reconnect_rebinds_authority_without_rekeying_device_session() {
    let device = android_device(DeviceKind::PhysicalAndroid);
    let first_interface = interface(device.device_ref.clone(), 4, 7);
    let first_lease = lease(device.device_ref.clone(), 4, 7);
    let session = open_device_session(DeviceSessionRequest {
        workspace_ref: reference("workspace.workspace"),
        device: &device,
        interface: &first_interface,
        lease: &first_lease,
        observed_fence_token: 9,
        capability_snapshot_ref: reference("runtime.capability_snapshot"),
        privacy_policy_refs: vec![reference("policy.privacy")],
        evidence_refs: vec![reference("proof.evidence")],
        started_at: "2026-08-30T00:00:02Z".to_owned(),
    })
    .expect("initial session");

    let next_interface = interface(device.device_ref.clone(), 5, 8);
    let next_lease = lease(device.device_ref.clone(), 5, 8);
    let recovered = recover_device_session(DeviceSessionRecoveryRequest {
        session: &session,
        device: &device,
        interface: &next_interface,
        lease: &next_lease,
        observed_fence_token: 9,
        capability_snapshot_ref: reference("runtime.capability_snapshot"),
        evidence_refs: vec![reference("proof.evidence")],
        recovered_at: "2026-08-30T00:10:00Z".to_owned(),
    })
    .expect("recovered session");

    assert_eq!(recovered.session_ref, session.session_ref);
    assert_eq!(recovered.device_ref, session.device_ref);
    assert_eq!(recovered.interface_ref, next_interface.interface_ref);
    assert_eq!(recovered.connection_ref, next_interface.connection_ref);
    assert_eq!(
        recovered.provider_generation,
        next_interface.provider_generation
    );
    assert_eq!(recovered.connection_epoch, 8);
    assert_eq!(recovered.lease_ref, next_lease.lease_ref);
    assert_eq!(recovered.recovery_generation, 1);
    assert_eq!(recovered.state, DeviceSessionState::Connected);
}

fn current_session_fixture() -> (
    DeviceRecord,
    DeviceInterfaceRecord,
    DeviceLease,
    ptah_android_runtime::DeviceSession,
) {
    let device = android_device(DeviceKind::PhysicalAndroid);
    let interface = interface(device.device_ref.clone(), 4, 7);
    let lease = lease(device.device_ref.clone(), 4, 7);
    let session = open_device_session(DeviceSessionRequest {
        workspace_ref: reference("workspace.workspace"),
        device: &device,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        capability_snapshot_ref: reference("runtime.capability_snapshot"),
        privacy_policy_refs: vec![reference("policy.privacy")],
        evidence_refs: vec![reference("proof.evidence")],
        started_at: "2026-08-30T00:00:02Z".to_owned(),
    })
    .expect("session");
    (device, interface, lease, session)
}

#[test]
fn package_install_ack_requires_exact_version_and_verified_signature_readback() {
    let (_device, interface, lease, session) = current_session_fixture();
    let attempt = admit_package_install(PackageInstallRequest {
        session: &session,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        package_object_ref: reference("object.object"),
        package_revision_ref: reference("object.revision"),
        package_id: "com.example.fixture".to_owned(),
        expected_version: "2.4.1".to_owned(),
        expected_signer: "CN=Fixture".to_owned(),
        command_evidence_refs: vec![reference("proof.evidence")],
        requested_at: "2026-08-30T00:20:00Z".to_owned(),
    })
    .expect("install attempt");
    assert!(!attempt.verified);

    let verified = verify_package_install(
        &attempt,
        PackageReadBack {
            provider_generation: interface.provider_generation,
            connection_epoch: interface.connection_epoch,
            package_id: "com.example.fixture".to_owned(),
            installed_version: "2.4.1".to_owned(),
            signatures: vec![SignatureObservation {
                scheme: "apk-v3".to_owned(),
                signer: Some("CN=Fixture".to_owned()),
                status: SignatureStatus::Verified,
            }],
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T00:20:02Z".to_owned(),
        },
    )
    .expect("verified install");
    assert_eq!(verified.package_id, "com.example.fixture");
    assert_eq!(verified.installed_version, "2.4.1");
    assert_eq!(verified.package_revision_ref, attempt.package_revision_ref);
}

fn verified_package_fixture(
    session: &ptah_android_runtime::DeviceSession,
    interface: &DeviceInterfaceRecord,
    lease: &DeviceLease,
) -> VerifiedPackageInstallation {
    let attempt = admit_package_install(PackageInstallRequest {
        session,
        interface,
        lease,
        observed_fence_token: 9,
        package_object_ref: reference("object.object"),
        package_revision_ref: reference("object.revision"),
        package_id: "com.example.fixture".to_owned(),
        expected_version: "2.4.1".to_owned(),
        expected_signer: "CN=Fixture".to_owned(),
        command_evidence_refs: vec![reference("proof.evidence")],
        requested_at: "2026-08-30T00:20:00Z".to_owned(),
    })
    .expect("install attempt");
    verify_package_install(
        &attempt,
        PackageReadBack {
            provider_generation: interface.provider_generation,
            connection_epoch: interface.connection_epoch,
            package_id: "com.example.fixture".to_owned(),
            installed_version: "2.4.1".to_owned(),
            signatures: vec![SignatureObservation {
                scheme: "apk-v3".to_owned(),
                signer: Some("CN=Fixture".to_owned()),
                status: SignatureStatus::Verified,
            }],
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T00:20:02Z".to_owned(),
        },
    )
    .expect("verified install")
}

#[test]
fn application_launch_ack_requires_visible_frame_and_semantic_readiness() {
    let (_device, interface, lease, session) = current_session_fixture();
    let package = verified_package_fixture(&session, &interface, &lease);
    let attempt = admit_application_launch(ApplicationLaunchRequest {
        session: &session,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        installation: &package,
        application_ref: reference("application.application"),
        application_revision_ref: reference("application.revision"),
        command_evidence_refs: vec![reference("proof.evidence")],
        requested_at: "2026-08-30T00:30:00Z".to_owned(),
    })
    .expect("launch attempt");
    assert!(!attempt.verified);

    let app = verify_application_launch(
        &attempt,
        ApplicationLaunchReadBack {
            provider_generation: interface.provider_generation,
            connection_epoch: interface.connection_epoch,
            package_id: "com.example.fixture".to_owned(),
            process_aliases: vec!["pid:4242".to_owned()],
            activity_or_context: "com.example.fixture/.MainActivity".to_owned(),
            visible_frame_ref: Some(reference("proof.evidence")),
            semantic_context_ref: Some(reference("application.semantic_context")),
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T00:30:02Z".to_owned(),
        },
    )
    .expect("verified launch");
    assert_eq!(app.device_session_ref, session.session_ref);
    assert_eq!(app.package_id, "com.example.fixture");
    assert_eq!(app.installed_version, "2.4.1");
    assert_eq!(app.state, ApplicationSessionState::Visible);
    assert_eq!(app.process_aliases, vec!["pid:4242"]);
}

fn visible_application_fixture(
    session: &ptah_android_runtime::DeviceSession,
    interface: &DeviceInterfaceRecord,
    lease: &DeviceLease,
) -> ApplicationSession {
    let package = verified_package_fixture(session, interface, lease);
    let attempt = admit_application_launch(ApplicationLaunchRequest {
        session,
        interface,
        lease,
        observed_fence_token: 9,
        installation: &package,
        application_ref: reference("application.application"),
        application_revision_ref: reference("application.revision"),
        command_evidence_refs: vec![reference("proof.evidence")],
        requested_at: "2026-08-30T00:30:00Z".to_owned(),
    })
    .expect("launch attempt");
    verify_application_launch(
        &attempt,
        ApplicationLaunchReadBack {
            provider_generation: interface.provider_generation,
            connection_epoch: interface.connection_epoch,
            package_id: "com.example.fixture".to_owned(),
            process_aliases: vec!["pid:4242".to_owned()],
            activity_or_context: "com.example.fixture/.MainActivity".to_owned(),
            visible_frame_ref: Some(reference("proof.evidence")),
            semantic_context_ref: Some(reference("application.semantic_context")),
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T00:30:02Z".to_owned(),
        },
    )
    .expect("visible app")
}

#[test]
fn stale_semantic_target_is_reacquired_from_newer_screen_context() {
    let (_device, interface, lease, session) = current_session_fixture();
    let app = visible_application_fixture(&session, &interface, &lease);
    let selector = SemanticSelector {
        resource_id: Some("com.example.fixture:id/login".to_owned()),
        text: Some("Login".to_owned()),
        description: None,
        class_name: Some("android.widget.Button".to_owned()),
    };
    let first = capture_screen_context(ScreenContextRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        capture_sequence: 1,
        backend_source: "androidx-uiautomator".to_owned(),
        backend_version: "fixture".to_owned(),
        nodes: vec![SemanticNode {
            backend_node_alias: "node-1".to_owned(),
            resource_id: selector.resource_id.clone(),
            text: selector.text.clone(),
            description: None,
            class_name: selector.class_name.clone(),
            interactive: true,
        }],
        screenshot_ref: Some(reference("proof.evidence")),
        evidence_refs: vec![reference("proof.evidence")],
        captured_at: "2026-08-30T00:40:00Z".to_owned(),
    })
    .expect("first context");
    let stale_target = resolve_semantic_target(&first, selector.clone()).expect("target");

    let second = capture_screen_context(ScreenContextRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        capture_sequence: 2,
        backend_source: "androidx-uiautomator".to_owned(),
        backend_version: "fixture".to_owned(),
        nodes: vec![SemanticNode {
            backend_node_alias: "node-99".to_owned(),
            resource_id: selector.resource_id.clone(),
            text: selector.text.clone(),
            description: None,
            class_name: selector.class_name.clone(),
            interactive: true,
        }],
        screenshot_ref: Some(reference("proof.evidence")),
        evidence_refs: vec![reference("proof.evidence")],
        captured_at: "2026-08-30T00:40:01Z".to_owned(),
    })
    .expect("second context");

    let reacquired = reacquire_semantic_target(&stale_target, &second).expect("reacquired target");
    assert_eq!(reacquired.target_ref, stale_target.target_ref);
    assert_eq!(reacquired.context_ref, second.context_ref);
    assert_eq!(reacquired.backend_node_alias, "node-99");
    assert_eq!(reacquired.capture_sequence, 2);
}

#[test]
fn input_acknowledgement_requires_newer_post_condition_readback() {
    let (_device, interface, lease, session) = current_session_fixture();
    let app = visible_application_fixture(&session, &interface, &lease);
    let login_selector = SemanticSelector {
        resource_id: Some("com.example.fixture:id/login".to_owned()),
        text: Some("Login".to_owned()),
        description: None,
        class_name: Some("android.widget.Button".to_owned()),
    };
    let before = capture_screen_context(ScreenContextRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        capture_sequence: 10,
        backend_source: "androidx-uiautomator".to_owned(),
        backend_version: "fixture".to_owned(),
        nodes: vec![SemanticNode {
            backend_node_alias: "login-node".to_owned(),
            resource_id: login_selector.resource_id.clone(),
            text: login_selector.text.clone(),
            description: None,
            class_name: login_selector.class_name.clone(),
            interactive: true,
        }],
        screenshot_ref: Some(reference("proof.evidence")),
        evidence_refs: vec![reference("proof.evidence")],
        captured_at: "2026-08-30T00:50:00Z".to_owned(),
    })
    .expect("before context");
    let target = resolve_semantic_target(&before, login_selector).expect("login target");
    let attempt = admit_input_action(InputActionRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        context: &before,
        action: InputAction::TapSemantic { target },
        command_evidence_refs: vec![reference("proof.evidence")],
        requested_at: "2026-08-30T00:50:01Z".to_owned(),
    })
    .expect("input attempt");
    assert!(!attempt.verified);

    let welcome_selector = SemanticSelector {
        resource_id: Some("com.example.fixture:id/welcome".to_owned()),
        text: Some("Welcome".to_owned()),
        description: None,
        class_name: Some("android.widget.TextView".to_owned()),
    };
    let ack_only = verify_input_action(
        &attempt,
        InputReadBack {
            backend_acknowledged: true,
            post_context: &before,
            expected_selector: Some(welcome_selector.clone()),
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T00:50:02Z".to_owned(),
        },
    )
    .expect_err("backend ack without newer post-condition must fail");
    assert_eq!(ack_only, AndroidRuntimeError::InputPostConditionUnverified);

    let after = capture_screen_context(ScreenContextRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        capture_sequence: 11,
        backend_source: "androidx-uiautomator".to_owned(),
        backend_version: "fixture".to_owned(),
        nodes: vec![SemanticNode {
            backend_node_alias: "welcome-node".to_owned(),
            resource_id: welcome_selector.resource_id.clone(),
            text: welcome_selector.text.clone(),
            description: None,
            class_name: welcome_selector.class_name.clone(),
            interactive: false,
        }],
        screenshot_ref: Some(reference("proof.evidence")),
        evidence_refs: vec![reference("proof.evidence")],
        captured_at: "2026-08-30T00:50:03Z".to_owned(),
    })
    .expect("after context");
    let verified = verify_input_action(
        &attempt,
        InputReadBack {
            backend_acknowledged: true,
            post_context: &after,
            expected_selector: Some(welcome_selector),
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T00:50:04Z".to_owned(),
        },
    )
    .expect("verified input");
    assert_eq!(verified.post_context_ref, after.context_ref);
    assert_eq!(verified.post_capture_sequence, 11);
}

#[test]
fn type_text_retains_only_digest_and_length_not_raw_payload() {
    let (_device, interface, lease, session) = current_session_fixture();
    let app = visible_application_fixture(&session, &interface, &lease);
    let selector = SemanticSelector {
        resource_id: Some("com.example.fixture:id/username".to_owned()),
        text: None,
        description: None,
        class_name: Some("android.widget.EditText".to_owned()),
    };
    let context = capture_screen_context(ScreenContextRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        capture_sequence: 20,
        backend_source: "androidx-uiautomator".to_owned(),
        backend_version: "fixture".to_owned(),
        nodes: vec![SemanticNode {
            backend_node_alias: "username-node".to_owned(),
            resource_id: selector.resource_id.clone(),
            text: None,
            description: None,
            class_name: selector.class_name.clone(),
            interactive: true,
        }],
        screenshot_ref: Some(reference("proof.evidence")),
        evidence_refs: vec![reference("proof.evidence")],
        captured_at: "2026-08-30T01:00:00Z".to_owned(),
    })
    .expect("context");
    let target = resolve_semantic_target(&context, selector).expect("target");
    let digest = "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8".to_owned();
    let attempt = admit_input_action(InputActionRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        context: &context,
        action: InputAction::TypeText {
            target,
            utf8_len: 5,
            text_sha256: digest.clone(),
        },
        command_evidence_refs: vec![reference("proof.evidence")],
        requested_at: "2026-08-30T01:00:01Z".to_owned(),
    })
    .expect("type attempt");
    match attempt.action {
        InputAction::TypeText {
            utf8_len,
            text_sha256,
            ..
        } => {
            assert_eq!(utf8_len, 5);
            assert_eq!(text_sha256, digest);
        }
        other => panic!("unexpected action: {other:?}"),
    }
}

#[test]
fn clipboard_write_uses_distinct_scope_and_retains_digest_only() {
    let (_device, interface, lease, session) = current_session_fixture();
    let app = visible_application_fixture(&session, &interface, &lease);
    let context = capture_screen_context(ScreenContextRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        capture_sequence: 30,
        backend_source: "androidx-uiautomator".to_owned(),
        backend_version: "fixture".to_owned(),
        nodes: vec![],
        screenshot_ref: Some(reference("proof.evidence")),
        evidence_refs: vec![reference("proof.evidence")],
        captured_at: "2026-08-30T01:10:00Z".to_owned(),
    })
    .expect("context");
    let digest = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".to_owned();
    let attempt = admit_input_action(InputActionRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        context: &context,
        action: InputAction::ClipboardSet {
            utf8_len: 5,
            content_sha256: digest.clone(),
        },
        command_evidence_refs: vec![reference("proof.evidence")],
        requested_at: "2026-08-30T01:10:01Z".to_owned(),
    })
    .expect("clipboard attempt");
    match attempt.action {
        InputAction::ClipboardSet {
            utf8_len,
            content_sha256,
        } => {
            assert_eq!(utf8_len, 5);
            assert_eq!(content_sha256, digest);
        }
        other => panic!("unexpected action: {other:?}"),
    }
}

#[test]
fn coordinate_tap_is_bound_to_exact_context_frame_and_geometry() {
    let (_device, interface, lease, session) = current_session_fixture();
    let app = visible_application_fixture(&session, &interface, &lease);
    let frame_ref = reference("proof.evidence");
    let context = capture_screen_context(ScreenContextRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        capture_sequence: 40,
        backend_source: "scrcpy".to_owned(),
        backend_version: "4.1".to_owned(),
        nodes: vec![],
        screenshot_ref: Some(frame_ref.clone()),
        evidence_refs: vec![reference("proof.evidence")],
        captured_at: "2026-08-30T01:20:00Z".to_owned(),
    })
    .expect("context");
    let attempt = admit_input_action(InputActionRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        context: &context,
        action: InputAction::TapCoordinates {
            frame_ref: frame_ref.clone(),
            geometry_ref: reference("device.display_geometry"),
            x: 540,
            y: 1200,
            viewport_width: 1080,
            viewport_height: 2400,
        },
        command_evidence_refs: vec![reference("proof.evidence")],
        requested_at: "2026-08-30T01:20:01Z".to_owned(),
    })
    .expect("coordinate tap");
    match attempt.action {
        InputAction::TapCoordinates {
            frame_ref: observed,
            x,
            y,
            viewport_width,
            viewport_height,
            ..
        } => {
            assert_eq!(observed, frame_ref);
            assert_eq!((x, y), (540, 1200));
            assert_eq!((viewport_width, viewport_height), (1080, 2400));
        }
        other => panic!("unexpected action: {other:?}"),
    }
}

#[test]
fn package_wrong_version_readback_fails_closed() {
    let (_device, interface, lease, session) = current_session_fixture();
    let attempt = admit_package_install(PackageInstallRequest {
        session: &session,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        package_object_ref: reference("object.object"),
        package_revision_ref: reference("object.revision"),
        package_id: "com.example.fixture".to_owned(),
        expected_version: "2.4.1".to_owned(),
        expected_signer: "CN=Fixture".to_owned(),
        command_evidence_refs: vec![reference("proof.evidence")],
        requested_at: "2026-08-30T01:30:00Z".to_owned(),
    })
    .expect("attempt");
    let error = verify_package_install(
        &attempt,
        PackageReadBack {
            provider_generation: interface.provider_generation,
            connection_epoch: interface.connection_epoch,
            package_id: "com.example.fixture".to_owned(),
            installed_version: "2.4.0".to_owned(),
            signatures: vec![SignatureObservation {
                scheme: "apk-v3".to_owned(),
                signer: Some("CN=Fixture".to_owned()),
                status: SignatureStatus::Verified,
            }],
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T01:30:01Z".to_owned(),
        },
    )
    .expect_err("version mismatch must fail");
    assert_eq!(error, AndroidRuntimeError::PackageReadBackMismatch);
}

#[test]
fn package_unverified_signer_fails_closed() {
    let (_device, interface, lease, session) = current_session_fixture();
    let attempt = admit_package_install(PackageInstallRequest {
        session: &session,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        package_object_ref: reference("object.object"),
        package_revision_ref: reference("object.revision"),
        package_id: "com.example.fixture".to_owned(),
        expected_version: "2.4.1".to_owned(),
        expected_signer: "CN=Fixture".to_owned(),
        command_evidence_refs: vec![reference("proof.evidence")],
        requested_at: "2026-08-30T01:31:00Z".to_owned(),
    })
    .expect("attempt");
    let error = verify_package_install(
        &attempt,
        PackageReadBack {
            provider_generation: interface.provider_generation,
            connection_epoch: interface.connection_epoch,
            package_id: "com.example.fixture".to_owned(),
            installed_version: "2.4.1".to_owned(),
            signatures: vec![SignatureObservation {
                scheme: "apk-v3".to_owned(),
                signer: Some("CN=Fixture".to_owned()),
                status: SignatureStatus::Unverified,
            }],
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T01:31:01Z".to_owned(),
        },
    )
    .expect_err("unverified signer must fail");
    assert_eq!(error, AndroidRuntimeError::PackageSignatureUnverified);
}

#[test]
fn launch_without_visible_frame_or_semantic_readiness_fails_closed() {
    let (_device, interface, lease, session) = current_session_fixture();
    let package = verified_package_fixture(&session, &interface, &lease);
    let attempt = admit_application_launch(ApplicationLaunchRequest {
        session: &session,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        installation: &package,
        application_ref: reference("application.application"),
        application_revision_ref: reference("application.revision"),
        command_evidence_refs: vec![reference("proof.evidence")],
        requested_at: "2026-08-30T01:32:00Z".to_owned(),
    })
    .expect("launch attempt");
    let error = verify_application_launch(
        &attempt,
        ApplicationLaunchReadBack {
            provider_generation: interface.provider_generation,
            connection_epoch: interface.connection_epoch,
            package_id: "com.example.fixture".to_owned(),
            process_aliases: vec!["pid:4242".to_owned()],
            activity_or_context: "com.example.fixture/.MainActivity".to_owned(),
            visible_frame_ref: None,
            semantic_context_ref: None,
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T01:32:01Z".to_owned(),
        },
    )
    .expect_err("process/activity alone must not prove launch");
    assert_eq!(error, AndroidRuntimeError::ApplicationReadBackMismatch);
}

#[test]
fn stale_semantic_target_cannot_be_acted_without_reacquisition() {
    let (_device, interface, lease, session) = current_session_fixture();
    let app = visible_application_fixture(&session, &interface, &lease);
    let selector = SemanticSelector {
        resource_id: Some("com.example.fixture:id/login".to_owned()),
        text: Some("Login".to_owned()),
        description: None,
        class_name: Some("android.widget.Button".to_owned()),
    };
    let first = capture_screen_context(ScreenContextRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        capture_sequence: 50,
        backend_source: "androidx-uiautomator".to_owned(),
        backend_version: "fixture".to_owned(),
        nodes: vec![SemanticNode {
            backend_node_alias: "old-node".to_owned(),
            resource_id: selector.resource_id.clone(),
            text: selector.text.clone(),
            description: None,
            class_name: selector.class_name.clone(),
            interactive: true,
        }],
        screenshot_ref: Some(reference("proof.evidence")),
        evidence_refs: vec![reference("proof.evidence")],
        captured_at: "2026-08-30T01:33:00Z".to_owned(),
    })
    .expect("first");
    let stale = resolve_semantic_target(&first, selector.clone()).expect("stale target");
    let second = capture_screen_context(ScreenContextRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        capture_sequence: 51,
        backend_source: "androidx-uiautomator".to_owned(),
        backend_version: "fixture".to_owned(),
        nodes: vec![SemanticNode {
            backend_node_alias: "new-node".to_owned(),
            resource_id: selector.resource_id.clone(),
            text: selector.text.clone(),
            description: None,
            class_name: selector.class_name.clone(),
            interactive: true,
        }],
        screenshot_ref: Some(reference("proof.evidence")),
        evidence_refs: vec![reference("proof.evidence")],
        captured_at: "2026-08-30T01:33:01Z".to_owned(),
    })
    .expect("second");
    let error = admit_input_action(InputActionRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        context: &second,
        action: InputAction::TapSemantic { target: stale },
        command_evidence_refs: vec![reference("proof.evidence")],
        requested_at: "2026-08-30T01:33:02Z".to_owned(),
    })
    .expect_err("stale target must fail");
    assert_eq!(error, AndroidRuntimeError::InputContextMismatch);
}

#[test]
fn application_stop_requires_independent_process_absence_readback() {
    let (_device, interface, lease, session) = current_session_fixture();
    let app = visible_application_fixture(&session, &interface, &lease);
    let attempt = ptah_android_runtime::admit_application_stop(
        ptah_android_runtime::ApplicationStopRequest {
            session: &session,
            application: &app,
            interface: &interface,
            lease: &lease,
            observed_fence_token: 9,
            command_evidence_refs: vec![reference("proof.evidence")],
            requested_at: "2026-08-30T01:40:00Z".to_owned(),
        },
    )
    .expect("stop attempt");

    let still_running = ptah_android_runtime::verify_application_stop(
        &attempt,
        ptah_android_runtime::ApplicationStopReadBack {
            provider_generation: interface.provider_generation,
            connection_epoch: interface.connection_epoch,
            package_id: app.package_id.clone(),
            process_aliases: vec!["pid:4242".to_owned()],
            activity_or_context: Some(app.activity_or_context.clone()),
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T01:40:01Z".to_owned(),
        },
    )
    .expect_err("command acceptance cannot prove stop while process remains");
    assert_eq!(
        still_running,
        AndroidRuntimeError::ApplicationStopUnverified
    );

    let stopped = ptah_android_runtime::verify_application_stop(
        &attempt,
        ptah_android_runtime::ApplicationStopReadBack {
            provider_generation: interface.provider_generation,
            connection_epoch: interface.connection_epoch,
            package_id: app.package_id.clone(),
            process_aliases: vec![],
            activity_or_context: None,
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T01:40:02Z".to_owned(),
        },
    )
    .expect("verified stop");
    assert_eq!(stopped.state, ApplicationSessionState::Stopped);
    assert!(stopped.process_aliases.is_empty());
}

#[test]
fn scroll_and_keyboard_input_are_bound_to_current_screen_context() {
    let (_device, interface, lease, session) = current_session_fixture();
    let app = visible_application_fixture(&session, &interface, &lease);
    let selector = SemanticSelector {
        resource_id: Some("com.example.fixture:id/list".to_owned()),
        text: None,
        description: None,
        class_name: Some("android.widget.ScrollView".to_owned()),
    };
    let context = capture_screen_context(ScreenContextRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        capture_sequence: 60,
        backend_source: "androidx-uiautomator".to_owned(),
        backend_version: "fixture".to_owned(),
        nodes: vec![SemanticNode {
            backend_node_alias: "list-node".to_owned(),
            resource_id: selector.resource_id.clone(),
            text: None,
            description: None,
            class_name: selector.class_name.clone(),
            interactive: true,
        }],
        screenshot_ref: Some(reference("proof.evidence")),
        evidence_refs: vec![reference("proof.evidence")],
        captured_at: "2026-08-30T01:41:00Z".to_owned(),
    })
    .expect("context");
    let target = resolve_semantic_target(&context, selector).expect("scroll target");

    let scroll = admit_input_action(InputActionRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        context: &context,
        action: InputAction::ScrollSemantic {
            target,
            delta_y: 480,
        },
        command_evidence_refs: vec![reference("proof.evidence")],
        requested_at: "2026-08-30T01:41:01Z".to_owned(),
    })
    .expect("scroll admission");
    assert!(matches!(
        scroll.action,
        InputAction::ScrollSemantic { delta_y: 480, .. }
    ));

    let key = admit_input_action(InputActionRequest {
        session: &session,
        application: &app,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 9,
        context: &context,
        action: InputAction::KeyPress {
            android_key_code: 66,
        },
        command_evidence_refs: vec![reference("proof.evidence")],
        requested_at: "2026-08-30T01:41:02Z".to_owned(),
    })
    .expect("keyboard admission");
    assert!(matches!(
        key.action,
        InputAction::KeyPress {
            android_key_code: 66
        }
    ));
}

#[test]
fn screenshot_recording_and_log_evidence_require_privacy_and_verified_artifact_readback() {
    let (_device, interface, lease, session) = current_session_fixture();
    for kind in [
        ptah_android_runtime::EvidenceCaptureKind::Screenshot,
        ptah_android_runtime::EvidenceCaptureKind::Recording,
        ptah_android_runtime::EvidenceCaptureKind::LogSegment,
    ] {
        let attempt = ptah_android_runtime::admit_evidence_capture(
            ptah_android_runtime::EvidenceCaptureRequest {
                session: &session,
                interface: &interface,
                lease: &lease,
                observed_fence_token: 9,
                kind,
                producer_backend: "fixture-backend".to_owned(),
                producer_version: "1.0".to_owned(),
                privacy_class: "workspace-private".to_owned(),
                retention_policy_ref: reference("policy.retention"),
                command_evidence_refs: vec![reference("proof.evidence")],
                requested_at: "2026-08-30T01:42:00Z".to_owned(),
            },
        )
        .expect("capture admission");
        let captured = ptah_android_runtime::verify_evidence_capture(
            &attempt,
            ptah_android_runtime::EvidenceCaptureReadBack {
                provider_generation: interface.provider_generation,
                connection_epoch: interface.connection_epoch,
                artifact_ref: Some(reference("object.artifact")),
                evidence_refs: vec![reference("proof.evidence")],
                observed_at: "2026-08-30T01:42:01Z".to_owned(),
            },
        )
        .expect("verified capture");
        assert_eq!(captured.kind, kind);
        assert_eq!(captured.privacy_class, "workspace-private");
    }
}

#[test]
fn cleanup_failure_quarantines_device_instead_of_returning_it_available() {
    let (_device, interface, lease, session) = current_session_fixture();
    let attempt =
        ptah_android_runtime::admit_device_cleanup(ptah_android_runtime::DeviceCleanupRequest {
            session: &session,
            interface: &interface,
            lease: &lease,
            observed_fence_token: 9,
            cleanup_recipe_ref: reference("device.cleanup_recipe"),
            command_evidence_refs: vec![reference("proof.evidence")],
            requested_at: "2026-08-30T01:43:00Z".to_owned(),
        })
        .expect("cleanup admission");
    let receipt = ptah_android_runtime::verify_device_cleanup(
        &attempt,
        ptah_android_runtime::DeviceCleanupReadBack {
            provider_generation: interface.provider_generation,
            connection_epoch: interface.connection_epoch,
            backend_acknowledged: true,
            residual_state_refs: vec![reference("proof.evidence")],
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T01:43:01Z".to_owned(),
        },
    )
    .expect("cleanup outcome must be recorded even when verification fails");
    assert_eq!(
        receipt.disposition,
        ptah_android_runtime::CleanupDisposition::Quarantined
    );
    assert_eq!(receipt.session_state, DeviceSessionState::Failed);
}

#[test]
fn verified_cleanup_closes_device_session() {
    let (_device, interface, lease, session) = current_session_fixture();
    let attempt =
        ptah_android_runtime::admit_device_cleanup(ptah_android_runtime::DeviceCleanupRequest {
            session: &session,
            interface: &interface,
            lease: &lease,
            observed_fence_token: 9,
            cleanup_recipe_ref: reference("device.cleanup_recipe"),
            command_evidence_refs: vec![reference("proof.evidence")],
            requested_at: "2026-08-30T01:44:00Z".to_owned(),
        })
        .expect("cleanup admission");
    let receipt = ptah_android_runtime::verify_device_cleanup(
        &attempt,
        ptah_android_runtime::DeviceCleanupReadBack {
            provider_generation: interface.provider_generation,
            connection_epoch: interface.connection_epoch,
            backend_acknowledged: true,
            residual_state_refs: vec![],
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T01:44:01Z".to_owned(),
        },
    )
    .expect("verified cleanup");
    assert_eq!(
        receipt.disposition,
        ptah_android_runtime::CleanupDisposition::Verified
    );
    assert_eq!(receipt.session_state, DeviceSessionState::Closed);
}

#[test]
fn stale_evidence_readback_epoch_is_rejected() {
    let (_device, interface, lease, session) = current_session_fixture();
    let attempt = ptah_android_runtime::admit_evidence_capture(
        ptah_android_runtime::EvidenceCaptureRequest {
            session: &session,
            interface: &interface,
            lease: &lease,
            observed_fence_token: lease.fence_token,
            kind: ptah_android_runtime::EvidenceCaptureKind::Screenshot,
            producer_backend: "fixture-backend".to_owned(),
            producer_version: "1.0".to_owned(),
            privacy_class: "workspace-private".to_owned(),
            retention_policy_ref: reference("policy.retention"),
            command_evidence_refs: vec![reference("proof.evidence")],
            requested_at: "2026-08-30T01:45:00Z".to_owned(),
        },
    )
    .expect("capture admission");
    let error = ptah_android_runtime::verify_evidence_capture(
        &attempt,
        ptah_android_runtime::EvidenceCaptureReadBack {
            provider_generation: interface.provider_generation,
            connection_epoch: interface.connection_epoch - 1,
            artifact_ref: Some(reference("object.artifact")),
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T01:45:01Z".to_owned(),
        },
    )
    .expect_err("stale evidence from an older connection epoch must fail closed");
    assert_eq!(error, AndroidRuntimeError::EvidenceCaptureUnverified);
}

#[test]
fn stale_package_readback_epoch_is_rejected() {
    let (_device, interface, lease, session) = current_session_fixture();
    let attempt = admit_package_install(PackageInstallRequest {
        session: &session,
        interface: &interface,
        lease: &lease,
        observed_fence_token: lease.fence_token,
        package_object_ref: reference("object.object"),
        package_revision_ref: reference("object.revision"),
        package_id: "com.example.fixture".to_owned(),
        expected_version: "2.4.1".to_owned(),
        expected_signer: "CN=Fixture".to_owned(),
        command_evidence_refs: vec![reference("proof.evidence")],
        requested_at: "2026-08-30T01:46:00Z".to_owned(),
    })
    .expect("install admission");
    let error = verify_package_install(
        &attempt,
        PackageReadBack {
            provider_generation: interface.provider_generation,
            connection_epoch: interface.connection_epoch - 1,
            package_id: "com.example.fixture".to_owned(),
            installed_version: "2.4.1".to_owned(),
            signatures: vec![SignatureObservation {
                scheme: "apk-v3".to_owned(),
                signer: Some("CN=Fixture".to_owned()),
                status: SignatureStatus::Verified,
            }],
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T01:46:01Z".to_owned(),
        },
    )
    .expect_err("package read-back from an older connection epoch must fail closed");
    assert_eq!(error, AndroidRuntimeError::PackageReadBackMismatch);
}

#[test]
fn stale_application_launch_readback_epoch_is_rejected() {
    let (_device, interface, lease, session) = current_session_fixture();
    let package = verified_package_fixture(&session, &interface, &lease);
    let attempt = admit_application_launch(ApplicationLaunchRequest {
        session: &session,
        interface: &interface,
        lease: &lease,
        observed_fence_token: lease.fence_token,
        installation: &package,
        application_ref: reference("application.application"),
        application_revision_ref: reference("application.revision"),
        command_evidence_refs: vec![reference("proof.evidence")],
        requested_at: "2026-08-30T01:47:00Z".to_owned(),
    })
    .expect("launch admission");
    let error = verify_application_launch(
        &attempt,
        ApplicationLaunchReadBack {
            provider_generation: interface.provider_generation,
            connection_epoch: interface.connection_epoch - 1,
            package_id: package.package_id.clone(),
            process_aliases: vec!["pid:4242".to_owned()],
            activity_or_context: "com.example.fixture/.MainActivity".to_owned(),
            visible_frame_ref: Some(reference("proof.evidence")),
            semantic_context_ref: Some(reference("application.semantic_context")),
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T01:47:01Z".to_owned(),
        },
    )
    .expect_err("launch read-back from an older connection epoch must fail closed");
    assert_eq!(error, AndroidRuntimeError::ApplicationReadBackMismatch);
}

#[test]
fn stale_cleanup_readback_epoch_quarantines_device() {
    let (_device, interface, lease, session) = current_session_fixture();
    let attempt =
        ptah_android_runtime::admit_device_cleanup(ptah_android_runtime::DeviceCleanupRequest {
            session: &session,
            interface: &interface,
            lease: &lease,
            observed_fence_token: lease.fence_token,
            cleanup_recipe_ref: reference("device.cleanup_recipe"),
            command_evidence_refs: vec![reference("proof.evidence")],
            requested_at: "2026-08-30T01:48:00Z".to_owned(),
        })
        .expect("cleanup admission");
    let receipt = ptah_android_runtime::verify_device_cleanup(
        &attempt,
        ptah_android_runtime::DeviceCleanupReadBack {
            provider_generation: interface.provider_generation,
            connection_epoch: interface.connection_epoch - 1,
            backend_acknowledged: true,
            residual_state_refs: vec![],
            evidence_refs: vec![reference("proof.evidence")],
            observed_at: "2026-08-30T01:48:01Z".to_owned(),
        },
    )
    .expect("stale cleanup must still produce a quarantine receipt");
    assert_eq!(
        receipt.disposition,
        ptah_android_runtime::CleanupDisposition::Quarantined
    );
    assert_eq!(receipt.session_state, DeviceSessionState::Failed);
}
