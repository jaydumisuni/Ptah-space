use ptah_device_runtime::{
    AdbObservationProvider, AppleMode, AppleObservationProvider, DeviceError, DeviceKind,
    DeviceLease, DeviceProviderBinding, DeviceRegistry, FastbootObservationProvider,
    FenceDecision, InterfaceLocality, InterfaceTransport, MutationClass, ObservationSeed,
    OperationAuthority, ProtocolClass, ProtocolOperationRequest, Reachability, TransitionReason,
    UsbSerialObservationProvider, admit_protocol_operation,
};
use ptah_identifiers::EntityRef;
use ptah_provider_api::{
    ProviderGeneration, ProviderHealth, ProviderInstance, ProviderKind, ProviderReachability,
    ProviderReadiness, ProviderRevision,
};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid fixture reference")
}

fn provider_revision(kind: ProviderKind) -> ProviderRevision {
    ProviderRevision {
        revision_ref: reference("runtime.provider_revision"),
        provider_ref: reference("runtime.provider"),
        provider_kind: kind,
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
        started_at: "2026-08-26T00:00:00Z".to_owned(),
        limitations: Vec::new(),
    }
}

fn binding(generation: u64, connection_epoch: u64) -> DeviceProviderBinding {
    let revision = provider_revision(ProviderKind::Device);
    let instance = provider_instance(revision.revision_ref.clone(), generation, connection_epoch);
    DeviceProviderBinding::bind(&revision, &instance).expect("device binding")
}

fn seed(
    alias: &str,
    identity: Vec<EntityRef>,
    continuity: Vec<EntityRef>,
    reachability: Reachability,
) -> ObservationSeed {
    ObservationSeed {
        profile_revision_ref: reference("device.profile_revision"),
        identity_basis_refs: identity,
        continuity_basis_refs: continuity,
        evidence_refs: vec![reference("proof.evidence")],
        backend_alias: alias.to_owned(),
        topology_or_address: Some("usb:1-2".to_owned()),
        endpoint_claims: vec!["18d1:4ee7".to_owned()],
        reachability,
        observed_at: "2026-08-26T00:00:01Z".to_owned(),
    }
}

fn adb_observation(
    provider: DeviceProviderBinding,
    alias: &str,
    identity: Vec<EntityRef>,
    continuity: Vec<EntityRef>,
    reachability: Reachability,
) -> ptah_device_runtime::TransportObservation {
    AdbObservationProvider::new(provider)
        .observe(
            InterfaceTransport::AdbUsb,
            seed(alias, identity, continuity, reachability),
            Some("1.0.41".to_owned()),
        )
        .expect("ADB observation")
}

fn current_registry() -> (
    DeviceRegistry,
    DeviceProviderBinding,
    EntityRef,
    EntityRef,
    ptah_device_runtime::ReconcileOutcome,
) {
    let provider = binding(1, 1);
    let identity = reference("proof.evidence");
    let continuity = reference("proof.evidence");
    let observation = adb_observation(
        provider.clone(),
        "SERIAL-A",
        vec![identity.clone()],
        vec![continuity.clone()],
        Reachability::Reachable,
    );
    let mut registry = DeviceRegistry::default();
    let outcome = registry.reconcile(observation).expect("reconcile");
    (registry, provider, identity, continuity, outcome)
}

/* 1 */
#[test]
fn device_provider_binding_requires_device_kind_and_exact_revision() {
    let process = provider_revision(ProviderKind::Process);
    let instance = provider_instance(process.revision_ref.clone(), 1, 1);
    assert!(matches!(
        DeviceProviderBinding::bind(&process, &instance),
        Err(DeviceError::Provider(_))
    ));

    let revision = provider_revision(ProviderKind::Device);
    let wrong_instance = provider_instance(reference("runtime.provider_revision"), 1, 1);
    assert!(matches!(
        DeviceProviderBinding::bind(&revision, &wrong_instance),
        Err(DeviceError::Provider(_))
    ));
}

/* 2 */
#[test]
fn backend_alias_change_does_not_replace_canonical_device_identity() {
    let provider = binding(1, 1);
    let identity = reference("proof.evidence");
    let continuity = reference("proof.evidence");
    let mut registry = DeviceRegistry::default();
    let first = registry
        .reconcile(adb_observation(
            provider.clone(),
            "SERIAL-A",
            vec![identity.clone()],
            vec![continuity.clone()],
            Reachability::Reachable,
        ))
        .expect("first");
    let second = registry
        .reconcile(adb_observation(
            provider,
            "SERIAL-B",
            vec![identity],
            vec![continuity],
            Reachability::Reachable,
        ))
        .expect("second");
    assert_eq!(first.device.device_ref, second.device.device_ref);
    assert!(!second.device_created);
    assert_eq!(second.interface.observed_aliases, vec!["SERIAL-B"]);
    assert_eq!(second.observation.device_ref, second.device.device_ref);
}

/* 3 */
#[test]
fn additional_identity_evidence_extends_existing_device_without_rekeying() {
    let provider = binding(1, 1);
    let identity_a = reference("proof.evidence");
    let identity_b = reference("proof.evidence");
    let continuity = reference("proof.evidence");
    let mut registry = DeviceRegistry::default();
    let first = registry
        .reconcile(adb_observation(
            provider.clone(),
            "A",
            vec![identity_a.clone()],
            vec![continuity.clone()],
            Reachability::Reachable,
        ))
        .expect("first");
    let second = registry
        .reconcile(adb_observation(
            provider.clone(),
            "A",
            vec![identity_a.clone(), identity_b],
            vec![continuity.clone()],
            Reachability::Reachable,
        ))
        .expect("second");
    assert_eq!(first.device.device_ref, second.device.device_ref);
    assert_eq!(second.device.identity_basis_refs.len(), 2);

    let apple = AppleObservationProvider::new(provider)
        .observe(
            AppleMode::Normal,
            seed(
                "APPLE",
                vec![identity_a],
                vec![continuity],
                Reachability::Reachable,
            ),
            None,
        )
        .expect("Apple observation");
    assert_eq!(
        registry
            .reconcile(apple)
            .expect_err("same stable basis cannot change Device kind"),
        DeviceError::DeviceKindMismatch
    );
}

/* 4 */
#[test]
fn identity_basis_overlapping_two_devices_fails_closed() {
    let provider = binding(1, 1);
    let identity_a = reference("proof.evidence");
    let identity_b = reference("proof.evidence");
    let continuity_a = reference("proof.evidence");
    let continuity_b = reference("proof.evidence");
    let mut registry = DeviceRegistry::default();
    registry
        .reconcile(adb_observation(
            provider.clone(),
            "A",
            vec![identity_a.clone()],
            vec![continuity_a],
            Reachability::Reachable,
        ))
        .expect("device A");
    registry
        .reconcile(adb_observation(
            provider.clone(),
            "B",
            vec![identity_b.clone()],
            vec![continuity_b],
            Reachability::Reachable,
        ))
        .expect("device B");
    let ambiguous = adb_observation(
        provider,
        "C",
        vec![identity_a, identity_b],
        vec![reference("proof.evidence")],
        Reachability::Reachable,
    );
    assert_eq!(
        registry
            .reconcile(ambiguous)
            .expect_err("ambiguous identity"),
        DeviceError::AmbiguousIdentity
    );
}

/* 5 */
#[test]
fn backend_alias_lookup_fails_when_multiple_devices_share_alias() {
    let provider = binding(1, 1);
    let mut registry = DeviceRegistry::default();
    for _ in 0..2 {
        registry
            .reconcile(adb_observation(
                provider.clone(),
                "DUPLICATE",
                vec![reference("proof.evidence")],
                vec![reference("proof.evidence")],
                Reachability::Reachable,
            ))
            .expect("distinct device");
    }
    assert_eq!(
        registry
            .resolve_backend_alias("DUPLICATE")
            .expect_err("alias ambiguity"),
        DeviceError::AmbiguousAlias
    );
}

/* 6 */
#[test]
fn fastboot_and_fastbootd_are_distinct_interfaces_on_one_device() {
    let provider = binding(1, 1);
    let identity = reference("proof.evidence");
    let continuity = reference("proof.evidence");
    let lane = FastbootObservationProvider::new(provider);
    let mut registry = DeviceRegistry::default();
    let fastboot = lane
        .observe(
            InterfaceTransport::FastbootUsb,
            false,
            seed(
                "FB",
                vec![identity.clone()],
                vec![continuity.clone()],
                Reachability::Reachable,
            ),
            None,
        )
        .expect("fastboot");
    let first = registry.reconcile(fastboot).expect("first");
    let fastbootd = lane
        .observe(
            InterfaceTransport::FastbootUsb,
            true,
            seed(
                "FB",
                vec![identity],
                vec![continuity],
                Reachability::Reachable,
            ),
            None,
        )
        .expect("fastbootd");
    let second = registry.reconcile(fastbootd).expect("second");
    assert_eq!(first.device.device_ref, second.device.device_ref);
    assert_ne!(first.interface.interface_ref, second.interface.interface_ref);
    assert_eq!(registry.interfaces().len(), 2);
}

/* 7 */
#[test]
fn provider_generation_change_advances_connection_epoch_and_older_generation_fails() {
    let (mut registry, _provider, identity, continuity, first) = current_registry();
    let second = registry
        .reconcile(adb_observation(
            binding(2, 1),
            "SERIAL-A",
            vec![identity.clone()],
            vec![continuity.clone()],
            Reachability::Reachable,
        ))
        .expect("provider restart");
    assert_eq!(
        second.interface.connection_epoch,
        first.interface.connection_epoch + 1
    );
    assert_eq!(
        second.connection.transition_reason,
        TransitionReason::ProviderRestart
    );
    assert_eq!(
        registry
            .reconcile(adb_observation(
                binding(1, 1),
                "SERIAL-A",
                vec![identity],
                vec![continuity],
                Reachability::Reachable,
            ))
            .expect_err("older Provider generation"),
        DeviceError::StaleProviderGeneration
    );
}

/* 8 */
#[test]
fn provider_control_epoch_change_advances_device_epoch_and_older_epoch_fails() {
    let (mut registry, _provider, identity, continuity, first) = current_registry();
    let second = registry
        .reconcile(adb_observation(
            binding(1, 2),
            "SERIAL-A",
            vec![identity.clone()],
            vec![continuity.clone()],
            Reachability::Reachable,
        ))
        .expect("provider connection replacement");
    assert_eq!(
        second.interface.connection_epoch,
        first.interface.connection_epoch + 1
    );
    assert_eq!(
        second.connection.transition_reason,
        TransitionReason::ProviderRestart
    );
    assert_eq!(
        registry
            .reconcile(adb_observation(
                binding(1, 1),
                "SERIAL-A",
                vec![identity],
                vec![continuity],
                Reachability::Reachable,
            ))
            .expect_err("older Provider control epoch"),
        DeviceError::StaleProviderConnectionEpoch
    );
}

/* 9 */
#[test]
fn topology_reenumeration_advances_epoch_without_replacing_device() {
    let (mut registry, provider, identity, continuity, first) = current_registry();
    let lane = AdbObservationProvider::new(provider);
    let mut changed_seed = seed(
        "SERIAL-A",
        vec![identity],
        vec![continuity],
        Reachability::Reachable,
    );
    changed_seed.topology_or_address = Some("usb:2-4".to_owned());
    let second = registry
        .reconcile(
            lane.observe(InterfaceTransport::AdbUsb, changed_seed, None)
                .expect("observation"),
        )
        .expect("reenumeration");
    assert_eq!(first.device.device_ref, second.device.device_ref);
    assert_eq!(
        second.connection.transition_reason,
        TransitionReason::Reenumeration
    );
}

/* 10 */
#[test]
fn changed_continuity_basis_advances_epoch_and_retains_predecessor() {
    let (mut registry, provider, identity, _continuity, first) = current_registry();
    let second = registry
        .reconcile(adb_observation(
            provider,
            "SERIAL-A",
            vec![identity],
            vec![reference("proof.evidence")],
            Reachability::Reachable,
        ))
        .expect("continuity replacement");
    assert_eq!(
        second.connection.transition_reason,
        TransitionReason::TransportContinuityLost
    );
    assert_eq!(
        second.connection.predecessor_connection_ref,
        Some(first.connection.connection_ref)
    );
}

/* 11 */
#[test]
fn intermittent_usb_recovery_advances_epoch_on_recovery() {
    let provider = binding(1, 1);
    let identity = reference("proof.evidence");
    let continuity = reference("proof.evidence");
    let mut registry = DeviceRegistry::default();
    let intermittent = registry
        .reconcile(adb_observation(
            provider.clone(),
            "SERIAL-A",
            vec![identity.clone()],
            vec![continuity.clone()],
            Reachability::Intermittent,
        ))
        .expect("intermittent");
    let recovered = registry
        .reconcile(adb_observation(
            provider,
            "SERIAL-A",
            vec![identity],
            vec![continuity],
            Reachability::Reachable,
        ))
        .expect("recovered");
    assert_eq!(
        recovered.interface.connection_epoch,
        intermittent.interface.connection_epoch + 1
    );
    assert_eq!(
        recovered.connection.transition_reason,
        TransitionReason::Reconnect
    );
    assert_eq!(registry.observations().len(), 2);
}

/* 12 */
#[test]
fn apple_provider_normalizes_normal_recovery_and_dfu_as_observations_only() {
    let lane = AppleObservationProvider::new(binding(1, 1));
    for (mode, expected) in [
        (AppleMode::Normal, "apple_normal"),
        (AppleMode::Recovery, "apple_recovery"),
        (AppleMode::Dfu, "apple_dfu"),
    ] {
        let observation = lane
            .observe(
                mode,
                seed(
                    "APPLE-UDID",
                    vec![reference("proof.evidence")],
                    vec![reference("proof.evidence")],
                    Reachability::Reachable,
                ),
                None,
            )
            .expect("Apple observation");
        assert_eq!(observation.transport, InterfaceTransport::UsbVendor);
        assert_eq!(observation.mode_or_protocol, expected);
        assert_eq!(observation.device_kind, DeviceKind::PhysicalIos);
    }
}

/* 13 */
#[test]
fn usb_serial_provider_retains_port_as_alias_and_node_local_provider_evidence() {
    let lane = UsbSerialObservationProvider::new(binding(1, 1));
    let identity = reference("proof.evidence");
    let observation = lane
        .observe(
            DeviceKind::PhysicalAndroid,
            "vendor_serial",
            seed(
                "COM17",
                vec![identity.clone()],
                vec![reference("proof.evidence")],
                Reachability::Reachable,
            ),
            None,
        )
        .expect("serial observation");
    assert_eq!(observation.transport, InterfaceTransport::UsbSerial);
    assert_eq!(observation.backend_aliases, vec!["COM17"]);
    assert_eq!(observation.identity_basis_refs, vec![identity]);
    let mut registry = DeviceRegistry::default();
    let current = registry.reconcile(observation).expect("reconcile");
    assert_eq!(current.interface.locality, InterfaceLocality::NodeLocal);
    assert_eq!(current.interface.node_generation, 1);
    assert_eq!(current.interface.endpoint_claims, vec!["18d1:4ee7"]);
    assert_eq!(current.interface.capability_claim_refs.len(), 1);
}

/* 14 */
#[test]
fn observation_lanes_reject_incompatible_transports_and_missing_basis() {
    let lane = AdbObservationProvider::new(binding(1, 1));
    assert_eq!(
        lane.observe(
            InterfaceTransport::UsbSerial,
            seed(
                "A",
                vec![reference("proof.evidence")],
                vec![reference("proof.evidence")],
                Reachability::Reachable,
            ),
            None,
        )
        .expect_err("wrong transport"),
        DeviceError::UnsupportedTransport
    );
    let mut missing = seed(
        "A",
        Vec::new(),
        vec![reference("proof.evidence")],
        Reachability::Reachable,
    );
    missing.topology_or_address = None;
    assert_eq!(
        lane.observe(InterfaceTransport::AdbUsb, missing, None)
            .expect_err("missing identity basis"),
        DeviceError::MissingIdentityBasis
    );
}

/* 15 */
#[test]
fn current_device_lease_and_fence_are_accepted() {
    let (_registry, provider, _identity, _continuity, current) = current_registry();
    let lease = DeviceLease::issue(
        current.device.device_ref.clone(),
        reference("core.session"),
        vec!["protocol.observe".to_owned()],
        7,
        provider.context.provider_generation,
        current.interface.connection_epoch,
        "2026-08-26T00:00:01Z",
        "2026-08-26T01:00:01Z",
    )
    .expect("lease");
    assert_eq!(
        lease
            .fence(&current.interface, 7, "protocol.observe")
            .expect("fence"),
        FenceDecision::Current
    );
}

/* 16 */
#[test]
fn lease_fails_closed_after_provider_generation_changes() {
    let (mut registry, provider, identity, continuity, current) = current_registry();
    let lease = DeviceLease::issue(
        current.device.device_ref.clone(),
        reference("core.session"),
        vec!["protocol.observe".to_owned()],
        2,
        provider.context.provider_generation,
        current.interface.connection_epoch,
        "2026-08-26T00:00:01Z",
        "2026-08-26T01:00:01Z",
    )
    .expect("lease");
    let advanced = registry
        .reconcile(adb_observation(
            binding(2, 1),
            "SERIAL-A",
            vec![identity],
            vec![continuity],
            Reachability::Reachable,
        ))
        .expect("advanced");
    assert_eq!(
        lease
            .fence(&advanced.interface, 2, "protocol.observe")
            .expect_err("stale generation"),
        DeviceError::StaleLeaseProviderGeneration
    );
}

/* 17 */
#[test]
fn lease_fails_closed_after_connection_epoch_changes() {
    let (mut registry, provider, identity, continuity, current) = current_registry();
    let lease = DeviceLease::issue(
        current.device.device_ref.clone(),
        reference("core.session"),
        vec!["protocol.observe".to_owned()],
        2,
        provider.context.provider_generation,
        current.interface.connection_epoch,
        "2026-08-26T00:00:01Z",
        "2026-08-26T01:00:01Z",
    )
    .expect("lease");
    let lane = AdbObservationProvider::new(provider);
    let mut changed = seed(
        "SERIAL-A",
        vec![identity],
        vec![continuity],
        Reachability::Reachable,
    );
    changed.topology_or_address = Some("usb:9-9".to_owned());
    let advanced = registry
        .reconcile(
            lane.observe(InterfaceTransport::AdbUsb, changed, None)
                .expect("observation"),
        )
        .expect("advanced");
    assert_eq!(
        lease
            .fence(&advanced.interface, 2, "protocol.observe")
            .expect_err("stale epoch"),
        DeviceError::StaleConnectionEpoch
    );
}

/* 18 */
#[test]
fn fence_token_scope_and_revocation_fail_closed() {
    let (_registry, provider, _identity, _continuity, current) = current_registry();
    let mut lease = DeviceLease::issue(
        current.device.device_ref.clone(),
        reference("core.session"),
        vec!["protocol.observe".to_owned()],
        5,
        provider.context.provider_generation,
        current.interface.connection_epoch,
        "2026-08-26T00:00:01Z",
        "2026-08-26T01:00:01Z",
    )
    .expect("lease");
    assert_eq!(
        lease
            .fence(&current.interface, 4, "protocol.observe")
            .expect_err("stale fence"),
        DeviceError::StaleFence
    );
    assert_eq!(
        lease
            .fence(&current.interface, 6, "protocol.observe")
            .expect_err("ahead fence"),
        DeviceError::AheadFence
    );
    assert_eq!(
        lease
            .fence(&current.interface, 5, "protocol.write")
            .expect_err("scope"),
        DeviceError::LeaseScopeDenied
    );
    lease.revoke();
    assert_eq!(
        lease
            .fence(&current.interface, 5, "protocol.observe")
            .expect_err("revoked"),
        DeviceError::LeaseRevoked
    );
}

fn operation_request<'a>(
    provider: &'a DeviceProviderBinding,
    current: &'a ptah_device_runtime::ReconcileOutcome,
    lease: &'a DeviceLease,
    mutation_class: MutationClass,
) -> ProtocolOperationRequest<'a> {
    ProtocolOperationRequest {
        device_ref: current.device.device_ref.clone(),
        device_profile_revision_ref: current.device.current_profile_revision_ref.clone(),
        device_session_ref: reference("device.session"),
        interface: &current.interface,
        provider,
        lease,
        observed_fence_token: lease.fence_token,
        protocol_class: ProtocolClass::Adb,
        protocol_operation_key: "adb.getprop".to_owned(),
        mutation_class,
        activity_ref: reference("activity.activity"),
        operation_ref: reference("activity.operation"),
        attempt_refs: vec![reference("activity.attempt")],
        evidence_refs: vec![reference("proof.evidence")],
        started_at: "2026-08-26T00:00:02Z".to_owned(),
        physical_authority_ref: None,
    }
}

/* 19 */
#[test]
fn read_protocol_operation_requires_current_device_provider_epoch_lease_and_attempt_evidence() {
    let (_registry, provider, _identity, _continuity, current) = current_registry();
    let lease = DeviceLease::issue(
        current.device.device_ref.clone(),
        reference("core.session"),
        vec!["protocol.observe".to_owned()],
        11,
        provider.context.provider_generation,
        current.interface.connection_epoch,
        "2026-08-26T00:00:01Z",
        "2026-08-26T01:00:01Z",
    )
    .expect("lease");
    let admitted = admit_protocol_operation(operation_request(
        &provider,
        &current,
        &lease,
        MutationClass::DeviceRead,
    ))
    .expect("read operation");
    assert_eq!(admitted.authority, OperationAuthority::ReadOnly);
    assert_eq!(
        admitted.device_profile_revision_ref,
        current.device.current_profile_revision_ref
    );
    assert_eq!(admitted.device_session_ref.entity_kind.as_str(), "device.session");
    assert_eq!(admitted.connection_epoch, current.interface.connection_epoch);
    assert_eq!(admitted.attempt_refs.len(), 1);
    assert_eq!(admitted.started_at, "2026-08-26T00:00:02Z");
}

/* 20 */
#[test]
fn physical_authority_evidence_never_upgrades_c08_into_device_write_authority() {
    let (_registry, provider, _identity, _continuity, current) = current_registry();
    let lease = DeviceLease::issue(
        current.device.device_ref.clone(),
        reference("core.session"),
        vec!["protocol.observe".to_owned()],
        13,
        provider.context.provider_generation,
        current.interface.connection_epoch,
        "2026-08-26T00:00:01Z",
        "2026-08-26T01:00:01Z",
    )
    .expect("lease");
    let mut request = operation_request(&provider, &current, &lease, MutationClass::DeviceWrite);
    request.physical_authority_ref = Some(reference("security.grant"));
    assert_eq!(
        admit_protocol_operation(request).expect_err("C08 cannot write"),
        DeviceError::MutationOutsideC08
    );
}
