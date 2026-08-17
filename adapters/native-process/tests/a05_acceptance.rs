//! A05 native process, PTY, attachment, lease and Provider acceptance tests.

use native_process::{
    ControlScope, DisconnectPolicy, NativeProcessError, NativeProcessProvider,
    NativeProcessProviderConfig, ProcessMode, ProcessSpec, ProcessState, StreamKind,
    StreamTopology, TerminalSize,
};
use ptah_identifiers::EntityRef;
use ptah_provider_api::{
    EndpointAliasType, ProviderGeneration, ProviderHealth, ProviderInstance, ProviderKind,
    ProviderReachability, ProviderReadiness, ProviderRevision,
};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid reference")
}

fn provider() -> NativeProcessProvider {
    let revision_ref = reference("runtime.provider_revision");
    NativeProcessProvider::new(NativeProcessProviderConfig {
        revision: ProviderRevision {
            revision_ref: revision_ref.clone(),
            provider_ref: reference("runtime.provider"),
            provider_kind: ProviderKind::Process,
            implementation_name: "native-process".to_owned(),
            implementation_version: "0.1.0".to_owned(),
            build_or_package_digest: "sha256:a05-test-native-process".to_owned(),
            configuration_digest: "sha256:a05-test-config".to_owned(),
            supported_facility_refs: vec![reference("runtime.facility")],
            capability_claim_refs: vec![reference("runtime.capability_claim")],
            dependency_refs: Vec::new(),
            node_requirements: Vec::new(),
            security_requirements: Vec::new(),
            known_limitations: Vec::new(),
        },
        instance: ProviderInstance {
            instance_ref: reference("runtime.provider_instance"),
            provider_revision_ref: revision_ref,
            node_ref: reference("core.node"),
            node_generation: 4,
            provider_generation: ProviderGeneration::new(2).expect("generation"),
            connection_epoch: 5,
            reachability: ProviderReachability::Reachable,
            readiness: ProviderReadiness::Ready,
            health: ProviderHealth::Healthy,
            endpoint_aliases: Vec::new(),
            process_or_service_refs: Vec::new(),
            observation_refs: vec![reference("proof.evidence")],
            started_at: "2026-08-17T00:00:00Z".to_owned(),
            limitations: Vec::new(),
        },
        clock: Arc::new(|| "2026-08-17T00:00:00Z".to_owned()),
    })
    .expect("Provider")
}

fn pipes(script: &str, max_stream_bytes: usize) -> ProcessSpec {
    ProcessSpec {
        program: "/bin/sh".to_owned(),
        args: vec!["-c".to_owned(), script.to_owned()],
        env: BTreeMap::new(),
        clear_env: false,
        cwd: None,
        mode: ProcessMode::Pipes,
        max_stream_bytes,
        disconnect_policy: DisconnectPolicy::Retain,
    }
}

fn pty(script: &str) -> ProcessSpec {
    ProcessSpec {
        program: "/bin/sh".to_owned(),
        args: vec!["-c".to_owned(), script.to_owned()],
        env: BTreeMap::new(),
        clear_env: false,
        cwd: None,
        mode: ProcessMode::Pty {
            size: TerminalSize::default(),
        },
        max_stream_bytes: 4096,
        disconnect_policy: DisconnectPolicy::Retain,
    }
}

#[cfg(unix)]
#[test]
fn native_pipe_streams_are_independent_and_spawn_ack_is_not_exit_proof() {
    let provider = provider();
    let process = provider
        .spawn(pipes("sleep 0.05; printf OUT; printf ERR >&2", 1024))
        .expect("spawn");

    let launched = provider.snapshot(process).expect("launched snapshot");
    assert_eq!(launched.record.state, ProcessState::Running);
    assert!(launched.record.exit.is_none());
    assert_eq!(
        launched.record.stream_topology,
        StreamTopology::SeparatedStdoutStderr
    );

    let exit = provider
        .wait_for_exit(process, Duration::from_secs(2))
        .expect("independently observed exit");
    assert!(exit.success);
    let finished = provider.snapshot(process).expect("finished snapshot");
    assert_eq!(finished.record.state, ProcessState::Exited);
    assert_eq!(finished.stdout.expect("stdout").bytes, b"OUT");
    assert_eq!(finished.stderr.expect("stderr").bytes, b"ERR");
}

#[cfg(unix)]
#[test]
fn pty_input_resize_and_merged_stream_limitation_are_explicit() {
    let provider = provider();
    let process = provider
        .spawn(pty(
            "printf 'READY\\n'; IFS= read -r line; printf 'GOT:%s\\n' \"$line\"",
        ))
        .expect("spawn");
    let holder = reference("identity.principal");
    let attachment = provider.attach(process, holder.clone()).expect("attach");
    let lease = provider
        .acquire_control(
            process,
            holder,
            vec![ControlScope::Input, ControlScope::Resize],
        )
        .expect("control lease");

    provider
        .resize(
            process,
            &lease,
            TerminalSize {
                rows: 40,
                cols: 120,
                pixel_width: 0,
                pixel_height: 0,
            },
        )
        .expect("resize");
    provider
        .write_input(process, &lease, b"hello\n")
        .expect("input");
    provider
        .wait_for_exit(process, Duration::from_secs(2))
        .expect("exit");

    let terminal = provider
        .read_attached(process, &attachment, StreamKind::Terminal)
        .expect("terminal stream");
    assert!(String::from_utf8_lossy(&terminal.bytes).contains("GOT:hello"));
    let record = provider.snapshot(process).expect("snapshot").record;
    assert_eq!(record.stream_topology, StreamTopology::PtyMergedTerminal);
    assert!(
        record
            .limitations
            .iter()
            .any(|value| value.contains("merged"))
    );
}

#[cfg(unix)]
#[test]
fn retained_terminal_detaches_and_reconnects_without_killing_work() {
    let provider = provider();
    let process = provider
        .spawn(pty("sleep 0.08; printf ALIVE"))
        .expect("spawn");
    let holder = reference("identity.principal");
    let first = provider
        .attach(process, holder.clone())
        .expect("first attach");
    provider.detach(process, &first).expect("detach");
    assert_eq!(
        provider.snapshot(process).expect("snapshot").record.state,
        ProcessState::Running
    );

    let second = provider.attach(process, holder).expect("reconnect");
    assert_ne!(first.attachment_ref, second.attachment_ref);
    provider
        .wait_for_exit(process, Duration::from_secs(2))
        .expect("natural exit");
    let terminal = provider
        .read_attached(process, &second, StreamKind::Terminal)
        .expect("terminal");
    assert!(String::from_utf8_lossy(&terminal.bytes).contains("ALIVE"));
}

#[cfg(unix)]
#[test]
fn policy_required_disconnect_terminates_terminal() {
    let provider = provider();
    let mut spec = pty("sleep 5");
    spec.disconnect_policy = DisconnectPolicy::Terminate;
    let process = provider.spawn(spec).expect("spawn");
    let attachment = provider
        .attach(process, reference("identity.principal"))
        .expect("attach");

    provider.detach(process, &attachment).expect("detach");
    let exit = provider
        .wait_for_exit(process, Duration::from_secs(2))
        .expect("policy termination observed");
    assert!(!exit.success);
    assert_eq!(
        provider.snapshot(process).expect("snapshot").record.state,
        ProcessState::Exited
    );
}

#[cfg(unix)]
#[test]
fn stale_attachment_and_replaced_control_lease_fail_closed() {
    let provider = provider();
    let process = provider.spawn(pty("sleep 0.15")).expect("spawn");
    let holder = reference("identity.principal");
    let attachment = provider.attach(process, holder.clone()).expect("attach");
    provider.detach(process, &attachment).expect("detach");
    assert!(matches!(
        provider.read_attached(process, &attachment, StreamKind::Terminal),
        Err(NativeProcessError::StaleAttachment)
    ));

    let first = provider
        .acquire_control(process, holder.clone(), vec![ControlScope::Input])
        .expect("first lease");
    let second = provider
        .acquire_control(process, holder, vec![ControlScope::Input])
        .expect("replacement lease");
    assert!(matches!(
        provider.write_input(process, &first, b"x"),
        Err(NativeProcessError::StaleLease)
    ));
    provider
        .write_input(process, &second, b"x")
        .expect("current lease");
    provider
        .wait_for_exit(process, Duration::from_secs(2))
        .expect("exit");
}

#[cfg(unix)]
#[test]
fn provider_generation_fences_old_terminal_control() {
    let provider = provider();
    let process = provider.spawn(pty("sleep 0.1")).expect("spawn");
    let lease = provider
        .acquire_control(
            process,
            reference("identity.principal"),
            vec![ControlScope::Input],
        )
        .expect("lease");

    assert_eq!(
        provider
            .advance_provider_generation()
            .expect("advance")
            .value(),
        3
    );
    assert!(matches!(
        provider.write_input(process, &lease, b"x"),
        Err(NativeProcessError::StaleProviderGeneration)
    ));
    provider
        .wait_for_exit(process, Duration::from_secs(2))
        .expect("exit remains observable");
}

#[cfg(unix)]
#[test]
fn several_ptys_remain_independent() {
    let provider = provider();
    let ids: Vec<_> = (0..6)
        .map(|index| {
            provider
                .spawn(pty(&format!("printf TERMINAL-{index}")))
                .expect("spawn")
        })
        .collect();

    for (index, process) in ids.into_iter().enumerate() {
        provider
            .wait_for_exit(process, Duration::from_secs(2))
            .expect("exit");
        let snapshot = provider.snapshot(process).expect("snapshot");
        let terminal = snapshot.terminal.expect("terminal");
        assert!(String::from_utf8_lossy(&terminal.bytes).contains(&format!("TERMINAL-{index}")));
    }
}

#[cfg(unix)]
#[test]
fn bounded_stream_truncation_is_visible() {
    let provider = provider();
    let process = provider
        .spawn(pipes("printf 0123456789", 4))
        .expect("spawn");
    provider
        .wait_for_exit(process, Duration::from_secs(2))
        .expect("exit");
    let stdout = provider
        .snapshot(process)
        .expect("snapshot")
        .stdout
        .expect("stdout");
    assert_eq!(stdout.bytes, b"6789");
    assert!(stdout.sequence > 0);
    assert_eq!(stdout.total_bytes, 10);
    assert_eq!(stdout.retained_bytes, 4);
    assert_eq!(stdout.truncated_bytes, 6);
}

#[cfg(unix)]
#[test]
fn pid_is_only_alias_and_a04_attempt_context_is_exactly_provider_bound() {
    let provider = provider();
    let process = provider.spawn(pipes(":", 32)).expect("spawn");
    let snapshot = provider.snapshot(process).expect("snapshot");
    let pid = snapshot.record.aliases.first().expect("PID alias");
    assert_eq!(pid.alias_type, EndpointAliasType::ProcessId);
    assert_ne!(pid.value, snapshot.record.process_ref.entity_id.to_string());

    let attempt = provider
        .attempt_context(8, reference("runtime.facility"))
        .expect("Attempt context");
    let context = provider.context().expect("Provider context");
    assert_eq!(attempt.provider_ref, context.provider_ref);
    assert_eq!(
        attempt.provider_generation,
        context.provider_generation.value()
    );
    assert_eq!(attempt.node_ref, context.node_ref);
    assert_eq!(attempt.node_generation, context.node_generation);
    assert_eq!(attempt.connection_epoch, context.connection_epoch);
    assert_eq!(attempt.producer_instance_ref, context.provider_instance_ref);

    provider
        .wait_for_exit(process, Duration::from_secs(2))
        .expect("exit");
}
