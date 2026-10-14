// SPDX-FileCopyrightText: 2026 John Dumisuni trading as THETECHGUY DIGITAL SOLUTIONS
// SPDX-License-Identifier: Apache-2.0
//! Optional KRATOS physical admission proof: Ptah A05 Process Provider launches
//! pinned TTG Internet Search through a controlled PTY input lease.
//!
//! Normal CI stays source-only; physical proof sets both PTAH_TTG_SEARCH_WHEEL
//! and PTAH_TTG_SEARCH_BRIDGE to approved absolute paths. No browser touched.

#![cfg(unix)]

use native_process::{
    ControlScope, DisconnectPolicy, NativeProcessProvider, NativeProcessProviderConfig,
    ProcessMode, ProcessSpec, StreamKind, TerminalSize,
};
use ptah_identifiers::EntityRef;
use ptah_provider_api::{
    ProviderGeneration, ProviderHealth, ProviderInstance, ProviderKind, ProviderReachability,
    ProviderReadiness, ProviderRevision,
};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("fixture reference")
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
            build_or_package_digest: "sha256:ptah-search-physical-proof".to_owned(),
            configuration_digest: "sha256:ptah-search-physical-config".to_owned(),
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
            provider_generation: ProviderGeneration::new(7).expect("positive"),
            connection_epoch: 5,
            reachability: ProviderReachability::Reachable,
            readiness: ProviderReadiness::Ready,
            health: ProviderHealth::Healthy,
            endpoint_aliases: Vec::new(),
            process_or_service_refs: Vec::new(),
            observation_refs: vec![reference("proof.evidence")],
            started_at: "2026-10-15T00:00:00Z".to_owned(),
            limitations: Vec::new(),
        },
        clock: Arc::new(|| "2026-10-15T00:00:00Z".to_owned()),
    })
    .expect("A05 Provider")
}

#[test]
fn pinned_search_runs_under_real_ptah_process_provider_with_fenced_input() {
    let (Ok(wheel), Ok(bridge)) = (
        std::env::var("PTAH_TTG_SEARCH_WHEEL"),
        std::env::var("PTAH_TTG_SEARCH_BRIDGE"),
    ) else {
        // This is a physical-host acceptance check, not a CI dependency on
        // developer home paths. CI still checks the Python adapter contracts.
        return;
    };
    assert!(std::path::Path::new(&wheel).is_absolute());
    assert!(std::path::Path::new(&bridge).is_absolute());
    let native = provider();
    let process = native
        .spawn(ProcessSpec {
            program: "/usr/bin/python3".to_owned(),
            args: vec![
                "-I".into(),
                "-B".into(),
                bridge,
                "--wheel".into(),
                wheel,
                "--provider-generation".into(),
                "7".into(),
            ],
            env: BTreeMap::new(),
            clear_env: false,
            cwd: None,
            mode: ProcessMode::Pty {
                size: TerminalSize {
                    rows: 40,
                    cols: 150,
                    pixel_width: 0,
                    pixel_height: 0,
                },
            },
            max_stream_bytes: 65536,
            disconnect_policy: DisconnectPolicy::Retain,
        })
        .expect("spawn pinned read-only provider");
    let holder = reference("identity.principal");
    let attachment = native.attach(process, holder.clone()).expect("attach");
    let lease = native
        .acquire_control(process, holder, vec![ControlScope::Input])
        .expect("current input lease");
    native.write_input(process,&lease,
        br#"{"operation":"doctor","request_id":"a05-native-doctor","expected_provider_generation":7}"#)
        .expect("write JSON");
    native
        .write_input(process, &lease, b"\n")
        .expect("terminate one line");
    let exit = native
        .wait_for_exit(process, Duration::from_secs(15))
        .expect("independently observed exit");
    let out = native
        .read_attached(process, &attachment, StreamKind::Terminal)
        .expect("observed terminal");
    let body = String::from_utf8_lossy(&out.bytes);
    assert!(exit.success, "adapter failed: {body}");
    assert!(
        body.contains("ttg-internet-search"),
        "missing provider label: {body}"
    );
    assert!(
        body.contains("a05-native-doctor"),
        "missing request id: {body}"
    );
    assert!(body.contains("0.7.0a2"), "missing exact release: {body}");
    assert!(
        body.contains("payment_budget_zmw"),
        "missing zero-cost proof: {body}"
    );
    assert!(
        body.contains("completed"),
        "missing actual process reply: {body}"
    );
}
