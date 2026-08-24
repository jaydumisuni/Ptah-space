//! B05 executable/application-package positive, negative and provenance acceptance corpus.

use ptah_archive_decomposition::{
    AdapterEmbeddedChild, AdapterExecutable, B05Error, EmbeddedExecutableChild, ExecutableAdapter,
    ExecutableClass, ExecutableContext, ExecutableLimits, ExecutableMetadata, ExecutableSection,
    ExecutionAssessment, SignatureObservation, SignatureStatus, StaticIsolation,
    StaticIsolationPolicy, TypeAgreement, TypeAssessment, inspect_executable,
};
use ptah_identifiers::EntityRef;
use ptah_object_store::{
    OriginClass, ProductionEvidence, Registration, RevisionRole,
};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid fixture reference")
}

fn production() -> ProductionEvidence {
    ProductionEvidence {
        activity_ref: reference("core.activity"),
        operation_ref: reference("core.operation"),
        attempt_ref: reference("core.attempt"),
        receipt_refs: vec![reference("proof.receipt")],
    }
}

fn context() -> ExecutableContext {
    ExecutableContext {
        workspace_ref: reference("core.workspace"),
        authority_ref: reference("auth.authority"),
        source_revision_ref: reference("object.revision"),
        production: production(),
    }
}

fn agreed(media_type: &str) -> TypeAssessment {
    TypeAssessment {
        declared_type: Some(media_type.to_owned()),
        detector_evidence: Vec::new(),
        agreement: TypeAgreement::Agreed(media_type.to_owned()),
        declared_matches_agreed_type: Some(true),
    }
}

fn unknown() -> TypeAssessment {
    TypeAssessment {
        declared_type: None,
        detector_evidence: Vec::new(),
        agreement: TypeAgreement::Unknown,
        declared_matches_agreed_type: None,
    }
}

fn disputed() -> TypeAssessment {
    TypeAssessment {
        declared_type: Some("application/x-elf".to_owned()),
        detector_evidence: Vec::new(),
        agreement: TypeAgreement::Disputed(vec![
            "application/x-elf".to_owned(),
            "application/x-msdownload".to_owned(),
        ]),
        declared_matches_agreed_type: Some(false),
    }
}

fn full_output() -> AdapterExecutable {
    AdapterExecutable {
        metadata: vec![ExecutableMetadata {
            key: "architecture".to_owned(),
            value: "x86_64".to_owned(),
        }],
        sections: vec![ExecutableSection {
            name: ".text".to_owned(),
            offset: 0,
            size: 4,
            flags: vec!["rx".to_owned()],
            packed_or_unknown: false,
        }],
        imports: vec!["kernel32.dll!CreateFileW".to_owned()],
        exports: vec!["fixture_export".to_owned()],
        signatures: vec![SignatureObservation {
            scheme: "authenticode".to_owned(),
            signer: Some("Fixture Signer".to_owned()),
            status: SignatureStatus::Verified,
        }],
        children: Vec::new(),
        observed_source_bytes: 0,
        complete_claim: true,
        unknown_regions: Vec::new(),
        warnings: Vec::new(),
        limitations: Vec::new(),
    }
}

fn registration_for(child: &EmbeddedExecutableChild) -> Registration {
    Registration {
        content_ref: reference("object.content"),
        object_ref: reference("object.object"),
        revision_ref: reference("object.revision"),
        location_ref: reference("storage.location"),
        sha256: child.sha256.clone(),
        byte_size: u64::try_from(child.bytes.len()).expect("fixture byte size"),
        cas_object_key: format!("sha256/{}", child.sha256),
        content_deduplicated: false,
    }
}

#[derive(Debug, Clone)]
struct FixtureAdapter {
    id: &'static str,
    media_type: &'static str,
    output: AdapterExecutable,
    observed_override: Option<u64>,
    isolation: StaticIsolation,
}

impl FixtureAdapter {
    fn passive(media_type: &'static str, output: AdapterExecutable) -> Self {
        Self {
            id: "b05.fixture.passive",
            media_type,
            output,
            observed_override: None,
            isolation: StaticIsolation::passive(),
        }
    }
}

impl ExecutableAdapter for FixtureAdapter {
    fn adapter_id(&self) -> &str {
        self.id
    }

    fn supports_media_type(&self, media_type: &str) -> bool {
        media_type == self.media_type
    }

    fn isolation(&self) -> StaticIsolation {
        self.isolation
    }

    fn inspect(
        &self,
        source_bytes: &[u8],
        _media_type: &str,
        _limits: ExecutableLimits,
    ) -> Result<AdapterExecutable, String> {
        let mut output = self.output.clone();
        output.observed_source_bytes = self.observed_override.unwrap_or_else(|| {
            u64::try_from(source_bytes.len()).expect("fixture source byte size")
        });
        Ok(output)
    }
}

#[test]
fn pe_static_inspection_retains_views_without_execution_claim() {
    let source = b"MZfixture".to_vec();
    let before = source.clone();
    let source_context = context();
    let adapter = FixtureAdapter::passive("application/x-msdownload", full_output());
    let report = inspect_executable(
        &source,
        &agreed("application/x-msdownload"),
        &source_context,
        ExecutableLimits::default(),
        &[&adapter],
    )
    .expect("PE static inspection");

    assert_eq!(source, before);
    assert_eq!(report.executable_class, Some(ExecutableClass::Pe));
    assert_eq!(
        report.execution_assessment,
        ExecutionAssessment::NotExecuted
    );
    assert!(report.coverage.complete_claim);
    let views = report.view_specs(&source_context);
    assert!(
        views
            .iter()
            .any(|view| view.view_kind == "executable.imports")
    );
    assert!(
        views
            .iter()
            .any(|view| view.view_kind == "executable.exports")
    );
    assert!(
        views
            .iter()
            .any(|view| view.view_kind == "executable.sections")
    );
    assert!(
        views
            .iter()
            .any(|view| view.view_kind == "executable.signatures")
    );
    assert!(
        views
            .iter()
            .any(|view| view.view_kind == "executable.coverage")
    );
}

#[test]
fn elf_and_macho_are_selected_from_b02_agreed_type_truth() {
    for (media_type, expected) in [
        ("application/x-elf", ExecutableClass::Elf),
        ("application/x-mach-o", ExecutableClass::MachO),
    ] {
        let adapter = FixtureAdapter::passive(media_type, full_output());
        let report = inspect_executable(
            b"12345678",
            &agreed(media_type),
            &context(),
            ExecutableLimits::default(),
            &[&adapter],
        )
        .expect("static binary inspection");
        assert_eq!(report.executable_class, Some(expected));
    }
}

#[test]
fn unknown_and_disputed_types_fail_open_only_as_explicit_partial_reports() {
    for assessment in [unknown(), disputed()] {
        let report = inspect_executable(
            b"unknown",
            &assessment,
            &context(),
            ExecutableLimits::default(),
            &[],
        )
        .expect("partial report");
        assert!(report.adapter_id.is_none());
        assert!(!report.coverage.complete_claim);
        assert!(!report.coverage.unknown_regions.is_empty());
        assert_eq!(
            report.execution_assessment,
            ExecutionAssessment::NotExecuted
        );
        assert_eq!(report.view_specs(&context()).len(), 1);
    }
}

#[test]
fn unsupported_agreed_type_and_missing_provider_keep_coverage_explicit() {
    let unsupported = inspect_executable(
        b"text",
        &agreed("text/plain"),
        &context(),
        ExecutableLimits::default(),
        &[],
    )
    .expect("unsupported partial report");
    assert!(!unsupported.coverage.unknown_regions.is_empty());
    assert_eq!(
        unsupported.view_specs(&context())[0].view_kind,
        "executable.coverage"
    );

    let missing = inspect_executable(
        b"dex\n035\0",
        &agreed("application/vnd.android.dex"),
        &context(),
        ExecutableLimits::default(),
        &[],
    )
    .expect("missing provider partial report");
    assert_eq!(missing.executable_class, Some(ExecutableClass::Dex));
    assert!(!missing.coverage.unknown_regions.is_empty());
}

#[test]
fn duplicate_and_unsafe_providers_fail_closed() {
    let first = FixtureAdapter::passive("application/x-elf", full_output());
    let mut second = first.clone();
    second.id = "b05.fixture.second";
    assert!(matches!(
        inspect_executable(
            b"12345678",
            &agreed("application/x-elf"),
            &context(),
            ExecutableLimits::default(),
            &[&first, &second],
        ),
        Err(B05Error::AmbiguousAdapter(_))
    ));

    let mut unsafe_adapter = first;
    unsafe_adapter.isolation = StaticIsolation {
        code_execution: StaticIsolationPolicy::Allowed,
        network_access: StaticIsolationPolicy::Denied,
        external_resource_loading: StaticIsolationPolicy::Denied,
    };
    assert!(matches!(
        inspect_executable(
            b"12345678",
            &agreed("application/x-elf"),
            &context(),
            ExecutableLimits::default(),
            &[&unsafe_adapter],
        ),
        Err(B05Error::UnsafeAdapterIsolation(_))
    ));
}

#[test]
fn source_extent_and_section_overclaim_fail_closed() {
    let mut output = full_output();
    output.sections[0].offset = 7;
    output.sections[0].size = 2;
    let adapter = FixtureAdapter::passive("application/x-elf", output);
    assert_eq!(
        inspect_executable(
            b"12345678",
            &agreed("application/x-elf"),
            &context(),
            ExecutableLimits::default(),
            &[&adapter],
        ),
        Err(B05Error::InvalidSectionExtent)
    );

    let mut adapter = FixtureAdapter::passive("application/x-elf", full_output());
    adapter.observed_override = Some(9);
    assert_eq!(
        inspect_executable(
            b"12345678",
            &agreed("application/x-elf"),
            &context(),
            ExecutableLimits::default(),
            &[&adapter],
        ),
        Err(B05Error::InvalidObservedSourceBytes)
    );
}

#[test]
fn packed_or_unknown_section_prevents_complete_static_coverage() {
    let mut output = full_output();
    output.sections[0].name = "UPX0".to_owned();
    output.sections[0].packed_or_unknown = true;
    let adapter = FixtureAdapter::passive("application/x-msdownload", output);
    let report = inspect_executable(
        b"MZfixture",
        &agreed("application/x-msdownload"),
        &context(),
        ExecutableLimits::default(),
        &[&adapter],
    )
    .expect("packed report");
    assert!(!report.coverage.complete_claim);
    assert!(
        report
            .coverage
            .unknown_regions
            .iter()
            .any(|gap| gap.contains("UPX0"))
    );
}

#[test]
fn apk_children_become_recovered_revisions_with_frozen_parent_provenance() {
    let source_context = context();
    let mut output = full_output();
    output.children = vec![
        AdapterEmbeddedChild {
            logical_path: "classes.dex".to_owned(),
            media_type: "application/vnd.android.dex".to_owned(),
            bytes: b"dex-child".to_vec(),
        },
        AdapterEmbeddedChild {
            logical_path: "res/raw/payload.bin".to_owned(),
            media_type: "application/octet-stream".to_owned(),
            bytes: b"payload".to_vec(),
        },
    ];
    let adapter = FixtureAdapter::passive("application/vnd.android.package-archive", output);
    let report = inspect_executable(
        b"PK-android-package",
        &agreed("application/vnd.android.package-archive"),
        &source_context,
        ExecutableLimits::default(),
        &[&adapter],
    )
    .expect("APK decomposition");

    assert_eq!(report.executable_class, Some(ExecutableClass::Apk));
    assert_eq!(report.children.len(), 2);
    let child = &report.children[0];
    let mut different_context = source_context.clone();
    different_context.source_revision_ref = reference("object.revision");
    assert_ne!(
        source_context.source_revision_ref,
        different_context.source_revision_ref
    );
    let spec = child.registration_spec(&different_context);
    assert_eq!(
        spec.source_refs,
        vec![source_context.source_revision_ref.clone()]
    );
    assert_eq!(spec.revision_role, RevisionRole::Recovered);
    assert_eq!(
        spec.origin_class,
        OriginClass::RecoveredEmbeddedSource
    );
    assert_eq!(
        spec.expected_sha256.as_deref(),
        Some(child.sha256.as_str())
    );
}

#[test]
fn embedded_child_relationship_binds_exact_registration_without_rebinding_parent() {
    let source_context = context();
    let mut output = full_output();
    output.children = vec![AdapterEmbeddedChild {
        logical_path: "base/dex/classes.dex".to_owned(),
        media_type: "application/vnd.android.dex".to_owned(),
        bytes: b"dex-child".to_vec(),
    }];
    let adapter = FixtureAdapter::passive("application/vnd.android.aab", output);
    let report = inspect_executable(
        b"PK-app-bundle",
        &agreed("application/vnd.android.aab"),
        &source_context,
        ExecutableLimits::default(),
        &[&adapter],
    )
    .expect("AAB decomposition");
    assert_eq!(report.executable_class, Some(ExecutableClass::Aab));

    let child = &report.children[0];
    let registration = registration_for(child);
    let mut different_context = source_context.clone();
    different_context.source_revision_ref = reference("object.revision");
    let relation = child
        .relationship_spec(&different_context, &registration)
        .expect("relationship plan");
    assert_eq!(
        relation.subject_refs,
        vec![source_context.source_revision_ref]
    );
    assert_eq!(
        relation.object_refs,
        vec![
            registration.object_ref.clone(),
            registration.revision_ref.clone()
        ]
    );
    assert_eq!(relation.relationship_type, "contains.embedded");
}

#[test]
fn unsafe_and_duplicate_child_paths_fail_closed() {
    for path in [
        "../classes.dex",
        "/classes.dex",
        "C:/classes.dex",
        "a\\classes.dex",
    ] {
        let mut output = full_output();
        output.children = vec![AdapterEmbeddedChild {
            logical_path: path.to_owned(),
            media_type: "application/vnd.android.dex".to_owned(),
            bytes: b"dex".to_vec(),
        }];
        let adapter = FixtureAdapter::passive("application/vnd.android.package-archive", output);
        assert_eq!(
            inspect_executable(
                b"PK-package",
                &agreed("application/vnd.android.package-archive"),
                &context(),
                ExecutableLimits::default(),
                &[&adapter],
            ),
            Err(B05Error::UnsafeChildPath)
        );
    }

    let mut overlong = full_output();
    overlong.children = vec![AdapterEmbeddedChild {
        logical_path: "a".repeat(8193),
        media_type: "application/vnd.android.dex".to_owned(),
        bytes: b"dex".to_vec(),
    }];
    let overlong_adapter =
        FixtureAdapter::passive("application/vnd.android.package-archive", overlong);
    assert_eq!(
        inspect_executable(
            b"PK-package",
            &agreed("application/vnd.android.package-archive"),
            &context(),
            ExecutableLimits::default(),
            &[&overlong_adapter],
        ),
        Err(B05Error::UnsafeChildPath)
    );

    let mut output = full_output();
    output.children = vec![
        AdapterEmbeddedChild {
            logical_path: "classes.dex".to_owned(),
            media_type: "application/vnd.android.dex".to_owned(),
            bytes: b"one".to_vec(),
        },
        AdapterEmbeddedChild {
            logical_path: "classes.dex".to_owned(),
            media_type: "application/vnd.android.dex".to_owned(),
            bytes: b"two".to_vec(),
        },
    ];
    let adapter = FixtureAdapter::passive("application/vnd.android.package-archive", output);
    assert_eq!(
        inspect_executable(
            b"PK-package",
            &agreed("application/vnd.android.package-archive"),
            &context(),
            ExecutableLimits::default(),
            &[&adapter],
        ),
        Err(B05Error::DuplicateChildPath)
    );
}

#[test]
fn child_retention_limits_preserve_partial_truth_instead_of_silent_drop() {
    let mut output = full_output();
    output.children = vec![
        AdapterEmbeddedChild {
            logical_path: "classes.dex".to_owned(),
            media_type: "application/vnd.android.dex".to_owned(),
            bytes: b"1234".to_vec(),
        },
        AdapterEmbeddedChild {
            logical_path: "classes2.dex".to_owned(),
            media_type: "application/vnd.android.dex".to_owned(),
            bytes: b"5678".to_vec(),
        },
    ];
    let adapter = FixtureAdapter::passive("application/vnd.android.package-archive", output);
    let limits = ExecutableLimits {
        max_children: 1,
        ..ExecutableLimits::default()
    };
    let report = inspect_executable(
        b"PK-package",
        &agreed("application/vnd.android.package-archive"),
        &context(),
        limits,
        &[&adapter],
    )
    .expect("bounded package decomposition");
    assert_eq!(report.children.len(), 1);
    assert!(!report.coverage.complete_claim);
    assert!(
        report
            .coverage
            .unknown_regions
            .iter()
            .any(|gap| gap.contains("max_children"))
    );
}

#[test]
fn list_retention_limits_are_explicit_coverage_gaps() {
    let mut output = full_output();
    output.imports = vec!["one".to_owned(), "two".to_owned()];
    let adapter = FixtureAdapter::passive("application/x-elf", output);
    let limits = ExecutableLimits {
        max_imports: 1,
        ..ExecutableLimits::default()
    };
    let report = inspect_executable(
        b"12345678",
        &agreed("application/x-elf"),
        &context(),
        limits,
        &[&adapter],
    )
    .expect("bounded import inspection");
    assert_eq!(report.imports, vec!["one"]);
    assert!(!report.coverage.complete_claim);
    assert!(
        report
            .coverage
            .unknown_regions
            .iter()
            .any(|gap| gap.contains("imports"))
    );
}

#[test]
fn provider_partial_source_and_explicit_unknown_regions_cannot_claim_complete() {
    let mut output = full_output();
    output.complete_claim = true;
    output.unknown_regions = vec!["encrypted overlay not inspected".to_owned()];
    let mut adapter = FixtureAdapter::passive("application/x-elf", output);
    adapter.observed_override = Some(4);
    let report = inspect_executable(
        b"12345678",
        &agreed("application/x-elf"),
        &context(),
        ExecutableLimits::default(),
        &[&adapter],
    )
    .expect("partial inspection");
    assert!(!report.coverage.complete_claim);
    assert!(report.coverage.unknown_regions.len() >= 2);
}

#[test]
fn signature_observation_is_a_static_view_not_an_execution_or_trust_grant() {
    let adapter = FixtureAdapter::passive("application/x-msdownload", full_output());
    let report = inspect_executable(
        b"MZfixture",
        &agreed("application/x-msdownload"),
        &context(),
        ExecutableLimits::default(),
        &[&adapter],
    )
    .expect("signed executable inspection");
    assert_eq!(report.signatures[0].status, SignatureStatus::Verified);
    assert_eq!(
        report.execution_assessment,
        ExecutionAssessment::NotExecuted
    );
    assert!(
        report
            .view_specs(&context())
            .iter()
            .any(|view| view.view_kind == "executable.signatures")
    );
}

#[test]
fn invalid_or_mismatched_child_registration_is_rejected() {
    let source_context = context();
    let mut output = full_output();
    output.children = vec![AdapterEmbeddedChild {
        logical_path: "classes.dex".to_owned(),
        media_type: "application/vnd.android.dex".to_owned(),
        bytes: b"dex".to_vec(),
    }];
    let adapter = FixtureAdapter::passive("application/vnd.android.package-archive", output);
    let report = inspect_executable(
        b"PK-package",
        &agreed("application/vnd.android.package-archive"),
        &source_context,
        ExecutableLimits::default(),
        &[&adapter],
    )
    .expect("package inspection");
    let child = &report.children[0];

    let mut wrong_kind = registration_for(child);
    wrong_kind.object_ref = reference("object.revision");
    assert_eq!(
        child.relationship_spec(&source_context, &wrong_kind),
        Err(B05Error::InvalidChildRegistration)
    );

    let mut wrong_digest = registration_for(child);
    wrong_digest.sha256 = "0".repeat(64);
    assert_eq!(
        child.relationship_spec(&source_context, &wrong_digest),
        Err(B05Error::ChildRegistrationMismatch)
    );

    let mut wrong_size = registration_for(child);
    wrong_size.byte_size += 1;
    assert_eq!(
        child.relationship_spec(&source_context, &wrong_size),
        Err(B05Error::ChildRegistrationMismatch)
    );
}
