//! D06 provenance/SBOM/signing acceptance corpus.

use ptah_identifiers::EntityRef;
use ptah_provenance::{
    CoverageState, D06Error, ExactSubject, PackageObservationProjection, SbomClaimScope,
    SbomConversion, SbomCoverage, SbomFormat, SbomProjection, SbomProjectionInput,
};

fn er(kind: &str) -> EntityRef {
    EntityRef::new(kind).unwrap()
}

#[test]
fn exact_immutable_subject_and_digest_are_required() {
    let exact = ExactSubject {
        subject_ref: er("core.object_revision"),
        digest_refs: vec![er("core.object_revision")],
        aliases: vec!["registry.example/app:latest".into()],
    };
    assert_eq!(exact.validate(), Ok(()));

    let missing_digest = ExactSubject {
        digest_refs: vec![],
        ..exact.clone()
    };
    assert_eq!(missing_digest.validate(), Err(D06Error::InexactSubject));
}

#[test]
fn mutable_alias_cannot_become_proof_subject_identity() {
    let mutable = ExactSubject {
        subject_ref: er("knowledge.source"),
        digest_refs: vec![er("core.object_revision")],
        aliases: vec!["main".into(), "latest".into()],
    };
    assert_eq!(mutable.validate(), Err(D06Error::InexactSubject));
}

fn exact_subject() -> ExactSubject {
    ExactSubject {
        subject_ref: er("core.object_revision"),
        digest_refs: vec![er("core.object_revision")],
        aliases: vec!["app:latest".into()],
    }
}

fn complete_coverage() -> SbomCoverage {
    SbomCoverage {
        requested: vec!["rootfs".into()],
        scanned: vec!["rootfs".into()],
        skipped: vec![],
        unsupported: vec![],
        errors: vec![],
        unknown_gaps: vec![],
        state: CoverageState::Complete,
    }
}

#[test]
fn package_observation_is_not_an_sbom() {
    let observation = PackageObservationProjection {
        subject: exact_subject(),
        package_ref: er("package.package"),
        package_revision_ref: er("package.revision"),
    };
    let sbom = SbomProjection::new(SbomProjectionInput {
        subject: exact_subject(),
        generator_facility_revision_ref: er("core.facility_revision"),
        generator_provider_revision_ref: er("core.provider_revision"),
        generator_configuration_ref: er("core.configuration_revision"),
        native_report_artifact_ref: er("core.artifact"),
        format: SbomFormat::SpdxJson,
        format_version: "2.3".into(),
        package_observation_refs: vec![er("provenance.package_observation")],
        coverage_ref: er("provenance.sbom_coverage"),
    })
    .unwrap();
    assert_eq!(
        observation.package_revision_ref.entity_kind.as_str(),
        "package.revision"
    );
    assert_ne!(
        sbom.coverage_ref.entity_kind.as_str(),
        observation.package_revision_ref.entity_kind.as_str()
    );
}

#[test]
fn sbom_coverage_is_mandatory() {
    assert_eq!(
        SbomProjection::new(SbomProjectionInput {
            subject: exact_subject(),
            generator_facility_revision_ref: er("core.facility_revision"),
            generator_provider_revision_ref: er("core.provider_revision"),
            generator_configuration_ref: er("core.configuration_revision"),
            native_report_artifact_ref: er("core.artifact"),
            format: SbomFormat::SyftJson,
            format_version: "1".into(),
            package_observation_refs: vec![],
            coverage_ref: er("provenance.sbom"),
        }),
        Err(D06Error::InvalidCoverage)
    );
}

#[test]
fn partial_coverage_cannot_claim_complete() {
    let mut coverage = complete_coverage();
    coverage.state = CoverageState::Partial;
    assert!(!coverage.claims_complete());
}

#[test]
fn skipped_unsupported_error_and_unknown_scope_remain_visible() {
    let coverage = SbomCoverage {
        requested: vec!["rootfs".into(), "vendor".into()],
        scanned: vec!["rootfs".into()],
        skipped: vec!["dev".into()],
        unsupported: vec!["vendor".into()],
        errors: vec!["pkgdb: unreadable".into()],
        unknown_gaps: vec!["overlay".into()],
        state: CoverageState::Partial,
    };
    assert!(!coverage.claims_complete());
    assert_eq!(coverage.gap_count(), 4);
}

#[test]
fn sbom_format_conversion_can_retain_information_loss() {
    let conversion = SbomConversion {
        from: SbomFormat::CycloneDxJson,
        to: SbomFormat::SpdxJson,
        information_loss: vec!["cyclonedx.formulation".into()],
    };
    assert!(!conversion.is_lossless());
}

#[test]
fn sbom_inventory_does_not_prove_vulnerability_state() {
    assert!(!SbomClaimScope::InventoryOnly.proves_vulnerability_state());
}

#[test]
fn sbom_inventory_does_not_prove_licence_or_release_acceptance() {
    assert!(!SbomClaimScope::InventoryOnly.proves_licence_acceptance());
    assert!(!SbomClaimScope::InventoryOnly.proves_release_acceptance());
}

#[test]
fn changed_generator_or_configuration_creates_distinct_sbom_evidence() {
    let a = SbomProjection::new(SbomProjectionInput {
        subject: exact_subject(),
        generator_facility_revision_ref: er("core.facility_revision"),
        generator_provider_revision_ref: er("core.provider_revision"),
        generator_configuration_ref: er("core.configuration_revision"),
        native_report_artifact_ref: er("core.artifact"),
        format: SbomFormat::SpdxJson,
        format_version: "2.3".into(),
        package_observation_refs: vec![],
        coverage_ref: er("provenance.sbom_coverage"),
    })
    .unwrap();
    let mut b = a.clone();
    b.generator_provider_revision_ref = er("core.provider_revision");
    b.generator_configuration_ref = er("core.configuration_revision");
    assert_ne!(a, b);
}
