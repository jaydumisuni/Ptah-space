//! D06 provenance/SBOM/signing acceptance corpus.

use ptah_identifiers::EntityRef;
use ptah_provenance::{
    AttestationProjection, BoundMaterial, CoverageState, D06Error, DisclosureAcknowledgement,
    DiscoveryMethod, EnvelopeType, ExactSubject, MaterialOrigin, OciDescriptor,
    OciReferrerProjection, OfflinePolicy, PackageObservationProjection, SbomClaimScope,
    SbomConversion, SbomCoverage, SbomFormat, SbomProjection, SbomProjectionInput,
    SignatureProjection, SigningMethod, TransparencyEvidenceProjection, TransparencyMode,
    TransparencyPolicy, TrustMode, TrustPolicyProjection, VerificationDecision,
    verify_signature_binding,
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

#[test]
fn attestation_creation_remains_unverified() {
    let attestation = AttestationProjection {
        subjects: vec![exact_subject()],
        predicate_type: "https://slsa.dev/provenance/v1".into(),
        predicate_version: "1".into(),
        statement_artifact_ref: er("core.artifact"),
        producer_ref: er("core.principal"),
        producer_facility_revision_ref: er("core.facility_revision"),
        materials: vec![],
        products: vec![],
        envelope_type: EnvelopeType::UnsignedStatement,
    };
    assert!(!attestation.is_verified());
}

#[test]
fn declared_and_observed_attestation_materials_remain_distinct() {
    let subject = exact_subject();
    let declared = BoundMaterial {
        subject: subject.clone(),
        origin: MaterialOrigin::Declared,
    };
    let observed = BoundMaterial {
        subject,
        origin: MaterialOrigin::Observed,
    };
    assert_ne!(declared, observed);
}

#[test]
fn in_toto_dsse_projection_preserves_exact_subjects_materials_and_products() {
    let subject = exact_subject();
    let material = BoundMaterial {
        subject: exact_subject(),
        origin: MaterialOrigin::Observed,
    };
    let product = BoundMaterial {
        subject: exact_subject(),
        origin: MaterialOrigin::Observed,
    };
    let attestation = AttestationProjection {
        subjects: vec![subject.clone()],
        predicate_type: "https://in-toto.io/attestation/release/v0.1".into(),
        predicate_version: "0.1".into(),
        statement_artifact_ref: er("core.artifact"),
        producer_ref: er("core.principal"),
        producer_facility_revision_ref: er("core.facility_revision"),
        materials: vec![material.clone()],
        products: vec![product.clone()],
        envelope_type: EnvelopeType::Dsse,
    };
    assert_eq!(attestation.subjects, vec![subject]);
    assert_eq!(attestation.materials, vec![material]);
    assert_eq!(attestation.products, vec![product]);
    assert_eq!(attestation.envelope_type, EnvelopeType::Dsse);
    assert_eq!(attestation.statement_digest_sha256().unwrap().len(), 64);
}

fn trust_policy() -> TrustPolicyProjection {
    TrustPolicyProjection {
        policy_ref: er("provenance.trust_policy"),
        policy_version: "1".into(),
        trust_mode: TrustMode::ProjectKeypair,
        trusted_root_refs: vec![er("core.object_revision")],
        transparency_policy: TransparencyPolicy::Optional,
        offline_policy: OfflinePolicy::Allowed,
    }
}

fn signature() -> SignatureProjection {
    SignatureProjection {
        signature_ref: er("provenance.signature"),
        subject: exact_subject(),
        signature_artifact_ref: er("core.artifact"),
        signing_method: SigningMethod::ProjectKeypair,
        signer_identity_or_key_ref: er("core.object_revision"),
    }
}

#[test]
fn signature_creation_is_not_verification() {
    assert!(!signature().is_verified());
}

#[test]
fn valid_signature_binding_proves_digest_binding_only() {
    let signature = signature();
    let observed = signature.subject.clone();
    let result = verify_signature_binding(&signature, &observed, &trust_policy()).unwrap();
    assert_eq!(result.decision, VerificationDecision::Valid);
    assert!(!result.proves_correctness());
    assert!(!result.proves_release_acceptance());
}

#[test]
fn signature_verification_requires_exact_trust_policy() {
    let policy = trust_policy();
    let mut wrong = policy.clone();
    wrong.policy_ref = er("provenance.trust_policy");
    wrong.policy_version = "2".into();
    let signature = signature();
    let observed = signature.subject.clone();
    let result = verify_signature_binding(&signature, &observed, &wrong).unwrap();
    assert_eq!(result.trust_policy_ref, wrong.policy_ref);
    assert_eq!(result.trust_policy_version, "2");
}

#[test]
fn changed_trust_policy_creates_new_verification_history() {
    let signature = signature();
    let observed = signature.subject.clone();
    let first = verify_signature_binding(&signature, &observed, &trust_policy()).unwrap();
    let mut changed = trust_policy();
    changed.policy_ref = er("provenance.trust_policy");
    changed.policy_version = "2".into();
    changed.offline_policy = OfflinePolicy::Required;
    let second = verify_signature_binding(&signature, &observed, &changed).unwrap();
    assert_ne!(first.trust_policy_ref, second.trust_policy_ref);
    assert_ne!(first.trust_policy_version, second.trust_policy_version);
}

#[test]
fn offline_verification_needs_no_fabricated_transparency_log() {
    let evidence = TransparencyEvidenceProjection::new(
        exact_subject(),
        TransparencyMode::OfflineNoLog,
        VerificationDecision::Valid,
        vec![],
        None,
    )
    .unwrap();
    assert!(evidence.entry_refs.is_empty());
    assert_eq!(evidence.mode, TransparencyMode::OfflineNoLog);
}

#[test]
fn public_transparency_requires_identity_disclosure_acknowledgement() {
    let without_ack = TransparencyEvidenceProjection::new(
        exact_subject(),
        TransparencyMode::PublicLog,
        VerificationDecision::Valid,
        vec![er("core.object_revision")],
        None,
    );
    assert_eq!(without_ack, Err(D06Error::DisclosureRequired));

    let ack = DisclosureAcknowledgement {
        principal_ref: er("core.principal"),
        policy_ref: er("core.policy_revision"),
        acknowledged_at: "2026-09-02T20:00:00Z".into(),
    };
    assert!(
        TransparencyEvidenceProjection::new(
            exact_subject(),
            TransparencyMode::PublicLog,
            VerificationDecision::Valid,
            vec![er("core.object_revision")],
            Some(ack),
        )
        .is_ok()
    );
}

#[test]
fn transparency_negative_and_inconclusive_outcomes_remain_explicit() {
    for decision in [
        VerificationDecision::Invalid,
        VerificationDecision::Unavailable,
        VerificationDecision::Inconclusive,
    ] {
        let evidence = TransparencyEvidenceProjection::new(
            exact_subject(),
            TransparencyMode::PrivateLog,
            decision,
            vec![er("core.object_revision")],
            None,
        )
        .unwrap();
        assert_eq!(evidence.decision, decision);
    }
}

#[test]
fn oci_oras_subject_referrer_relationship_is_exact_digest_bound() {
    let subject = OciDescriptor::new(
        "application/vnd.oci.image.manifest.v1+json".into(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        123,
    )
    .unwrap();
    let referrer = OciDescriptor::new(
        "application/vnd.oci.artifact.manifest.v1+json".into(),
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        456,
    )
    .unwrap();
    let relation = OciReferrerProjection::new(
        subject.clone(),
        referrer.clone(),
        "application/spdx+json".into(),
        Some("registry.example/app:latest".into()),
        DiscoveryMethod::OciReferrersApi,
    )
    .unwrap();
    assert_eq!(relation.subject.digest, subject.digest);
    assert_eq!(relation.referrer.digest, referrer.digest);
    assert_eq!(
        OciDescriptor::new("application/json".into(), "sha256:ABCDEF".into(), 1),
        Err(D06Error::InvalidOciDescriptor)
    );
}

#[test]
fn oci_oras_referrer_discovery_does_not_imply_trust() {
    let relation = OciReferrerProjection::new(
        OciDescriptor::new(
            "application/vnd.oci.image.manifest.v1+json".into(),
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
            10,
        )
        .unwrap(),
        OciDescriptor::new(
            "application/vnd.oci.artifact.manifest.v1+json".into(),
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(),
            20,
        )
        .unwrap(),
        "application/vnd.in-toto+json".into(),
        Some("registry.example/app".into()),
        DiscoveryMethod::OrasFallback,
    )
    .unwrap();
    assert!(!relation.grants_trust());
}
