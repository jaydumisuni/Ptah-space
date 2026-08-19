use super::{
    DigestDomain, DigestValue, DomainResultState, EntityRef, File, HashMap, OpenOptions, Path,
    RangeRecord, SourceDescriptor, SourceKind, StartTransferSpec, TransferError, TransferMode,
    TransferRequestSpec, ValidatedExecution, Value, VerificationDomain, VerificationDomainResult,
    field_ref, field_refs, same_ref, utc_shape, validate_idempotency_key, validate_storage_class,
};

pub(super) fn validate_request(spec: &TransferRequestSpec) -> Result<(), TransferError> {
    validate_source(&spec.source)?;
    validate_storage_class(&spec.destination.storage_class)?;
    if spec.requested_verification_domains.is_empty()
        || !verification_domains_unique(&spec.requested_verification_domains)
    {
        return Err(TransferError::InvalidField(
            "requested_verification_domains",
        ));
    }
    if !entity_refs_unique(&spec.network_or_grant_refs)
        || !entity_refs_unique(&spec.credential_refs)
    {
        return Err(TransferError::InvalidField("request_refs"));
    }
    Ok(())
}

pub(super) fn validate_source(source: &SourceDescriptor) -> Result<(), TransferError> {
    let expected_present = match source.source_kind {
        SourceKind::Content => source.content_ref.is_some(),
        SourceKind::ObjectRevision => source.object_revision_ref.is_some(),
        SourceKind::StorageLocation => source.location_ref.is_some(),
        SourceKind::RemoteDescriptor => source.remote_alias_ref.is_some(),
        SourceKind::Stream => source.stream_ref.is_some(),
    };
    if !expected_present {
        return Err(TransferError::InvalidField("source"));
    }
    for digest in &source.expected_digests {
        if !matches!(
            digest.algorithm.as_str(),
            "sha256" | "sha512" | "blake3" | "md5" | "provider_checksum" | "other"
        ) || !(4..=1024).contains(&digest.value.len())
            || !digest.value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'+' | b'/' | b'=' | b'_' | b':' | b'.' | b'-')
            })
        {
            return Err(TransferError::InvalidField("expected_digests"));
        }
        if digest.algorithm == "sha256"
            && (digest.value.len() != 64
                || !digest
                    .value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
        {
            return Err(TransferError::InvalidField("expected_digests"));
        }
    }
    for validator in &source.validator_observations {
        if !matches!(
            validator.validator_type.as_str(),
            "etag" | "last_modified" | "provider_version" | "content_length" | "custom"
        ) || validator.value.len() > 2048
            || validator.value.trim().is_empty()
            || !utc_shape(&validator.observed_at)
        {
            return Err(TransferError::InvalidField("validator_observations"));
        }
    }
    Ok(())
}

pub(super) fn entity_refs_unique(refs: &[EntityRef]) -> bool {
    let mut seen = std::collections::HashSet::new();
    refs.iter()
        .all(|reference| seen.insert((reference.entity_id, reference.entity_kind.clone())))
}

pub(super) fn verification_domains_unique(domains: &[VerificationDomain]) -> bool {
    let mut seen = std::collections::HashSet::new();
    domains.iter().all(|domain| seen.insert(*domain))
}

pub(super) fn validate_start_spec(spec: &StartTransferSpec) -> Result<(), TransferError> {
    validate_idempotency_key(&spec.idempotency_key)?;
    if spec.chunk_size == 0 || spec.chunk_size > 16 * 1024 * 1024 {
        return Err(TransferError::InvalidField("chunk_size"));
    }
    if !matches!(
        spec.compression_mode.as_str(),
        "none" | "source_encoded" | "transport_encoded" | "destination_encoded" | "other"
    ) {
        return Err(TransferError::InvalidField("compression_mode"));
    }
    if !matches!(
        spec.encryption_mode.as_str(),
        "none" | "transport_only" | "client_side_payload" | "provider_side" | "hybrid" | "other"
    ) {
        return Err(TransferError::InvalidField("encryption_mode"));
    }
    Ok(())
}

pub(super) fn request_spec_from_document(
    document: &Value,
) -> Result<TransferRequestSpec, TransferError> {
    let envelope = document
        .get("envelope")
        .ok_or(TransferError::TypeMismatch)?;
    Ok(TransferRequestSpec {
        requestor_ref: field_ref(document, "requestor_ref")?,
        workspace_ref: field_ref(document, "workspace_ref")?,
        authority_ref: serde_json::from_value(
            envelope
                .get("authority_ref")
                .cloned()
                .ok_or(TransferError::AuthorityMismatch)?,
        )?,
        transfer_mode: serde_json::from_value(
            document
                .get("transfer_mode")
                .cloned()
                .ok_or(TransferError::TypeMismatch)?,
        )?,
        source: serde_json::from_value(
            document
                .get("source")
                .cloned()
                .ok_or(TransferError::TypeMismatch)?,
        )?,
        destination: serde_json::from_value(
            document
                .get("destination")
                .cloned()
                .ok_or(TransferError::TypeMismatch)?,
        )?,
        resumability_policy: serde_json::from_value(
            document
                .get("resumability_policy")
                .cloned()
                .ok_or(TransferError::TypeMismatch)?,
        )?,
        network_or_grant_refs: field_refs(document, "network_or_grant_refs")?,
        credential_refs: field_refs(document, "credential_refs")?,
        privacy_policy_ref: field_ref(document, "privacy_policy_ref")?,
        retention_policy_ref: field_ref(document, "retention_policy_ref")?,
        requested_verification_domains: serde_json::from_value(
            document
                .get("requested_verification_domains")
                .cloned()
                .ok_or(TransferError::TypeMismatch)?,
        )?,
    })
}

pub(super) fn scope_from_document(
    document: &Value,
) -> Result<(EntityRef, EntityRef), TransferError> {
    let envelope = document
        .get("envelope")
        .ok_or(TransferError::TypeMismatch)?;
    let workspace_ref: EntityRef = serde_json::from_value(
        envelope
            .get("workspace_ref")
            .cloned()
            .ok_or(TransferError::WorkspaceMismatch)?,
    )?;
    let authority_ref: EntityRef = serde_json::from_value(
        envelope
            .get("authority_ref")
            .cloned()
            .ok_or(TransferError::AuthorityMismatch)?,
    )?;
    Ok((workspace_ref, authority_ref))
}

pub(super) fn ensure_request_state(
    document: &Value,
    allowed: &[&str],
) -> Result<(), TransferError> {
    let state = document
        .get("lifecycle")
        .and_then(|value| value.get("current_state"))
        .and_then(Value::as_str)
        .ok_or(TransferError::TypeMismatch)?;
    if !allowed.contains(&state) {
        return Err(TransferError::InvalidTransition);
    }
    Ok(())
}

pub(super) fn ensure_run_state(document: &Value, allowed: &[&str]) -> Result<(), TransferError> {
    ensure_request_state(document, allowed)
}

pub(super) fn ensure_mode(document: &Value, expected: TransferMode) -> Result<(), TransferError> {
    let mode: TransferMode = serde_json::from_value(
        document
            .get("transfer_mode")
            .cloned()
            .ok_or(TransferError::TypeMismatch)?,
    )?;
    if mode != expected {
        return Err(TransferError::TypeMismatch);
    }
    Ok(())
}

pub(super) fn is_current_attempt(run: &Value, attempt: &EntityRef) -> Result<bool, TransferError> {
    Ok(field_refs(run, "attempt_refs")?
        .last()
        .is_some_and(|current| same_ref(current, attempt)))
}

pub(super) fn manifest_provider_matches(
    manifest: &Value,
    provider_revision: &EntityRef,
) -> Result<bool, TransferError> {
    Ok(field_refs(manifest, "transport_provider_revision_refs")?
        .iter()
        .any(|reference| same_ref(reference, provider_revision)))
}

pub(super) fn manifest_matches_request(
    manifest: &Value,
    request: &TransferRequestSpec,
) -> Result<bool, TransferError> {
    let manifest_source: SourceDescriptor = serde_json::from_value(
        manifest
            .get("source")
            .cloned()
            .ok_or(TransferError::TypeMismatch)?,
    )?;
    let manifest_destination: crate::DestinationDescriptor = serde_json::from_value(
        manifest
            .get("destination")
            .cloned()
            .ok_or(TransferError::TypeMismatch)?,
    )?;
    let expected_credentials = crate::util::unique_refs(
        request
            .network_or_grant_refs
            .iter()
            .chain(request.credential_refs.iter())
            .cloned(),
    );
    let expected_policies = crate::util::unique_refs([
        request.privacy_policy_ref.clone(),
        request.retention_policy_ref.clone(),
    ]);
    Ok(manifest_source == request.source
        && manifest_destination == request.destination
        && field_refs(manifest, "credential_or_grant_refs")? == expected_credentials
        && field_refs(manifest, "policy_refs")? == expected_policies)
}

pub(super) fn start_spec_from_manifest(
    manifest: &Value,
) -> Result<StartTransferSpec, TransferError> {
    let nominal_size = manifest
        .get("chunk_or_range_scheme")
        .and_then(|value| value.get("nominal_size"))
        .and_then(Value::as_u64)
        .ok_or(TransferError::TypeMismatch)?;
    Ok(StartTransferSpec {
        idempotency_key: manifest
            .get("idempotency_key")
            .and_then(Value::as_str)
            .ok_or(TransferError::TypeMismatch)?
            .to_owned(),
        compression_mode: manifest
            .get("compression_mode")
            .and_then(Value::as_str)
            .ok_or(TransferError::TypeMismatch)?
            .to_owned(),
        encryption_mode: manifest
            .get("encryption_mode")
            .and_then(Value::as_str)
            .ok_or(TransferError::TypeMismatch)?
            .to_owned(),
        chunk_size: usize::try_from(nominal_size).map_err(|_| TransferError::AccountingOverflow)?,
    })
}

pub(super) fn range_from_value(value: &Value) -> Result<RangeRecord, TransferError> {
    let state = value
        .get("state")
        .and_then(Value::as_str)
        .ok_or(TransferError::TypeMismatch)?;
    let state = match state {
        "verified" => "verified",
        "received_unverified" => "received_unverified",
        "planned" => "planned",
        "requested" => "requested",
        "failed" => "failed",
        "invalidated" => "invalidated",
        _ => return Err(TransferError::TypeMismatch),
    };
    let digest = value
        .get("transport_digest")
        .and_then(|digest| digest.get("value"))
        .and_then(Value::as_str)
        .ok_or(TransferError::TypeMismatch)?
        .to_owned();
    Ok(RangeRecord {
        offset: value
            .get("offset")
            .and_then(Value::as_u64)
            .ok_or(TransferError::TypeMismatch)?,
        length: value
            .get("length")
            .and_then(Value::as_u64)
            .ok_or(TransferError::TypeMismatch)?,
        state,
        digest,
        attempt_ref: serde_json::from_value(
            value
                .get("attempt_ref")
                .cloned()
                .ok_or(TransferError::TypeMismatch)?,
        )?,
    })
}

pub(super) fn expected_canonical_sha256(
    source: &SourceDescriptor,
) -> Result<Option<String>, TransferError> {
    let values: Vec<_> = source
        .expected_digests
        .iter()
        .filter(|digest| {
            digest.algorithm == "sha256" && digest.digest_domain == DigestDomain::CanonicalContent
        })
        .map(|digest| digest.value.clone())
        .collect();
    match values.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(value.clone())),
        _ => Err(TransferError::InvalidField("expected_digests")),
    }
}

#[allow(clippy::needless_pass_by_value)]
pub(super) fn verified_transfer_domains(
    request: &TransferRequestSpec,
    execution: &ValidatedExecution,
    expected_sha: Option<String>,
    destination_sha: &str,
    observed_size: u64,
    transport_completed: bool,
) -> Vec<VerificationDomainResult> {
    let evidence = execution.receipt_refs.clone();
    let size_state = request
        .source
        .expected_size
        .map_or(DomainResultState::NotPerformed, |size| {
            if size == observed_size {
                DomainResultState::Passed
            } else {
                DomainResultState::Failed
            }
        });
    let digest_state =
        expected_sha
            .as_deref()
            .map_or(DomainResultState::NotPerformed, |expected| {
                if expected == destination_sha {
                    DomainResultState::Passed
                } else {
                    DomainResultState::Failed
                }
            });
    vec![
        domain_result(
            VerificationDomain::TransportCompleted,
            if transport_completed {
                DomainResultState::Passed
            } else {
                DomainResultState::Unknown
            },
            Some(observed_size),
            Vec::new(),
            evidence.clone(),
        ),
        domain_result(
            VerificationDomain::ByteCountMatched,
            size_state,
            Some(observed_size),
            Vec::new(),
            evidence.clone(),
        ),
        domain_result(
            VerificationDomain::TransportChecksumsMatched,
            DomainResultState::Passed,
            Some(observed_size),
            Vec::new(),
            evidence.clone(),
        ),
        domain_result(
            VerificationDomain::ContentDigestMatched,
            digest_state,
            Some(observed_size),
            vec![DigestValue::canonical_sha256(destination_sha)],
            evidence.clone(),
        ),
        domain_result(
            VerificationDomain::DestinationReadbackMatched,
            digest_state,
            Some(observed_size),
            vec![DigestValue::canonical_sha256(destination_sha)],
            evidence,
        ),
    ]
}

pub(super) fn failed_transfer_domains(
    request: &TransferRequestSpec,
    execution: &ValidatedExecution,
    expected_sha: Option<String>,
    observed_sha: &str,
    observed_size: u64,
) -> Vec<VerificationDomainResult> {
    let mut domains = verified_transfer_domains(
        request,
        execution,
        expected_sha,
        observed_sha,
        observed_size,
        true,
    );
    for result in &mut domains {
        if matches!(
            result.domain,
            VerificationDomain::ByteCountMatched
                | VerificationDomain::ContentDigestMatched
                | VerificationDomain::DestinationReadbackMatched
        ) && result.result == DomainResultState::NotPerformed
        {
            result.result = DomainResultState::Unknown;
        }
    }
    domains
}

#[allow(clippy::needless_pass_by_value)]
pub(super) fn upload_source_failure_domains(
    request: &TransferRequestSpec,
    execution: &ValidatedExecution,
    expected_sha: Option<String>,
    observed_sha: &str,
    observed_size: u64,
) -> Vec<VerificationDomainResult> {
    let evidence = execution.receipt_refs.clone();
    let size_state = request
        .source
        .expected_size
        .map_or(DomainResultState::NotPerformed, |size| {
            if size == observed_size {
                DomainResultState::Passed
            } else {
                DomainResultState::Failed
            }
        });
    let digest_state =
        expected_sha
            .as_deref()
            .map_or(DomainResultState::NotPerformed, |expected| {
                if expected == observed_sha {
                    DomainResultState::Passed
                } else {
                    DomainResultState::Failed
                }
            });
    vec![
        domain_result(
            VerificationDomain::TransportCompleted,
            DomainResultState::NotPerformed,
            Some(observed_size),
            Vec::new(),
            evidence.clone(),
        ),
        domain_result(
            VerificationDomain::ByteCountMatched,
            size_state,
            Some(observed_size),
            Vec::new(),
            evidence.clone(),
        ),
        domain_result(
            VerificationDomain::ContentDigestMatched,
            digest_state,
            Some(observed_size),
            vec![DigestValue::canonical_sha256(observed_sha)],
            evidence.clone(),
        ),
        domain_result(
            VerificationDomain::DestinationReadbackMatched,
            DomainResultState::NotPerformed,
            None,
            Vec::new(),
            evidence,
        ),
    ]
}

pub(super) fn upload_verification_domains(
    execution: &ValidatedExecution,
    source_sha: &str,
    destination_sha: &str,
    observed_size: u64,
    passed: bool,
) -> Vec<VerificationDomainResult> {
    let state = if passed {
        DomainResultState::Passed
    } else {
        DomainResultState::Failed
    };
    let evidence = execution.receipt_refs.clone();
    vec![
        domain_result(
            VerificationDomain::TransportCompleted,
            DomainResultState::Passed,
            Some(observed_size),
            Vec::new(),
            evidence.clone(),
        ),
        domain_result(
            VerificationDomain::ByteCountMatched,
            state,
            Some(observed_size),
            Vec::new(),
            evidence.clone(),
        ),
        domain_result(
            VerificationDomain::ContentDigestMatched,
            state,
            Some(observed_size),
            vec![DigestValue::canonical_sha256(source_sha)],
            evidence.clone(),
        ),
        domain_result(
            VerificationDomain::DestinationReadbackMatched,
            state,
            Some(observed_size),
            vec![DigestValue::canonical_sha256(destination_sha)],
            evidence,
        ),
    ]
}

pub(super) fn domain_result(
    domain: VerificationDomain,
    result: DomainResultState,
    observed_size: Option<u64>,
    observed_digests: Vec<DigestValue>,
    evidence_refs: Vec<EntityRef>,
) -> VerificationDomainResult {
    VerificationDomainResult {
        domain,
        result,
        observed_size,
        observed_digests,
        evidence_refs,
        limitations: Vec::new(),
    }
}

pub(super) fn verification_state_for_request(
    request: &TransferRequestSpec,
    domains: &[VerificationDomainResult],
) -> &'static str {
    if domains
        .iter()
        .any(|result| result.result == DomainResultState::Failed)
    {
        return "failed";
    }
    let states: HashMap<VerificationDomain, DomainResultState> = domains
        .iter()
        .map(|result| (result.domain, result.result))
        .collect();
    if request
        .requested_verification_domains
        .iter()
        .all(|domain| states.get(domain) == Some(&DomainResultState::Passed))
    {
        "verified"
    } else {
        "partial"
    }
}

pub(super) fn copy_synced(source: &Path, destination: &Path) -> Result<(), TransferError> {
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

pub(super) fn sync_directory(path: &Path) -> Result<(), TransferError> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
