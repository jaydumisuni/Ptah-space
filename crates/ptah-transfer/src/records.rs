use crate::util::{ValidatedExecution, envelope, state_projection};
use crate::{
    AcceptedOutputRefs, DigestDomain, DigestValue, DomainResultState, TRANSFER_MANIFEST_SCHEMA_ID,
    TRANSFER_PROGRESS_SCHEMA_ID, TRANSFER_REQUEST_SCHEMA_ID, TRANSFER_RUN_SCHEMA_ID,
    TRANSFER_VERIFICATION_SCHEMA_ID, TransferConfig, TransferRequestSpec,
    TransferVerificationReport, VerificationDomain,
};
use ptah_identifiers::EntityRef;
use serde_json::{Value, json};

pub(crate) fn request_submitted_document(
    request_ref: &EntityRef,
    spec: &TransferRequestSpec,
    now: &str,
) -> Value {
    json!({
        "envelope": envelope(
            request_ref,
            TRANSFER_REQUEST_SCHEMA_ID,
            1,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
        ),
        "lifecycle": state_projection("transfer.request.lifecycle", "submitted", 1),
        "requestor_ref": spec.requestor_ref,
        "workspace_ref": spec.workspace_ref,
        "transfer_mode": spec.transfer_mode,
        "source": spec.source,
        "destination": spec.destination,
        "resumability_policy": spec.resumability_policy,
        "network_or_grant_refs": spec.network_or_grant_refs,
        "credential_refs": spec.credential_refs,
        "privacy_policy_ref": spec.privacy_policy_ref,
        "retention_policy_ref": spec.retention_policy_ref,
        "requested_verification_domains": spec.requested_verification_domains,
        "submitted_at": now,
        "limitations": [],
        "extensions": {}
    })
}

pub(crate) fn request_accepted_document(
    submitted: &Value,
    execution: &ValidatedExecution,
    now: &str,
) -> Result<Value, crate::TransferError> {
    let mut accepted = submitted.clone();
    let envelope = accepted
        .get_mut("envelope")
        .and_then(Value::as_object_mut)
        .ok_or(crate::TransferError::TypeMismatch)?;
    envelope.insert("record_revision".to_owned(), json!(2));
    envelope.insert("updated_at".to_owned(), json!(now));
    accepted["lifecycle"] = state_projection("transfer.request.lifecycle", "accepted", 2);
    accepted["accepted_activity_ref"] = serde_json::to_value(&execution.activity_ref)?;
    accepted["decision_receipt_refs"] = serde_json::to_value(&execution.receipt_refs)?;
    Ok(accepted)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn transfer_run_document(
    run_ref: &EntityRef,
    request_ref: &EntityRef,
    request: &TransferRequestSpec,
    execution: &ValidatedExecution,
    idempotency_key: &str,
    manifest_ref: &EntityRef,
    state: &str,
    revision: u64,
    now: &str,
) -> Value {
    let mut document = json!({
        "envelope": envelope(
            run_ref,
            TRANSFER_RUN_SCHEMA_ID,
            revision,
            &request.workspace_ref,
            &request.authority_ref,
            now,
        ),
        "lifecycle": state_projection("transfer.run.lifecycle", state, revision),
        "request_ref": request_ref,
        "activity_ref": execution.activity_ref,
        "operation_ref": execution.operation_ref,
        "transfer_mode": request.transfer_mode,
        "source": request.source,
        "destination": request.destination,
        "idempotency_key": idempotency_key,
        "correlation_nonce": execution.correlation_nonce,
        "attempt_refs": [execution.attempt_ref],
        "manifest_refs": [manifest_ref],
        "progress_snapshot_refs": [],
        "verification_refs": [],
        "partial_location_or_alias_refs": [],
        "receipt_refs": execution.receipt_refs,
        "created_at": now,
        "started_at": now,
        "limitations": [],
        "extensions": {}
    });
    if request
        .source
        .provider_instance_ref
        .as_ref()
        .is_some_and(|reference| crate::util::same_ref(reference, &execution.provider_instance_ref))
    {
        document["source_provider_generation"] = json!(execution.provider_generation);
    }
    if crate::util::same_ref(
        &request.destination.provider_instance_ref,
        &execution.provider_instance_ref,
    ) {
        document["destination_provider_generation"] = json!(execution.provider_generation);
    }
    document
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn manifest_document(
    manifest_ref: &EntityRef,
    run_ref: &EntityRef,
    request: &TransferRequestSpec,
    config: &TransferConfig,
    execution: &ValidatedExecution,
    idempotency_key: &str,
    compression_mode: &str,
    encryption_mode: &str,
    chunk_size: usize,
    now: &str,
) -> Value {
    let expected_size = request.source.expected_size;
    let expected_digests = request.source.expected_digests.clone();
    let credential_or_grant_refs = crate::util::unique_refs(
        request
            .network_or_grant_refs
            .iter()
            .chain(request.credential_refs.iter())
            .cloned(),
    );
    let policy_refs = crate::util::unique_refs([
        request.privacy_policy_ref.clone(),
        request.retention_policy_ref.clone(),
    ]);
    let mut manifest = json!({
        "envelope": envelope(
            manifest_ref,
            TRANSFER_MANIFEST_SCHEMA_ID,
            1,
            &request.workspace_ref,
            &request.authority_ref,
            now,
        ),
        "transfer_run_ref": run_ref,
        "source": request.source,
        "destination": request.destination,
        "expected_digests": expected_digests,
        "transport_provider_revision_refs": [config.provider_revision_ref],
        "protocol_revision": config.protocol_revision,
        "chunk_or_range_scheme": {
            "scheme": "fixed_chunks",
            "unit": "bytes",
            "nominal_size": chunk_size,
            "checksum_domain": "sha256:transport_chunk"
        },
        "compression_mode": compression_mode,
        "encryption_mode": encryption_mode,
        "idempotency_key": idempotency_key,
        "correlation_nonce": execution.correlation_nonce,
        "credential_or_grant_refs": credential_or_grant_refs,
        "policy_refs": policy_refs,
        "created_at": now,
        "limitations": [],
        "extensions": {}
    });
    if let Some(expected_size) = expected_size {
        manifest["expected_size"] = json!(expected_size);
    }
    manifest
}

#[derive(Debug, Clone)]
pub(crate) struct RangeRecord {
    pub(crate) offset: u64,
    pub(crate) length: u64,
    pub(crate) state: &'static str,
    pub(crate) digest: String,
    pub(crate) attempt_ref: EntityRef,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn progress_document(
    snapshot_ref: &EntityRef,
    run_ref: &EntityRef,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    execution: &ValidatedExecution,
    expected_size: Option<u64>,
    bytes_received: u64,
    bytes_verified: u64,
    ranges: &[RangeRecord],
    bytes_acknowledged: u64,
    event_refs: &[EntityRef],
    now: &str,
    valid_until: &str,
) -> Value {
    let range_values: Vec<Value> = ranges
        .iter()
        .map(|range| {
            json!({
                "offset": range.offset,
                "length": range.length,
                "state": range.state,
                "transport_digest": DigestValue {
                    algorithm: "sha256".to_owned(),
                    value: range.digest.clone(),
                    digest_domain: DigestDomain::TransportChunk,
                },
                "attempt_ref": range.attempt_ref,
            })
        })
        .collect();
    let mut document = json!({
        "envelope": envelope(
            snapshot_ref,
            TRANSFER_PROGRESS_SCHEMA_ID,
            1,
            workspace_ref,
            authority_ref,
            now,
        ),
        "transfer_run_ref": run_ref,
        "attempt_ref": execution.attempt_ref,
        "provider_instance_ref": execution.provider_instance_ref,
        "provider_generation": execution.provider_generation,
        "connection_epoch": execution.connection_epoch,
        "observed_at": now,
        "valid_until": valid_until,
        "bytes_expected_known": expected_size.is_some(),
        "bytes_received_unverified": bytes_received,
        "bytes_verified": bytes_verified,
        "bytes_acknowledged_by_provider": bytes_acknowledged,
        "ranges": range_values,
        "event_refs": event_refs,
        "receipt_refs": [],
        "limitations": [],
        "extensions": {}
    });
    if let Some(expected_size) = expected_size {
        document["bytes_expected"] = json!(expected_size);
    }
    document
}

#[derive(Debug, Clone)]
pub(crate) struct VerificationDomainResult {
    pub(crate) domain: VerificationDomain,
    pub(crate) result: DomainResultState,
    pub(crate) observed_size: Option<u64>,
    pub(crate) observed_digests: Vec<DigestValue>,
    pub(crate) evidence_refs: Vec<EntityRef>,
    pub(crate) limitations: Vec<String>,
}

impl VerificationDomainResult {
    fn to_value(&self) -> Value {
        let mut value = json!({
            "domain": self.domain,
            "result": self.result,
            "observed_digests": self.observed_digests,
            "evidence_refs": self.evidence_refs,
            "limitations": self.limitations,
        });
        if let Some(size) = self.observed_size {
            value["observed_size"] = json!(size);
        }
        value
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verification_document(
    verification_ref: &EntityRef,
    run_ref: &EntityRef,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    config: &TransferConfig,
    execution: &ValidatedExecution,
    state: &str,
    domain_results: &[VerificationDomainResult],
    accepted: Option<&AcceptedOutputRefs>,
    quarantine_refs: &[EntityRef],
    now: &str,
) -> Value {
    let domains: Vec<Value> = domain_results
        .iter()
        .map(VerificationDomainResult::to_value)
        .collect();
    let mut document = json!({
        "envelope": envelope(
            verification_ref,
            TRANSFER_VERIFICATION_SCHEMA_ID,
            1,
            workspace_ref,
            authority_ref,
            now,
        ),
        "transfer_run_ref": run_ref,
        "verification_state": state,
        "protocol_ref": config.protocol_ref,
        "activity_ref": execution.activity_ref,
        "operation_ref": execution.operation_ref,
        "attempt_ref": execution.attempt_ref,
        "destination_provider_instance_ref": config.provider_instance_ref,
        "destination_provider_generation": config.provider_generation,
        "domain_results": domains,
        "quarantine_or_partial_refs": quarantine_refs,
        "observed_at": now,
        "receipt_refs": execution.receipt_refs,
        "limitations": [],
        "extensions": {}
    });
    if let Some(accepted) = accepted {
        document["accepted_content_ref"] = json!(accepted.content_ref.clone());
        document["accepted_object_revision_ref"] = json!(accepted.object_revision_ref.clone());
        document["accepted_location_ref"] = json!(accepted.location_ref.clone());
    }
    document
}

pub(crate) fn report_from_verification(
    run_ref: EntityRef,
    verification_ref: EntityRef,
    verification_state: String,
    source_sha256: Option<String>,
    destination_sha256: String,
    observed_size: u64,
    materialized_path: Option<std::path::PathBuf>,
) -> TransferVerificationReport {
    TransferVerificationReport {
        run_ref,
        verification_ref,
        verification_state,
        source_sha256,
        destination_sha256,
        observed_size,
        materialized_path,
    }
}
