#[test]
fn interrupted_download_resumes_same_run_and_operation_with_new_attempt() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let mut engine = engine(&temp);
    let bytes = b"resumable-download-payload";
    let request = request_spec(bytes, TransferMode::Download);
    let request_ref = engine
        .create_request(request.clone())
        .expect("create Request");
    let first = create_attempt(
        &runtime,
        &request.workspace_ref,
        &request.authority_ref,
        request_ref.clone(),
    );
    let handle = engine
        .start_download(
            request_ref.entity_id,
            start_evidence(&runtime, &first),
            start_spec(),
        )
        .expect("start download");

    let split = 10usize;
    let progress = engine
        .append_download_chunk(handle.run_ref.entity_id, 0, &bytes[..split])
        .expect("append first range");
    assert_eq!(progress.bytes_received_unverified, 0);
    assert_eq!(progress.bytes_verified, split as u64);
    engine
        .pause_download(handle.run_ref.entity_id)
        .expect("pause");
    runtime
        .fail_attempt(first.attempt_id, "PTAH_TEST_INTERRUPTED")
        .expect("fail first Attempt");

    let second_context = attempt_context();
    let second_attempt_id = runtime
        .retry_operation(
            first.operation_id,
            Some(reference("policy.retry")),
            second_context.clone(),
        )
        .expect("retry same Operation");
    runtime
        .dispatch_attempt(second_attempt_id)
        .expect("dispatch retry");
    runtime
        .accept_attempt(second_attempt_id)
        .expect("accept retry");
    runtime
        .begin_attempt_execution(second_attempt_id)
        .expect("execute retry");
    let second = AttemptFixture {
        activity_id: first.activity_id,
        operation_id: first.operation_id,
        attempt_id: second_attempt_id,
        context: second_context,
        nonce: runtime
            .attempt(second_attempt_id)
            .expect("read retry")
            .expect("retry retained")
            .correlation_nonce()
            .to_owned(),
    };
    let resume_receipt = append_receipt(
        &runtime,
        &second,
        ReceiptKind::WorkDispatch,
        vec![ProofLevel::Dispatched],
    );
    let resumed = engine
        .resume_download(
            handle.run_ref.entity_id,
            ResumeSpec {
                source: request.source.clone(),
                destination: request.destination.clone(),
                evidence: evidence(&second, vec![resume_receipt]),
            },
        )
        .expect("resume");
    assert_eq!(resumed.bytes_received_unverified, 0);
    assert_eq!(resumed.bytes_verified, split as u64);
    assert_ne!(first.attempt_id, second.attempt_id);

    engine
        .append_download_chunk(handle.run_ref.entity_id, split as u64, &bytes[split..])
        .expect("append remainder");
    let run = assert_resume_manifest_bindings(
        &temp.ledger(),
        &handle.run_ref,
        &first.nonce,
        &second.nonce,
    );
    let attempts = run
        .get("attempt_refs")
        .and_then(serde_json::Value::as_array)
        .expect("attempt refs");
    assert_eq!(attempts.len(), 2);
}

#[test]
fn corrupt_partial_is_detected_before_resume() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let mut engine = engine(&temp);
    let bytes = b"partial-corruption-proof";
    let request = request_spec(bytes, TransferMode::Download);
    let request_ref = engine.create_request(request.clone()).expect("request");
    let first = create_attempt(
        &runtime,
        &request.workspace_ref,
        &request.authority_ref,
        request_ref.clone(),
    );
    let handle = engine
        .start_download(
            request_ref.entity_id,
            start_evidence(&runtime, &first),
            start_spec(),
        )
        .expect("start");
    engine
        .append_download_chunk(handle.run_ref.entity_id, 0, &bytes[..8])
        .expect("chunk");
    engine
        .pause_download(handle.run_ref.entity_id)
        .expect("pause");
    fs::write(&handle.partial_path, b"corrupt!").expect("corrupt partial");
    runtime
        .fail_attempt(first.attempt_id, "PTAH_TEST_INTERRUPTED")
        .expect("fail");
    let retry_context = attempt_context();
    let retry_id = runtime
        .retry_operation(
            first.operation_id,
            Some(reference("policy.retry")),
            retry_context.clone(),
        )
        .expect("retry");
    runtime.dispatch_attempt(retry_id).expect("dispatch");
    runtime.accept_attempt(retry_id).expect("accept");
    runtime.begin_attempt_execution(retry_id).expect("execute");
    let retry = AttemptFixture {
        activity_id: first.activity_id,
        operation_id: first.operation_id,
        attempt_id: retry_id,
        context: retry_context,
        nonce: runtime
            .attempt(retry_id)
            .expect("read")
            .expect("retained")
            .correlation_nonce()
            .to_owned(),
    };
    let dispatch = append_receipt(
        &runtime,
        &retry,
        ReceiptKind::WorkDispatch,
        vec![ProofLevel::Dispatched],
    );
    assert!(matches!(
        engine.resume_download(
            handle.run_ref.entity_id,
            ResumeSpec {
                source: request.source,
                destination: request.destination,
                evidence: evidence(&retry, vec![dispatch]),
            },
        ),
        Err(TransferError::PartialStateCorrupt)
    ));
}

#[test]
fn source_and_provider_drift_invalidate_resume() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let mut engine = engine(&temp);
    let bytes = b"resume-drift-proof";
    let request = request_spec(bytes, TransferMode::Download);
    let request_ref = engine.create_request(request.clone()).expect("request");
    let first = create_attempt(
        &runtime,
        &request.workspace_ref,
        &request.authority_ref,
        request_ref.clone(),
    );
    let handle = engine
        .start_download(
            request_ref.entity_id,
            start_evidence(&runtime, &first),
            start_spec(),
        )
        .expect("start");
    engine
        .append_download_chunk(handle.run_ref.entity_id, 0, &bytes[..6])
        .expect("chunk");
    engine
        .pause_download(handle.run_ref.entity_id)
        .expect("pause");
    runtime
        .fail_attempt(first.attempt_id, "PTAH_TEST_INTERRUPTED")
        .expect("fail");
    let retry_context = attempt_context();
    let retry_id = runtime
        .retry_operation(
            first.operation_id,
            Some(reference("policy.retry")),
            retry_context.clone(),
        )
        .expect("retry");
    runtime.dispatch_attempt(retry_id).expect("dispatch");
    runtime.accept_attempt(retry_id).expect("accept");
    runtime.begin_attempt_execution(retry_id).expect("execute");
    let retry = AttemptFixture {
        activity_id: first.activity_id,
        operation_id: first.operation_id,
        attempt_id: retry_id,
        context: retry_context,
        nonce: runtime
            .attempt(retry_id)
            .expect("read")
            .expect("retained")
            .correlation_nonce()
            .to_owned(),
    };
    let dispatch = append_receipt(
        &runtime,
        &retry,
        ReceiptKind::WorkDispatch,
        vec![ProofLevel::Dispatched],
    );
    let mut drifted = request.source.clone();
    drifted.validator_observations[0].value = "source-etag-v2".to_owned();
    assert!(matches!(
        engine.resume_download(
            handle.run_ref.entity_id,
            ResumeSpec {
                source: drifted,
                destination: request.destination.clone(),
                evidence: evidence(&retry, vec![dispatch.clone()]),
            },
        ),
        Err(TransferError::ResumeMismatch)
    ));

    let mut changed = config();
    changed.provider_generation += 1;
    let mut changed_engine = TransferEngine::open(
        temp.ledger(),
        temp.staging(),
        changed,
        EventBus::new(64),
        fixed_clock(),
    )
    .expect("open changed provider engine");
    assert!(matches!(
        changed_engine.resume_download(
            handle.run_ref.entity_id,
            ResumeSpec {
                source: request.source,
                destination: request.destination,
                evidence: evidence(&retry, vec![dispatch]),
            },
        ),
        Err(TransferError::ResumeMismatch)
    ));
}

#[test]
fn provider_acknowledgement_never_completes_download() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let mut engine = engine(&temp);
    let bytes = b"ack-is-not-completion";
    let request = request_spec(bytes, TransferMode::Download);
    let request_ref = engine.create_request(request.clone()).expect("request");
    let transfer = create_attempt(
        &runtime,
        &request.workspace_ref,
        &request.authority_ref,
        request_ref.clone(),
    );
    let handle = engine
        .start_download(
            request_ref.entity_id,
            start_evidence(&runtime, &transfer),
            start_spec(),
        )
        .expect("start");
    engine
        .append_download_chunk(handle.run_ref.entity_id, 0, bytes)
        .expect("bytes");
    engine
        .acknowledge_transport(
            handle.run_ref.entity_id,
            ProviderAcknowledgement::Acknowledged,
            output_evidence(&runtime, &transfer),
        )
        .expect("acknowledge transport");
    assert_eq!(
        lifecycle_state(&temp.ledger(), handle.run_ref.entity_id),
        "verifying"
    );
    assert_ne!(
        lifecycle_state(&temp.ledger(), handle.run_ref.entity_id),
        "completed"
    );
}

#[test]
fn digest_mismatch_retains_negative_verification_and_fails_run() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let mut engine = engine(&temp);
    let bytes = b"actual-destination-bytes";
    let mut request = request_spec(bytes, TransferMode::Download);
    request.source.expected_digests = vec![DigestValue::canonical_sha256("0".repeat(64))];
    let request_ref = engine.create_request(request.clone()).expect("request");
    let transfer = create_attempt(
        &runtime,
        &request.workspace_ref,
        &request.authority_ref,
        request_ref.clone(),
    );
    let handle = engine
        .start_download(
            request_ref.entity_id,
            start_evidence(&runtime, &transfer),
            start_spec(),
        )
        .expect("start");
    engine
        .append_download_chunk(handle.run_ref.entity_id, 0, bytes)
        .expect("bytes");
    engine
        .acknowledge_transport(
            handle.run_ref.entity_id,
            ProviderAcknowledgement::Acknowledged,
            output_evidence(&runtime, &transfer),
        )
        .expect("ack");
    let verify = create_attempt(
        &runtime,
        &request.workspace_ref,
        &request.authority_ref,
        handle.run_ref.clone(),
    );
    assert!(matches!(
        engine.verify_and_materialize_download(
            handle.run_ref.entity_id,
            temp.destination(),
            Path::new("candidate.bin"),
            readback_evidence(&runtime, &verify),
        ),
        Err(TransferError::VerificationFailed)
    ));
    assert_eq!(
        lifecycle_state(&temp.ledger(), handle.run_ref.entity_id),
        "failed"
    );
    let run = ledger_document(&temp.ledger(), handle.run_ref.entity_id);
    let refs = run
        .get("verification_refs")
        .and_then(serde_json::Value::as_array)
        .expect("verification refs");
    assert_eq!(refs.len(), 1);
    let verification_ref: EntityRef =
        serde_json::from_value(refs[0].clone()).expect("verification ref");
    let verification = ledger_document(&temp.ledger(), verification_ref.entity_id);
    assert_eq!(
        verification
            .get("verification_state")
            .and_then(serde_json::Value::as_str),
        Some("failed")
    );
}

#[test]
fn traversal_and_symlink_destination_escape_are_rejected() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let mut engine = engine(&temp);
    let bytes = b"safe-destination-proof";
    let request = request_spec(bytes, TransferMode::Download);
    let request_ref = engine.create_request(request.clone()).expect("request");
    let transfer = create_attempt(
        &runtime,
        &request.workspace_ref,
        &request.authority_ref,
        request_ref.clone(),
    );
    let handle = engine
        .start_download(
            request_ref.entity_id,
            start_evidence(&runtime, &transfer),
            start_spec(),
        )
        .expect("start");
    engine
        .append_download_chunk(handle.run_ref.entity_id, 0, bytes)
        .expect("bytes");
    engine
        .acknowledge_transport(
            handle.run_ref.entity_id,
            ProviderAcknowledgement::Acknowledged,
            output_evidence(&runtime, &transfer),
        )
        .expect("ack");
    let verify = create_attempt(
        &runtime,
        &request.workspace_ref,
        &request.authority_ref,
        handle.run_ref.clone(),
    );
    let proof = readback_evidence(&runtime, &verify);
    assert!(matches!(
        engine.verify_and_materialize_download(
            handle.run_ref.entity_id,
            temp.destination(),
            Path::new("../escape.bin"),
            proof.clone(),
        ),
        Err(TransferError::UnsafeDestination)
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let root = temp.destination();
        fs::create_dir_all(&root).expect("destination root");
        let outside = temp.root.join("outside");
        fs::create_dir_all(&outside).expect("outside");
        symlink(&outside, root.join("redirect")).expect("symlink redirect");
        assert!(matches!(
            engine.verify_and_materialize_download(
                handle.run_ref.entity_id,
                &root,
                Path::new("redirect/escape.bin"),
                proof,
            ),
            Err(TransferError::UnsafeDestination)
        ));
        assert!(!outside.join("escape.bin").exists());
    }
}

#[test]
fn independent_transfer_runs_progress_without_global_transfer_lock() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let mut engine = engine(&temp);
    let a = b"independent-a";
    let b = b"independent-b";
    let request_a = request_spec(a, TransferMode::Download);
    let request_b = request_spec(b, TransferMode::Download);
    let ref_a = engine.create_request(request_a.clone()).expect("request A");
    let ref_b = engine.create_request(request_b.clone()).expect("request B");
    let attempt_a = create_attempt(
        &runtime,
        &request_a.workspace_ref,
        &request_a.authority_ref,
        ref_a.clone(),
    );
    let attempt_b = create_attempt(
        &runtime,
        &request_b.workspace_ref,
        &request_b.authority_ref,
        ref_b.clone(),
    );
    let run_a = engine
        .start_download(
            ref_a.entity_id,
            start_evidence(&runtime, &attempt_a),
            start_spec(),
        )
        .expect("run A");
    let run_b = engine
        .start_download(
            ref_b.entity_id,
            start_evidence(&runtime, &attempt_b),
            StartTransferSpec {
                idempotency_key: "a08-transfer-key-0002".to_owned(),
                ..start_spec()
            },
        )
        .expect("run B");
    let progress_a = engine
        .append_download_chunk(run_a.run_ref.entity_id, 0, &a[..5])
        .expect("A progress");
    let progress_b = engine
        .append_download_chunk(run_b.run_ref.entity_id, 0, &b[..5])
        .expect("B progress");
    assert_eq!(progress_a.bytes_verified, 5);
    assert_eq!(progress_b.bytes_verified, 5);
    assert_eq!(
        lifecycle_state(&temp.ledger(), run_a.run_ref.entity_id),
        "transferring"
    );
    assert_eq!(
        lifecycle_state(&temp.ledger(), run_b.run_ref.entity_id),
        "transferring"
    );
}

#[test]
fn active_transfer_run_does_not_block_unrelated_activity_admission() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let mut engine = engine(&temp);
    let bytes = b"unrelated-activity-proof";
    let request = request_spec(bytes, TransferMode::Download);
    let request_ref = engine.create_request(request.clone()).expect("request");
    let transfer = create_attempt(
        &runtime,
        &request.workspace_ref,
        &request.authority_ref,
        request_ref.clone(),
    );
    let handle = engine
        .start_download(
            request_ref.entity_id,
            start_evidence(&runtime, &transfer),
            start_spec(),
        )
        .expect("start transfer");
    assert_eq!(
        lifecycle_state(&temp.ledger(), handle.run_ref.entity_id),
        "transferring"
    );

    let unrelated = runtime
        .create_activity(ActivitySpec {
            request_ref: reference("core.request"),
            workspace_ref: request.workspace_ref.clone(),
            caller_ref: request.authority_ref.clone(),
            authority_ref: request.authority_ref.clone(),
            activity_kind: "unrelated.parallel_work".to_owned(),
            intent_ref: reference("core.intent"),
            priority: 0,
            max_attempts: 1,
        })
        .expect("create unrelated Activity");
    assert_eq!(
        runtime.admit_next().expect("admit unrelated Activity"),
        Some(unrelated)
    );
    assert_eq!(
        lifecycle_state(&temp.ledger(), handle.run_ref.entity_id),
        "transferring"
    );
}

#[test]
fn successful_download_retains_exact_source_and_destination_digests() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let mut engine = engine(&temp);
    let bytes = b"positive-download-verification";
    let request = request_spec(bytes, TransferMode::Download);
    let request_ref = engine.create_request(request.clone()).expect("request");
    let transfer = create_attempt(
        &runtime,
        &request.workspace_ref,
        &request.authority_ref,
        request_ref.clone(),
    );
    let handle = engine
        .start_download(
            request_ref.entity_id,
            start_evidence(&runtime, &transfer),
            start_spec(),
        )
        .expect("start");
    engine
        .append_download_chunk(handle.run_ref.entity_id, 0, bytes)
        .expect("bytes");
    engine
        .acknowledge_transport(
            handle.run_ref.entity_id,
            ProviderAcknowledgement::Acknowledged,
            output_evidence(&runtime, &transfer),
        )
        .expect("ack");
    let verify = create_attempt(
        &runtime,
        &request.workspace_ref,
        &request.authority_ref,
        handle.run_ref.clone(),
    );
    let report = engine
        .verify_and_materialize_download(
            handle.run_ref.entity_id,
            temp.destination(),
            Path::new("nested/payload.bin"),
            readback_evidence(&runtime, &verify),
        )
        .expect("verify download");
    let expected_sha = sha256(bytes);
    assert_eq!(report.verification_state, "verified");
    assert_eq!(report.source_sha256.as_deref(), Some(expected_sha.as_str()));
    assert_eq!(report.destination_sha256, expected_sha);
    assert_eq!(
        fs::read(report.materialized_path.expect("materialized path")).expect("read destination"),
        bytes
    );
    assert_eq!(
        lifecycle_state(&temp.ledger(), handle.run_ref.entity_id),
        "verifying"
    );
}
