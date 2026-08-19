#[test]
fn upload_keeps_source_hash_ack_and_destination_readback_separate() {
    let temp = TempRoot::new();
    fs::create_dir_all(temp.source_root()).expect("source root");
    let bytes = b"upload-separation-proof";
    fs::write(temp.source_root().join("payload.bin"), bytes).expect("write source");
    let runtime = runtime(&temp.ledger());
    let mut engine = engine(&temp);
    let request = request_spec(bytes, TransferMode::Upload);
    let request_ref = engine.create_request(request.clone()).expect("request");
    let transfer = create_attempt(
        &runtime,
        &request.workspace_ref,
        &request.authority_ref,
        request_ref.clone(),
    );
    let handle = engine
        .start_upload(
            request_ref.entity_id,
            start_evidence(&runtime, &transfer),
            start_spec(),
        )
        .expect("start");
    let mut sink = MemorySink::default();
    let observed = engine
        .stream_upload_file(
            handle.run_ref.entity_id,
            temp.source_root(),
            Path::new("payload.bin"),
            &mut sink,
            5,
        )
        .expect("stream upload");
    assert_eq!(observed.source_sha256, sha256(bytes));
    assert_eq!(observed.source_size, bytes.len() as u64);
    engine
        .verify_upload_source(
            handle.run_ref.entity_id,
            &observed,
            hash_evidence(&runtime, &transfer),
        )
        .expect("verify source before finalize");
    let ack = engine
        .finalize_upload_transport(handle.run_ref.entity_id, &mut sink)
        .expect("finalize provider");
    assert_eq!(ack, ProviderAcknowledgement::Acknowledged);
    assert_eq!(
        lifecycle_state(&temp.ledger(), handle.run_ref.entity_id),
        "transferring"
    );
    engine
        .acknowledge_transport(
            handle.run_ref.entity_id,
            ack,
            output_evidence(&runtime, &transfer),
        )
        .expect("retain acknowledgement");
    assert_eq!(
        lifecycle_state(&temp.ledger(), handle.run_ref.entity_id),
        "verifying"
    );

    let verify = create_attempt(
        &runtime,
        &request.workspace_ref,
        &request.authority_ref,
        handle.run_ref.clone(),
    );
    let report = engine
        .verify_upload_sink(
            handle.run_ref.entity_id,
            &mut sink,
            readback_evidence(&runtime, &verify),
            4,
        )
        .expect("read back upload");
    let expected_sha = sha256(bytes);
    assert_eq!(report.source_sha256.as_deref(), Some(expected_sha.as_str()));
    assert_eq!(report.destination_sha256, expected_sha);
    assert_eq!(report.observed_size, bytes.len() as u64);
    assert_eq!(
        lifecycle_state(&temp.ledger(), handle.run_ref.entity_id),
        "verifying"
    );
}

#[test]
fn upload_source_mismatch_is_retained_before_provider_finalize() {
    let temp = TempRoot::new();
    fs::create_dir_all(temp.source_root()).expect("source root");
    let bytes = b"upload-source-mismatch";
    fs::write(temp.source_root().join("payload.bin"), bytes).expect("write source");
    let runtime = runtime(&temp.ledger());
    let mut engine = engine(&temp);
    let mut request = request_spec(bytes, TransferMode::Upload);
    request.source.expected_digests = vec![DigestValue::canonical_sha256("f".repeat(64))];
    let request_ref = engine.create_request(request.clone()).expect("request");
    let transfer = create_attempt(
        &runtime,
        &request.workspace_ref,
        &request.authority_ref,
        request_ref.clone(),
    );
    let handle = engine
        .start_upload(
            request_ref.entity_id,
            start_evidence(&runtime, &transfer),
            start_spec(),
        )
        .expect("start");
    let mut sink = MemorySink::default();
    let observed = engine
        .stream_upload_file(
            handle.run_ref.entity_id,
            temp.source_root(),
            Path::new("payload.bin"),
            &mut sink,
            6,
        )
        .expect("stream source");
    assert!(matches!(
        engine.verify_upload_source(
            handle.run_ref.entity_id,
            &observed,
            hash_evidence(&runtime, &transfer),
        ),
        Err(TransferError::VerificationFailed)
    ));
    assert_eq!(
        lifecycle_state(&temp.ledger(), handle.run_ref.entity_id),
        "failed"
    );
    assert_eq!(sink.bytes, bytes);
}
