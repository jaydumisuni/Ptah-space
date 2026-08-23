//! B01 adversarial regression for mutation of a source while upload bytes are in flight.

use ptah_transfer::{B01Error, ResumableUploadSink, UploadCursor, resumable_upload_file};
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct MutatingUploadSink {
    bytes: Vec<u8>,
    source: PathBuf,
    mutated: bool,
    finalized: bool,
}

impl ResumableUploadSink for MutatingUploadSink {
    fn accepted_len(&self) -> Result<u64, String> {
        Ok(self.bytes.len() as u64)
    }

    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), String> {
        if offset != self.bytes.len() as u64 {
            return Err(format!(
                "non-contiguous provider write: offset={offset}, accepted={}",
                self.bytes.len()
            ));
        }
        self.bytes.extend_from_slice(bytes);
        if !self.mutated {
            let mut source = fs::OpenOptions::new()
                .write(true)
                .open(&self.source)
                .map_err(|error| error.to_string())?;
            source
                .seek(SeekFrom::Start(0))
                .map_err(|error| error.to_string())?;
            source.write_all(b"Z").map_err(|error| error.to_string())?;
            source.sync_all().map_err(|error| error.to_string())?;
            self.mutated = true;
        }
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), String> {
        self.finalized = true;
        Ok(())
    }
}

#[test]
fn active_upload_detects_source_mutation_before_finalization() {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "ptah-b01-source-mutation-{}-{sequence}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create temp root");
    let source = root.join("mutable-source.bin");
    let bytes: Vec<u8> = (0..256_000)
        .map(|index| u8::try_from(index % 251).expect("modulo fits u8"))
        .collect();
    fs::write(&source, bytes).expect("write source");

    let mut sink = MutatingUploadSink {
        bytes: Vec::new(),
        source: source.clone(),
        mutated: false,
        finalized: false,
    };
    let result =
        resumable_upload_file(&source, &mut sink, UploadCursor::default(), 64 * 1024, None);

    assert!(matches!(
        result,
        Err(B01Error::SourceChangedDuringUpload { .. })
    ));
    assert!(sink.mutated);
    assert!(!sink.finalized);
    assert!(!sink.bytes.is_empty());
    let _ = fs::remove_dir_all(root);
}
