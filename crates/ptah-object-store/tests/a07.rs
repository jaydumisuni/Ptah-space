//! A07 durable Object/Revision/Artifact graph and local CAS integration acceptance suite.

use ptah_activity_runtime::{
    ActivityRuntime, ActivitySpec, AttemptContext, IdempotencyClass, LedgerJournal, OperationSpec,
    RetryClass, SideEffectClass,
};
use ptah_identifiers::{EntityId, EntityRef};
use ptah_ledger::{EntityRecordRepository, Ledger};
use ptah_object_store::{
    ARTIFACT_SCHEMA_ID, ArtifactPromotionSpec, CONTENT_SCHEMA_ID, HASH_OBSERVATION_SCHEMA_ID,
    LOCATION_SCHEMA_ID, OBJECT_SCHEMA_ID, ObjectStore, ObjectStoreConfig, ObjectStoreError,
    OriginClass, ProductionEvidence, REVISION_SCHEMA_ID, RegisterObjectSpec, RelationshipSpec,
    RevisionRole, StoreClock, VerificationSpec, ViewSpec,
};
use ptah_receipts::{
    AuthorityClass, ProofLevel, ReceiptContext, ReceiptKind, ReceiptOutcome, ReceiptSpec,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
const NOW: &str = "2026-08-17T17:30:00Z";

struct TempRoot {
    root: PathBuf,
}

impl TempRoot {
    fn new() -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ptah-a07-object-store-test-{}-{serial}",
            process::id()
        ));
        fs::create_dir_all(&root).expect("create temp root");
        Self { root }
    }

    fn ledger(&self) -> PathBuf {
        self.root.join("ptah.sqlite3")
    }

    fn cas(&self) -> PathBuf {
        self.root.join("cas")
    }

    fn moved_cas(&self) -> PathBuf {
        self.root.join("cas-moved")
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct EvidenceBundle {
    production: ProductionEvidence,
    completion_receipt_id: EntityId,
    activity_id: EntityId,
    operation_id: EntityId,
    attempt_id: EntityId,
}

#[derive(Clone, Copy)]
enum EvidenceMode {
    Register,
    Readback,
    OutputOnly,
}

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid test reference")
}

fn fixed_clock() -> StoreClock {
    Arc::new(|| NOW.to_owned())
}

fn config() -> ObjectStoreConfig {
    ObjectStoreConfig {
        backend_ref: reference("storage.backend"),
        connection_ref: reference("storage.connection"),
        producer_ref: reference("runtime.provider_instance"),
        producer_version: "a07-test-1.0.0".to_owned(),
    }
}

fn runtime(ledger_path: &Path) -> ActivityRuntime {
    let journal = Arc::new(LedgerJournal::open(ledger_path).expect("open A04 journal"));
    ActivityRuntime::new(8, journal, fixed_clock()).expect("create A04 runtime")
}

include!("a07_activity_fixture.rs");
include!("a07_evidence_modes.rs");
include!("a07_receipt_fixture.rs");
include!("a07_support.rs");
include!("a07_registration_content.rs");
include!("a07_registration_authority.rs");
include!("a07_storage_schema.rs");
include!("a07_storage_relocation.rs");
include!("a07_storage_integrity.rs");
include!("a07_graph_relationship.rs");
include!("a07_graph_identity.rs");
include!("a07_contract_validation.rs");
