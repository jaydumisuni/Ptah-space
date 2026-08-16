#![forbid(unsafe_code)]
//! Repository-owned Ptah metadata ledger.
//!
//! A03 persists canonical Ptah records behind a backend-neutral repository
//! boundary. `SQLite` is an implementation detail: canonical identity remains the
//! Ptah `UUIDv7` entity identity and `SQLite` row identifiers never cross this API.

use ptah_contracts::generated;
use ptah_identifiers::{
    EntityId, EntityKind, EntityRef, IdentifierError, NodeGeneration, RecordRevision,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{path::Path, str::FromStr, time::Duration};
use thiserror::Error;

/// Latest repository-owned `SQLite` schema version for A03.
pub const LATEST_LEDGER_SCHEMA_VERSION: u32 = 2;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const META_CATALOG_DIGEST: &str = "frozen_catalog_set_sha256";
const META_FREEZE_COMMIT: &str = "phase_0b_freeze_commit";
/// Stable fail-closed outcome for a write from an older Node generation.
pub const STALE_NODE_GENERATION_CODE: &str = "PTAH_STALE_NODE_GENERATION";

#[derive(Debug, Clone, Copy)]
struct Migration {
    version: u32,
    name: &'static str,
    up_sql: &'static str,
    down_sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "ledger-foundation-and-frozen-schema-registry",
        up_sql: include_str!("../migrations/0001_ledger_core.up.sql"),
        down_sql: include_str!("../migrations/0001_ledger_core.down.sql"),
    },
    Migration {
        version: 2,
        name: "canonical-entity-records",
        up_sql: include_str!("../migrations/0002_entity_records.up.sql"),
        down_sql: include_str!("../migrations/0002_entity_records.down.sql"),
    },
];

/// A canonical record accepted at the A03 ledger boundary.
///
/// This type validates the identity, kind, revision and frozen schema-index
/// fields required for persistence. Complete JSON Schema semantic validation
/// remains owned by the frozen contract/conformance layer rather than being
/// silently reimplemented inside the storage adapter.
#[derive(Debug, Clone, PartialEq)]
pub struct CanonicalRecord {
    entity_id: EntityId,
    entity_kind: EntityKind,
    schema_id: String,
    schema_version: String,
    record_revision: RecordRevision,
    authority_ref: EntityRef,
    node_generation: Option<NodeGeneration>,
    document: Value,
}

impl CanonicalRecord {
    /// Parse a JSON document into a canonical ledger record.
    ///
    /// Frozen entity schemas normally carry canonical metadata inside an
    /// `envelope`; the common envelope schema itself carries the same fields at
    /// the document root. Both shapes are accepted without weakening identity,
    /// schema, revision or authority validation.
    ///
    /// # Errors
    ///
    /// Returns an error when required indexing fields are absent or malformed,
    /// canonical identity/authority validation fails, a `core.node` record omits
    /// `node_generation`, or the schema pair is outside the frozen registry.
    pub fn from_document(document: Value) -> Result<Self, LedgerError> {
        let object = document.as_object().ok_or(LedgerError::DocumentNotObject)?;
        let envelope = match object.get("envelope") {
            Some(value) => value
                .as_object()
                .ok_or(LedgerError::InvalidDocumentField("envelope"))?,
            None => object,
        };
        let entity_id_text = required_string(envelope, "entity_id")?;
        let entity_kind_text = required_string(envelope, "entity_kind")?;
        let schema_id = required_string(envelope, "schema_id")?.to_owned();
        let schema_version = required_string(envelope, "schema_version")?.to_owned();
        let revision = envelope
            .get("record_revision")
            .ok_or(LedgerError::MissingDocumentField("record_revision"))?
            .as_u64()
            .ok_or(LedgerError::InvalidDocumentField("record_revision"))?;
        let authority_value = envelope
            .get("authority_ref")
            .ok_or(LedgerError::MissingDocumentField("authority_ref"))?;

        let entity_id = EntityId::from_str(entity_id_text)?;
        let entity_kind = EntityKind::new(entity_kind_text)?;
        let record_revision = RecordRevision::new(revision)?;
        let authority_ref: EntityRef = serde_json::from_value(authority_value.clone())
            .map_err(|_| LedgerError::InvalidDocumentField("authority_ref"))?;
        let node_generation = object
            .get("node_generation")
            .map(|value| {
                value
                    .as_u64()
                    .map(NodeGeneration::new)
                    .ok_or(LedgerError::InvalidDocumentField("node_generation"))
            })
            .transpose()?;

        if entity_kind.as_str() == "core.node" && node_generation.is_none() {
            return Err(LedgerError::MissingDocumentField("node_generation"));
        }
        if !frozen_schema_exists(&schema_id, &schema_version) {
            return Err(LedgerError::UnknownSchema {
                schema_id,
                schema_version,
            });
        }

        Ok(Self {
            entity_id,
            entity_kind,
            schema_id,
            schema_version,
            record_revision,
            authority_ref,
            node_generation,
            document,
        })
    }

    /// Return the canonical Ptah entity identity.
    #[must_use]
    pub const fn entity_id(&self) -> EntityId {
        self.entity_id
    }

    /// Return the canonical Ptah entity kind.
    #[must_use]
    pub fn entity_kind(&self) -> &EntityKind {
        &self.entity_kind
    }

    /// Return the frozen schema identifier.
    #[must_use]
    pub fn schema_id(&self) -> &str {
        &self.schema_id
    }

    /// Return the frozen schema version.
    #[must_use]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Return the positive canonical record revision.
    #[must_use]
    pub const fn record_revision(&self) -> RecordRevision {
        self.record_revision
    }

    /// Return the canonical authority/provenance reference retained with the row.
    #[must_use]
    pub const fn authority_ref(&self) -> &EntityRef {
        &self.authority_ref
    }

    /// Return the Node generation carried by a generation-aware record.
    #[must_use]
    pub const fn node_generation(&self) -> Option<NodeGeneration> {
        self.node_generation
    }

    /// Return the preserved JSON document.
    #[must_use]
    pub const fn document(&self) -> &Value {
        &self.document
    }
}

/// Backend-neutral repository boundary for canonical Ptah entity records.
pub trait EntityRecordRepository {
    /// Read one exact canonical record revision.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails or retained bytes no longer match
    /// their canonical index fields.
    fn record(
        &self,
        entity_id: EntityId,
        revision: RecordRevision,
    ) -> Result<Option<CanonicalRecord>, LedgerError>;

    /// Read the highest retained revision for one canonical entity.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails or retained bytes are inconsistent.
    fn latest_record(&self, entity_id: EntityId) -> Result<Option<CanonicalRecord>, LedgerError>;

    /// List retained revisions for one canonical entity in ascending order.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails or a stored revision is invalid.
    fn revisions(&self, entity_id: EntityId) -> Result<Vec<RecordRevision>, LedgerError>;
}

/// Repository-owned `SQLite` WAL ledger.
pub struct Ledger {
    connection: Connection,
}

impl Ledger {
    /// Open or create a file-backed A03 ledger and migrate it to the supported
    /// repository schema version.
    ///
    /// # Errors
    ///
    /// Fails closed for newer/incompatible database versions, migration-history
    /// drift, frozen-schema registry drift, unavailable WAL mode, or `SQLite` I/O.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let mut connection = Connection::open(path)?;
        let discovered_version = read_user_version(&connection)?;
        if discovered_version > LATEST_LEDGER_SCHEMA_VERSION {
            return Err(LedgerError::IncompatibleDatabaseVersion {
                found: discovered_version,
                supported: LATEST_LEDGER_SCHEMA_VERSION,
            });
        }

        validate_migration_history(&connection, discovered_version)?;

        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(LedgerError::WalUnavailable(journal_mode));
        }
        connection.execute_batch("PRAGMA synchronous = FULL;")?;

        apply_pending_migrations(&mut connection, discovered_version)?;
        validate_migration_history(&connection, LATEST_LEDGER_SCHEMA_VERSION)?;
        validate_or_seed_contract_registry(&mut connection)?;

        Ok(Self { connection })
    }

    /// Return the `SQLite` journal mode reported by the open ledger.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot report the current journal mode.
    pub fn journal_mode(&self) -> Result<String, LedgerError> {
        Ok(self
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))?)
    }

    /// Return the repository-owned `SQLite` schema version.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot report a valid non-negative version.
    pub fn schema_version(&self) -> Result<u32, LedgerError> {
        read_user_version(&self.connection)
    }

    /// Return the number of frozen schema pairs registered in this ledger.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be queried or its count is invalid.
    pub fn registered_schema_count(&self) -> Result<usize, LedgerError> {
        let count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM ptah_schema_registry", [], |row| {
                    row.get(0)
                })?;
        usize::try_from(count).map_err(|_| LedgerError::InvalidDatabaseInteger {
            field: "schema_registry_count",
            value: count,
        })
    }

    /// Start an immediate write transaction.
    ///
    /// Dropping the returned transaction without committing rolls it back.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot begin the transaction.
    pub fn begin_write(&mut self) -> Result<LedgerWrite<'_>, LedgerError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Ok(LedgerWrite {
            transaction: Some(transaction),
        })
    }

    /// Request an explicit WAL checkpoint and return `SQLite`'s frame accounting.
    ///
    /// # Errors
    ///
    /// Returns an error when checkpoint execution fails or `SQLite` returns an
    /// invalid negative frame count.
    pub fn checkpoint(&self, mode: CheckpointMode) -> Result<CheckpointReport, LedgerError> {
        let sql = mode.sql();
        let (busy, log_frames, checkpointed_frames): (i64, i64, i64) =
            self.connection
                .query_row(sql, [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        Ok(CheckpointReport {
            busy: sql_non_negative("checkpoint_busy", busy)?,
            log_frames: sql_non_negative("checkpoint_log_frames", log_frames)?,
            checkpointed_frames: sql_non_negative("checkpointed_frames", checkpointed_frames)?,
        })
    }
}

impl EntityRecordRepository for Ledger {
    fn record(
        &self,
        entity_id: EntityId,
        revision: RecordRevision,
    ) -> Result<Option<CanonicalRecord>, LedgerError> {
        let revision = revision_to_sql(revision)?;
        let raw = self
            .connection
            .query_row(
                "SELECT entity_id, entity_kind, schema_id, schema_version, record_revision, authority_ref_json, node_generation, document_json \
                 FROM ptah_entity_records WHERE entity_id = ?1 AND record_revision = ?2",
                params![entity_id.to_string(), revision],
                raw_record_from_row,
            )
            .optional()?;
        raw.map(decode_stored_record).transpose()
    }

    fn latest_record(&self, entity_id: EntityId) -> Result<Option<CanonicalRecord>, LedgerError> {
        let raw = self
            .connection
            .query_row(
                "SELECT entity_id, entity_kind, schema_id, schema_version, record_revision, authority_ref_json, node_generation, document_json \
                 FROM ptah_entity_records WHERE entity_id = ?1 ORDER BY record_revision DESC LIMIT 1",
                params![entity_id.to_string()],
                raw_record_from_row,
            )
            .optional()?;
        raw.map(decode_stored_record).transpose()
    }

    fn revisions(&self, entity_id: EntityId) -> Result<Vec<RecordRevision>, LedgerError> {
        let mut statement = self.connection.prepare(
            "SELECT record_revision FROM ptah_entity_records \
             WHERE entity_id = ?1 ORDER BY record_revision ASC",
        )?;
        let values =
            statement.query_map(params![entity_id.to_string()], |row| row.get::<_, i64>(0))?;
        values
            .map(|value| {
                let value = value?;
                sql_revision(value)
            })
            .collect()
    }
}

/// One repository-owned write transaction.
pub struct LedgerWrite<'connection> {
    transaction: Option<Transaction<'connection>>,
}

impl LedgerWrite<'_> {
    /// Insert one immutable canonical record revision into the transaction.
    ///
    /// Existing `(entity_id, record_revision)` pairs are never overwritten.
    /// Entity kind cannot drift across revisions. For generation-aware Node
    /// records, a generation older than the greatest retained generation is
    /// rejected with [`STALE_NODE_GENERATION_CODE`].
    ///
    /// # Errors
    ///
    /// Returns an error for backend failure, revision/generation range overflow,
    /// missing frozen schema registration, non-monotonic revision, entity-kind
    /// drift, or a stale Node generation.
    pub fn insert(&self, record: &CanonicalRecord) -> Result<(), LedgerError> {
        let transaction = self
            .transaction
            .as_ref()
            .ok_or(LedgerError::TransactionAlreadyFinished)?;
        let revision = revision_to_sql(record.record_revision)?;
        let schema_present: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM ptah_schema_registry WHERE schema_id = ?1 AND schema_version = ?2)",
            params![record.schema_id, record.schema_version],
            |row| row.get(0),
        )?;
        if !schema_present {
            return Err(LedgerError::UnknownSchema {
                schema_id: record.schema_id.clone(),
                schema_version: record.schema_version.clone(),
            });
        }

        let retained: Option<(String, i64)> = transaction
            .query_row(
                "SELECT entity_kind, record_revision FROM ptah_entity_records                  WHERE entity_id = ?1 ORDER BY record_revision DESC LIMIT 1",
                params![record.entity_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((retained_kind, retained_revision)) = retained {
            if retained_kind != record.entity_kind.as_str() {
                return Err(LedgerError::EntityKindDrift {
                    entity_id: record.entity_id.to_string(),
                    retained: retained_kind,
                    attempted: record.entity_kind.as_str().to_owned(),
                });
            }
            let current_revision = sql_revision(retained_revision)?.value();
            if record.record_revision.value() <= current_revision {
                return Err(LedgerError::NonMonotonicRevision {
                    attempted: record.record_revision.value(),
                    current: current_revision,
                });
            }
        }

        let node_generation = record.node_generation.map(generation_to_sql).transpose()?;
        if let Some(requested_generation) = record.node_generation {
            let retained_generation: Option<i64> = transaction.query_row(
                "SELECT MAX(node_generation) FROM ptah_entity_records WHERE entity_id = ?1",
                params![record.entity_id.to_string()],
                |row| row.get(0),
            )?;
            if let Some(retained_generation) = retained_generation {
                let current_generation = sql_generation(retained_generation)?;
                if requested_generation < current_generation {
                    return Err(LedgerError::StaleNodeGeneration {
                        requested: requested_generation.value(),
                        current: current_generation.value(),
                        stable_outcome_code: STALE_NODE_GENERATION_CODE,
                    });
                }
            }
        }

        let authority_ref_json = serde_json::to_string(record.authority_ref())?;
        let document_json = serde_json::to_string(record.document())?;
        transaction.execute(
            "INSERT INTO ptah_entity_records              (entity_id, record_revision, entity_kind, schema_id, schema_version, authority_ref_json, node_generation, document_json)              VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.entity_id.to_string(),
                revision,
                record.entity_kind.as_str(),
                record.schema_id,
                record.schema_version,
                authority_ref_json,
                node_generation,
                document_json,
            ],
        )?;
        Ok(())
    }

    /// Commit this write transaction durably according to `SQLite`'s configured
    /// WAL and `synchronous=FULL` policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the transaction was already finished or `SQLite`
    /// cannot commit it.
    pub fn commit(mut self) -> Result<(), LedgerError> {
        let transaction = self
            .transaction
            .take()
            .ok_or(LedgerError::TransactionAlreadyFinished)?;
        transaction.commit()?;
        Ok(())
    }
}

impl Drop for LedgerWrite<'_> {
    fn drop(&mut self) {
        if let Some(transaction) = self.transaction.take() {
            let _ = transaction.rollback();
        }
    }
}

/// `SQLite` WAL checkpoint mode exposed by the repository boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointMode {
    /// Checkpoint available frames without waiting for readers.
    Passive,
    /// Wait for writers and checkpoint all available frames.
    Full,
    /// Checkpoint and restart the WAL when possible.
    Restart,
    /// Checkpoint and truncate the WAL to zero bytes when possible.
    Truncate,
}

impl CheckpointMode {
    const fn sql(self) -> &'static str {
        match self {
            Self::Passive => "PRAGMA wal_checkpoint(PASSIVE)",
            Self::Full => "PRAGMA wal_checkpoint(FULL)",
            Self::Restart => "PRAGMA wal_checkpoint(RESTART)",
            Self::Truncate => "PRAGMA wal_checkpoint(TRUNCATE)",
        }
    }
}

/// Result returned by an explicit WAL checkpoint request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointReport {
    /// Number of busy readers/writers reported by `SQLite`.
    pub busy: u64,
    /// Number of frames present in the WAL at checkpoint time.
    pub log_frames: u64,
    /// Number of frames checkpointed into the database.
    pub checkpointed_frames: u64,
}

/// A03 ledger failures.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// `SQLite` backend failure.
    #[error("SQLite ledger failure: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Canonical identifier validation failure.
    #[error("canonical identifier failure: {0}")]
    Identifier(#[from] IdentifierError),
    /// JSON encoding/decoding failure.
    #[error("JSON ledger failure: {0}")]
    Json(#[from] serde_json::Error),
    /// The persisted document is not a JSON object.
    #[error("canonical record document must be a JSON object")]
    DocumentNotObject,
    /// A required canonical index field is absent.
    #[error("canonical record is missing required field {0}")]
    MissingDocumentField(&'static str),
    /// A required canonical index field has the wrong JSON type or range.
    #[error("canonical record has invalid field {0}")]
    InvalidDocumentField(&'static str),
    /// The `(schema_id, schema_version)` pair is outside the frozen contract set.
    #[error("unknown frozen schema pair: {schema_id} @ {schema_version}")]
    UnknownSchema {
        /// Canonical schema identifier supplied by the record.
        schema_id: String,
        /// Schema version supplied by the record.
        schema_version: String,
    },
    /// A positive Ptah revision cannot be represented by `SQLite`'s signed integer.
    #[error("record revision {0} exceeds SQLite INTEGER range")]
    RevisionOutOfRange(u64),
    /// The database was created by a ledger schema newer than this binary supports.
    #[error("ledger schema version {found} is newer than supported version {supported}")]
    IncompatibleDatabaseVersion {
        /// Version discovered in `PRAGMA user_version`.
        found: u32,
        /// Latest version compiled into this ledger implementation.
        supported: u32,
    },
    /// Retained migration history does not match immutable compiled migrations.
    #[error("migration history mismatch at version {version}: {reason}")]
    MigrationHistoryMismatch {
        /// Migration version whose retained evidence drifted.
        version: u32,
        /// Human-readable mismatch reason.
        reason: String,
    },
    /// The durable frozen-schema registry has drifted from generated contracts.
    #[error("frozen contract registry mismatch: {0}")]
    ContractRegistryMismatch(String),
    /// `SQLite` refused WAL mode for the file-backed ledger.
    #[error("SQLite WAL mode unavailable; backend reported {0}")]
    WalUnavailable(String),
    /// A supposedly non-negative `SQLite` value was negative or out of range.
    #[error("invalid SQLite integer for {field}: {value}")]
    InvalidDatabaseInteger {
        /// Logical field being decoded.
        field: &'static str,
        /// Raw `SQLite` integer value.
        value: i64,
    },
    /// A stored JSON document disagrees with its canonical index columns.
    #[error("stored canonical record index/document mismatch: {0}")]
    StoredRecordMismatch(&'static str),
    /// A Node generation cannot be represented by `SQLite`'s signed integer.
    #[error("node generation {0} exceeds SQLite INTEGER range")]
    NodeGenerationOutOfRange(u64),
    /// A canonical entity attempted to change kind across revisions.
    #[error("entity kind drift for {entity_id}: retained {retained}, attempted {attempted}")]
    EntityKindDrift {
        /// Canonical entity identity whose kind would drift.
        entity_id: String,
        /// Retained entity kind.
        retained: String,
        /// Attempted replacement kind.
        attempted: String,
    },
    /// A revision is not strictly greater than the retained latest revision.
    #[error("non-monotonic record revision: attempted {attempted}, current {current}")]
    NonMonotonicRevision {
        /// Attempted canonical record revision.
        attempted: u64,
        /// Greatest retained canonical record revision.
        current: u64,
    },
    /// A write came from an older Node generation than the durable ledger truth.
    #[error("{stable_outcome_code}: stale node generation requested={requested} current={current}")]
    StaleNodeGeneration {
        /// Generation carried by the rejected record.
        requested: u64,
        /// Greatest durable generation already retained for the Node.
        current: u64,
        /// Stable machine-readable fail-closed outcome code.
        stable_outcome_code: &'static str,
    },
    /// A write transaction has already been committed or rolled back.
    #[error("ledger write transaction already finished")]
    TransactionAlreadyFinished,
}

type RawRecord = (
    String,
    String,
    String,
    String,
    i64,
    String,
    Option<i64>,
    String,
);

fn required_string<'value>(
    object: &'value serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<&'value str, LedgerError> {
    object
        .get(field)
        .ok_or(LedgerError::MissingDocumentField(field))?
        .as_str()
        .ok_or(LedgerError::InvalidDocumentField(field))
}

fn frozen_schema_exists(schema_id: &str, schema_version: &str) -> bool {
    generated::SCHEMAS
        .iter()
        .any(|binding| binding.schema_id == schema_id && binding.schema_version == schema_version)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn migration_digest(sql: &str) -> String {
    sha256_hex(sql.as_bytes())
}

fn migration_for(version: u32) -> Option<&'static Migration> {
    MIGRATIONS
        .iter()
        .find(|migration| migration.version == version)
}

fn read_user_version(connection: &Connection) -> Result<u32, LedgerError> {
    let value: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    u32::try_from(value).map_err(|_| LedgerError::InvalidDatabaseInteger {
        field: "user_version",
        value,
    })
}

fn table_exists(connection: &Connection, name: &str) -> Result<bool, LedgerError> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
        params![name],
        |row| row.get(0),
    )?)
}

fn validate_migration_history(
    connection: &Connection,
    current_version: u32,
) -> Result<(), LedgerError> {
    if current_version == 0 {
        return Ok(());
    }
    if !table_exists(connection, "ptah_migration_history")? {
        return Err(LedgerError::MigrationHistoryMismatch {
            version: current_version,
            reason: "migration history table is missing".to_owned(),
        });
    }

    let mut statement = connection.prepare(
        "SELECT version, name, up_sha256, down_sha256 \
         FROM ptah_migration_history ORDER BY version ASC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let retained: Vec<_> = rows.collect::<Result<_, _>>()?;
    let expected_len =
        usize::try_from(current_version).map_err(|_| LedgerError::MigrationHistoryMismatch {
            version: current_version,
            reason: "schema version cannot be represented by this process".to_owned(),
        })?;
    if retained.len() != expected_len {
        return Err(LedgerError::MigrationHistoryMismatch {
            version: current_version,
            reason: format!(
                "expected {expected_len} history rows but retained {}",
                retained.len()
            ),
        });
    }

    for (index, (version_raw, name, up_sha256, down_sha256)) in retained.iter().enumerate() {
        let version =
            u32::try_from(*version_raw).map_err(|_| LedgerError::MigrationHistoryMismatch {
                version: current_version,
                reason: format!("invalid stored migration version {version_raw}"),
            })?;
        let expected_version =
            u32::try_from(index + 1).map_err(|_| LedgerError::MigrationHistoryMismatch {
                version,
                reason: "migration sequence exceeds supported integer range".to_owned(),
            })?;
        let migration = migration_for(expected_version).ok_or_else(|| {
            LedgerError::MigrationHistoryMismatch {
                version,
                reason: "compiled migration is missing".to_owned(),
            }
        })?;
        if version != migration.version
            || name != migration.name
            || up_sha256 != &migration_digest(migration.up_sql)
            || down_sha256 != &migration_digest(migration.down_sql)
        {
            return Err(LedgerError::MigrationHistoryMismatch {
                version,
                reason: "retained name or immutable directional digest drifted".to_owned(),
            });
        }
    }
    Ok(())
}

fn apply_pending_migrations(
    connection: &mut Connection,
    current_version: u32,
) -> Result<(), LedgerError> {
    let mut expected_next =
        current_version
            .checked_add(1)
            .ok_or(LedgerError::IncompatibleDatabaseVersion {
                found: current_version,
                supported: LATEST_LEDGER_SCHEMA_VERSION,
            })?;
    for migration in MIGRATIONS
        .iter()
        .filter(|migration| migration.version > current_version)
    {
        if migration.version != expected_next {
            return Err(LedgerError::MigrationHistoryMismatch {
                version: migration.version,
                reason: format!("compiled migration sequence expected version {expected_next}"),
            });
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(migration.up_sql)?;
        transaction.execute(
            "INSERT INTO ptah_migration_history (version, name, up_sha256, down_sha256) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                i64::from(migration.version),
                migration.name,
                migration_digest(migration.up_sql),
                migration_digest(migration.down_sql),
            ],
        )?;
        transaction.execute_batch(&format!("PRAGMA user_version = {};", migration.version))?;
        transaction.commit()?;
        expected_next = expected_next.checked_add(1).unwrap_or(expected_next);
    }
    Ok(())
}

fn validate_or_seed_contract_registry(connection: &mut Connection) -> Result<(), LedgerError> {
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM ptah_schema_registry", [], |row| {
            row.get(0)
        })?;
    if count == 0 {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for binding in generated::SCHEMAS {
            transaction.execute(
                "INSERT INTO ptah_schema_registry \
                 (schema_id, schema_version, catalog_id, sha256, repository_path, maturity) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    binding.schema_id,
                    binding.schema_version,
                    binding.catalog_id,
                    binding.sha256,
                    binding.repository_path,
                    binding.maturity,
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO ptah_ledger_meta (key, value) VALUES (?1, ?2)",
            params![META_CATALOG_DIGEST, generated::CATALOG_SET_SHA256],
        )?;
        transaction.execute(
            "INSERT INTO ptah_ledger_meta (key, value) VALUES (?1, ?2)",
            params![META_FREEZE_COMMIT, generated::PHASE_0B_FREEZE_COMMIT],
        )?;
        transaction.commit()?;
    }

    validate_contract_registry(connection)?;
    validate_meta(
        connection,
        META_CATALOG_DIGEST,
        generated::CATALOG_SET_SHA256,
    )?;
    validate_meta(
        connection,
        META_FREEZE_COMMIT,
        generated::PHASE_0B_FREEZE_COMMIT,
    )?;
    Ok(())
}

fn validate_contract_registry(connection: &Connection) -> Result<(), LedgerError> {
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM ptah_schema_registry", [], |row| {
            row.get(0)
        })?;
    let expected = i64::try_from(generated::SCHEMA_COUNT).map_err(|_| {
        LedgerError::ContractRegistryMismatch(
            "compiled schema count exceeds SQLite range".to_owned(),
        )
    })?;
    if count != expected {
        return Err(LedgerError::ContractRegistryMismatch(format!(
            "expected {expected} frozen schemas but found {count}"
        )));
    }

    for binding in generated::SCHEMAS {
        let retained: Option<(String, String, String, Option<String>)> = connection
            .query_row(
                "SELECT catalog_id, sha256, repository_path, maturity \
                 FROM ptah_schema_registry WHERE schema_id = ?1 AND schema_version = ?2",
                params![binding.schema_id, binding.schema_version],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((catalog_id, sha256, repository_path, maturity)) = retained else {
            return Err(LedgerError::ContractRegistryMismatch(format!(
                "missing {} @ {}",
                binding.schema_id, binding.schema_version
            )));
        };
        if catalog_id != binding.catalog_id
            || sha256 != binding.sha256
            || repository_path != binding.repository_path
            || maturity.as_deref() != binding.maturity
        {
            return Err(LedgerError::ContractRegistryMismatch(format!(
                "frozen binding drifted for {} @ {}",
                binding.schema_id, binding.schema_version
            )));
        }
    }
    Ok(())
}

fn validate_meta(
    connection: &Connection,
    key: &'static str,
    expected: &'static str,
) -> Result<(), LedgerError> {
    let retained: Option<String> = connection
        .query_row(
            "SELECT value FROM ptah_ledger_meta WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    match retained {
        Some(value) if value == expected => Ok(()),
        Some(value) => Err(LedgerError::ContractRegistryMismatch(format!(
            "metadata {key} expected {expected} but found {value}"
        ))),
        None => Err(LedgerError::ContractRegistryMismatch(format!(
            "required metadata {key} is missing"
        ))),
    }
}

fn revision_to_sql(revision: RecordRevision) -> Result<i64, LedgerError> {
    i64::try_from(revision.value()).map_err(|_| LedgerError::RevisionOutOfRange(revision.value()))
}

fn sql_revision(value: i64) -> Result<RecordRevision, LedgerError> {
    let unsigned = u64::try_from(value).map_err(|_| LedgerError::InvalidDatabaseInteger {
        field: "record_revision",
        value,
    })?;
    Ok(RecordRevision::new(unsigned)?)
}

fn sql_non_negative(field: &'static str, value: i64) -> Result<u64, LedgerError> {
    u64::try_from(value).map_err(|_| LedgerError::InvalidDatabaseInteger { field, value })
}

fn generation_to_sql(generation: NodeGeneration) -> Result<i64, LedgerError> {
    i64::try_from(generation.value())
        .map_err(|_| LedgerError::NodeGenerationOutOfRange(generation.value()))
}

fn sql_generation(value: i64) -> Result<NodeGeneration, LedgerError> {
    let unsigned = u64::try_from(value).map_err(|_| LedgerError::InvalidDatabaseInteger {
        field: "node_generation",
        value,
    })?;
    Ok(NodeGeneration::new(unsigned))
}

fn raw_record_from_row(row: &Row<'_>) -> rusqlite::Result<RawRecord> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn decode_stored_record(raw: RawRecord) -> Result<CanonicalRecord, LedgerError> {
    let (
        entity_id,
        entity_kind,
        schema_id,
        schema_version,
        revision,
        authority_ref_json,
        node_generation,
        document_json,
    ) = raw;
    let document: Value = serde_json::from_str(&document_json)?;
    let record = CanonicalRecord::from_document(document)?;
    let indexed_revision = sql_revision(revision)?;
    let indexed_authority: EntityRef = serde_json::from_str(&authority_ref_json)?;
    let indexed_generation = node_generation.map(sql_generation).transpose()?;
    if record.entity_id.to_string() != entity_id {
        return Err(LedgerError::StoredRecordMismatch("entity_id"));
    }
    if record.entity_kind.as_str() != entity_kind {
        return Err(LedgerError::StoredRecordMismatch("entity_kind"));
    }
    if record.schema_id != schema_id {
        return Err(LedgerError::StoredRecordMismatch("schema_id"));
    }
    if record.schema_version != schema_version {
        return Err(LedgerError::StoredRecordMismatch("schema_version"));
    }
    if record.record_revision != indexed_revision {
        return Err(LedgerError::StoredRecordMismatch("record_revision"));
    }
    if record.authority_ref != indexed_authority {
        return Err(LedgerError::StoredRecordMismatch("authority_ref"));
    }
    if record.node_generation != indexed_generation {
        return Err(LedgerError::StoredRecordMismatch("node_generation"));
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        ffi::OsString,
        fmt::Write as _,
        fs,
        path::PathBuf,
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_DB: AtomicU64 = AtomicU64::new(0);
    const NODE_SCHEMA_ID: &str = "urn:ptah:schema:runtime:node:0.1.0";
    const NODE_SCHEMA_VERSION: &str = "0.1.0";

    struct TempDb(PathBuf);

    impl TempDb {
        fn new() -> Self {
            let serial = NEXT_DB.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "ptah-a03-ledger-test-{}-{serial}.sqlite3",
                process::id()
            )))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            for suffix in ["-wal", "-shm"] {
                let mut sidecar: OsString = self.0.as_os_str().to_owned();
                sidecar.push(suffix);
                let _ = fs::remove_file(PathBuf::from(sidecar));
            }
        }
    }

    fn authority_ref() -> EntityRef {
        EntityRef::new("identity.principal").expect("canonical authority ref")
    }

    fn node_record(
        entity_id: EntityId,
        revision: u64,
        generation: u64,
        payload: &str,
    ) -> CanonicalRecord {
        CanonicalRecord::from_document(json!({
            "envelope": {
                "entity_id": entity_id.to_string(),
                "entity_kind": "core.node",
                "schema_id": NODE_SCHEMA_ID,
                "schema_version": NODE_SCHEMA_VERSION,
                "record_revision": revision,
                "authority_ref": authority_ref(),
            },
            "node_generation": generation,
            "test_payload": payload,
        }))
        .expect("construct canonical Node test record")
    }

    fn schema_fingerprint(connection: &Connection) -> String {
        let mut material = String::new();
        let mut statement = connection
            .prepare(
                "SELECT type, name, sql FROM sqlite_schema \
                 WHERE name LIKE 'ptah_%' AND sql IS NOT NULL ORDER BY type, name",
            )
            .expect("prepare schema fingerprint");
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .expect("query schema fingerprint");
        for row in rows {
            let (kind, name, sql) = row.expect("schema fingerprint row");
            writeln!(&mut material, "{kind}|{name}|{sql}").expect("write schema fingerprint");
        }

        let mut statement = connection
            .prepare(
                "SELECT version, name, up_sha256, down_sha256 FROM ptah_migration_history \
                 ORDER BY version",
            )
            .expect("prepare migration fingerprint");
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .expect("query migration fingerprint");
        for row in rows {
            let (version, name, up, down) = row.expect("migration fingerprint row");
            writeln!(&mut material, "{version}|{name}|{up}|{down}")
                .expect("write migration fingerprint");
        }

        let mut statement = connection
            .prepare(
                "SELECT schema_id, schema_version, catalog_id, sha256, repository_path, \
                 COALESCE(maturity, '') FROM ptah_schema_registry ORDER BY schema_id, schema_version",
            )
            .expect("prepare registry fingerprint");
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .expect("query registry fingerprint");
        for row in rows {
            let (id, version, catalog, digest, path, maturity) =
                row.expect("registry fingerprint row");
            writeln!(
                &mut material,
                "{id}|{version}|{catalog}|{digest}|{path}|{maturity}"
            )
            .expect("write registry fingerprint");
        }
        sha256_hex(material.as_bytes())
    }

    #[test]
    fn migration_sql_is_committed_execution_authority() {
        assert_eq!(
            migration_for(1).expect("migration 1").up_sql,
            include_str!("../migrations/0001_ledger_core.up.sql")
        );
        assert_eq!(
            migration_for(1).expect("migration 1").down_sql,
            include_str!("../migrations/0001_ledger_core.down.sql")
        );
        assert_eq!(
            migration_for(2).expect("migration 2").up_sql,
            include_str!("../migrations/0002_entity_records.up.sql")
        );
        assert_eq!(
            migration_for(2).expect("migration 2").down_sql,
            include_str!("../migrations/0002_entity_records.down.sql")
        );
    }

    #[test]
    fn nested_frozen_envelope_is_indexed_canonically() {
        let id = EntityId::new_v7();
        let record = node_record(id, 1, 4, "nested");
        assert_eq!(record.entity_id(), id);
        assert_eq!(record.entity_kind().as_str(), "core.node");
        assert_eq!(record.node_generation(), Some(NodeGeneration::new(4)));
        assert_eq!(
            record.authority_ref().entity_kind.as_str(),
            "identity.principal"
        );
    }

    #[test]
    fn missing_authority_provenance_is_rejected() {
        let id = EntityId::new_v7();
        let result = CanonicalRecord::from_document(json!({
            "envelope": {
                "entity_id": id.to_string(),
                "entity_kind": "core.node",
                "schema_id": NODE_SCHEMA_ID,
                "schema_version": NODE_SCHEMA_VERSION,
                "record_revision": 1
            },
            "node_generation": 0
        }));
        assert!(matches!(
            result,
            Err(LedgerError::MissingDocumentField("authority_ref"))
        ));
    }

    #[test]
    fn opens_in_wal_and_registers_frozen_schema_set() {
        let db = TempDb::new();
        let ledger = Ledger::open(db.path()).expect("open A03 ledger");
        assert_eq!(ledger.journal_mode().expect("journal mode"), "wal");
        assert_eq!(ledger.schema_version().expect("schema version"), 2);
        assert_eq!(
            ledger.registered_schema_count().expect("schema count"),
            generated::SCHEMA_COUNT
        );
    }

    #[test]
    fn restart_preserves_canonical_records_and_provenance() {
        let db = TempDb::new();
        let entity_id = EntityId::new_v7();
        let expected = node_record(entity_id, 1, 0, "durable");
        {
            let mut ledger = Ledger::open(db.path()).expect("open ledger");
            let write = ledger.begin_write().expect("begin write");
            write.insert(&expected).expect("insert record");
            write.commit().expect("commit record");
            ledger
                .checkpoint(CheckpointMode::Truncate)
                .expect("checkpoint durable record");
        }
        let ledger = Ledger::open(db.path()).expect("reopen ledger");
        let observed = ledger
            .record(entity_id, RecordRevision::new(1).expect("revision"))
            .expect("read record")
            .expect("record retained");
        assert_eq!(observed, expected);
        assert_eq!(observed.authority_ref(), expected.authority_ref());
    }

    #[test]
    fn dropped_write_transaction_cannot_manufacture_success() {
        let db = TempDb::new();
        let entity_id = EntityId::new_v7();
        let candidate = node_record(entity_id, 1, 0, "uncommitted");
        {
            let mut ledger = Ledger::open(db.path()).expect("open ledger");
            {
                let write = ledger.begin_write().expect("begin write");
                write.insert(&candidate).expect("stage record");
            }
            assert!(
                ledger
                    .record(entity_id, RecordRevision::new(1).expect("revision"))
                    .expect("query after rollback")
                    .is_none()
            );
        }
        let ledger = Ledger::open(db.path()).expect("reopen ledger");
        assert!(
            ledger
                .latest_record(entity_id)
                .expect("query reopened ledger")
                .is_none()
        );
    }

    #[test]
    fn stale_generation_write_fails_closed_with_stable_outcome() {
        let db = TempDb::new();
        let entity_id = EntityId::new_v7();
        let mut ledger = Ledger::open(db.path()).expect("open ledger");
        {
            let write = ledger.begin_write().expect("begin write");
            write
                .insert(&node_record(entity_id, 1, 3, "current"))
                .expect("insert generation 3");
            write.commit().expect("commit generation 3");
        }
        {
            let write = ledger.begin_write().expect("begin stale write");
            let error = write
                .insert(&node_record(entity_id, 2, 2, "stale"))
                .expect_err("older generation must fail");
            assert!(matches!(
                error,
                LedgerError::StaleNodeGeneration {
                    requested: 2,
                    current: 3,
                    stable_outcome_code: STALE_NODE_GENERATION_CODE
                }
            ));
        }
        assert_eq!(
            ledger
                .revisions(entity_id)
                .expect("retained revisions")
                .iter()
                .map(|value| value.value())
                .collect::<Vec<_>>(),
            vec![1]
        );
    }

    #[test]
    fn same_or_newer_generation_can_advance_revision() {
        let db = TempDb::new();
        let entity_id = EntityId::new_v7();
        let mut ledger = Ledger::open(db.path()).expect("open ledger");
        for (revision, generation) in [(1, 0), (2, 0), (3, 1)] {
            let write = ledger.begin_write().expect("begin write");
            write
                .insert(&node_record(entity_id, revision, generation, "advance"))
                .expect("insert monotonic generation/revision");
            write.commit().expect("commit record");
        }
        assert_eq!(
            ledger
                .latest_record(entity_id)
                .expect("latest")
                .expect("record")
                .node_generation(),
            Some(NodeGeneration::new(1))
        );
    }

    #[test]
    fn non_monotonic_revision_fails_before_sqlite_conflict() {
        let db = TempDb::new();
        let entity_id = EntityId::new_v7();
        let mut ledger = Ledger::open(db.path()).expect("open ledger");
        let write = ledger.begin_write().expect("first write");
        write
            .insert(&node_record(entity_id, 2, 0, "first"))
            .expect("insert revision 2");
        write.commit().expect("commit revision 2");
        let write = ledger.begin_write().expect("old revision write");
        assert!(matches!(
            write.insert(&node_record(entity_id, 1, 0, "old")),
            Err(LedgerError::NonMonotonicRevision {
                attempted: 1,
                current: 2
            })
        ));
    }

    #[test]
    fn migration_replay_is_deterministic() {
        let first = TempDb::new();
        let second = TempDb::new();
        let first_ledger = Ledger::open(first.path()).expect("first migration replay");
        let first_fingerprint = schema_fingerprint(&first_ledger.connection);
        drop(first_ledger);
        let first_reopened = Ledger::open(first.path()).expect("reopen first migrated ledger");
        assert_eq!(
            schema_fingerprint(&first_reopened.connection),
            first_fingerprint
        );
        let second_ledger = Ledger::open(second.path()).expect("second migration replay");
        assert_eq!(
            schema_fingerprint(&second_ledger.connection),
            first_fingerprint
        );
    }

    #[test]
    fn directional_migration_down_then_up_restores_schema() {
        let db = TempDb::new();
        let ledger = Ledger::open(db.path()).expect("open latest ledger");
        let expected = schema_fingerprint(&ledger.connection);
        drop(ledger);

        let mut connection = Connection::open(db.path()).expect("open raw database");
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .expect("foreign keys");
        let migration = migration_for(2).expect("migration 2");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin directional migration");
        transaction
            .execute_batch(migration.down_sql)
            .expect("apply down migration");
        transaction
            .execute("DELETE FROM ptah_migration_history WHERE version = 2", [])
            .expect("delete migration history");
        transaction
            .execute_batch("PRAGMA user_version = 1;")
            .expect("set version 1");
        transaction.commit().expect("commit down migration");
        drop(connection);

        let replayed = Ledger::open(db.path()).expect("replay migration 2");
        assert_eq!(schema_fingerprint(&replayed.connection), expected);
    }

    #[test]
    fn newer_database_version_fails_closed_without_mutation() {
        let db = TempDb::new();
        let connection = Connection::open(db.path()).expect("create future database");
        connection
            .execute_batch("PRAGMA user_version = 3;")
            .expect("mark future version");
        drop(connection);
        assert!(matches!(
            Ledger::open(db.path()),
            Err(LedgerError::IncompatibleDatabaseVersion {
                found: 3,
                supported: 2
            })
        ));
        let connection = Connection::open(db.path()).expect("inspect future database");
        assert_eq!(read_user_version(&connection).expect("future version"), 3);
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name LIKE 'ptah_%'",
                [],
                |row| row.get(0),
            )
            .expect("count tables");
        assert_eq!(count, 0);
    }

    #[test]
    fn migration_history_tamper_fails_closed() {
        let db = TempDb::new();
        drop(Ledger::open(db.path()).expect("open ledger"));
        let connection = Connection::open(db.path()).expect("raw database");
        connection
            .execute(
                "UPDATE ptah_migration_history SET up_sha256 = 'tampered' WHERE version = 1",
                [],
            )
            .expect("tamper history");
        drop(connection);
        assert!(matches!(
            Ledger::open(db.path()),
            Err(LedgerError::MigrationHistoryMismatch { version: 1, .. })
        ));
    }

    #[test]
    fn authority_index_tamper_is_detected_on_read() {
        let db = TempDb::new();
        let entity_id = EntityId::new_v7();
        let mut ledger = Ledger::open(db.path()).expect("open ledger");
        let write = ledger.begin_write().expect("begin write");
        write
            .insert(&node_record(entity_id, 1, 0, "authority"))
            .expect("insert");
        write.commit().expect("commit");
        let wrong =
            serde_json::to_string(&EntityRef::new("identity.principal").expect("other authority"))
                .expect("serialize");
        ledger
            .connection
            .execute(
                "UPDATE ptah_entity_records SET authority_ref_json = ?1 WHERE entity_id = ?2",
                params![wrong, entity_id.to_string()],
            )
            .expect("tamper authority index");
        assert!(matches!(
            ledger.latest_record(entity_id),
            Err(LedgerError::StoredRecordMismatch("authority_ref"))
        ));
    }

    #[test]
    fn backend_row_ids_do_not_exist_on_canonical_tables() {
        let db = TempDb::new();
        let ledger = Ledger::open(db.path()).expect("open ledger");
        assert!(
            ledger
                .connection
                .prepare("SELECT rowid FROM ptah_entity_records")
                .is_err()
        );
        let sql: String = ledger.connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'ptah_entity_records'",
            [], |row| row.get(0)
        ).expect("entity table SQL");
        assert!(sql.contains("WITHOUT ROWID"));
    }

    #[test]
    fn unknown_schema_pair_is_rejected_before_storage() {
        let entity_id = EntityId::new_v7();
        let result = CanonicalRecord::from_document(json!({
            "envelope": {
                "entity_id": entity_id.to_string(),
                "entity_kind": "core.node",
                "schema_id": "urn:ptah:schema:runtime:not-real:9.9.9",
                "schema_version": "9.9.9",
                "record_revision": 1,
                "authority_ref": authority_ref()
            },
            "node_generation": 0
        }));
        assert!(matches!(result, Err(LedgerError::UnknownSchema { .. })));
    }

    #[test]
    fn revisions_are_canonical_and_ordered() {
        let db = TempDb::new();
        let entity_id = EntityId::new_v7();
        let mut ledger = Ledger::open(db.path()).expect("open ledger");
        for revision in [1, 2, 3] {
            let write = ledger.begin_write().expect("begin revision write");
            write
                .insert(&node_record(entity_id, revision, 0, "revision"))
                .expect("insert");
            write.commit().expect("commit");
        }
        assert_eq!(
            ledger
                .revisions(entity_id)
                .expect("list revisions")
                .iter()
                .map(|revision| revision.value())
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }
}
