use crate::{
    AuthorityBinding, FenceToken, LeaseError, LeaseRecord, LeaseRegistry, LeaseState,
    ReservationError, ReservationRecord, ReservationRegistry, ReservationState, ReservedResource,
};
use ptah_identifiers::{EntityId, EntityRef, NodeId};
use ptah_ledger::{CanonicalRecord, Ledger};
use ptah_node_agent::{NodeResourceSnapshot, ResourceUnit};
use ptah_node_link::SessionBinding;
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};
use thiserror::Error;

const JOURNAL_KIND: &str = "runtime.e02-authority-journal";
const COMMON_ENVELOPE_SCHEMA_ID: &str = "urn:ptah:schema:common:entity-envelope:0.1.0";
const COMMON_ENVELOPE_SCHEMA_VERSION: &str = "0.1.0";
const EXTENSION_KEY: &str = "ptah.e02_authority_recovery";
const EXTENSION_SCHEMA_ID: &str = "urn:ptah:extension:e02-authority-recovery:0.1.0";
const EXTENSION_SCHEMA_VERSION: &str = "0.1.0";

/// Durable E02 recovery failure. Every recovery failure is fail-closed: no
/// partially reconstructed authority is returned to callers.
#[derive(Debug, Error)]
pub enum RecoveryError {
    /// A03 rejected canonical journal storage or database open/recovery.
    #[error("A03 ledger rejected E02 durable authority: {0}")]
    Ledger(String),
    /// Read-only traversal of A03's canonical record table failed.
    #[error("A03 durable authority read failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Persisted JSON could not be decoded.
    #[error("E02 durable authority JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    /// Persisted authority is internally inconsistent or ambiguous.
    #[error("E02 durable authority is corrupt or ambiguous: {0}")]
    Corrupt(String),
    /// A currently bound Reservation cites resource evidence other than the
    /// caller's exact current A02 snapshot.
    #[error("recovered Reservation cites stale resource evidence")]
    StaleResourceEvidence,
    /// Rehydrating Reservation accounting failed closed.
    #[error("recovered Reservation is inadmissible: {0}")]
    Reservation(#[from] ReservationError),
    /// Rehydrating Lease/Fence authority failed closed.
    #[error("recovered Lease is inadmissible: {0}")]
    Lease(#[from] LeaseError),
    /// A persisted Fence did not equal the deterministic next Fence reconstructed
    /// from retained history.
    #[error("recovered Fence mismatch: persisted {persisted}, reconstructed {reconstructed}")]
    FenceMismatch {
        /// Fence stored in durable truth.
        persisted: u64,
        /// Fence produced by deterministic replay.
        reconstructed: u64,
    },
    /// A Unix timestamp cannot be represented as the frozen UTC date-time form.
    #[error("Unix timestamp is outside supported RFC3339 range")]
    TimestampOutOfRange,
}

/// Reconstructed current-session Reservation and Lease/Fence authorities.
pub struct RecoveredAuthority {
    reservations: ReservationRegistry,
    leases: LeaseRegistry,
}

impl RecoveredAuthority {
    /// Read recovered Reservation accounting.
    #[must_use]
    pub const fn reservations(&self) -> &ReservationRegistry {
        &self.reservations
    }

    /// Mutate recovered Reservation accounting through the normal E02 API.
    #[must_use]
    pub fn reservations_mut(&mut self) -> &mut ReservationRegistry {
        &mut self.reservations
    }

    /// Read recovered Lease/Fence authority.
    #[must_use]
    pub const fn leases(&self) -> &LeaseRegistry {
        &self.leases
    }

    /// Mutate recovered Lease/Fence authority through the normal E02 API.
    #[must_use]
    pub fn leases_mut(&mut self) -> &mut LeaseRegistry {
        &mut self.leases
    }
}

/// A03-backed append-only E02 authority journal.
///
/// E02 deliberately does not introduce a private database schema. Writes go
/// through [`Ledger`] as canonical `common.entity-envelope` records, with the
/// recovery payload carried by the frozen envelope's `extensions` field. Reads
/// traverse A03's existing immutable canonical-record table/index and revalidate
/// each document through [`CanonicalRecord`] before using any payload bytes.
pub struct DurableAuthorityStore {
    path: PathBuf,
    ledger: Ledger,
}

impl DurableAuthorityStore {
    /// Open or create the A03 ledger used for E02 authority recovery.
    ///
    /// # Errors
    /// Returns [`RecoveryError`] when A03 rejects the database, migration state,
    /// WAL policy or frozen contract registry.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RecoveryError> {
        let path = path.as_ref().to_path_buf();
        let ledger = Ledger::open(&path).map_err(ledger_error)?;
        Ok(Self { path, ledger })
    }

    /// Append one immutable Reservation recovery snapshot.
    ///
    /// The journal snapshot is not a substitute for the frozen
    /// `resource.reservation` projection; it is only restart reconstruction data
    /// for the already-validated E02 mechanical authority.
    ///
    /// # Errors
    /// Returns [`RecoveryError`] if retained journal truth is corrupt, sequence
    /// allocation overflows, timestamp conversion fails or A03 rejects the write.
    pub fn persist_reservation(
        &mut self,
        record: &ReservationRecord,
    ) -> Result<(), RecoveryError> {
        let sequence = self.next_sequence()?;
        let persisted = PersistedReservation::from_record(record);
        let timestamp = unix_seconds_to_rfc3339(record.created_at_unix_seconds())?;
        self.append(
            JournalEntry::Reservation {
                journal_sequence: sequence,
                reservation: persisted,
            },
            record.binding().attempt_ref(),
            &timestamp,
        )
    }

    /// Append one immutable Lease/Fence recovery snapshot.
    ///
    /// # Errors
    /// Returns [`RecoveryError`] if retained journal truth is corrupt, sequence
    /// allocation overflows, timestamp conversion fails or A03 rejects the write.
    pub fn persist_lease(&mut self, record: &LeaseRecord) -> Result<(), RecoveryError> {
        let sequence = self.next_sequence()?;
        let persisted = PersistedLease::from_record(record);
        let timestamp = unix_seconds_to_rfc3339(record.issued_at_unix_seconds())?;
        self.append(
            JournalEntry::Lease {
                journal_sequence: sequence,
                lease: persisted,
            },
            record.binding().attempt_ref(),
            &timestamp,
        )
    }

    /// Deterministically reconstruct current authority for one exact current E01
    /// session and A02 resource snapshot.
    ///
    /// Old Node generations/epochs never regain current Reservation/Lease state,
    /// but their highest Fence remains a permanent floor so reconnect cannot
    /// reset ownership to a reused token.
    ///
    /// # Errors
    /// Returns [`RecoveryError`] for malformed, ambiguous, stale-evidence or
    /// mechanically inadmissible durable state. No partial authority is returned.
    pub fn recover(
        &self,
        session: &SessionBinding,
        snapshot: &NodeResourceSnapshot,
        now_unix_seconds: u64,
    ) -> Result<RecoveredAuthority, RecoveryError> {
        let entries = self.read_entries()?;
        let (reservations, leases) = latest_snapshots(entries)?;
        validate_lease_history(&reservations, &leases)?;

        let mut reservation_registry = ReservationRegistry::new(session, snapshot)?;
        let mut current_reservations: Vec<_> = reservations
            .values()
            .filter(|reservation| reservation.matches_session(session))
            .cloned()
            .collect();
        current_reservations.sort_by(|left, right| {
            left.created_at_unix_seconds
                .cmp(&right.created_at_unix_seconds)
                .then_with(|| {
                    left.reservation_ref
                        .entity_id
                        .to_string()
                        .cmp(&right.reservation_ref.entity_id.to_string())
                })
        });

        for reservation in &current_reservations {
            if reservation.resource_snapshot_ref != snapshot.snapshot_ref {
                return Err(RecoveryError::StaleResourceEvidence);
            }
            let resources = reservation
                .resources
                .iter()
                .map(PersistedResource::to_runtime)
                .collect::<Result<Vec<_>, _>>()?;
            reservation_registry.reserve(
                reservation.reservation_ref.clone(),
                AuthorityBinding::new(
                    reservation.attempt_ref.clone(),
                    reservation.node_id,
                    reservation.node_generation.into(),
                    reservation.connection_epoch.into(),
                ),
                reservation.resource_snapshot_ref.clone(),
                resources,
                reservation.created_at_unix_seconds,
                reservation.expires_at_unix_seconds,
            )?;
        }

        let mut lease_registry = LeaseRegistry::new();
        let mut current_leases_by_attempt: HashMap<EntityRef, Vec<PersistedLease>> = HashMap::new();
        let mut global_fence_floor: HashMap<EntityRef, u64> = HashMap::new();
        for lease in leases.values() {
            global_fence_floor
                .entry(lease.attempt_ref.clone())
                .and_modify(|current| *current = (*current).max(lease.fence))
                .or_insert(lease.fence);
            if lease.matches_session(session) {
                current_leases_by_attempt
                    .entry(lease.attempt_ref.clone())
                    .or_default()
                    .push(lease.clone());
            }
        }

        let mut attempts: Vec<_> = current_leases_by_attempt.into_iter().collect();
        attempts.sort_by(|(left, _), (right, _)| {
            left.entity_id.to_string().cmp(&right.entity_id.to_string())
        });
        for (attempt_ref, mut attempt_leases) in attempts {
            attempt_leases.sort_by_key(|lease| lease.fence);
            if let Some(first) = attempt_leases.first()
                && first.fence > 1
            {
                let floor = FenceToken::new(first.fence - 1)
                    .map_err(|error| RecoveryError::Corrupt(error.to_string()))?;
                lease_registry.recover_fence_floor(attempt_ref.clone(), floor);
            }

            for persisted in &attempt_leases {
                let reservation = reservation_registry
                    .reservation(&persisted.reservation_ref)
                    .ok_or_else(|| {
                        RecoveryError::Corrupt(format!(
                            "current-session Lease {} has no recoverable Reservation",
                            persisted.lease_ref.entity_id
                        ))
                    })?
                    .clone();
                let reconstructed = lease_registry.issue(
                    &reservation,
                    persisted.lease_ref.clone(),
                    persisted.issued_at_unix_seconds,
                    persisted.expires_at_unix_seconds,
                )?;
                if reconstructed.fence().value() != persisted.fence {
                    return Err(RecoveryError::FenceMismatch {
                        persisted: persisted.fence,
                        reconstructed: reconstructed.fence().value(),
                    });
                }
            }
        }

        for (attempt_ref, value) in global_fence_floor {
            let floor = FenceToken::new(value)
                .map_err(|error| RecoveryError::Corrupt(error.to_string()))?;
            lease_registry.recover_fence_floor(attempt_ref, floor);
        }

        for lease in leases
            .values()
            .filter(|lease| lease.matches_session(session))
        {
            match lease.state {
                PersistedLeaseState::Active => {}
                PersistedLeaseState::Revoked => {
                    if lease_registry.state(&lease.lease_ref) == Some(LeaseState::Active) {
                        lease_registry.revoke(&lease.lease_ref)?;
                    }
                }
                PersistedLeaseState::Expired => {
                    lease_registry.expire(lease.expires_at_unix_seconds);
                }
                PersistedLeaseState::Superseded => {
                    let recorded = lease_registry.state(&lease.lease_ref);
                    let fenced_out = lease_registry
                        .highest_fence(&lease.attempt_ref)
                        .is_some_and(|highest| highest.value() > lease.fence);
                    if recorded != Some(LeaseState::Superseded) && !fenced_out {
                        return Err(RecoveryError::Corrupt(format!(
                            "Lease {} claims superseded without a newer Fence",
                            lease.lease_ref.entity_id
                        )));
                    }
                }
            }
        }
        lease_registry.expire(now_unix_seconds);

        for reservation in &current_reservations {
            match reservation.state {
                PersistedReservationState::Active => {}
                PersistedReservationState::Released => {
                    reservation_registry.release(
                        &reservation.reservation_ref,
                        reservation.created_at_unix_seconds,
                    )?;
                }
                PersistedReservationState::Revoked => {
                    reservation_registry.revoke(&reservation.reservation_ref)?;
                }
                PersistedReservationState::Expired => {
                    reservation_registry.expire(reservation.expires_at_unix_seconds);
                }
            }
        }
        reservation_registry.expire(now_unix_seconds);

        for lease in leases
            .values()
            .filter(|lease| lease.matches_session(session))
        {
            if reservation_registry
                .reservation(&lease.reservation_ref)
                .is_some_and(|reservation| reservation.state() != ReservationState::Active)
                && lease_registry.state(&lease.lease_ref) == Some(LeaseState::Active)
            {
                lease_registry.revoke(&lease.lease_ref)?;
            }
        }

        Ok(RecoveredAuthority {
            reservations: reservation_registry,
            leases: lease_registry,
        })
    }

    fn next_sequence(&self) -> Result<u64, RecoveryError> {
        self.read_entries()?
            .into_iter()
            .map(|entry| entry.sequence())
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| RecoveryError::Corrupt("journal sequence overflow".to_owned()))
    }

    fn append(
        &mut self,
        entry: JournalEntry,
        authority_ref: &EntityRef,
        timestamp: &str,
    ) -> Result<(), RecoveryError> {
        let journal_ref = EntityRef::new(JOURNAL_KIND)
            .map_err(|error| RecoveryError::Corrupt(error.to_string()))?;
        let extension_value = serde_json::to_value(entry)?;
        let document = json!({
            "entity_id": journal_ref.entity_id.to_string(),
            "entity_kind": JOURNAL_KIND,
            "schema_id": COMMON_ENVELOPE_SCHEMA_ID,
            "schema_version": COMMON_ENVELOPE_SCHEMA_VERSION,
            "record_revision": 1,
            "created_at": timestamp,
            "updated_at": timestamp,
            "global_scope": "ptah_global",
            "authority_ref": authority_ref,
            "privacy_class": "internal",
            "audience": "private_owner",
            "redaction_policy": "none",
            "retention_policy": {
                "policy_id": "ptah.e02.authority-recovery",
                "policy_version": "0.1.0",
                "retention_class": "operational"
            },
            "extensions": {
                EXTENSION_KEY: {
                    "schema_id": EXTENSION_SCHEMA_ID,
                    "schema_version": EXTENSION_SCHEMA_VERSION,
                    "value": extension_value
                }
            }
        });
        let record = CanonicalRecord::from_document(document).map_err(ledger_error)?;
        let write = self.ledger.begin_write().map_err(ledger_error)?;
        write.insert(&record).map_err(ledger_error)?;
        write.commit().map_err(ledger_error)
    }

    fn read_entries(&self) -> Result<Vec<JournalEntry>, RecoveryError> {
        let connection = Connection::open_with_flags(&self.path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut statement = connection.prepare(
            "SELECT entity_id, entity_kind, schema_id, schema_version, record_revision, \
                    authority_ref_json, node_generation, document_json \
             FROM ptah_entity_records WHERE entity_kind = ?1 \
             ORDER BY entity_id ASC, record_revision ASC",
        )?;
        let rows = statement.query_map(params![JOURNAL_KIND], |row| {
            Ok(StoredRow {
                entity_id: row.get(0)?,
                entity_kind: row.get(1)?,
                schema_id: row.get(2)?,
                schema_version: row.get(3)?,
                record_revision: row.get(4)?,
                authority_ref_json: row.get(5)?,
                node_generation: row.get(6)?,
                document_json: row.get(7)?,
            })
        })?;

        let mut entries = Vec::new();
        let mut sequences = HashSet::new();
        for row in rows {
            let row = row?;
            let document: Value = serde_json::from_str(&row.document_json)?;
            let canonical = CanonicalRecord::from_document(document.clone()).map_err(ledger_error)?;
            validate_stored_row(&row, &canonical)?;
            let value = document
                .get("extensions")
                .and_then(|extensions| extensions.get(EXTENSION_KEY))
                .and_then(|extension| extension.get("value"))
                .ok_or_else(|| {
                    RecoveryError::Corrupt("journal extension payload is missing".to_owned())
                })?;
            let entry: JournalEntry = serde_json::from_value(value.clone())?;
            validate_entry(&entry, canonical.authority_ref())?;
            if !sequences.insert(entry.sequence()) {
                return Err(RecoveryError::Corrupt(format!(
                    "duplicate journal sequence {}",
                    entry.sequence()
                )));
            }
            entries.push(entry);
        }
        entries.sort_by_key(JournalEntry::sequence);
        Ok(entries)
    }
}

#[derive(Debug)]
struct StoredRow {
    entity_id: String,
    entity_kind: String,
    schema_id: String,
    schema_version: String,
    record_revision: i64,
    authority_ref_json: String,
    node_generation: Option<i64>,
    document_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "entry_kind", rename_all = "snake_case")]
enum JournalEntry {
    Reservation {
        journal_sequence: u64,
        reservation: PersistedReservation,
    },
    Lease {
        journal_sequence: u64,
        lease: PersistedLease,
    },
}

impl JournalEntry {
    const fn sequence(&self) -> u64 {
        match self {
            Self::Reservation {
                journal_sequence, ..
            }
            | Self::Lease {
                journal_sequence, ..
            } => *journal_sequence,
        }
    }

    const fn attempt_ref(&self) -> &EntityRef {
        match self {
            Self::Reservation { reservation, .. } => &reservation.attempt_ref,
            Self::Lease { lease, .. } => &lease.attempt_ref,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct PersistedResource {
    resource_key: String,
    unit: ResourceUnit,
    quantity: f64,
}

impl PersistedResource {
    fn from_runtime(resource: &ReservedResource) -> Self {
        Self {
            resource_key: resource.resource_key().to_owned(),
            unit: resource.unit(),
            quantity: resource.quantity(),
        }
    }

    fn to_runtime(&self) -> Result<ReservedResource, RecoveryError> {
        ReservedResource::new(self.resource_key.clone(), self.unit, self.quantity)
            .map_err(RecoveryError::from)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PersistedReservationState {
    Active,
    Released,
    Expired,
    Revoked,
}

impl From<ReservationState> for PersistedReservationState {
    fn from(value: ReservationState) -> Self {
        match value {
            ReservationState::Active => Self::Active,
            ReservationState::Released => Self::Released,
            ReservationState::Expired => Self::Expired,
            ReservationState::Revoked => Self::Revoked,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct PersistedReservation {
    reservation_ref: EntityRef,
    attempt_ref: EntityRef,
    node_id: NodeId,
    node_generation: u64,
    connection_epoch: u64,
    resource_snapshot_ref: EntityRef,
    resources: Vec<PersistedResource>,
    created_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    state: PersistedReservationState,
}

impl PersistedReservation {
    fn from_record(record: &ReservationRecord) -> Self {
        Self {
            reservation_ref: record.reservation_ref().clone(),
            attempt_ref: record.binding().attempt_ref().clone(),
            node_id: record.binding().node_id(),
            node_generation: record.binding().node_generation().value(),
            connection_epoch: record.binding().connection_epoch().value(),
            resource_snapshot_ref: record.resource_snapshot_ref().clone(),
            resources: record
                .resources()
                .iter()
                .map(PersistedResource::from_runtime)
                .collect(),
            created_at_unix_seconds: record.created_at_unix_seconds(),
            expires_at_unix_seconds: record.expires_at_unix_seconds(),
            state: record.state().into(),
        }
    }

    fn matches_session(&self, session: &SessionBinding) -> bool {
        self.node_id == session.node_id
            && self.node_generation == session.node_generation.value()
            && self.connection_epoch == session.connection_epoch.value()
    }

    fn same_immutable_authority(&self, other: &Self) -> bool {
        self.reservation_ref == other.reservation_ref
            && self.attempt_ref == other.attempt_ref
            && self.node_id == other.node_id
            && self.node_generation == other.node_generation
            && self.connection_epoch == other.connection_epoch
            && self.resource_snapshot_ref == other.resource_snapshot_ref
            && self.resources == other.resources
            && self.created_at_unix_seconds == other.created_at_unix_seconds
            && self.expires_at_unix_seconds == other.expires_at_unix_seconds
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PersistedLeaseState {
    Active,
    Expired,
    Revoked,
    Superseded,
}

impl From<LeaseState> for PersistedLeaseState {
    fn from(value: LeaseState) -> Self {
        match value {
            LeaseState::Active => Self::Active,
            LeaseState::Expired => Self::Expired,
            LeaseState::Revoked => Self::Revoked,
            LeaseState::Superseded => Self::Superseded,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedLease {
    lease_ref: EntityRef,
    reservation_ref: EntityRef,
    attempt_ref: EntityRef,
    node_id: NodeId,
    node_generation: u64,
    connection_epoch: u64,
    fence: u64,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    state: PersistedLeaseState,
}

impl PersistedLease {
    fn from_record(record: &LeaseRecord) -> Self {
        Self {
            lease_ref: record.lease_ref().clone(),
            reservation_ref: record.reservation_ref().clone(),
            attempt_ref: record.binding().attempt_ref().clone(),
            node_id: record.binding().node_id(),
            node_generation: record.binding().node_generation().value(),
            connection_epoch: record.binding().connection_epoch().value(),
            fence: record.fence().value(),
            issued_at_unix_seconds: record.issued_at_unix_seconds(),
            expires_at_unix_seconds: record.expires_at_unix_seconds(),
            state: record.state().into(),
        }
    }

    fn matches_session(&self, session: &SessionBinding) -> bool {
        self.node_id == session.node_id
            && self.node_generation == session.node_generation.value()
            && self.connection_epoch == session.connection_epoch.value()
    }

    fn same_immutable_authority(&self, other: &Self) -> bool {
        self.lease_ref == other.lease_ref
            && self.reservation_ref == other.reservation_ref
            && self.attempt_ref == other.attempt_ref
            && self.node_id == other.node_id
            && self.node_generation == other.node_generation
            && self.connection_epoch == other.connection_epoch
            && self.fence == other.fence
            && self.issued_at_unix_seconds == other.issued_at_unix_seconds
            && self.expires_at_unix_seconds == other.expires_at_unix_seconds
    }
}

fn latest_snapshots(
    entries: Vec<JournalEntry>,
) -> Result<
    (
        HashMap<EntityId, PersistedReservation>,
        HashMap<EntityId, PersistedLease>,
    ),
    RecoveryError,
> {
    let mut reservations: HashMap<EntityId, (u64, PersistedReservation)> = HashMap::new();
    let mut leases: HashMap<EntityId, (u64, PersistedLease)> = HashMap::new();

    for entry in entries {
        match entry {
            JournalEntry::Reservation {
                journal_sequence,
                reservation,
            } => {
                let key = reservation.reservation_ref.entity_id;
                if let Some((_, retained)) = reservations.get(&key)
                    && !retained.same_immutable_authority(&reservation)
                {
                    return Err(RecoveryError::Corrupt(format!(
                        "Reservation {key} changed immutable authority"
                    )));
                }
                reservations.insert(key, (journal_sequence, reservation));
            }
            JournalEntry::Lease {
                journal_sequence,
                lease,
            } => {
                let key = lease.lease_ref.entity_id;
                if let Some((_, retained)) = leases.get(&key)
                    && !retained.same_immutable_authority(&lease)
                {
                    return Err(RecoveryError::Corrupt(format!(
                        "Lease {key} changed immutable authority"
                    )));
                }
                leases.insert(key, (journal_sequence, lease));
            }
        }
    }

    Ok((
        reservations
            .into_iter()
            .map(|(id, (_, value))| (id, value))
            .collect(),
        leases
            .into_iter()
            .map(|(id, (_, value))| (id, value))
            .collect(),
    ))
}

fn validate_lease_history(
    reservations: &HashMap<EntityId, PersistedReservation>,
    leases: &HashMap<EntityId, PersistedLease>,
) -> Result<(), RecoveryError> {
    let mut fences: HashMap<EntityRef, HashSet<u64>> = HashMap::new();
    for lease in leases.values() {
        if !reservations.contains_key(&lease.reservation_ref.entity_id) {
            return Err(RecoveryError::Corrupt(format!(
                "Lease {} references unknown Reservation {}",
                lease.lease_ref.entity_id, lease.reservation_ref.entity_id
            )));
        }
        if lease.fence == 0 || lease.expires_at_unix_seconds <= lease.issued_at_unix_seconds {
            return Err(RecoveryError::Corrupt(format!(
                "Lease {} has invalid Fence or validity interval",
                lease.lease_ref.entity_id
            )));
        }
        if !fences
            .entry(lease.attempt_ref.clone())
            .or_default()
            .insert(lease.fence)
        {
            return Err(RecoveryError::Corrupt(format!(
                "Attempt {} has duplicate Fence {}",
                lease.attempt_ref.entity_id, lease.fence
            )));
        }
    }
    Ok(())
}

fn validate_entry(entry: &JournalEntry, authority_ref: &EntityRef) -> Result<(), RecoveryError> {
    if entry.sequence() == 0 {
        return Err(RecoveryError::Corrupt(
            "journal sequence must be positive".to_owned(),
        ));
    }
    if entry.attempt_ref() != authority_ref {
        return Err(RecoveryError::Corrupt(
            "journal authority_ref does not match Attempt".to_owned(),
        ));
    }
    match entry {
        JournalEntry::Reservation { reservation, .. } => {
            if reservation.resources.is_empty()
                || reservation
                    .resources
                    .iter()
                    .any(|resource| {
                        resource.resource_key.is_empty()
                            || !resource.quantity.is_finite()
                            || resource.quantity <= 0.0
                    })
                || reservation.expires_at_unix_seconds <= reservation.created_at_unix_seconds
            {
                return Err(RecoveryError::Corrupt(format!(
                    "Reservation {} has invalid resource or validity data",
                    reservation.reservation_ref.entity_id
                )));
            }
        }
        JournalEntry::Lease { lease, .. } => {
            if lease.fence == 0 || lease.expires_at_unix_seconds <= lease.issued_at_unix_seconds {
                return Err(RecoveryError::Corrupt(format!(
                    "Lease {} has invalid Fence or validity data",
                    lease.lease_ref.entity_id
                )));
            }
        }
    }
    Ok(())
}

fn validate_stored_row(row: &StoredRow, record: &CanonicalRecord) -> Result<(), RecoveryError> {
    let revision = u64::try_from(row.record_revision)
        .map_err(|_| RecoveryError::Corrupt("negative journal revision".to_owned()))?;
    let indexed_authority: EntityRef = serde_json::from_str(&row.authority_ref_json)?;
    if row.entity_id != record.entity_id().to_string()
        || row.entity_kind != record.entity_kind().as_str()
        || row.schema_id != record.schema_id()
        || row.schema_version != record.schema_version()
        || revision != record.record_revision().value()
        || indexed_authority != *record.authority_ref()
        || row.node_generation.is_some()
        || row.entity_kind != JOURNAL_KIND
        || row.schema_id != COMMON_ENVELOPE_SCHEMA_ID
        || row.schema_version != COMMON_ENVELOPE_SCHEMA_VERSION
        || revision != 1
    {
        return Err(RecoveryError::Corrupt(
            "A03 row indexes disagree with canonical journal document".to_owned(),
        ));
    }
    Ok(())
}

fn ledger_error(error: impl std::fmt::Display) -> RecoveryError {
    RecoveryError::Ledger(error.to_string())
}

fn unix_seconds_to_rfc3339(seconds: u64) -> Result<String, RecoveryError> {
    let days = seconds / 86_400;
    let seconds_of_day = seconds % 86_400;
    let days = i64::try_from(days).map_err(|_| RecoveryError::TimestampOutOfRange)?;
    let (year, month, day) = civil_from_days(days)?;
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn civil_from_days(days_since_epoch: i64) -> Result<(i64, i64, i64), RecoveryError> {
    let shifted = days_since_epoch
        .checked_add(719_468)
        .ok_or(RecoveryError::TimestampOutOfRange)?;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096)
            / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    if !(0..=9999).contains(&year) {
        return Err(RecoveryError::TimestampOutOfRange);
    }
    Ok((year, month, day))
}
