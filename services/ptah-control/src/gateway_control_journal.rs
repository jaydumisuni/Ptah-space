//! Durable Control-owned dispatch intent and uncertainty receipts.
//! No synthetic "success" from a successful wire write.
use crate::gateway_witness::{
    EffectVerificationError, NodeCompletion, SignedEffectObservation, TrustedWitness,
    VerifiedEffectEvidence, verify_effect,
};
use crate::node_link::DispatchAuthorityFrames;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug)]
/// Errors while recording and reading Control-owned dispatch uncertainty.
pub enum ControlJournalError {
    /// `SQLite` read/write/transaction failed.
    Storage(rusqlite::Error),
    /// Ownership, identity, or repeated Attempt failure.
    Conflict(&'static str),
    /// Rejected independently signed witness evidence.
    Witness(EffectVerificationError),
    /// Malformed request or state location.
    Invalid(&'static str),
}
impl From<rusqlite::Error> for ControlJournalError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value)
    }
}
struct WriterLock(File);
impl Drop for WriterLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
/// Durable Control dispatch journal. Database closes before ownership unlocks.
pub struct ControlDispatchJournal {
    db: Connection,
    _lock: WriterLock,
}
/// Read-only outcome state, never execution authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchObservation {
    /// Exact serialized dispatch identity.
    pub dispatch: String,
    /// Exact serialized Attempt identity.
    pub attempt: String,
    /// Content-bound Cookpit request.
    pub request_digest: String,
    /// Dispatch transmission is not an A05 completion receipt.
    pub phase: String,
    /// Control-issued Fence.
    pub fence: u64,
}
fn key<T: serde::Serialize>(value: &T) -> Result<String, ControlJournalError> {
    serde_json::to_string(value).map_err(|_| ControlJournalError::Invalid("identity serialization"))
}
fn digest_valid(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
impl ControlDispatchJournal {
    /// Own one on-disk journal with a process-wide OS lock.
    /// During recovery, unfinished sent/unconfirmed work becomes uncertain,
    /// never executable and never automatically resent.
    ///
    /// # Errors
    /// Fails closed for symlink state, duplicate writer and database faults.
    pub fn open(path: &Path) -> Result<Self, ControlJournalError> {
        if path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err(ControlJournalError::Invalid("journal symlink"));
        }
        let mut name: OsString = path.as_os_str().to_owned();
        name.push(".lock");
        let lockpath = PathBuf::from(name);
        if lockpath
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err(ControlJournalError::Invalid("lock symlink"));
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lockpath)
            .map_err(|_| ControlJournalError::Invalid("lock unavailable"))?;
        lock.try_lock()
            .map_err(|_| ControlJournalError::Conflict("Control journal already owned"))?;
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(3))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS control_verified_effects(
                dispatch TEXT PRIMARY KEY,
                attempt TEXT NOT NULL UNIQUE,
                witness_id TEXT NOT NULL,
                evidence_digest TEXT NOT NULL,
                exit_code INTEGER NOT NULL,
                stdout_digest TEXT NOT NULL,
                FOREIGN KEY(dispatch) REFERENCES control_dispatches(dispatch)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS control_dispatches(
               dispatch TEXT PRIMARY KEY,
               attempt TEXT NOT NULL UNIQUE,
               node TEXT NOT NULL,
               generation INTEGER NOT NULL,
               epoch INTEGER NOT NULL,
               fence INTEGER NOT NULL CHECK(fence>0),
               request_digest TEXT NOT NULL,
               phase TEXT NOT NULL CHECK(phase IN
                 ('issued_unknown','sent_unconfirmed','needs_reconciliation')),
               transport_count INTEGER NOT NULL DEFAULT 0
             ) WITHOUT ROWID;",
        )?;
        db.execute(
            "UPDATE control_dispatches SET phase='needs_reconciliation'
            WHERE phase!='needs_reconciliation'",
            [],
        )?;
        Ok(Self {
            db,
            _lock: WriterLock(lock),
        })
    }
    /// Persist the exact E02 grant before transmitting its first frame.
    /// A previously used Attempt is never a replay token.
    ///
    /// # Errors
    /// Rejects reused Attempt, malformed digest and storage failures.
    pub fn stage_issued(
        &mut self,
        frame: &DispatchAuthorityFrames,
        digest: &str,
    ) -> Result<(), ControlJournalError> {
        if !digest_valid(digest) {
            return Err(ControlJournalError::Invalid("request digest"));
        }
        if frame.request.attempt_ref != frame.reservation.attempt_ref
            || frame.request.attempt_ref != frame.lease.attempt_ref
            || frame.request.node_id != frame.reservation.node_id
            || frame.request.node_id != frame.lease.node_id
            || frame.request.node_generation != frame.reservation.node_generation
            || frame.request.node_generation != frame.lease.node_generation
            || frame.request.connection_epoch != frame.reservation.connection_epoch
            || frame.request.connection_epoch != frame.lease.connection_epoch
            || frame.request.fence != frame.lease.fence
            || frame.request.lease_ref != frame.lease.lease_ref
            || frame.request.reservation_ref != frame.reservation.reservation_ref
        {
            return Err(ControlJournalError::Invalid("E02 frame mismatch"));
        }
        let dispatch = key(&frame.request.dispatch_ref)?;
        let attempt = key(&frame.request.attempt_ref)?;
        let node = key(&frame.request.node_id)?;
        let generation = i64::try_from(frame.request.node_generation.value())
            .map_err(|_| ControlJournalError::Invalid("generation overflow"))?;
        let epoch = i64::try_from(frame.request.connection_epoch.value())
            .map_err(|_| ControlJournalError::Invalid("epoch overflow"))?;
        let fence = i64::try_from(frame.request.fence)
            .map_err(|_| ControlJournalError::Invalid("fence overflow"))?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO control_dispatches
            (dispatch,attempt,node,generation,epoch,fence,request_digest,phase)
            VALUES(?1,?2,?3,?4,?5,?6,?7,'issued_unknown')",
            params![dispatch, attempt, node, generation, epoch, fence, digest],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Mark all frames transmitted. This is NOT execution or completion success.
    ///
    /// # Errors
    /// Rejects ambiguous/unowned attempts and storage failures.
    pub fn mark_sent(
        &mut self,
        frame: &DispatchAuthorityFrames,
    ) -> Result<(), ControlJournalError> {
        let dispatch = key(&frame.request.dispatch_ref)?;
        let updated = self.db.execute(
            "UPDATE control_dispatches SET phase='sent_unconfirmed',transport_count=1
             WHERE dispatch=?1 AND phase='issued_unknown'",
            params![dispatch],
        )?;
        if updated != 1 {
            return Err(ControlJournalError::Conflict("not newly issued"));
        }
        Ok(())
    }

    /// Validate and durably retain an independent signed external-effect proof.
    /// The original Control dispatch phase is deliberately unchanged: a valid
    /// witness is evidence, NOT permission to replay or promote other actions.
    ///
    /// # Errors
    /// Rejects wrong signer, missing Node result, stale Control/Node identity,
    /// conflicting witness evidence and storage failures.
    pub fn record_verified_effect(
        &mut self,
        frame: &DispatchAuthorityFrames,
        node: &NodeCompletion,
        signed: &SignedEffectObservation,
        trusted: &TrustedWitness<'_>,
    ) -> Result<VerifiedEffectEvidence, ControlJournalError> {
        let control = self.lookup(frame)?.ok_or(ControlJournalError::Conflict(
            "Control Attempt not journaled",
        ))?;
        let verified =
            verify_effect(&control, node, signed, trusted).map_err(ControlJournalError::Witness)?;
        let expected_node = key(&frame.request.node_id)?;
        if signed.observation.node != expected_node
            || signed.observation.generation != frame.request.node_generation.value()
            || signed.observation.connection_epoch != frame.request.connection_epoch.value()
        {
            return Err(ControlJournalError::Conflict(
                "Control Node generation/epoch mismatch",
            ));
        }
        let dispatch = control.dispatch;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: (String, i64, i64) = tx.query_row(
            "SELECT node,generation,epoch FROM control_dispatches WHERE dispatch=?1",
            params![&dispatch],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if stored.0 != expected_node
            || u64::try_from(stored.1).ok() != Some(signed.observation.generation)
            || u64::try_from(stored.2).ok() != Some(signed.observation.connection_epoch)
        {
            return Err(ControlJournalError::Conflict(
                "persisted Control owner mismatch",
            ));
        }
        let witness = verified.witness_id.clone();
        let digest = verified.canonical_sha256.clone();
        tx.execute(
            "INSERT OR IGNORE INTO control_verified_effects
              (dispatch,attempt,witness_id,evidence_digest,exit_code,stdout_digest)
              VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                &dispatch,
                &control.attempt,
                &witness,
                &digest,
                signed.observation.observed_exit_code,
                &signed.observation.observed_stdout_digest
            ],
        )?;
        let found: (String, String, String, i32, String) = tx.query_row(
            "SELECT attempt,witness_id,evidence_digest,exit_code,stdout_digest
             FROM control_verified_effects WHERE dispatch=?1",
            params![&dispatch],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        if found
            != (
                control.attempt,
                witness,
                digest,
                signed.observation.observed_exit_code,
                signed.observation.observed_stdout_digest.clone(),
            )
        {
            return Err(ControlJournalError::Conflict("immutable witness changed"));
        }
        tx.commit()?;
        Ok(verified)
    }

    /// Read persisted witness-evidence identity without promoting dispatch.
    ///
    /// # Errors
    /// Propagates storage and identity errors.
    pub fn verified_effect(
        &self,
        frame: &DispatchAuthorityFrames,
    ) -> Result<Option<VerifiedEffectEvidence>, ControlJournalError> {
        let id = key(&frame.request.dispatch_ref)?;
        self.db
            .query_row(
                "SELECT evidence_digest,witness_id FROM control_verified_effects
             WHERE dispatch=?1",
                params![id],
                |r| {
                    Ok(VerifiedEffectEvidence {
                        canonical_sha256: r.get(0)?,
                        witness_id: r.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Inspect all uncertain effect attempts after reopening or before shutdown.
    ///
    /// # Errors
    /// Propagates storage failures; does not auto-complete or re-issue work.
    pub fn unresolved(&self) -> Result<Vec<DispatchObservation>, ControlJournalError> {
        let mut stmt = self.db.prepare(
            "SELECT dispatch,attempt,request_digest,phase,fence
             FROM control_dispatches ORDER BY attempt,dispatch",
        )?;
        let mut rows = stmt.query([])?;
        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            let fence: i64 = row.get(4)?;
            result.push(DispatchObservation {
                dispatch: row.get(0)?,
                attempt: row.get(1)?,
                request_digest: row.get(2)?,
                phase: row.get(3)?,
                fence: u64::try_from(fence)
                    .map_err(|_| ControlJournalError::Invalid("stored fence"))?,
            });
        }
        Ok(result)
    }
    /// Exact lookup for a staged dispatch. No execution status inferred.
    ///
    /// # Errors
    /// Propagates storage failures.
    pub fn lookup(
        &self,
        frame: &DispatchAuthorityFrames,
    ) -> Result<Option<DispatchObservation>, ControlJournalError> {
        let dispatch = key(&frame.request.dispatch_ref)?;
        self.db
            .query_row(
                "SELECT dispatch,attempt,request_digest,phase,fence
             FROM control_dispatches WHERE dispatch=?1",
                params![dispatch],
                |row| {
                    let fence: i64 = row.get(4)?;
                    Ok(DispatchObservation {
                        dispatch: row.get(0)?,
                        attempt: row.get(1)?,
                        request_digest: row.get(2)?,
                        phase: row.get(3)?,
                        fence: u64::try_from(fence).unwrap_or(0),
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }
}
