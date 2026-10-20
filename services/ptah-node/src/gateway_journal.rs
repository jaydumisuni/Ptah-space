//! Durable, fail-closed Ptah Node dispatch journal.
//! Never allocates E01/E02/E05 authority and never automatically replays
//! an attempt whose process outcome might already have happened.
use crate::{
    NodeDispatchError, NodeDispatchGuard, NodeProviderDispatchError,
    spawn_native_process_if_authorized,
};
use native_process::{NativeProcessProvider, ProcessSpec};
use ptah_activity_runtime::AttemptContext;
use ptah_identifiers::EntityId;
use ptah_node_agent::NodeAgent;
use ptah_node_link::DispatchRequestFrame;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug)]
/// Gateway persistence failures, separate from Ptah authority decisions.
pub enum JournalError {
    /// Storage transaction failed.
    Storage(rusqlite::Error),
    /// Node-side E02 authority failed.
    Authority(NodeDispatchError),
    /// A05 provider dispatch was rejected after an irrevocable durable stage.
    Dispatch(NodeProviderDispatchError),
    /// Malformed or incomplete attempt evidence.
    Invalid(&'static str),
    /// Attempt currentness or idempotency mismatch.
    Conflict(&'static str),
}
impl From<rusqlite::Error> for JournalError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value)
    }
}
impl From<NodeDispatchError> for JournalError {
    fn from(value: NodeDispatchError) -> Self {
        Self::Authority(value)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Idempotent result of atomically committing a pre-effect marker.
pub enum StageResult {
    /// First attempt now durably fenced before its effect.
    StagedNew,
    /// Already staged or completed; must never spawn a duplicate.
    AlreadyRegistered,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Read-only attempt evidence preserved across process restarts.
pub struct RetainedAttempt {
    /// Immutable canonical Attempt identity.
    pub attempt: String,
    /// Immutable canonical originating Node identity.
    pub node: String,
    /// Node Generation at dispatch.
    pub generation: u64,
    /// E01 connection epoch at dispatch.
    pub connection_epoch: u64,
    /// Exact Cookpit request digest.
    pub digest: String,
    /// In-flight, completed or awaiting reconciliation.
    pub phase: String,
    /// Highest control-issued fence recorded for this dispatch.
    pub fence: u64,
    /// Independently observed A05 process exit code, if available.
    pub exit_code: Option<i32>,
    /// SHA-256 of actual untruncated A05 stdout.
    pub stdout_digest: Option<String>,
    /// Spawned process identity; never infer from another attempt.
    pub process_ref: Option<String>,
}

/// An unresolved durable dispatch requiring owner-mediated effect reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCandidate {
    /// Original dispatch identity.
    pub dispatch: String,
    /// Original A04 Attempt identity.
    pub attempt: String,
    /// Exact request digest.
    pub digest: String,
    /// Original Node identity.
    pub node: String,
    /// Original Node Generation.
    pub generation: u64,
    /// Original connection epoch.
    pub epoch: u64,
    /// Last persisted control-issued fence for this attempt.
    pub fence: u64,
}

/// Persistent Node-side attempt ownership and evidence store.
pub struct GatewayJournal {
    db: Connection,
    _owner_lock: JournalFileLock,
}

struct JournalFileLock(File);
impl Drop for JournalFileLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

fn identity<T: serde::Serialize>(value: &T) -> Result<String, JournalError> {
    serde_json::to_string(value).map_err(|_| JournalError::Invalid("identity serialization"))
}
fn valid_digest(d: &str) -> bool {
    d.len() == 71
        && d.starts_with("sha256:")
        && d[7..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
impl GatewayJournal {
    /// Open durable WAL storage and conservatively reconcile abandoned attempts.
    ///
    /// # Errors
    ///
    /// Rejects unreadable databases and symbolic links, and propagates database errors.
    pub fn open(path: &Path) -> Result<Self, JournalError> {
        if path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err(JournalError::Invalid("database symlink"));
        }
        // Single writer across processes: the exclusive OS lock survives
        // every SQLite transaction until this GatewayJournal is dropped.
        // A second process must not convert the first process's in-flight
        // work into a false abandoned/reconciliation candidate.
        let mut lock_name: OsString = path.as_os_str().to_owned();
        lock_name.push(".lock");
        let lock_path = PathBuf::from(lock_name);
        if lock_path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err(JournalError::Invalid("lockfile symlink"));
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|_| JournalError::Invalid("lock unavailable"))?;
        lock.try_lock()
            .map_err(|_| JournalError::Conflict("journal already owned"))?;
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(3))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS ptah_gateway_attempts (
               dispatch TEXT PRIMARY KEY,
               attempt TEXT NOT NULL,
               digest TEXT NOT NULL,
               node TEXT NOT NULL,
               generation INTEGER NOT NULL,
               epoch INTEGER NOT NULL,
               fence INTEGER NOT NULL CHECK(fence > 0),
               phase TEXT NOT NULL CHECK(phase IN ('in_flight','needs_reconciliation','completed')),
               exit_code INTEGER,
               stdout_digest TEXT,
               process_ref TEXT,
               UNIQUE(attempt, fence)
             ) WITHOUT ROWID;",
        )?;
        // Existing candidates remain without a process identity; a schema
        // migration must not invent proof that a past attempt completed.
        let has_process_ref = {
            let mut stmt = db.prepare("PRAGMA table_info(ptah_gateway_attempts)")?;
            let fields = stmt
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            fields.iter().any(|field| field == "process_ref")
        };
        if !has_process_ref {
            db.execute_batch("ALTER TABLE ptah_gateway_attempts ADD COLUMN process_ref TEXT;")?;
        }
        db.execute(
            "UPDATE ptah_gateway_attempts SET phase='needs_reconciliation'
             WHERE phase='in_flight'",
            [],
        )?;
        Ok(Self {
            db,
            _owner_lock: JournalFileLock(lock),
        })
    }

    /// The caller must present an actual current E02 Node-side guard.
    /// A previously staged request is idempotent, never executable again.
    ///
    /// # Errors
    ///
    /// Rejects stale session/lease authority, invalid digests, conflicts and storage failures.
    pub fn stage(
        &mut self,
        agent: &NodeAgent,
        guard: &NodeDispatchGuard,
        frame: &DispatchRequestFrame,
        now: u64,
        digest: &str,
    ) -> Result<StageResult, JournalError> {
        if !valid_digest(digest) {
            return Err(JournalError::Invalid("request digest"));
        }
        guard.invoke_if_authorized(agent, frame, now, || ())?;
        let id = identity(&frame.dispatch_ref)?;
        let attempt = identity(&frame.attempt_ref)?;
        let node = identity(&frame.node_id)?;
        let generation = i64::try_from(frame.node_generation.value())
            .map_err(|_| JournalError::Invalid("generation overflow"))?;
        let epoch = i64::try_from(frame.connection_epoch.value())
            .map_err(|_| JournalError::Invalid("epoch overflow"))?;
        let fence =
            i64::try_from(frame.fence).map_err(|_| JournalError::Invalid("fence overflow"))?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<(String, String, String, i64, i64, i64)> = tx
            .query_row(
                "SELECT attempt,digest,node,generation,epoch,fence
             FROM ptah_gateway_attempts WHERE dispatch=?1",
                params![id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .optional()?;
        if let Some(found) = prior {
            if found != (attempt, digest.to_owned(), node, generation, epoch, fence) {
                return Err(JournalError::Conflict("dispatch identity changed"));
            }
            tx.commit()?;
            return Ok(StageResult::AlreadyRegistered);
        }
        // An A04 Attempt is single-effect. Raising a Fence after a crash does
        // not prove the previous external effect was absent. An owner must
        // reconcile it and issue a NEW Attempt identity before dispatching
        // any replacement work. Even a completed Attempt is not a replay token.
        let previous_attempts: i64 = tx.query_row(
            "SELECT COUNT(*) FROM ptah_gateway_attempts WHERE attempt=?1",
            params![attempt],
            |row| row.get(0),
        )?;
        if previous_attempts != 0 {
            return Err(JournalError::Conflict("attempt identity already used"));
        }
        tx.execute(
            "INSERT INTO ptah_gateway_attempts
             (dispatch,attempt,digest,node,generation,epoch,fence,phase)
             VALUES (?1,?2,?3,?4,?5,?6,?7,'in_flight')",
            params![id, attempt, digest, node, generation, epoch, fence],
        )?;
        tx.commit()?;
        Ok(StageResult::StagedNew)
    }

    /// Durably stage the exact E02-approved dispatch before any A05 side effect.
    /// A repeated dispatch identity is never spawned again, regardless of phase.
    ///
    /// # Errors
    ///
    /// Rejects missing/expired E02 authority, invalid request digest, a duplicate
    /// or conflicting durable attempt, stale Provider context or failed spawn.
    // Preserve the full explicit E02/A05 authority signature at this boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_once(
        &mut self,
        agent: &NodeAgent,
        guard: &NodeDispatchGuard,
        frame: &DispatchRequestFrame,
        now: u64,
        digest: &str,
        provider: &NativeProcessProvider,
        expected: &AttemptContext,
        spec: ProcessSpec,
    ) -> Result<EntityId, JournalError> {
        if self.stage(agent, guard, frame, now, digest)? != StageResult::StagedNew {
            return Err(JournalError::Conflict("attempt already registered"));
        }
        let process =
            spawn_native_process_if_authorized(guard, agent, frame, now, provider, expected, spec)
                .map_err(JournalError::Dispatch)?;
        // Stage was durable *before* spawn. A failed binding never permits
        // retrying the same Attempt; the outcome remains uncertain.
        let dispatch = identity(&frame.dispatch_ref)?;
        let attempt = identity(&frame.attempt_ref)?;
        let process_ref = identity(&process)?;
        let updated = self.db.execute(
            "UPDATE ptah_gateway_attempts SET process_ref=?1
             WHERE dispatch=?2 AND attempt=?3 AND phase='in_flight'
             AND process_ref IS NULL",
            params![process_ref, dispatch, attempt],
        )?;
        if updated != 1 {
            return Err(JournalError::Conflict(
                "spawned A05 process not bound to Attempt",
            ));
        }
        Ok(process)
    }

    /// Read back one immutable dispatch identity.
    ///
    /// # Errors
    ///
    /// Propagates identity serialization and database errors.
    pub fn get(
        &self,
        frame: &DispatchRequestFrame,
    ) -> Result<Option<RetainedAttempt>, JournalError> {
        let id = identity(&frame.dispatch_ref)?;
        self.db
            .query_row(
                "SELECT attempt,node,generation,epoch,digest,phase,fence,exit_code,stdout_digest,process_ref
             FROM ptah_gateway_attempts WHERE dispatch=?1",
                params![id],
                |r| {
                    let fence: i64 = r.get(6)?;
                    let generation: i64 = r.get(2)?;
                    let epoch: i64 = r.get(3)?;
                    Ok(RetainedAttempt {
                        attempt: r.get(0)?,
                        node: r.get(1)?,
                        generation: u64::try_from(generation)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        connection_epoch: u64::try_from(epoch)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        digest: r.get(4)?,
                        phase: r.get(5)?,
                        fence: u64::try_from(fence).map_err(|_| rusqlite::Error::InvalidQuery)?,
                        exit_code: r.get(7)?,
                        stdout_digest: r.get(8)?,
                        process_ref: r.get(9)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Enumerate crash-interrupted attempts for explicit owner reconciliation.
    /// This is read-only and never promotes an attempt to completed or runnable.
    ///
    /// # Errors
    ///
    /// Propagates database errors and rejects an invalid stored fence.
    pub fn unresolved(&self) -> Result<Vec<RecoveryCandidate>, JournalError> {
        let mut statement = self.db.prepare(
            "SELECT dispatch,attempt,digest,node,generation,epoch,fence
             FROM ptah_gateway_attempts
             WHERE phase='needs_reconciliation'
             ORDER BY attempt, fence, dispatch",
        )?;
        let mut rows = statement.query([])?;
        let mut candidates = Vec::new();
        while let Some(row) = rows.next()? {
            let generation: i64 = row.get(4)?;
            let epoch: i64 = row.get(5)?;
            let fence: i64 = row.get(6)?;
            candidates.push(RecoveryCandidate {
                dispatch: row.get(0)?,
                attempt: row.get(1)?,
                digest: row.get(2)?,
                node: row.get(3)?,
                generation: u64::try_from(generation)
                    .map_err(|_| JournalError::Invalid("stored generation"))?,
                epoch: u64::try_from(epoch).map_err(|_| JournalError::Invalid("stored epoch"))?,
                fence: u64::try_from(fence).map_err(|_| JournalError::Invalid("stored fence"))?,
            });
        }
        Ok(candidates)
    }

    /// Observe a real A05 exit and complete only this exact in-flight attempt.
    /// Incomplete, truncated or ambiguous output cannot create success evidence.
    ///
    /// # Errors
    ///
    /// Rejects missing or mismatched A05 evidence, replay, truncation and storage failures.
    pub fn complete_from_process(
        &mut self,
        agent: &NodeAgent,
        frame: &DispatchRequestFrame,
        request_digest: &str,
        provider: &NativeProcessProvider,
        process_id: EntityId,
    ) -> Result<String, JournalError> {
        let dispatch_identity = identity(&frame.dispatch_ref)?;
        let attempt_identity = identity(&frame.attempt_ref)?;
        let exact_process = identity(&process_id)?;
        let saved: Option<(String, Option<String>)> = self
            .db
            .query_row(
                "SELECT attempt,process_ref FROM ptah_gateway_attempts WHERE dispatch=?1",
                params![&dispatch_identity],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if saved != Some((attempt_identity.clone(), Some(exact_process.clone()))) {
            return Err(JournalError::Conflict(
                "wrong process for persisted Attempt",
            ));
        }
        let snapshot = provider
            .snapshot(process_id)
            .map_err(|_| JournalError::Invalid("A05 snapshot unavailable"))?;
        if snapshot.record.node_generation != agent.generation().value() {
            return Err(JournalError::Conflict("A05 node generation mismatch"));
        }
        let exit = snapshot
            .record
            .exit
            .as_ref()
            .ok_or(JournalError::Invalid("no observed A05 exit"))?;
        let stdout = snapshot
            .stdout
            .as_ref()
            .ok_or(JournalError::Invalid("no A05 stdout readback"))?;
        if stdout.truncated_bytes != 0 {
            return Err(JournalError::Invalid("truncated A05 output"));
        }
        let digest = format!("sha256:{:x}", Sha256::digest(&stdout.bytes));
        let id = identity(&frame.dispatch_ref)?;
        let node = identity(&frame.node_id)?;
        let generation = i64::try_from(frame.node_generation.value())
            .map_err(|_| JournalError::Invalid("generation overflow"))?;
        let epoch = i64::try_from(frame.connection_epoch.value())
            .map_err(|_| JournalError::Invalid("epoch overflow"))?;
        let fence =
            i64::try_from(frame.fence).map_err(|_| JournalError::Invalid("fence overflow"))?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = tx.execute(
            "UPDATE ptah_gateway_attempts
             SET phase='completed',exit_code=?1,stdout_digest=?2
             WHERE dispatch=?3 AND digest=?4 AND node=?5 AND generation=?6
             AND epoch=?7 AND fence=?8 AND phase='in_flight'
              AND attempt=?9 AND process_ref=?10",
            params![
                exit.exit_code,
                &digest,
                id,
                request_digest,
                node,
                generation,
                epoch,
                fence,
                attempt_identity,
                exact_process
            ],
        )?;
        if updated != 1 {
            return Err(JournalError::Conflict("attempt not in flight"));
        }
        tx.commit()?;
        Ok(digest)
    }
}
