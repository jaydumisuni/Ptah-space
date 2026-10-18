//! E06-02 atomic per-origin local intent journal. Queueing never grants authority.
use crate::{IntentValidationError, LocalSequence, QueuedIntent, ReplayDisposition};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{path::Path, time::Duration};

#[derive(Debug)]
pub enum DurableIntentError {
    Storage(rusqlite::Error),
    Envelope(IntentValidationError),
    Integrity(&'static str),
    Conflict(&'static str),
}
impl From<rusqlite::Error> for DurableIntentError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<IntentValidationError> for DurableIntentError {
    fn from(e: IntentValidationError) -> Self {
        Self::Envelope(e)
    }
}

/// An offline intent prepared without a sequence or dispatch authority.
/// The journal assigns its origin sequence only inside the commit transaction.
#[derive(Debug, Clone)]
pub struct IntentDraft {
    pub intent_id: String,
    pub node_id: String,
    pub workspace_id: String,
    pub activity_id: String,
    pub operation_id: String,
    pub attempt_id: String,
    pub action: String,
    pub canonical_input_digest: String,
}
impl IntentDraft {
    /// Validate an unsequenced draft before opening any persistent journal.
    /// Sequence 1 is only a syntax-validation placeholder, never persisted.
    pub fn validate(&self) -> Result<(), DurableIntentError> {
        self.candidate(1).map(|_| ())
    }

    fn candidate(&self, sequence: u64) -> Result<QueuedIntent, DurableIntentError> {
        Ok(QueuedIntent::try_new(
            self.intent_id.clone(),
            self.workspace_id.clone(),
            self.activity_id.clone(),
            self.operation_id.clone(),
            self.attempt_id.clone(),
            LocalSequence {
                node_id: self.node_id.clone(),
                value: sequence,
            },
            self.action.clone(),
            self.canonical_input_digest.clone(),
        )?)
    }
}

pub struct DurableIntentJournal {
    db: Connection,
}
fn row_intent(row: &rusqlite::Row<'_>) -> rusqlite::Result<QueuedIntent> {
    let node: String = row.get(0)?;
    let sequence: String = row.get(1)?;
    let fields: Vec<String> = (2..=8)
        .map(|i| row.get(i))
        .collect::<rusqlite::Result<_>>()?;
    // Never reconstruct a trusted revalidation flag from an unchecked stored row.
    if row.get::<_, i64>(9)? != 1 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let value = decode_sequence(&sequence).map_err(|_| rusqlite::Error::InvalidQuery)?;
    QueuedIntent::try_new(
        fields[0].clone(),
        fields[1].clone(),
        fields[2].clone(),
        fields[3].clone(),
        fields[4].clone(),
        LocalSequence {
            node_id: node,
            value,
        },
        fields[5].clone(),
        fields[6].clone(),
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)
}
fn encode_sequence(value: u64) -> String {
    format!("{value:020}")
}
fn decode_sequence(value: &str) -> Result<u64, DurableIntentError> {
    let sequence = value
        .parse::<u64>()
        .map_err(|_| DurableIntentError::Integrity("sequence encoding"))?;
    if encode_sequence(sequence) != value || sequence == 0 {
        return Err(DurableIntentError::Integrity("noncanonical sequence"));
    }
    Ok(sequence)
}
// A duplicate replay is still a journal acknowledgement. Check the committed
// cursor against its immutable tail before returning Idempotent, without an
// O(n) scan on every append. Full interior-gap validation remains on open().
fn verify_replay_origin_tail(
    tx: &rusqlite::Transaction<'_>,
    node: &str,
) -> Result<(), DurableIntentError> {
    let cursor: Option<String> = tx
        .query_row(
            "SELECT sequence FROM origin_cursor WHERE node=?1",
            params![node],
            |row| row.get(0),
        )
        .optional()?;
    let tail: Option<String> = tx
        .query_row(
            "SELECT sequence FROM queued_intents WHERE node=?1
             ORDER BY sequence DESC LIMIT 1",
            params![node],
            |row| row.get(0),
        )
        .optional()?;
    if cursor != tail {
        return Err(DurableIntentError::Integrity(
            "cursor/journal tail mismatch",
        ));
    }
    // A matching pair is not sufficient: both values may have been corrupted
    // into the same noncanonical sequence after this journal was opened.
    if let Some(raw) = cursor.as_deref() {
        let committed = decode_sequence(raw)?;
        // A matching count and tail can conceal a forged interior sequence
        // or an invalid envelope in an earlier row. Revalidate every stored
        // envelope on duplicate replay, not only its sequence; distinct
        // appends retain their O(1) allocation path.
        let mut stmt = tx.prepare(
            "SELECT node,sequence,intent_id,workspace_id,activity_id,operation_id,
             attempt_id,action,digest,revalidate FROM queued_intents
             WHERE node=?1 ORDER BY sequence",
        )?;
        let rows = stmt.query_map(params![node], row_intent)?;
        let mut expected = 0_u64;
        for row in rows {
            let item = row?;
            expected = expected
                .checked_add(1)
                .ok_or(DurableIntentError::Integrity("origin sequence overflow"))?;
            if item.origin.value != expected {
                return Err(DurableIntentError::Integrity(
                    "noncontiguous origin journal",
                ));
            }
        }
        if expected != committed {
            return Err(DurableIntentError::Integrity(
                "noncontiguous origin journal",
            ));
        }
    }
    Ok(())
}

impl DurableIntentJournal {
    /// Open the WAL/FULL journal and verify complete per-origin contiguous history.
    /// This store cannot execute or approve queued intents.
    ///
    /// # Errors
    /// Rejects symlinks, corrupt journal rows/cursors and SQLite errors.
    pub fn open(path: &Path) -> Result<Self, DurableIntentError> {
        // Materialize a new database with private permissions before SQLite
        // opens it. Existing files may not be symlinks or aliased hardlinks.
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
            match path.symlink_metadata() {
                Ok(metadata) => {
                    if !metadata.is_file()
                        || metadata.nlink() != 1
                        || (metadata.permissions().mode() & 0o077) != 0
                    {
                        return Err(DurableIntentError::Integrity("unsafe journal file"));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let opened = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path);
                    match opened {
                        Ok(file) => drop(file),
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                            let metadata = path
                                .symlink_metadata()
                                .map_err(|_| DurableIntentError::Integrity("journal race"))?;
                            if !metadata.is_file()
                                || metadata.nlink() != 1
                                || (metadata.permissions().mode() & 0o077) != 0
                            {
                                return Err(DurableIntentError::Integrity(
                                    "unsafe concurrent journal",
                                ));
                            }
                        }
                        Err(_) => {
                            return Err(DurableIntentError::Integrity("journal create failed"))
                        }
                    }
                }
                Err(_) => return Err(DurableIntentError::Integrity("journal metadata failed")),
            }
            // SQLite may reuse pre-existing WAL/SHM sidecars. Reject unsafe
            // aliases before SQLite can open or modify an unrelated target.
            for suffix in ["-wal", "-shm"] {
                let mut name = path.as_os_str().to_os_string();
                name.push(suffix);
                match Path::new(&name).symlink_metadata() {
                    Ok(metadata)
                        if !metadata.is_file()
                            || metadata.nlink() != 1
                            || (metadata.permissions().mode() & 0o077) != 0 =>
                    {
                        return Err(DurableIntentError::Integrity("unsafe journal sidecar"));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => {
                        return Err(DurableIntentError::Integrity(
                            "journal sidecar metadata failed",
                        ));
                    }
                }
            }
        }
        #[cfg(not(unix))]
        if path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err(DurableIntentError::Integrity("journal path is symlink"));
        }
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(10))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS origin_cursor(
                node TEXT PRIMARY KEY, sequence TEXT NOT NULL CHECK(length(sequence)=20)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS queued_intents(
                node TEXT NOT NULL,sequence TEXT NOT NULL CHECK(length(sequence)=20),
                intent_id TEXT NOT NULL UNIQUE,workspace_id TEXT NOT NULL,
                activity_id TEXT NOT NULL,operation_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL,action TEXT NOT NULL,digest TEXT NOT NULL,
                revalidate INTEGER NOT NULL DEFAULT 1 CHECK(revalidate=1),
                PRIMARY KEY(node,sequence)
            ) WITHOUT ROWID;",
        )?;
        let store = Self { db };
        store.verify()?;
        Ok(store)
    }

    /// Read all recovered envelopes in deterministic Node/sequence order.
    /// No replay authorization or state promotion occurs.
    ///
    /// # Errors
    /// Rejects invalid rows and storage failures.
    pub fn history(&self) -> Result<Vec<QueuedIntent>, DurableIntentError> {
        let mut stmt = self.db.prepare(
            "SELECT node,sequence,intent_id,workspace_id,activity_id,operation_id,
             attempt_id,action,digest,revalidate FROM queued_intents ORDER BY node,sequence",
        )?;
        let rows = stmt.query_map([], row_intent)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Verify all origin streams and stored cursors, including hidden interior gaps.
    ///
    /// # Errors
    /// Rejects any gap, cursor mismatch, forged envelope or invalid checkpoint.
    pub fn verify(&self) -> Result<(), DurableIntentError> {
        let history = self.history()?;
        let mut last = std::collections::HashMap::<&str, u64>::new();
        for item in &history {
            if !item.revalidate_required {
                return Err(DurableIntentError::Integrity("authority flag"));
            }
            let previous = last.get(item.origin.node_id.as_str()).copied().unwrap_or(0);
            let expected = previous
                .checked_add(1)
                .ok_or(DurableIntentError::Integrity("origin sequence overflow"))?;
            if item.origin.value != expected {
                return Err(DurableIntentError::Integrity(
                    "noncontiguous origin journal",
                ));
            }
            last.insert(item.origin.node_id.as_str(), item.origin.value);
        }
        let mut stmt = self.db.prepare("SELECT node,sequence FROM origin_cursor")?;
        let cursors =
            stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut seen = 0;
        for cursor in cursors {
            let (node, raw) = cursor?;
            let value = decode_sequence(&raw)?;
            if last.get(node.as_str()).copied() != Some(value) {
                return Err(DurableIntentError::Integrity("cursor/journal mismatch"));
            }
            seen += 1;
        }
        if seen != last.len() {
            return Err(DurableIntentError::Integrity("journal without cursor"));
        }
        Ok(())
    }

    /// Allocate sequence and persist canonical intent in one SQLite IMMEDIATE
    /// transaction; no sequence is observable until durable commit completes.
    /// Exact duplicate drafts return the unchanged committed envelope.
    /// This does not authorize or execute queued operations.
    ///
    /// # Errors
    /// Rejects invalid drafts, conflicting reused identity or broken cursor/tail.
    pub fn enqueue(
        &mut self,
        draft: &IntentDraft,
    ) -> Result<(QueuedIntent, ReplayDisposition), DurableIntentError> {
        // Reject malformed drafts before acquiring a writer lock. Otherwise an
        // unrelated writer can mask an envelope error as a storage timeout.
        draft.validate()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = tx
            .query_row(
                "SELECT node,sequence,intent_id,workspace_id,activity_id,operation_id,
             attempt_id,action,digest,revalidate FROM queued_intents WHERE intent_id=?1",
                params![draft.intent_id],
                row_intent,
            )
            .optional()?
        {
            let candidate = draft.candidate(existing.origin.value)?;
            if existing != candidate {
                return Err(DurableIntentError::Conflict(
                    "reused intent identity changed",
                ));
            }
            verify_replay_origin_tail(&tx, &existing.origin.node_id)?;
            tx.commit()?;
            return Ok((existing, ReplayDisposition::Idempotent));
        }
        let prior: Option<String> = tx
            .query_row(
                "SELECT sequence FROM origin_cursor WHERE node=?1",
                params![draft.node_id],
                |r| r.get(0),
            )
            .optional()?;
        let tail: Option<String> = tx
            .query_row(
                "SELECT sequence FROM queued_intents WHERE node=?1
             ORDER BY sequence DESC LIMIT 1",
                params![draft.node_id],
                |r| r.get(0),
            )
            .optional()?;
        if prior != tail {
            return Err(DurableIntentError::Integrity(
                "cursor/journal tail mismatch",
            ));
        }
        let next = match prior {
            Some(previous) => decode_sequence(&previous)?
                .checked_add(1)
                .ok_or(DurableIntentError::Integrity("sequence exhausted"))?,
            None => 1,
        };
        let intent = draft.candidate(next)?;
        tx.execute(
            "INSERT INTO queued_intents(node,sequence,intent_id,workspace_id,activity_id,
             operation_id,attempt_id,action,digest,revalidate)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
            params![
                &intent.origin.node_id,
                encode_sequence(next),
                &intent.intent_id,
                &intent.workspace_id,
                &intent.activity_id,
                &intent.operation_id,
                &intent.attempt_id,
                &intent.action,
                &intent.canonical_input_digest,
            ],
        )?;
        tx.execute(
            "INSERT INTO origin_cursor(node,sequence) VALUES(?1,?2)
             ON CONFLICT(node) DO UPDATE SET sequence=excluded.sequence",
            params![&intent.origin.node_id, encode_sequence(next)],
        )?;
        tx.commit()?;
        Ok((intent, ReplayDisposition::Distinct))
    }

    /// Atomically append the next intent and its cursor, never exposing a reservation gap.
    /// Exact duplicate intent returns Idempotent and does not allocate a sequence.
    ///
    /// # Errors
    /// Rejects malformed envelopes, noncontiguity, conflict, exhausted u64 or DB faults.
    pub fn append(
        &mut self,
        intent: &QueuedIntent,
    ) -> Result<ReplayDisposition, DurableIntentError> {
        // Public envelope fields can be mutated after construction; validate all.
        let validated = QueuedIntent::try_new(
            intent.intent_id.clone(),
            intent.workspace_id.clone(),
            intent.activity_id.clone(),
            intent.operation_id.clone(),
            intent.attempt_id.clone(),
            intent.origin.clone(),
            intent.action.clone(),
            intent.canonical_input_digest.clone(),
        )?;
        if validated != *intent {
            return Err(DurableIntentError::Integrity(
                "queued intent cannot grant authority",
            ));
        }
        // Full journal recovery validation occurs on open(). The immediate
        // transaction below serializes writers and validates the local tail;
        // avoid rescanning O(n) history for every O(1) append.
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Look up the immutable identity before checking the next sequence.
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT node,sequence FROM queued_intents WHERE intent_id=?1",
                params![intent.intent_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((node, sequence)) = existing {
            if node != intent.origin.node_id || encode_sequence(intent.origin.value) != sequence {
                return Err(DurableIntentError::Conflict("intent identity conflicts"));
            }
            let stored = tx.query_row(
                "SELECT node,sequence,intent_id,workspace_id,activity_id,operation_id,
                 attempt_id,action,digest,revalidate FROM queued_intents WHERE intent_id=?1",
                params![intent.intent_id],
                row_intent,
            )?;
            if stored == *intent {
                verify_replay_origin_tail(&tx, &intent.origin.node_id)?;
                tx.commit()?;
                return Ok(ReplayDisposition::Idempotent);
            }
            return Err(DurableIntentError::Conflict("intent content changed"));
        }
        let prior: Option<String> = tx
            .query_row(
                "SELECT sequence FROM origin_cursor WHERE node=?1",
                params![intent.origin.node_id],
                |r| r.get(0),
            )
            .optional()?;
        let tail: Option<String> = tx
            .query_row(
                "SELECT sequence FROM queued_intents WHERE node=?1
             ORDER BY sequence DESC LIMIT 1",
                params![intent.origin.node_id],
                |row| row.get(0),
            )
            .optional()?;
        if tail != prior {
            return Err(DurableIntentError::Integrity(
                "cursor/journal tail mismatch",
            ));
        }
        let next = match prior {
            Some(value) => decode_sequence(&value)?
                .checked_add(1)
                .ok_or(DurableIntentError::Integrity("sequence exhausted"))?,
            None => 1,
        };
        if intent.origin.value != next {
            return Err(DurableIntentError::Integrity("expected atomic successor"));
        }
        tx.execute(
            "INSERT INTO queued_intents(node,sequence,intent_id,workspace_id,activity_id,
             operation_id,attempt_id,action,digest,revalidate)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1)",
            params![
                intent.origin.node_id,
                encode_sequence(next),
                intent.intent_id,
                intent.workspace_id,
                intent.activity_id,
                intent.operation_id,
                intent.attempt_id,
                intent.action,
                intent.canonical_input_digest
            ],
        )?;
        tx.execute(
            "INSERT INTO origin_cursor(node,sequence) VALUES(?1,?2)
             ON CONFLICT(node) DO UPDATE SET sequence=excluded.sequence",
            params![intent.origin.node_id, encode_sequence(next)],
        )?;
        tx.commit()?;
        Ok(ReplayDisposition::Distinct)
    }
}

#[cfg(test)]
mod sequence_codec_tests {
    use super::{decode_sequence, encode_sequence};
    #[test]
    fn full_unsigned_u64_range_has_ordered_canonical_encoding() {
        let numbers = [1_u64, 2, 9, 10, 1_000_000, u64::MAX - 1, u64::MAX];
        for n in numbers {
            let text = encode_sequence(n);
            assert_eq!(text.len(), 20);
            assert_eq!(decode_sequence(&text).unwrap(), n);
        }
        for pair in numbers.windows(2) {
            assert!(encode_sequence(pair[0]) < encode_sequence(pair[1]));
        }
        assert!(decode_sequence("00000000000000000000").is_err());
        assert!(decode_sequence("1").is_err());
        assert!(decode_sequence("18446744073709551616").is_err());
    }
}
