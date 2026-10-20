//! E06-04: immutable negative reconciliation evidence.
//!
//! A receipt records what a separate owner/observer reported. It never grants
//! E01-E05 authority and never authorizes local or remote execution.
use crate::LocalSequence;

/// A negative or unresolved result. There is intentionally no "approved" variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconciliationFinding {
    MissingE01,
    StaleE01,
    MissingE02,
    StaleFence,
    MissingE03,
    MissingE04,
    MissingE05,
    ChangedObject,
    ConflictingEffect,
    InterruptedReconnect,
    UnknownOutcome,
}
impl ReconciliationFinding {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingE01 => "missing_e01",
            Self::StaleE01 => "stale_e01",
            Self::MissingE02 => "missing_e02",
            Self::StaleFence => "stale_fence",
            Self::MissingE03 => "missing_e03",
            Self::MissingE04 => "missing_e04",
            Self::MissingE05 => "missing_e05",
            Self::ChangedObject => "changed_object",
            Self::ConflictingEffect => "conflicting_effect",
            Self::InterruptedReconnect => "interrupted_reconnect",
            Self::UnknownOutcome => "unknown_outcome",
        }
    }
    #[must_use]
    pub fn from_strict(value: &str) -> Option<Self> {
        Some(match value {
            "missing_e01" => Self::MissingE01,
            "stale_e01" => Self::StaleE01,
            "missing_e02" => Self::MissingE02,
            "stale_fence" => Self::StaleFence,
            "missing_e03" => Self::MissingE03,
            "missing_e04" => Self::MissingE04,
            "missing_e05" => Self::MissingE05,
            "changed_object" => Self::ChangedObject,
            "conflicting_effect" => Self::ConflictingEffect,
            "interrupted_reconnect" => Self::InterruptedReconnect,
            "unknown_outcome" => Self::UnknownOutcome,
            _ => return None,
        })
    }
}

/// A local record of an independent evidence reference, NOT verified authority.
/// Store only digests, never credentials, device identifiers or private evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciliationReceipt {
    pub intent_id: String,
    pub origin: LocalSequence,
    pub finding: ReconciliationFinding,
    pub evidence_digest: String,
}
impl ReconciliationReceipt {
    /// E06 receipts must never be interpreted as execution authorizations.
    #[must_use]
    pub const fn authority_granted(&self) -> bool {
        false
    }
}
/// Reject ambiguous evidence addresses; digest syntax alone does NOT verify its source.
#[must_use]
pub fn valid_evidence_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

use crate::{
    durable::{DurableIntentError, DurableIntentJournal},
    ReplayDisposition,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

impl DurableIntentJournal {
    /// Return only immutable *negative* evidence tied to queued intent identities.
    ///
    /// This checks local integrity, not cryptographic trust or E01-E05 authority.
    ///
    /// # Errors
    /// Rejects altered, orphaned, noncanonical or conflicting stored records.
    pub fn findings(&self) -> Result<Vec<ReconciliationReceipt>, DurableIntentError> {
        let mut stmt = self.db.prepare(
            "SELECT f.node,f.sequence,f.intent_id,f.finding,f.evidence_digest,q.intent_id
             FROM reconciliation_findings f
             LEFT JOIN queued_intents q ON q.node=f.node AND q.sequence=f.sequence
             ORDER BY f.node,f.sequence",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?;
        let mut findings = Vec::new();
        for result in rows {
            let (node, raw_sequence, intent_id, finding, evidence_digest, queue_identity) = result?;
            if queue_identity.as_deref() != Some(intent_id.as_str()) {
                return Err(DurableIntentError::Integrity(
                    "orphaned reconciliation receipt",
                ));
            }
            if !valid_evidence_digest(&evidence_digest) {
                return Err(DurableIntentError::Integrity(
                    "invalid reconciliation evidence digest",
                ));
            }
            let parsed = ReconciliationFinding::from_strict(&finding).ok_or(
                DurableIntentError::Integrity("invalid reconciliation finding"),
            )?;
            let sequence = raw_sequence
                .parse::<u64>()
                .map_err(|_| DurableIntentError::Integrity("invalid receipt sequence"))?;
            if sequence == 0 || format!("{sequence:020}") != raw_sequence {
                return Err(DurableIntentError::Integrity(
                    "noncanonical receipt sequence",
                ));
            }
            findings.push(ReconciliationReceipt {
                intent_id,
                origin: LocalSequence {
                    node_id: node,
                    value: sequence,
                },
                finding: parsed,
                evidence_digest,
            });
        }
        Ok(findings)
    }

    /// Validate every retained finding on reopen, including its queued parent.
    ///
    /// # Errors
    /// Fails closed on tampered or orphaned records.
    pub fn verify_findings(&self) -> Result<(), DurableIntentError> {
        self.findings().map(|_| ())
    }

    /// Append one terminal negative or unresolved finding to the exact intent.
    ///
    /// The evidence digest identifies an external observation but does NOT
    /// establish its authenticity. No positive approval, replay or dispatch
    /// transition exists in this API. A conflicting second receipt is rejected,
    /// never last-write-wins. Reattempts need a fresh intent and owner review.
    ///
    /// # Errors
    /// Rejects unknown intents, invalid digests and conflicting replays.
    pub fn record_finding(
        &mut self,
        intent_id: &str,
        finding: ReconciliationFinding,
        evidence_digest: &str,
    ) -> Result<(ReconciliationReceipt, ReplayDisposition), DurableIntentError> {
        if !valid_evidence_digest(evidence_digest) {
            return Err(DurableIntentError::Integrity(
                "invalid reconciliation evidence digest",
            ));
        }
        // Recheck existing state before a write, even if an attacker changed it
        // after open. This is separate from verifying the external observer.
        self.verify()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let queued: Option<(String, String)> = tx
            .query_row(
                "SELECT node,sequence FROM queued_intents WHERE intent_id=?1",
                params![intent_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (node, raw_sequence) =
            queued.ok_or(DurableIntentError::Conflict("unknown queued intent"))?;
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT finding,evidence_digest FROM reconciliation_findings
                 WHERE intent_id=?1",
                params![intent_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let disposition = if let Some((old_finding, old_digest)) = existing {
            if old_finding != finding.as_str() || old_digest != evidence_digest {
                return Err(DurableIntentError::Conflict(
                    "conflicting reconciliation receipt",
                ));
            }
            ReplayDisposition::Idempotent
        } else {
            tx.execute(
                "INSERT INTO reconciliation_findings
                 (node,sequence,intent_id,finding,evidence_digest)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    node,
                    raw_sequence,
                    intent_id,
                    finding.as_str(),
                    evidence_digest
                ],
            )?;
            ReplayDisposition::Distinct
        };
        tx.commit()?;
        let sequence = raw_sequence
            .parse::<u64>()
            .map_err(|_| DurableIntentError::Integrity("invalid receipt sequence"))?;
        Ok((
            ReconciliationReceipt {
                intent_id: intent_id.to_owned(),
                origin: LocalSequence {
                    node_id: node,
                    value: sequence,
                },
                finding,
                evidence_digest: evidence_digest.to_owned(),
            },
            disposition,
        ))
    }
}
