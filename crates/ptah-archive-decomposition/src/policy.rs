use crate::{
    ArchiveBackend, DecompositionBudget, DecompositionError, DecompositionOutcome,
    DecompositionPlan, DecompositionSpec, InventoryEntry, MemberKind, ParseReport, ParseTerminal,
    RecoveredMember,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

struct Planner<'a, B: ArchiveBackend + ?Sized> {
    backend: &'a B,
    budget: DecompositionBudget,
    inventory: Vec<InventoryEntry>,
    recovered: Vec<RecoveredMember>,
    canonical_paths: HashSet<String>,
    processed_bytes: u64,
    warnings: Vec<String>,
    limitations: Vec<String>,
    unknown_gaps: Vec<String>,
    outcome: DecompositionOutcome,
}

/// Build a deterministic backend-neutral A12 plan without mutating canonical state.
///
/// # Errors
/// Fails only for invalid caller policy, a backend that cannot return a bounded
/// report at all, or accounting/path invariants that prevent truthful planning.
pub fn decompose<B: ArchiveBackend + ?Sized>(
    source_bytes: &[u8],
    spec: &DecompositionSpec,
    backend: &B,
) -> Result<DecompositionPlan, DecompositionError> {
    validate_budget(spec.budget)?;
    if spec.source_revision_ref.entity_kind.as_str() != "object.revision" {
        return Err(DecompositionError::SourceMismatch);
    }
    let identity = stable_decomposition_identity(spec);
    let backend_identity = backend.identity();
    let mut planner = Planner {
        backend,
        budget: spec.budget,
        inventory: Vec::new(),
        recovered: Vec::new(),
        canonical_paths: HashSet::new(),
        processed_bytes: 0,
        warnings: Vec::new(),
        limitations: Vec::new(),
        unknown_gaps: Vec::new(),
        outcome: DecompositionOutcome::Complete,
    };
    let root_digest = sha256(source_bytes);
    planner.walk_container(source_bytes, &root_digest, 0, None, "")?;
    let processed_members = u64::try_from(planner.inventory.len())
        .map_err(|_| DecompositionError::AccountingOverflow)?;
    let achieved_level = if planner.inventory.is_empty() {
        "L1_detected"
    } else if planner.recovered.is_empty() {
        "L2_inventoried"
    } else {
        "L3_decomposed"
    };
    Ok(DecompositionPlan {
        decomposition_identity: identity,
        source_revision_ref: spec.source_revision_ref.clone(),
        backend: backend_identity,
        inventory: planner.inventory,
        recovered_members: planner.recovered,
        outcome: planner.outcome,
        requested_level: spec.requested_level.clone(),
        achieved_level: achieved_level.to_owned(),
        budget_request: spec.budget,
        processed_members,
        processed_bytes: planner.processed_bytes,
        unknown_gaps: planner.unknown_gaps,
        warnings: planner.warnings,
        limitations: planner.limitations,
    })
}

/// Return the stable A12 decomposition identity. Replaceable backend details are
/// deliberately excluded so backend replacement does not become product identity.
#[must_use]
pub fn stable_decomposition_identity(spec: &DecompositionSpec) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ptah.a12.decomposition.v0.1.0\0");
    hasher.update(spec.source_revision_ref.entity_id.to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.source_revision_ref.entity_kind.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.requested_level.as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.budget.max_depth.to_le_bytes());
    hasher.update(spec.budget.max_members.to_le_bytes());
    hasher.update(spec.budget.max_expanded_bytes.to_le_bytes());
    hasher.update(spec.budget.max_member_bytes.to_le_bytes());
    hasher.update(spec.budget.max_path_chars.to_le_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

impl<B: ArchiveBackend + ?Sized> Planner<'_, B> {
    fn walk_container(
        &mut self,
        bytes: &[u8],
        container_digest: &str,
        depth: u32,
        parent_inventory_index: Option<usize>,
        path_prefix: &str,
    ) -> Result<(), DecompositionError> {
        if depth > self.budget.max_depth {
            self.mark_incomplete(
                DecompositionOutcome::BudgetExhausted,
                format!("nested depth exceeds {}", self.budget.max_depth),
            );
            return Ok(());
        }
        let report = self.backend.parse(bytes)?;
        self.warnings.extend(report.warnings.iter().cloned());
        self.limitations.extend(report.limitations.iter().cloned());
        if matches!(
            report.terminal,
            ParseTerminal::UnsupportedFormat | ParseTerminal::Opaque
        ) && depth > 0
        {
            return Ok(());
        }
        self.consume_report(
            report,
            container_digest,
            depth,
            parent_inventory_index,
            path_prefix,
        )
    }

    fn consume_report(
        &mut self,
        report: ParseReport,
        container_digest: &str,
        depth: u32,
        parent_inventory_index: Option<usize>,
        path_prefix: &str,
    ) -> Result<(), DecompositionError> {
        for member in report.members {
            if self.member_limit_reached()? {
                self.mark_incomplete(
                    DecompositionOutcome::BudgetExhausted,
                    "member-count budget exhausted".to_owned(),
                );
                break;
            }
            if !self.consume_member(
                &member,
                container_digest,
                depth,
                parent_inventory_index,
                path_prefix,
            )? {
                break;
            }
        }
        self.apply_terminal(report.terminal);
        Ok(())
    }

    fn consume_member(
        &mut self,
        member: &crate::ParsedMember,
        container_digest: &str,
        depth: u32,
        parent_inventory_index: Option<usize>,
        path_prefix: &str,
    ) -> Result<bool, DecompositionError> {
        let Ok(local_path) = canonical_member_path(&member.path, self.budget.max_path_chars) else {
            self.mark_incomplete(
                DecompositionOutcome::Failed,
                format!("rejected archive path: {}", member.path),
            );
            return Ok(false);
        };
        let logical_path = join_path(path_prefix, &local_path);
        if !self.canonical_paths.insert(logical_path.clone()) {
            self.mark_incomplete(
                DecompositionOutcome::Failed,
                format!("duplicate canonical path: {logical_path}"),
            );
            return Ok(false);
        }
        let entry_index = self.inventory.len();
        match member.kind {
            MemberKind::Regular => self.consume_regular_member(
                &member.bytes,
                &logical_path,
                container_digest,
                depth,
                parent_inventory_index,
                entry_index,
            ),
            MemberKind::Directory => {
                self.inventory.push(InventoryEntry {
                    logical_path,
                    kind: MemberKind::Directory,
                    depth,
                    container_sha256: container_digest.to_owned(),
                    member_sha256: None,
                    byte_size: 0,
                });
                Ok(true)
            }
            kind @ (MemberKind::Symlink | MemberKind::Hardlink | MemberKind::Special) => {
                self.inventory.push(InventoryEntry {
                    logical_path: logical_path.clone(),
                    kind,
                    depth,
                    container_sha256: container_digest.to_owned(),
                    member_sha256: None,
                    byte_size: 0,
                });
                self.mark_incomplete(
                    DecompositionOutcome::Failed,
                    format!("rejected {} entry: {logical_path}", kind.as_str()),
                );
                Ok(false)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn consume_regular_member(
        &mut self,
        bytes: &[u8],
        logical_path: &str,
        container_digest: &str,
        depth: u32,
        parent_inventory_index: Option<usize>,
        entry_index: usize,
    ) -> Result<bool, DecompositionError> {
        let size =
            u64::try_from(bytes.len()).map_err(|_| DecompositionError::AccountingOverflow)?;
        if size > self.budget.max_member_bytes {
            self.mark_incomplete(
                DecompositionOutcome::BudgetExhausted,
                format!("member exceeds per-member budget: {logical_path}"),
            );
            return Ok(false);
        }
        let next_total = self
            .processed_bytes
            .checked_add(size)
            .ok_or(DecompositionError::AccountingOverflow)?;
        if next_total > self.budget.max_expanded_bytes {
            self.mark_incomplete(
                DecompositionOutcome::BudgetExhausted,
                format!("expanded-byte budget exhausted at: {logical_path}"),
            );
            return Ok(false);
        }
        let member_digest = sha256(bytes);
        self.inventory.push(InventoryEntry {
            logical_path: logical_path.to_owned(),
            kind: MemberKind::Regular,
            depth,
            container_sha256: container_digest.to_owned(),
            member_sha256: Some(member_digest.clone()),
            byte_size: size,
        });
        self.recovered.push(RecoveredMember {
            inventory_index: entry_index,
            parent_inventory_index,
            logical_path: logical_path.to_owned(),
            bytes: bytes.to_owned(),
            container_sha256: container_digest.to_owned(),
            member_sha256: member_digest.clone(),
            depth,
        });
        self.processed_bytes = next_total;
        if depth < self.budget.max_depth {
            self.walk_container(
                bytes,
                &member_digest,
                depth + 1,
                Some(entry_index),
                logical_path,
            )?;
        }
        Ok(true)
    }

    fn member_limit_reached(&self) -> Result<bool, DecompositionError> {
        let count = u64::try_from(self.inventory.len())
            .map_err(|_| DecompositionError::AccountingOverflow)?;
        Ok(count >= self.budget.max_members)
    }

    fn apply_terminal(&mut self, terminal: ParseTerminal) {
        let mapped = terminal_outcome(terminal);
        if mapped != DecompositionOutcome::Complete {
            self.mark_incomplete(mapped, format!("parser terminal: {}", mapped.as_str()));
        }
    }

    fn mark_incomplete(&mut self, outcome: DecompositionOutcome, reason: String) {
        if self.outcome == DecompositionOutcome::Complete {
            self.outcome = outcome;
        } else if self.outcome != outcome && !matches!(self.outcome, DecompositionOutcome::Failed) {
            self.outcome = DecompositionOutcome::Partial;
        }
        if !self.unknown_gaps.iter().any(|item| item == &reason) {
            self.unknown_gaps.push(reason.clone());
        }
        if !self.limitations.iter().any(|item| item == &reason) {
            self.limitations.push(reason);
        }
    }
}

fn validate_budget(budget: DecompositionBudget) -> Result<(), DecompositionError> {
    if budget.max_members == 0 {
        return Err(DecompositionError::InvalidBudget("max_members"));
    }
    if budget.max_expanded_bytes == 0 {
        return Err(DecompositionError::InvalidBudget("max_expanded_bytes"));
    }
    if budget.max_member_bytes == 0 || budget.max_member_bytes > budget.max_expanded_bytes {
        return Err(DecompositionError::InvalidBudget("max_member_bytes"));
    }
    if budget.max_path_chars == 0 || budget.max_path_chars > 8192 {
        return Err(DecompositionError::InvalidBudget("max_path_chars"));
    }
    Ok(())
}

fn canonical_member_path(raw: &str, max_chars: usize) -> Result<String, DecompositionError> {
    if raw.is_empty() || raw.contains('\0') || raw.chars().count() > max_chars {
        return Err(DecompositionError::InvalidPath(raw.to_owned()));
    }
    if raw.starts_with('/') || raw.starts_with('\\') || is_windows_drive_path(raw) {
        return Err(DecompositionError::InvalidPath(raw.to_owned()));
    }
    let normalized = raw.replace('\\', "/");
    if normalized.starts_with("//") {
        return Err(DecompositionError::InvalidPath(raw.to_owned()));
    }
    let mut parts = Vec::new();
    for component in normalized.split('/') {
        match component {
            "" | "." => {}
            ".." => return Err(DecompositionError::InvalidPath(raw.to_owned())),
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        return Err(DecompositionError::InvalidPath(raw.to_owned()));
    }
    let result = parts.join("/");
    if result.chars().count() > max_chars {
        return Err(DecompositionError::InvalidPath(raw.to_owned()));
    }
    Ok(result)
}

fn is_windows_drive_path(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn join_path(prefix: &str, local: &str) -> String {
    if prefix.is_empty() {
        local.to_owned()
    } else {
        format!("{prefix}/{local}")
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

const fn terminal_outcome(terminal: ParseTerminal) -> DecompositionOutcome {
    match terminal {
        ParseTerminal::Complete => DecompositionOutcome::Complete,
        ParseTerminal::LockedEncrypted => DecompositionOutcome::LockedEncrypted,
        ParseTerminal::CredentialRequired => DecompositionOutcome::CredentialRequired,
        ParseTerminal::WrongCredential => DecompositionOutcome::WrongCredential,
        ParseTerminal::UnsupportedEncryption => DecompositionOutcome::UnsupportedEncryption,
        ParseTerminal::Malformed => DecompositionOutcome::Malformed,
        ParseTerminal::Truncated => DecompositionOutcome::Truncated,
        ParseTerminal::ParserError => DecompositionOutcome::ParserError,
        ParseTerminal::ParserCrash => DecompositionOutcome::ParserCrash,
        ParseTerminal::Timeout => DecompositionOutcome::Timeout,
        ParseTerminal::BudgetExhausted => DecompositionOutcome::BudgetExhausted,
        ParseTerminal::UnsupportedFormat => DecompositionOutcome::UnsupportedFormat,
        ParseTerminal::Opaque => DecompositionOutcome::Opaque,
        ParseTerminal::Cancelled => DecompositionOutcome::Cancelled,
        ParseTerminal::Failed => DecompositionOutcome::Failed,
    }
}
