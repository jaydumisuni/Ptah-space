//! Read-only projection of Control-verified, independently witnessed A05 effects.
//! A written Control checkpoint is never an execution receipt by itself.
use ptah_control::AuthorizedSubmission;
use rusqlite::{Connection, OpenFlags, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Serialize)]
pub(crate) struct IndependentEffect {
    pub(crate) witness_id: String,
    pub(crate) evidence_digest: String,
    pub(crate) exit_code: i32,
    pub(crate) stdout_digest: String,
    pub(crate) control_state: &'static str,
    pub(crate) completion_accepted: bool,
}

pub(crate) fn submission_digest(submission: &AuthorizedSubmission) -> Result<String, String> {
    let bytes = serde_json::to_vec(submission)
        .map_err(|e| format!("cannot encode original Control submission: {e}"))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

/// Only a persisted Control verified-effect entry bound to the exact submitted
/// payload digest may appear. No local witness signing and no auto acceptance.
pub(crate) fn lookup_effect(
    path: &Path,
    submission: &AuthorizedSubmission,
) -> Result<Option<IndependentEffect>, String> {
    let metadata = path
        .symlink_metadata()
        .map_err(|e| format!("receipt database unavailable: {e}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(String::from("receipt database must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
            return Err(String::from(
                "verified evidence database ownership boundary unsafe",
            ));
        }
    }
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("cannot open read-only evidence: {e}"))?;
    db.busy_timeout(std::time::Duration::from_secs(1))
        .map_err(|e| format!("cannot bound read-only evidence: {e}"))?;
    let digest = submission_digest(submission)?;
    let mut statement = db
        .prepare(
            "SELECT v.witness_id,v.evidence_digest,v.exit_code,v.stdout_digest
         FROM control_verified_effects v
         INNER JOIN control_dispatches d ON d.dispatch=v.dispatch AND d.attempt=v.attempt
         WHERE d.request_digest=?1 LIMIT 2",
        )
        .map_err(|e| format!("verified evidence schema unavailable: {e}"))?;
    let rows = statement
        .query_map(params![digest], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i32>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|e| format!("verified evidence lookup failed: {e}"))?;
    let entries = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| format!("verified evidence invalid: {e}"))?;
    if entries.len() > 1 {
        return Err(String::from(
            "multiple effects for one submission: reconciliation required",
        ));
    }
    let Some((witness_id, evidence_digest, exit_code, stdout_digest)) = entries.into_iter().next()
    else {
        return Ok(None);
    };
    let is_digest = |v: &str| {
        v.len() == 71
            && v.starts_with("sha256:")
            && v[7..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    };
    if witness_id.is_empty() || !is_digest(&evidence_digest) || !is_digest(&stdout_digest) {
        return Err(String::from("corrupt independent effect receipt"));
    }
    Ok(Some(IndependentEffect {
        witness_id,
        evidence_digest,
        exit_code,
        stdout_digest,
        control_state: "independent_witness_evidence_only",
        completion_accepted: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ptah_control::{ControlKind, HumanControlRequest, HumanSnapshot, authorize_control};
    use rusqlite::params;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn submission() -> AuthorizedSubmission {
        let snapshot: HumanSnapshot =
            serde_json::from_str(include_str!("../tests/fixtures/a14_snapshot.json"))
                .expect("fixture");
        authorize_control(
            &snapshot,
            HumanControlRequest {
                request_id: "receipt-readback-1".into(),
                kind: ControlKind::CheckpointRequest,
                target_id: snapshot.authority.workspace_id.clone(),
                expected: snapshot.authority.clone(),
                provider_id: None,
                expected_provider_generation: None,
                approval_id: None,
                payload: serde_json::json!({"caller_context":{
                    "schema":"ptah.tool-caller.v1","tool":"supervisor","project":"ptah"
                }}),
            },
        )
        .expect("authorized checkpoint")
    }
    #[test]
    fn witnessed_effect_is_bound_to_original_submission_digest() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("ptah-receipt-{}-{nonce}.db", std::process::id()));
        let origin = submission();
        let digest = submission_digest(&origin).unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE control_dispatches(
                dispatch TEXT, attempt TEXT, request_digest TEXT);
             CREATE TABLE control_verified_effects(
                dispatch TEXT,attempt TEXT,witness_id TEXT,
                evidence_digest TEXT,exit_code INTEGER,stdout_digest TEXT);",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        conn.execute(
            "INSERT INTO control_dispatches VALUES(?1,?2,?3)",
            params!["dispatch-1", "attempt-1", &digest],
        )
        .unwrap();
        assert!(lookup_effect(&path, &origin).unwrap().is_none());
        conn.execute(
            "INSERT INTO control_verified_effects VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                "dispatch-1",
                "attempt-1",
                "trusted-observer",
                format!("sha256:{}", "1".repeat(64)),
                0,
                format!("sha256:{}", "2".repeat(64))
            ],
        )
        .unwrap();
        let observed = lookup_effect(&path, &origin).unwrap().unwrap();
        assert_eq!(observed.witness_id, "trusted-observer");
        assert!(!observed.completion_accepted);
        let mut altered = origin.clone();
        altered.request_id = "receipt-readback-2".into();
        assert!(lookup_effect(&path, &altered).unwrap().is_none());
        conn.execute(
            "INSERT INTO control_dispatches VALUES(?1,?2,?3)",
            params!["dispatch-2", "attempt-2", &digest],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO control_verified_effects VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                "dispatch-2",
                "attempt-2",
                "trusted-observer",
                format!("sha256:{}", "3".repeat(64)),
                0,
                format!("sha256:{}", "2".repeat(64))
            ],
        )
        .unwrap();
        assert!(
            lookup_effect(&path, &origin).is_err(),
            "ambiguous receipts never pass"
        );
        drop(conn);
        std::fs::remove_file(path).unwrap();
    }
}
