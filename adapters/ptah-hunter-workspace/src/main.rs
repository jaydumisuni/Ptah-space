//! Native on-demand Ptah D02 workspace connection for any admitted caller.
//! Knights/trusted ingress owns authentication; Ptah does not re-authorize.
//! Runs one bounded JSON operation then exits. No daemon, provider or lease.
use ptah_ai_workspace::{HunterAdapter, RecordClass, RetrievalRequest, WorkspaceReader};
use ptah_identifiers::EntityRef;
use ptah_workspace::{CreateWorkspace, WorkspaceStore};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
};

const MAX_REQUEST: u64 = 8_192;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    action: String,
    workspace_ref: Option<EntityRef>,
    workspace_key: Option<String>,
    title: Option<String>,
    // Backward-compatible provenance metadata, not a login, Grant or token.
    owner_ref: Option<EntityRef>,
    authority_ref: Option<EntityRef>,
    policy_ref: Option<EntityRef>,
    observed_at: Option<String>,
}
fn clock(timestamp: &str) -> Result<Arc<dyn Fn() -> String + Send + Sync>, String> {
    let safe = timestamp.len() >= 20
        && timestamp.len() <= 40
        && timestamp.ends_with('Z')
        && timestamp
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | ':' | '.'));
    if !safe {
        return Err("INVALID_CURRENT_UTC_CLOCK".into());
    }
    let time = timestamp.to_owned();
    Ok(Arc::new(move || time.clone()))
}
fn inspection(ledger: &Path, req: &Request) -> Result<Value, String> {
    let reference = req.workspace_ref.as_ref().ok_or("WORKSPACE_REF_REQUIRED")?;
    if reference.entity_kind.as_str() != "core.workspace" {
        return Err("WORKSPACE_IDENTITY_CLASS_INVALID".into());
    }
    if req.authority_ref.is_some()
        || req.policy_ref.is_some()
        || req.title.is_some()
        || req.workspace_key.is_some()
    {
        return Err("INSPECT_MUST_NOT_REQUEST_CREATION".into());
    }
    let timestamp = req.observed_at.as_deref().ok_or("CLOCK_REQUIRED")?;
    // Resolve the workspace from the parent-selected ledger. This is durable
    // data/provenance lookup, never a second Ptah caller authorization.
    // Client JSON owner_ref is intentionally NOT used as a credential.
    let projection = WorkspaceStore::open(ledger, clock(timestamp)?)
        .map_err(|_| "PTAH_LEDGER_READ_FAILED")?
        .workspace(reference.entity_id)
        .map_err(|_| "WORKSPACE_NOT_FOUND_OR_INVALID")?;
    if projection.workspace_ref != *reference {
        return Err("WORKSPACE_REFERENCE_MISMATCH".into());
    }
    let reader =
        WorkspaceReader::open(ledger, clock(timestamp)?).map_err(|_| "PTAH_LEDGER_READ_FAILED")?;
    let request = RetrievalRequest {
        actor_ref: projection.owner_ref.clone(),
        source_workspace_ref: reference.clone(),
        target_workspace_ref: reference.clone(),
        record_class: RecordClass::Workspace,
        entity_ref: reference.clone(),
        record_revision: None,
        required_scope: "workspace.read".into(),
        grant_ref: None,
    };
    let record = HunterAdapter::new(&reader)
        .retrieve_exact(&request)
        .map_err(|_| "PTAH_D02_EXACT_RETRIEVAL_DENIED")?;
    // Verify canonical owner *metadata* is internally consistent with the
    // projection. Do not compare it to a caller-supplied owner/identity.
    let recorded_owner: EntityRef = serde_json::from_value(
        record.document.get("owner_ref").cloned().ok_or("OWNER_RECORD_MISSING")?
    ).map_err(|_| "OWNER_RECORD_INVALID")?;
    if recorded_owner != projection.owner_ref {
        return Err("WORKSPACE_METADATA_INCONSISTENT".into());
    }
    if record
        .document
        .get("lifecycle")
        .and_then(|x| x.get("current_state"))
        .and_then(Value::as_str)
        != Some("active")
    {
        return Err("WORKSPACE_NOT_ACTIVE".into());
    }
    Ok(json!({
        "ok":true,"schema":"ptah.hunter-workspace-bridge/1",
        "state":"existing_workspace",
        "workspaceRef":reference,"ownerRef":projection.owner_ref,
        "ownerRefIsMetadataOnly":true,"secondAuthorizationPerformed":false,
        "recordRevision":record.record_revision.value(),
        "recordSchema":record.schema_id,
        "d02ExactRead":true,"e02LeaseIssued":false,
        "executionDispatched":false,"localPathMaterialized":false
    }))
}
fn process(ledger: &Path, request: Request) -> Result<Value, String> {
    match request.action.as_str() {
        "inspect" => inspection(ledger, &request),
        "provision" => {
            if request.workspace_ref.is_some() {
                return Err("PROVISION_CANNOT_SUPPLY_WORKSPACE_REF".into());
            }
            let key = request
                .workspace_key
                .as_deref()
                .ok_or("WORKSPACE_KEY_REQUIRED")?;
            let title = request.title.as_deref().ok_or("TITLE_REQUIRED")?;
            // Existing ledger contracts require provenance-shaped references,
            // not authentication tokens. Accept supplied metadata for backward
            // compatibility, otherwise assign local record provenance without
            // creating a login, membership, Grant or approval.
            let owner = request.owner_ref.clone()
                .map_or_else(|| EntityRef::new("identity.principal"), Ok)
                .map_err(|_| "WORKSPACE_METADATA_INVALID")?;
            let authority = request.authority_ref.clone()
                .map_or_else(|| EntityRef::new("authority.owner"), Ok)
                .map_err(|_| "WORKSPACE_METADATA_INVALID")?;
            let policy_refs = request.policy_ref.clone().into_iter().collect();
            if owner.entity_kind.as_str() != "identity.principal"
                || authority.entity_kind.as_str() != "authority.owner"
                || request.policy_ref.as_ref().is_some_and(|policy|
                    policy.entity_kind.as_str() != "policy.workspace")
            {
                return Err("WORKSPACE_METADATA_KIND_INVALID".into());
            }
            let now = request.observed_at.as_deref().ok_or("CLOCK_REQUIRED")?;
            let mut store =
                WorkspaceStore::open(ledger, clock(now)?).map_err(|_| "PTAH_LEDGER_OPEN_FAILED")?;
            let created = store
                .create_workspace(CreateWorkspace {
                    workspace_key: key.into(),
                    title: title.into(),
                    description: None,
                    owner_ref: owner.clone(),
                    authority_ref: authority.clone(),
                    created_by_ref: owner,
                    policy_refs,
                })
                .map_err(|_| "PTAH_WORKSPACE_CREATE_FAILED")?;
            drop(store);
            inspection(
                ledger,
                &Request {
                    action: "inspect".into(),
                    workspace_ref: Some(created.workspace_ref),
                    workspace_key: None,
                    title: None,
                    owner_ref: None,
                    authority_ref: None,
                    policy_ref: None,
                    observed_at: request.observed_at,
                },
            )
        }
        _ => Err("UNKNOWN_WORKSPACE_OPERATION".into()),
    }
}
fn main() {
    let result = (|| -> Result<Value, String> {
        let mut args = std::env::args_os().skip(1);
        let ledger = args
            .next()
            .map(PathBuf::from)
            .ok_or("LEDGER_ARG_REQUIRED")?;
        if args.next().is_some() {
            return Err("UNEXPECTED_CLI_ARGS".into());
        }
        // The parent controller owns the exact ledger path and exclusive lock.
        // Never infer it from the caller's JSON operation or Workspace reference.
        let mut buf = Vec::new();
        io::stdin()
            .take(MAX_REQUEST + 1)
            .read_to_end(&mut buf)
            .map_err(|_| "REQUEST_READ_FAILED")?;
        if buf.len() as u64 > MAX_REQUEST {
            return Err("REQUEST_TOO_LARGE".into());
        }
        let request: Request =
            serde_json::from_slice(&buf).map_err(|_| "INVALID_REQUEST_SCHEMA")?;
        process(&ledger, request)
    })();
    match result {
        Ok(value) => println!("{value}"),
        Err(err) => {
            println!(
                "{}",
                json!({"ok":false,"schema":"ptah.hunter-workspace-bridge/1",
                  "error":err,"executionDispatched":false,"e02LeaseIssued":false})
            );
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_arbitrary_fields_and_unbound_ids() {
        let principal = EntityRef::new("identity.principal").unwrap();
        let input = json!({"action":"inspect","owner_ref":principal,"unexpected":"test"});
        assert!(serde_json::from_value::<Request>(input).is_err());
        let req = Request {
            action: "inspect".into(),
            workspace_ref: None,
            workspace_key: None,
            title: None,
            owner_ref: Some(principal),
            authority_ref: None,
            policy_ref: None,
            observed_at: Some("2026-10-18T08:40:00Z".into()),
        };
        assert!(process(Path::new("/tmp/ptah-no-ledger-file"), req).is_err());
    }
    #[test]
    fn creates_and_inspects_without_any_owner_or_policy_approval_fields() {
        let path = std::env::temp_dir().join(format!(
            "ptah-knights-open-{}.sqlite3",
            ptah_identifiers::EntityId::new_v7()
        ));
        let new_request: Request = serde_json::from_value(json!({
            "action":"provision",
            "workspace_key":"shared.all-callers",
            "title":"Shared Ptah Workspace",
            "observed_at":"2026-10-19T20:10:00Z"
        })).expect("no login/owner/grant metadata required");
        let created=process(&path,new_request).expect("any admitted caller can create");
        assert_eq!(created["state"], "existing_workspace");
        assert_eq!(created["ownerRefIsMetadataOnly"], true);
        assert_eq!(created["secondAuthorizationPerformed"], false);
        let inspected=process(&path,serde_json::from_value(json!({
            "action":"inspect",
            "workspace_ref": created["workspaceRef"],
            "observed_at":"2026-10-19T20:11:00Z"
        })).unwrap()).expect("any admitted caller can inspect");
        assert_eq!(inspected["workspaceRef"],created["workspaceRef"]);
        assert_eq!(inspected["ownerRef"],created["ownerRef"]);
        let arbitrary_other=EntityRef::new("identity.principal").unwrap();
        let repeated=process(&path,serde_json::from_value(json!({
            "action":"inspect",
            "workspace_ref": created["workspaceRef"],
            "owner_ref": arbitrary_other,
            "observed_at":"2026-10-19T20:11:00Z"
        })).unwrap()).expect("client-supplied owner identity is not an access control");
        assert_eq!(repeated["workspaceRef"],created["workspaceRef"]);
        assert_eq!(repeated["secondAuthorizationPerformed"],false);
        let _=std::fs::remove_file(&path);
    }
    #[test]
    fn provision_then_reopen_exact_d02_record_for_other_admitted_caller() {
        let path = std::env::temp_dir().join(format!(
            "ptah-hunter-d02-{}.sqlite3",
            ptah_identifiers::EntityId::new_v7()
        ));
        let owner = EntityRef::new("identity.principal").unwrap();
        let recorded = process(
            &path,
            Request {
                action: "provision".into(),
                workspace_ref: None,
                workspace_key: Some("hunter.test".into()),
                title: Some("Test Hunter Workspace".into()),
                owner_ref: Some(owner.clone()),
                authority_ref: Some(EntityRef::new("authority.owner").unwrap()),
                policy_ref: Some(EntityRef::new("policy.workspace").unwrap()),
                observed_at: Some("2026-10-18T08:45:00Z".into()),
            },
        )
        .expect("provision");
        assert_eq!(recorded["d02ExactRead"], true);
        let reference: EntityRef =
            serde_json::from_value(recorded["workspaceRef"].clone()).unwrap();
        let query = |actor| Request {
            action: "inspect".into(),
            workspace_ref: Some(reference.clone()),
            workspace_key: None,
            title: None,
            owner_ref: Some(actor),
            authority_ref: None,
            policy_ref: None,
            observed_at: Some("2026-10-18T08:46:00Z".into()),
        };
        assert_eq!(
            process(&path, query(owner)).unwrap()["workspaceRef"],
            recorded["workspaceRef"]
        );
        let wrong = EntityRef::new("identity.principal").unwrap();
        let other = process(&path, query(wrong)).expect("other admitted caller");
        assert_eq!(other["workspaceRef"], recorded["workspaceRef"]);
        assert_eq!(other["ownerRef"], recorded["ownerRef"]);
        assert_eq!(other["secondAuthorizationPerformed"], false);
        assert_eq!(other["ownerRefIsMetadataOnly"], true);
        let _ = std::fs::remove_file(&path);
    }
}
