//! Native on-demand Ptah D02 workspace connection for Hunter.
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
    owner_ref: EntityRef,
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
    let reader =
        WorkspaceReader::open(ledger, clock(timestamp)?).map_err(|_| "PTAH_LEDGER_READ_FAILED")?;
    let request = RetrievalRequest {
        actor_ref: req.owner_ref.clone(),
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
    // D02's mechanical same-workspace check does not independently bind the
    // requesting caller to the Workspace owner: enforce this extra boundary.
    let recorded_owner: EntityRef = serde_json::from_value(
        record
            .document
            .get("owner_ref")
            .cloned()
            .ok_or("OWNER_RECORD_MISSING")?,
    )
    .map_err(|_| "OWNER_RECORD_INVALID")?;
    if recorded_owner != req.owner_ref {
        return Err("WORKSPACE_OWNER_MISMATCH".into());
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
        "state":"existing_authorized_workspace",
        "workspaceRef":reference,"ownerRef":req.owner_ref,
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
            let authority = request
                .authority_ref
                .clone()
                .ok_or("AUTHORITY_REF_REQUIRED")?;
            let policy = request.policy_ref.clone().ok_or("POLICY_REF_REQUIRED")?;
            if authority.entity_kind.as_str() != "authority.owner"
                || policy.entity_kind.as_str() != "policy.workspace"
                || request.owner_ref.entity_kind.as_str() != "identity.principal"
            {
                return Err("OWNER_AUTHORITY_REFERENCE_CLASS_INVALID".into());
            }
            let now = request.observed_at.as_deref().ok_or("CLOCK_REQUIRED")?;
            let mut store =
                WorkspaceStore::open(ledger, clock(now)?).map_err(|_| "PTAH_LEDGER_OPEN_FAILED")?;
            let created = store
                .create_workspace(CreateWorkspace {
                    workspace_key: key.into(),
                    title: title.into(),
                    description: None,
                    owner_ref: request.owner_ref.clone(),
                    authority_ref: authority.clone(),
                    created_by_ref: request.owner_ref.clone(),
                    policy_refs: vec![policy],
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
                    owner_ref: request.owner_ref,
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
            owner_ref: principal,
            authority_ref: None,
            policy_ref: None,
            observed_at: Some("2026-10-18T08:40:00Z".into()),
        };
        assert!(process(Path::new("/tmp/ptah-no-ledger-file"), req).is_err());
    }
    #[test]
    fn provision_then_reopen_exact_d02_record_and_refuse_wrong_owner() {
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
                owner_ref: owner.clone(),
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
            owner_ref: actor,
            authority_ref: None,
            policy_ref: None,
            observed_at: Some("2026-10-18T08:46:00Z".into()),
        };
        assert_eq!(
            process(&path, query(owner)).unwrap()["workspaceRef"],
            recorded["workspaceRef"]
        );
        let wrong = EntityRef::new("identity.principal").unwrap();
        assert_eq!(
            process(&path, query(wrong)).unwrap_err(),
            "WORKSPACE_OWNER_MISMATCH"
        );
        let _ = std::fs::remove_file(&path);
    }
}
