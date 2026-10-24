//! Separate exact binary-entry acceptance for Hunter's D02 on-demand bridge.
use ptah_identifiers::EntityRef;
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

fn native(ledger: &PathBuf, value: &Value) -> (bool, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ptah-hunter-workspace"))
        .arg(ledger)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run native Ptah binary");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(value.to_string().as_bytes())
        .unwrap();
    let result = child.wait_with_output().expect("wait");
    let body = serde_json::from_slice(&result.stdout).expect("bounded Ptah JSON");
    (result.status.success(), body)
}
#[test]
fn durable_workspace_reopens_for_any_admitted_caller_without_second_owner_gate() {
    let ledger = std::env::temp_dir().join(format!(
        "ptah-hunter-cli-{}.sqlite3",
        ptah_identifiers::EntityId::new_v7()
    ));
    let principal = EntityRef::new("identity.principal").unwrap();
    let authority = EntityRef::new("authority.owner").unwrap();
    let policy = EntityRef::new("policy.workspace").unwrap();
    let (ok, created) = native(
        &ledger,
        &json!({"action":"provision",
      "workspace_key":"hunter.native-cli-proof","title":"One bounded Ptah Workspace",
      "owner_ref":principal,"authority_ref":authority,"policy_ref":policy,
      "observed_at":"2026-10-18T08:40:00Z"}),
    );
    assert!(ok);
    assert_eq!(created["d02ExactRead"], true);
    assert_eq!(created["e02LeaseIssued"], false);
    assert_eq!(created["executionDispatched"], false);
    let valid = json!({"action":"inspect","workspace_ref":created["workspaceRef"],
      "owner_ref":principal,"observed_at":"2026-10-18T08:41:00Z"});
    let (again_ok, again) = native(&ledger, &valid);
    assert!(again_ok);
    assert_eq!(again["workspaceRef"], created["workspaceRef"]);
    assert_eq!(again["recordRevision"], created["recordRevision"]);
    let denied = json!({"action":"inspect","workspace_ref":created["workspaceRef"],
      "owner_ref":EntityRef::new("identity.principal").unwrap(),
      "observed_at":"2026-10-18T08:41:00Z"});
    let (allowed, body) = native(&ledger, &denied);
    assert!(
        allowed,
        "client-supplied owner metadata is not a permission gate"
    );
    assert_eq!(body["workspaceRef"], created["workspaceRef"]);
    assert_eq!(body["secondAuthorizationPerformed"], false);
    assert_eq!(body["ownerRefIsMetadataOnly"], true);
    let _ = fs::remove_file(ledger);
}
#[test]
fn native_open_workspace_needs_no_ptah_owner_enrollment_grant_or_policy() {
    let ledger = std::env::temp_dir().join(format!(
        "ptah-knights-bridge-{}.sqlite3",
        ptah_identifiers::EntityId::new_v7()
    ));
    let (ok, created) = native(
        &ledger,
        &json!({
            "action":"provision","workspace_key":"shared.knights-open",
            "title":"Admitted caller shared workspace",
            "observed_at":"2026-10-19T21:00:00Z"
        }),
    );
    assert!(
        ok,
        "Ptah must not require a second login, policy or Grant: {created}"
    );
    assert_eq!(created["secondAuthorizationPerformed"], false);
    assert_eq!(created["ownerRefIsMetadataOnly"], true);
    let (ok, repeated) = native(
        &ledger,
        &json!({
            "action":"inspect","workspace_ref":created["workspaceRef"],
            "observed_at":"2026-10-19T21:01:00Z"
        }),
    );
    assert!(ok);
    assert_eq!(repeated["workspaceRef"], created["workspaceRef"]);
    assert_eq!(repeated["ownerRef"], created["ownerRef"]);
    assert_eq!(repeated["d02ExactRead"], true);
    let _ = fs::remove_file(ledger);
}
#[test]
fn no_unapproved_json_fields_or_fake_ptah_lease() {
    let ledger = std::env::temp_dir().join(format!(
        "ptah-hunter-deny-{}.sqlite3",
        ptah_identifiers::EntityId::new_v7()
    ));
    let (ok, body) = native(
        &ledger,
        &json!({"action":"inspect",
       "owner_ref":EntityRef::new("identity.principal").unwrap(),
       "leaseApproved":true,"observed_at":"2026-10-18T08:42:00Z"}),
    );
    assert!(!ok);
    assert_eq!(body["error"], "INVALID_REQUEST_SCHEMA");
    assert_eq!(body["e02LeaseIssued"], false);
    let _ = fs::remove_file(ledger);
}
