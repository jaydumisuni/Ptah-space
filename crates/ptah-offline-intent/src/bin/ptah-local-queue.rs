//! Local-first queue CLI. No network, process execution or authority promotion.
use ptah_offline_intent::degraded::DegradedProjection;
use ptah_offline_intent::durable::{DurableIntentJournal, IntentDraft};
use std::{env, path::Path};

fn main() {
    if let Err(message) = run() {
        eprintln!("ptah-local-queue: {message}");
        std::process::exit(2);
    }
}
fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or("expected status|enqueue")?;
    let path = args.next().ok_or("expected private SQLite journal path")?;
    // Reject invalid commands and arity before opening or creating storage.
    let parts = args.collect::<Vec<_>>();
    match command.as_str() {
        "status" if !parts.is_empty() => return Err(String::from("unexpected arguments")),
        "enqueue" if parts.len() != 8 => {
            return Err(String::from(
                "enqueue requires NODE INTENT WORKSPACE ACTIVITY OPERATION ATTEMPT ACTION DIGEST",
            ))
        }
        "status" | "enqueue" => {}
        _ => return Err(String::from("unknown command; expected status|enqueue")),
    }
    let draft = if command == "enqueue" {
        let draft = IntentDraft {
            node_id: parts[0].clone(),
            intent_id: parts[1].clone(),
            workspace_id: parts[2].clone(),
            activity_id: parts[3].clone(),
            operation_id: parts[4].clone(),
            attempt_id: parts[5].clone(),
            action: parts[6].clone(),
            canonical_input_digest: parts[7].clone(),
        };
        draft
            .validate()
            .map_err(|e| format!("queue rejected: {e:?}"))?;
        Some(draft)
    } else {
        None
    };
    let mut queue = DurableIntentJournal::open(Path::new(&path))
        .map_err(|error| format!("journal failed closed: {error:?}"))?;
    match command.as_str() {
        "status" => {
            let projection = DegradedProjection::from_queue(&queue)
                .map_err(|e| format!("degraded projection failed: {e:?}"))?;
            println!(
                "{}",
                serde_json::json!({
                    "schema":"ptah.e06.local-queue-status.v1",
                    "state":projection.state.as_str(),
                    "count":projection.pending_count,
                    "authority_granted":projection.authority_granted,
                    "revalidate_required":projection.revalidate_required,
                })
            );
        }
        "enqueue" => {
            let draft = draft.as_ref().ok_or("missing validated enqueue draft")?;
            let (committed, disposition) = queue
                .enqueue(draft)
                .map_err(|e| format!("queue rejected: {e:?}"))?;
            println!(
                "{}",
                serde_json::json!({
                    "schema":"ptah.e06.local-queue-receipt.v1",
                    "state":"queued_not_authorized",
                    "origin_node":committed.origin.node_id,
                    "origin_sequence":committed.origin.value.to_string(),
                    "intent_id":committed.intent_id,
                    "disposition":format!("{disposition:?}"),
                    "authority_granted":false,
                    "revalidate_required":true,
                })
            );
        }
        _ => return Err(String::from("unknown command; expected status|enqueue")),
    }
    Ok(())
}
