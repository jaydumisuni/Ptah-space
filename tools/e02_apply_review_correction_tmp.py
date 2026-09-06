from pathlib import Path
import re

DURABLE = Path("crates/ptah-placement-runtime/src/durable.rs")
RECOVERY_TEST = Path("crates/ptah-placement-runtime/tests/e02_recovery.rs")

text = DURABLE.read_text(encoding="utf-8")

text, count = re.subn(
    r'(let journal_ref = EntityRef::new\(JOURNAL_KIND\)\n\s+\.map_err\(\|error\| RecoveryError::Corrupt\(error\.to_string\(\)\)\)\?;\n)(\s*)let document = json!',
    r'\1\2let timestamp = rfc3339_utc(journal_event_unix_seconds(&entry))?;\n\2let document = json!',
    text,
    count=1,
)
if count != 1:
    raise SystemExit(f"journal timestamp insertion count={count}")

old = '            "created_at": "2026-09-06T00:00:00Z",\n            "updated_at": "2026-09-06T00:00:00Z",'
new = '            "created_at": timestamp.clone(),\n            "updated_at": timestamp,'
if text.count(old) != 1:
    raise SystemExit(f"hard-coded timestamp block count={text.count(old)}")
text = text.replace(old, new, 1)

marker = '\n#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]\nstruct StoredResource {'
helpers = r'''

fn journal_event_unix_seconds(entry: &JournalEntry) -> u64 {
    match entry {
        JournalEntry::Reservation { value, .. } => value.created_at,
        JournalEntry::Lease { value, .. } => value.issued_at,
    }
}

fn rfc3339_utc(unix_seconds: u64) -> Result<String, RecoveryError> {
    const SECONDS_PER_DAY: u64 = 86_400;
    let days = unix_seconds / SECONDS_PER_DAY;
    let seconds_of_day = unix_seconds % SECONDS_PER_DAY;
    let days = i64::try_from(days)
        .map_err(|_| RecoveryError::Corrupt("journal timestamp exceeds RFC3339 range".to_owned()))?;

    let shifted = days
        .checked_add(719_468)
        .ok_or_else(|| RecoveryError::Corrupt("journal timestamp overflow".to_owned()))?;
    let era = if shifted >= 0 {
        shifted / 146_097
    } else {
        (shifted - 146_096) / 146_097
    };
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    if !(0..=9_999).contains(&year) {
        return Err(RecoveryError::Corrupt(
            "journal timestamp exceeds four-digit RFC3339 year".to_owned(),
        ));
    }

    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}
'''
if text.count(marker) != 1:
    raise SystemExit(f"StoredResource marker count={text.count(marker)}")
text = text.replace(marker, helpers + marker, 1)
DURABLE.write_text(text, encoding="utf-8")

text = RECOVERY_TEST.read_text(encoding="utf-8")
old = "use std::{fs, path::PathBuf, process};"
new = "use rusqlite::Connection;\nuse serde_json::Value;\nuse std::{fs, path::PathBuf, process};"
if text.count(old) != 1:
    raise SystemExit(f"recovery import marker count={text.count(old)}")
text = text.replace(old, new, 1)

marker = "#[test]\nfn restart_preserves_higher_fence_and_next_issue_is_strictly_newer() {"
inserted = r'''#[test]
fn canonical_journal_timestamp_matches_reservation_creation_time() {
    let path = temp_db("canonical-time");
    let session = session(NodeId::new(), 7, 11);
    let snapshot = resource_snapshot(&session);
    let mut reservations = ReservationRegistry::new(&session, &snapshot).expect("registry");
    let reservation_ref = reserve(
        &mut reservations,
        &snapshot,
        &session,
        entity("activity.attempt"),
        1.0,
    );
    let record = reservations
        .reservation(&reservation_ref)
        .expect("record")
        .clone();
    let mut store = DurableAuthorityStore::open(&path).expect("store");
    store.persist_reservation(&record).expect("persist reservation");
    drop(store);

    let connection = Connection::open(&path).expect("ledger connection");
    let document_json: String = connection
        .query_row(
            "SELECT document_json FROM ptah_entity_records WHERE entity_kind = ?1",
            ["runtime.e02-authority-journal"],
            |row| row.get(0),
        )
        .expect("journal row");
    let document: Value = serde_json::from_str(&document_json).expect("canonical JSON");
    assert_eq!(document["created_at"], "2027-01-15T08:00:00Z");
    assert_eq!(document["updated_at"], "2027-01-15T08:00:00Z");
    cleanup(&path);
}

#[test]
fn restart_preserves_higher_fence_and_next_issue_is_strictly_newer() {'''
if text.count(marker) != 1:
    raise SystemExit(f"recovery insertion marker count={text.count(marker)}")
text = text.replace(marker, inserted, 1)
RECOVERY_TEST.write_text(text, encoding="utf-8")
