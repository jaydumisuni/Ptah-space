//! Formula-owned, custody-bound launcher for Ptah's EXISTING E07 Control.
//! It delegates after preflight; it implements no transport or mathematical authority.
use ptah_formula_work_cells::{FormulaDispatchCustody, preflight_with_custody};
use std::{
    collections::BTreeMap,
    env, fs,
    path::Path,
    process::{Command, ExitCode},
};

fn execute() -> Result<i32, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut opt = BTreeMap::new();
    let mut private_lan = false;
    let mut i = 0;
    while i < args.len() {
        let key = args[i].as_str();
        if key == "--allow-private-lan" {
            if private_lan {
                return Err("duplicate LAN permission".into());
            }
            private_lan = true;
            i += 1;
            continue;
        }
        if !matches!(
            key,
            "--formula-handoff"
                | "--formula-work-cell"
                | "--formula-authority"
                | "--control-bin"
                | "--listen"
                | "--server-cert"
                | "--server-key"
                | "--client-ca"
                | "--enrollments"
                | "--journal"
                | "--request-digest"
        ) {
            return Err(format!("unexpected option: {key}"));
        }
        let value = args
            .get(i + 1)
            .ok_or_else(|| format!("missing value: {key}"))?;
        if value.is_empty() || opt.insert(key.to_string(), value.clone()).is_some() {
            return Err(format!("missing or duplicate: {key}"));
        }
        i += 2;
    }
    let val = |key: &str| {
        opt.get(key)
            .ok_or_else(|| format!("missing required option: {key}"))
    };
    let handoff = Path::new(val("--formula-handoff")?);
    let md = fs::symlink_metadata(handoff).map_err(|e| format!("packet metadata: {e}"))?;
    if !md.file_type().is_file() || !(1..=1_048_576).contains(&md.len()) {
        return Err("packet must be a bounded regular file, not a symlink".into());
    }
    let packet = fs::read(handoff).map_err(|e| format!("packet read: {e}"))?;
    let custody = FormulaDispatchCustody {
        manifest_digest: val("--request-digest")?.clone(),
        work_cell_digest: val("--formula-work-cell")?.clone(),
        required_authority: val("--formula-authority")?.clone(),
    };
    let approved = preflight_with_custody(&packet, &custody)
        .map_err(|e| format!("Formula custody denied: {e}"))?;
    if approved.manifest_digest != custody.manifest_digest {
        return Err("manifest digest drift".into());
    }
    let control = Path::new(val("--control-bin")?);
    if !control.is_absolute() || !control.is_file() {
        return Err("Ptah Control executable must be an existing absolute file".into());
    }
    let mut command = Command::new(control);
    for key in [
        "--listen",
        "--server-cert",
        "--server-key",
        "--client-ca",
        "--enrollments",
        "--journal",
        "--request-digest",
    ] {
        command.arg(key).arg(val(key)?);
    }
    if private_lan {
        command.arg("--allow-private-lan");
    }
    let status = command
        .status()
        .map_err(|e| format!("native Ptah Control: {e}"))?;
    Ok(status.code().unwrap_or(1))
}

fn main() -> ExitCode {
    match execute() {
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(msg) => {
            eprintln!("ptah-formula-control: {msg}");
            ExitCode::from(2)
        }
    }
}
