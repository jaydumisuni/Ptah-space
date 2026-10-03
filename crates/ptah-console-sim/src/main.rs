#![forbid(unsafe_code)]
//! CLI entrypoint for the Ptah PS4 simulated-console firmware selector.

use ptah_console_sim::{Ps4Console, Ps4FirmwareRegistry};
use serde::Serialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Serialize)]
struct ProfileListEntry<'a> {
    firmware: &'a str,
    status: &'a str,
    engine: Option<&'a str>,
    profile_key: &'a str,
    profile_digest: &'a str,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let registry = Ps4FirmwareRegistry::embedded().map_err(|error| error.to_string())?;
    let args = env::args().skip(1).collect::<Vec<_>>();

    if args.iter().any(|arg| arg == "--list") {
        let mut entries = Vec::new();
        for firmware in registry.firmware_versions() {
            let profile = registry
                .profile(firmware)
                .ok_or_else(|| format!("registry profile vanished: {firmware}"))?;
            let identity = registry
                .profile_identity(firmware)
                .ok_or_else(|| format!("registry identity vanished: {firmware}"))?;
            entries.push(ProfileListEntry {
                firmware,
                status: status_text(profile.ttg_status),
                engine: profile.engine.map(engine_text),
                profile_key: &identity.profile_key,
                profile_digest: &identity.profile_digest,
            });
        }
        let rendered = serde_json::to_string_pretty(&entries).map_err(|error| error.to_string())?;
        println!("{rendered}");
        return Ok(());
    }

    let firmware = parse_value(&args, "--firmware")?.ok_or_else(|| usage().to_owned())?;
    let state_path = parse_value(&args, "--state")?.map_or_else(
        || PathBuf::from(".ptah-ps4-console-state.json"),
        PathBuf::from,
    );

    let mut console = load_console(&state_path)?;
    let machine = console
        .select_and_boot(&registry, &firmware)
        .map_err(|error| error.to_string())?;
    save_console(&state_path, &console)?;

    let rendered = serde_json::to_string_pretty(&machine).map_err(|error| error.to_string())?;
    println!("{rendered}");
    Ok(())
}

fn usage() -> &'static str {
    "usage: ptah-ps4-sim --firmware <version> [--state <path>] | ptah-ps4-sim --list"
}

fn parse_value(args: &[String], flag: &str) -> Result<Option<String>, String> {
    let Some(index) = args.iter().position(|arg| arg == flag) else {
        return Ok(None);
    };
    let value = args
        .get(index + 1)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))?;
    Ok(Some(value))
}

fn load_console(path: &Path) -> Result<Ps4Console, String> {
    if !path.exists() {
        return Ps4Console::new().map_err(|error| error.to_string());
    }
    let raw = fs::read_to_string(path).map_err(|error| {
        format!(
            "failed to read PS4 console state {}: {error}",
            path.display()
        )
    })?;
    serde_json::from_str(&raw)
        .map_err(|error| format!("invalid PS4 console state {}: {error}", path.display()))
}

fn save_console(path: &Path, console: &Ps4Console) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create PS4 console-state directory {}: {error}",
                parent.display()
            )
        })?;
    }
    let rendered = serde_json::to_string_pretty(console).map_err(|error| error.to_string())?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, rendered + "\n").map_err(|error| {
        format!(
            "failed to write PS4 console state {}: {error}",
            tmp.display()
        )
    })?;
    fs::rename(&tmp, path).map_err(|error| {
        format!(
            "failed to commit PS4 console state {}: {error}",
            path.display()
        )
    })
}

const fn status_text(status: ptah_console_sim::FirmwareStatus) -> &'static str {
    match status {
        ptah_console_sim::FirmwareStatus::Proved => "proved",
        ptah_console_sim::FirmwareStatus::Candidate => "candidate",
        ptah_console_sim::FirmwareStatus::DetectedBlocked => "detected_blocked",
    }
}

const fn engine_text(engine: ptah_console_sim::Ps4Engine) -> &'static str {
    match engine {
        ptah_console_sim::Ps4Engine::Lapse => "lapse",
        ptah_console_sim::Ps4Engine::Poops => "poops",
    }
}
