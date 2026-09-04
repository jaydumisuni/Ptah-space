#![forbid(unsafe_code)]
//! Ptah human-control service executable and HTTP projection boundary.

mod server;

use server::{ControlServer, ServerConfig};
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match parse_args().and_then(|config| ControlServer::new(config).run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ptah-control: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_args() -> Result<ServerConfig, String> {
    let mut args = env::args().skip(1);
    if args.next().as_deref() != Some("serve") {
        return Err(String::from(
            "usage: ptah-control serve --snapshot <state.json> --submissions <requests.ndjson> [--listen 127.0.0.1:7800]",
        ));
    }

    let mut snapshot = None;
    let mut submissions = None;
    let mut listen = String::from("127.0.0.1:7800");
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--snapshot" => snapshot = Some(PathBuf::from(value)),
            "--submissions" => submissions = Some(PathBuf::from(value)),
            "--listen" => listen = value,
            _ => return Err(format!("unknown argument: {flag}")),
        }
    }

    Ok(ServerConfig {
        listen,
        snapshot_path: snapshot.ok_or_else(|| String::from("--snapshot is required"))?,
        submission_path: submissions.ok_or_else(|| String::from("--submissions is required"))?,
    })
}
