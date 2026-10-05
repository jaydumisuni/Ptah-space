#![forbid(unsafe_code)]
use ptah_router_sim::X100Router;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let state = value(&args, "--state")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".ptah-x100-router-state.json"));
    let mut router = load(&state)?;
    let machine = router.cold_boot().map_err(|e| e.to_string())?;
    save(&state, &router)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&machine).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|x| x == flag)
        .and_then(|i| args.get(i + 1))
        .filter(|x| !x.trim().is_empty())
        .cloned()
}

fn load(path: &Path) -> Result<X100Router, String> {
    if !path.exists() {
        return X100Router::new().map_err(|e| e.to_string());
    }
    serde_json::from_str(&fs::read_to_string(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

fn save(path: &Path, router: &X100Router) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(
        &tmp,
        serde_json::to_string_pretty(router).map_err(|e| e.to_string())? + "\n",
    )
    .map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}
