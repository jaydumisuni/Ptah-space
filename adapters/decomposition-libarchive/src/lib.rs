#![forbid(unsafe_code)]
//! A12 libarchive 3.8.7 parser adapter.
//!
//! The selected C parser is confined to a sidecar process. Safe Rust verifies
//! exact executable/source/version identity and parses a bounded binary protocol.
//! Neither layer performs filesystem extraction.

use ptah_archive_decomposition::{
    ArchiveBackend, BackendIdentity, DecompositionError, MemberKind, ParseReport, ParseTerminal,
    ParsedMember,
};
use ptah_identifiers::EntityRef;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"PTAHA12\0";
const PROTOCOL_VERSION: u32 = 1;

/// Exact libarchive helper configuration and parser-side resource ceiling.
#[derive(Debug, Clone)]
pub struct LibarchiveConfig {
    /// Helper executable path.
    pub helper_path: PathBuf,
    /// Required helper SHA-256.
    pub expected_helper_sha256: String,
    /// Required locked libarchive source SHA-256.
    pub expected_source_sha256: String,
    /// Required libarchive version; A12 is locked to `3.8.7`.
    pub expected_version: String,
    /// Canonical Provider identity.
    pub provider_ref: EntityRef,
    /// Canonical Provider generation.
    pub provider_generation: u64,
    /// Maximum members accepted from the sidecar protocol.
    pub max_members: u64,
    /// Maximum bytes accepted for one protocol member.
    pub max_member_bytes: u64,
    /// Maximum cumulative protocol member bytes.
    pub max_total_bytes: u64,
    /// Maximum UTF-8 path bytes accepted from the sidecar.
    pub max_path_bytes: u32,
}

/// Qualified exact libarchive backend.
pub struct LibarchiveBackend {
    config: LibarchiveConfig,
}

/// Adapter startup/protocol failures.
#[derive(Debug, Error)]
pub enum LibarchiveError {
    /// Helper file cannot be read or executed.
    #[error("libarchive helper I/O failure: {0}")]
    Io(#[from] io::Error),
    /// Helper executable hash changed.
    #[error("libarchive helper SHA-256 mismatch")]
    HelperDigestMismatch,
    /// Probe output did not match the locked A12 backend.
    #[error("libarchive helper probe mismatch: {0}")]
    ProbeMismatch(&'static str),
    /// Sidecar protocol is malformed or exceeds configured bounds.
    #[error("libarchive sidecar protocol violation: {0}")]
    Protocol(&'static str),
}

impl LibarchiveBackend {
    /// Open and qualify the exact helper before any archive bytes are parsed.
    ///
    /// # Errors
    /// Returns an error when helper bytes, protocol, source identity, version or
    /// in-process filter qualification differs from the locked configuration.
    pub fn open(config: LibarchiveConfig) -> Result<Self, LibarchiveError> {
        validate_config(&config)?;
        verify_helper_digest(&config)?;
        verify_probe(&config)?;
        Ok(Self { config })
    }

    fn parse_bounded(&self, bytes: &[u8]) -> Result<ParseReport, LibarchiveError> {
        verify_helper_digest(&self.config)?;
        verify_probe(&self.config)?;
        let mut child = Command::new(&self.config.helper_path)
            .arg("--parse-stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or(LibarchiveError::Protocol("stdin"))?;
            stdin.write_all(bytes)?;
        }
        let mut stdout = child
            .stdout
            .take()
            .ok_or(LibarchiveError::Protocol("stdout"))?;
        let report = read_protocol(&mut stdout, &self.config)?;
        let status = child.wait()?;
        if !status.success() {
            return Err(LibarchiveError::Protocol("helper exit"));
        }
        Ok(report)
    }
}

impl ArchiveBackend for LibarchiveBackend {
    fn identity(&self) -> BackendIdentity {
        BackendIdentity {
            provider_ref: self.config.provider_ref.clone(),
            provider_generation: self.config.provider_generation,
            implementation: "libarchive".to_owned(),
            implementation_version: self.config.expected_version.clone(),
            source_sha256: self.config.expected_source_sha256.clone(),
            executable_sha256: self.config.expected_helper_sha256.clone(),
        }
    }

    fn parse(&self, bytes: &[u8]) -> Result<ParseReport, DecompositionError> {
        self.parse_bounded(bytes)
            .map_err(|error| DecompositionError::Backend(error.to_string()))
    }
}

fn validate_config(config: &LibarchiveConfig) -> Result<(), LibarchiveError> {
    if config.expected_version != "3.8.7" {
        return Err(LibarchiveError::ProbeMismatch("version lock"));
    }
    if config.expected_helper_sha256.len() != 64 || config.expected_source_sha256.len() != 64 {
        return Err(LibarchiveError::ProbeMismatch("digest syntax"));
    }
    if config.max_members == 0
        || config.max_member_bytes == 0
        || config.max_total_bytes == 0
        || config.max_member_bytes > config.max_total_bytes
        || config.max_path_bytes == 0
    {
        return Err(LibarchiveError::Protocol("invalid resource ceiling"));
    }
    Ok(())
}

fn verify_helper_digest(config: &LibarchiveConfig) -> Result<(), LibarchiveError> {
    let bytes = fs::read(&config.helper_path)?;
    let observed = format!("{:x}", Sha256::digest(&bytes));
    if observed != config.expected_helper_sha256 {
        return Err(LibarchiveError::HelperDigestMismatch);
    }
    Ok(())
}

fn verify_probe(config: &LibarchiveConfig) -> Result<(), LibarchiveError> {
    let output = Command::new(&config.helper_path).arg("--probe").output()?;
    if !output.status.success() {
        return Err(LibarchiveError::ProbeMismatch("exit"));
    }
    let text =
        std::str::from_utf8(&output.stdout).map_err(|_| LibarchiveError::ProbeMismatch("utf8"))?;
    let mut protocol = None;
    let mut version = None;
    let mut source = None;
    let mut filters = None;
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "protocol" => protocol = Some(value),
                "libarchive" => version = Some(value),
                "source_sha256" => source = Some(value),
                "filters" => filters = Some(value),
                _ => {}
            }
        }
    }
    if protocol != Some("1") {
        return Err(LibarchiveError::ProbeMismatch("protocol"));
    }
    if version != Some(config.expected_version.as_str()) {
        return Err(LibarchiveError::ProbeMismatch("version"));
    }
    if source != Some(config.expected_source_sha256.as_str()) {
        return Err(LibarchiveError::ProbeMismatch("source"));
    }
    if filters != Some("in_process") {
        return Err(LibarchiveError::ProbeMismatch("filters"));
    }
    Ok(())
}

fn read_protocol(
    reader: &mut impl Read,
    config: &LibarchiveConfig,
) -> Result<ParseReport, LibarchiveError> {
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC || read_u32(reader)? != PROTOCOL_VERSION {
        return Err(LibarchiveError::Protocol("header"));
    }
    let mut members = Vec::new();
    let mut total_bytes = 0u64;
    loop {
        match read_u8(reader)? {
            1 => {
                if u64::try_from(members.len())
                    .map_err(|_| LibarchiveError::Protocol("member count"))?
                    >= config.max_members
                {
                    return Ok(budget_report(members, "adapter member ceiling"));
                }
                let kind = decode_kind(read_u8(reader)?)?;
                let path_len = read_u32(reader)?;
                let data_len = read_u64(reader)?;
                if path_len > config.max_path_bytes || data_len > config.max_member_bytes {
                    return Ok(budget_report(members, "adapter member/path ceiling"));
                }
                total_bytes = total_bytes
                    .checked_add(data_len)
                    .ok_or(LibarchiveError::Protocol("byte overflow"))?;
                if total_bytes > config.max_total_bytes {
                    return Ok(budget_report(members, "adapter total-byte ceiling"));
                }
                let path = read_string(reader, path_len)?;
                let data_len_usize = usize::try_from(data_len)
                    .map_err(|_| LibarchiveError::Protocol("member length"))?;
                let mut data = vec![0u8; data_len_usize];
                reader.read_exact(&mut data)?;
                members.push(ParsedMember {
                    path,
                    kind,
                    bytes: data,
                });
            }
            2 => {
                let terminal = decode_terminal(read_u8(reader)?)?;
                let format_len = read_u32(reader)?;
                if format_len > 256 {
                    return Err(LibarchiveError::Protocol("format length"));
                }
                let format = read_string(reader, format_len)?;
                let diagnostic_len = read_u32(reader)?;
                if diagnostic_len > 512 {
                    return Err(LibarchiveError::Protocol("diagnostic length"));
                }
                let diagnostic = read_string(reader, diagnostic_len)?;
                let mut limitations = Vec::new();
                if !diagnostic.is_empty() {
                    limitations.push(diagnostic);
                }
                return Ok(ParseReport {
                    format: (!format.is_empty()).then_some(format),
                    members,
                    terminal,
                    warnings: Vec::new(),
                    limitations,
                });
            }
            _ => return Err(LibarchiveError::Protocol("record tag")),
        }
    }
}

fn budget_report(members: Vec<ParsedMember>, reason: &str) -> ParseReport {
    ParseReport {
        format: None,
        members,
        terminal: ParseTerminal::BudgetExhausted,
        warnings: Vec::new(),
        limitations: vec![reason.to_owned()],
    }
}
fn decode_kind(value: u8) -> Result<MemberKind, LibarchiveError> {
    match value {
        1 => Ok(MemberKind::Regular),
        2 => Ok(MemberKind::Directory),
        3 => Ok(MemberKind::Symlink),
        4 => Ok(MemberKind::Hardlink),
        5 => Ok(MemberKind::Special),
        _ => Err(LibarchiveError::Protocol("member kind")),
    }
}
fn decode_terminal(value: u8) -> Result<ParseTerminal, LibarchiveError> {
    match value {
        0 => Ok(ParseTerminal::Complete),
        1 => Ok(ParseTerminal::LockedEncrypted),
        5 => Ok(ParseTerminal::Malformed),
        6 => Ok(ParseTerminal::Truncated),
        7 => Ok(ParseTerminal::ParserError),
        11 => Ok(ParseTerminal::UnsupportedFormat),
        _ => Err(LibarchiveError::Protocol("terminal")),
    }
}
fn read_u8(reader: &mut impl Read) -> Result<u8, LibarchiveError> {
    let mut b = [0u8; 1];
    reader.read_exact(&mut b)?;
    Ok(b[0])
}
fn read_u32(reader: &mut impl Read) -> Result<u32, LibarchiveError> {
    let mut b = [0u8; 4];
    reader.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn read_u64(reader: &mut impl Read) -> Result<u64, LibarchiveError> {
    let mut b = [0u8; 8];
    reader.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}
fn read_string(reader: &mut impl Read, length: u32) -> Result<String, LibarchiveError> {
    let length = usize::try_from(length).map_err(|_| LibarchiveError::Protocol("string length"))?;
    let mut bytes = vec![0u8; length];
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| LibarchiveError::Protocol("utf8"))
}

/// Compute a helper executable SHA-256 for freeze/qualification records.
///
/// # Errors
/// Returns an I/O error when the helper cannot be read.
pub fn helper_sha256(path: impl AsRef<Path>) -> Result<String, io::Error> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}
