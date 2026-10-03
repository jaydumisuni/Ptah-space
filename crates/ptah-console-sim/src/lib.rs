#![forbid(unsafe_code)]
//! Ptah-backed simulated console substrate.
//!
//! The first implementation models a `PlayStation 4` as a Ptah
//! `DeviceKind::VirtualMachine`. Firmware is selected only at startup and is
//! bound to one immutable embedded firmware-profile record. This crate does not
//! emulate Sony CPU instructions and does not execute a physical exploit; it
//! supplies the machine/profile boundary that TTG-Simulation can drive.

use ptah_device_runtime::DeviceKind;
use ptah_identifiers::{EntityRef, IdentifierError, RecordRevision};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

/// Stable simulated-console family implemented by this crate.
pub const CONSOLE_FAMILY: &str = "playstation4";
/// Record revision applied to the selected Ptah Device Profile Revision.
pub const PROFILE_RECORD_REVISION: u64 = 1;

/// Supported PS4 exploit-engine family recorded by a firmware profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ps4Engine {
    /// Lapse engine family.
    Lapse,
    /// Poops engine family.
    Poops,
}

/// Qualification state carried by one firmware profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirmwareStatus {
    /// Hardware/product evidence exists for the profile.
    Proved,
    /// Profile exists but still requires qualification.
    Candidate,
    /// Firmware is detected but must fail closed.
    DetectedBlocked,
}

/// Immutable PS4 firmware profile consumed at machine startup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ps4FirmwareProfile {
    /// Firmware version shown to the simulated console.
    pub firmware: String,
    /// Exploit engine selected by this profile; blocked profiles carry none.
    pub engine: Option<Ps4Engine>,
    /// TTG qualification state.
    pub ttg_status: FirmwareStatus,
    /// Execution policy text retained from the source registry.
    pub execution: String,
    /// Firmware-specific kernel-patch path.
    pub patch_path: Option<String>,
    /// Firmware-specific payload path.
    pub payload_path: Option<String>,
    /// Expected SHA-256 for the patch.
    pub patch_sha256: Option<String>,
    /// Expected SHA-256 for the payload.
    pub payload_sha256: Option<String>,
    /// Expected payload size.
    pub payload_size: Option<u64>,
    /// Optional source warning retained verbatim.
    #[serde(default)]
    pub evidence_warning: Option<String>,
    /// Source authority that supplied this profile.
    pub source_authority: String,
}

/// Exact executable material selected by one non-blocked firmware profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ps4BootMaterial {
    /// Selected exploit engine.
    pub engine: Ps4Engine,
    /// Kernel-patch path from the product registry.
    pub patch_path: String,
    /// Payload path from the product registry.
    pub payload_path: String,
    /// Expected kernel-patch SHA-256.
    pub patch_sha256: String,
    /// Expected payload SHA-256.
    pub payload_sha256: String,
    /// Expected payload byte length.
    pub payload_size: u64,
}

impl Ps4FirmwareProfile {
    /// Return executable boot material for an admitted profile.
    ///
    /// Blocked firmware has no executable boot material.
    #[must_use]
    pub fn boot_material(&self) -> Option<Ps4BootMaterial> {
        Some(Ps4BootMaterial {
            engine: self.engine?,
            patch_path: self.patch_path.clone()?,
            payload_path: self.payload_path.clone()?,
            patch_sha256: self.patch_sha256.clone()?,
            payload_sha256: self.payload_sha256.clone()?,
            payload_size: self.payload_size?,
        })
    }
}

/// Stable firmware-profile identity independent of Ptah session UUIDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileIdentity {
    /// Stable profile key.
    pub profile_key: String,
    /// SHA-256 of the exact embedded profile JSON bytes.
    pub profile_digest: String,
}

/// Booted simulated PS4 machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ps4Machine {
    /// Canonical Ptah Device identity for this simulated boot session.
    pub device_ref: EntityRef,
    /// Canonical Ptah Device Profile Revision identity for this boot session.
    pub profile_revision_ref: EntityRef,
    /// Ptah Device kind; always `virtual_machine`.
    pub device_kind: DeviceKind,
    /// Stable console family.
    pub console_family: &'static str,
    /// Exact firmware selected before boot.
    pub firmware: String,
    /// Stable identity of the selected firmware profile.
    pub profile_identity: ProfileIdentity,
    /// Full selected firmware profile.
    pub profile: Ps4FirmwareProfile,
    /// Boot generation. A new startup creates generation 1.
    pub boot_generation: u64,
    /// Machine state after successful startup.
    pub state: Ps4MachineState,
}

/// Lifecycle state exposed by the simulated PS4 machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ps4MachineState {
    /// Profile is selected and machine boot completed.
    Booted,
}

/// Machine/profile construction failures.
#[derive(Debug, Error)]
pub enum ConsoleSimError {
    /// Ptah canonical identifier construction failed.
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
    /// Embedded firmware profile JSON is invalid.
    #[error("invalid embedded PS4 firmware profile {firmware}: {message}")]
    InvalidProfile {
        /// Firmware whose embedded record failed validation.
        firmware: String,
        /// Validation or parse failure.
        message: String,
    },
    /// Requested firmware is not present in the admitted registry.
    #[error("unsupported PS4 firmware profile: {0}")]
    UnsupportedFirmware(String),
    /// Requested firmware exists but is explicitly blocked.
    #[error("PS4 firmware profile is detected but blocked: {0}")]
    BlockedFirmware(String),
}

/// Immutable embedded PS4 firmware registry.
#[derive(Debug, Clone)]
pub struct Ps4FirmwareRegistry {
    profiles: BTreeMap<String, EmbeddedProfile>,
}

#[derive(Debug, Clone)]
struct EmbeddedProfile {
    profile: Ps4FirmwareProfile,
    identity: ProfileIdentity,
}

const EMBEDDED_PROFILES: [(&str, &str); 8] = [
    ("11.00", include_str!("../profiles/ps4/11.00.json")),
    ("11.50", include_str!("../profiles/ps4/11.50.json")),
    ("12.00", include_str!("../profiles/ps4/12.00.json")),
    ("12.02", include_str!("../profiles/ps4/12.02.json")),
    ("12.50", include_str!("../profiles/ps4/12.50.json")),
    ("12.52", include_str!("../profiles/ps4/12.52.json")),
    ("13.00", include_str!("../profiles/ps4/13.00.json")),
    ("14.00", include_str!("../profiles/ps4/14.00.json")),
];

impl Ps4FirmwareRegistry {
    /// Parse and validate the embedded firmware registry.
    ///
    /// # Errors
    /// Fails when any embedded profile does not match its registry key or
    /// violates profile invariants.
    pub fn embedded() -> Result<Self, ConsoleSimError> {
        let mut profiles = BTreeMap::new();
        for (firmware, raw) in EMBEDDED_PROFILES {
            let profile: Ps4FirmwareProfile =
                serde_json::from_str(raw).map_err(|error| ConsoleSimError::InvalidProfile {
                    firmware: firmware.to_owned(),
                    message: error.to_string(),
                })?;
            validate_profile(firmware, &profile)?;
            let digest = sha256_hex(raw.as_bytes());
            let identity = ProfileIdentity {
                profile_key: format!("ps4-fw-{firmware}-{prefix}", prefix = &digest[..16]),
                profile_digest: digest,
            };
            profiles.insert(firmware.to_owned(), EmbeddedProfile { profile, identity });
        }
        Ok(Self { profiles })
    }

    /// Return the firmware versions visible to the startup selector.
    #[must_use]
    pub fn firmware_versions(&self) -> Vec<&str> {
        self.profiles.keys().map(String::as_str).collect()
    }

    /// Return an immutable profile by firmware version.
    #[must_use]
    pub fn profile(&self, firmware: &str) -> Option<&Ps4FirmwareProfile> {
        self.profiles.get(firmware).map(|entry| &entry.profile)
    }

    /// Return the stable profile identity by firmware version.
    #[must_use]
    pub fn profile_identity(&self, firmware: &str) -> Option<&ProfileIdentity> {
        self.profiles.get(firmware).map(|entry| &entry.identity)
    }

    /// Boot one simulated PS4 from a firmware selected before startup.
    ///
    /// # Errors
    /// Fails closed for unknown or blocked firmware profiles or invalid Ptah
    /// identifier construction.
    pub fn boot(&self, firmware: &str) -> Result<Ps4Machine, ConsoleSimError> {
        let embedded = self
            .profiles
            .get(firmware)
            .ok_or_else(|| ConsoleSimError::UnsupportedFirmware(firmware.to_owned()))?;
        if embedded.profile.ttg_status == FirmwareStatus::DetectedBlocked
            || embedded.profile.execution == "blocked"
        {
            return Err(ConsoleSimError::BlockedFirmware(firmware.to_owned()));
        }

        let device_ref = EntityRef::new("device.device")?;
        let mut profile_revision_ref = EntityRef::new("device.profile_revision")?;
        profile_revision_ref.record_revision = Some(RecordRevision::new(PROFILE_RECORD_REVISION)?);

        Ok(Ps4Machine {
            device_ref,
            profile_revision_ref,
            device_kind: DeviceKind::VirtualMachine,
            console_family: CONSOLE_FAMILY,
            firmware: firmware.to_owned(),
            profile_identity: embedded.identity.clone(),
            profile: embedded.profile.clone(),
            boot_generation: 1,
            state: Ps4MachineState::Booted,
        })
    }
}

fn validate_profile(key: &str, profile: &Ps4FirmwareProfile) -> Result<(), ConsoleSimError> {
    if profile.firmware != key {
        return Err(invalid_profile(key, "firmware key does not match profile"));
    }
    if profile.source_authority.trim().is_empty() {
        return Err(invalid_profile(key, "source authority is empty"));
    }

    if profile.ttg_status == FirmwareStatus::DetectedBlocked || profile.execution == "blocked" {
        if profile.engine.is_some()
            || profile.patch_path.is_some()
            || profile.payload_path.is_some()
            || profile.patch_sha256.is_some()
            || profile.payload_sha256.is_some()
            || profile.payload_size.is_some()
        {
            return Err(invalid_profile(
                key,
                "blocked firmware must not carry executable profile material",
            ));
        }
        return Ok(());
    }

    if profile.engine.is_none() {
        return Err(invalid_profile(key, "engine is required"));
    }
    if profile.patch_path.as_deref().is_none_or(str::is_empty)
        || profile.payload_path.as_deref().is_none_or(str::is_empty)
    {
        return Err(invalid_profile(key, "patch and payload paths are required"));
    }
    let Some(patch_sha) = profile.patch_sha256.as_deref() else {
        return Err(invalid_profile(key, "patch SHA-256 is required"));
    };
    let Some(payload_sha) = profile.payload_sha256.as_deref() else {
        return Err(invalid_profile(key, "payload SHA-256 is required"));
    };
    if !is_sha256(patch_sha) || !is_sha256(payload_sha) {
        return Err(invalid_profile(key, "invalid SHA-256 field"));
    }
    if profile.payload_size.is_none_or(|size| size == 0) {
        return Err(invalid_profile(key, "payload size must be positive"));
    }
    Ok(())
}

fn invalid_profile(firmware: &str, message: &str) -> ConsoleSimError {
    ConsoleSimError::InvalidProfile {
        firmware: firmware.to_owned(),
        message: message.to_owned(),
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}
