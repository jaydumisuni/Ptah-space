#![forbid(unsafe_code)]
//! Ptah-backed virtual ZLT X100 PRO router.

use ptah_device_runtime::DeviceKind;
use ptah_identifiers::{EntityRef, IdentifierError, RecordRevision};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const ROUTER_FAMILY: &str = "zlt_x100_pro";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbProfile {
    pub download_vid: String,
    pub download_pid: String,
    pub normal_vid: String,
    pub normal_pid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoaderProfile {
    pub helper_addr: String,
    pub helper_sha256: String,
    pub fdl1_addr: String,
    pub fdl1_sha256: String,
    pub stock_fdl1_sha256: String,
    pub fdl2_addr: String,
    pub fdl2_sha256: String,
    pub fdl2_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorWireProfile {
    pub connect_before_fdl2: bool,
    pub change_baud: u32,
    pub change_baud_payload_hex: String,
    pub change_baud_byte_order: String,
    pub keep_charge_after_change_baud: bool,
    pub fdl2_exec_payload_hex: String,
    pub fdl2_exec_payload_byte_order: String,
    pub fdl2_exec_ack_required: bool,
    pub fdl2_exec_settle_ms: u64,
    pub same_process_same_usb_handle: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gen1Profile {
    pub strategy: String,
    pub preserve_stock_boot_chain: bool,
    pub preserve_stock_kernel_and_radio_firmware: bool,
    pub runtime_target: String,
    pub runtime_service: String,
    pub physical_device_writes_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X100Profile {
    pub profile_id: String,
    pub router_family: String,
    pub model: String,
    pub platform: String,
    pub stock_firmware: String,
    pub usb: UsbProfile,
    pub loader: LoaderProfile,
    pub vendor_wire: VendorWireProfile,
    pub gen1: Gen1Profile,
    pub source_authority: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileIdentity {
    pub profile_key: String,
    pub profile_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum X100MachineState {
    Bootrom,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X100Router {
    pub device_ref: EntityRef,
    pub profile_revision_ref: EntityRef,
    pub profile_identity: ProfileIdentity,
    pub profile: X100Profile,
    pub boot_generation: u64,
    pub state: X100MachineState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct X100Machine {
    pub device_ref: EntityRef,
    pub profile_revision_ref: EntityRef,
    pub device_kind: DeviceKind,
    pub router_family: &'static str,
    pub profile_identity: ProfileIdentity,
    pub profile: X100Profile,
    pub boot_generation: u64,
    pub state: X100MachineState,
}

#[derive(Debug, Error)]
pub enum RouterSimError {
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
    #[error("invalid embedded X100 profile: {0}")]
    InvalidProfile(String),
    #[error("X100 boot generation overflowed")]
    BootGenerationOverflow,
}

impl X100Router {
    pub fn new() -> Result<Self, RouterSimError> {
        let raw = include_str!("../profiles/x100/r106.json");
        let profile: X100Profile =
            serde_json::from_str(raw).map_err(|e| RouterSimError::InvalidProfile(e.to_string()))?;
        if profile.profile_id != "zlt-x100-pro-r106" || profile.router_family != ROUTER_FAMILY {
            return Err(RouterSimError::InvalidProfile(
                "identity mismatch".to_owned(),
            ));
        }
        let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
        let mut profile_revision_ref = EntityRef::new("device.profile_revision")?;
        profile_revision_ref.record_revision = Some(RecordRevision::new(1)?);
        Ok(Self {
            device_ref: EntityRef::new("device.device")?,
            profile_revision_ref,
            profile_identity: ProfileIdentity {
                profile_key: "x100-r106-evidence-bound".to_owned(),
                profile_digest: digest,
            },
            profile,
            boot_generation: 0,
            state: X100MachineState::Bootrom,
        })
    }

    pub fn cold_boot(&mut self) -> Result<X100Machine, RouterSimError> {
        self.boot_generation = self
            .boot_generation
            .checked_add(1)
            .ok_or(RouterSimError::BootGenerationOverflow)?;
        self.state = X100MachineState::Bootrom;
        Ok(X100Machine {
            device_ref: self.device_ref.clone(),
            profile_revision_ref: self.profile_revision_ref.clone(),
            device_kind: DeviceKind::VirtualMachine,
            router_family: ROUTER_FAMILY,
            profile_identity: self.profile_identity.clone(),
            profile: self.profile.clone(),
            boot_generation: self.boot_generation,
            state: self.state,
        })
    }
}
