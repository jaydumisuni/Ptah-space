#![forbid(unsafe_code)]
//! C08 device identity and transport substrate.
//!
//! This crate owns canonical Device grouping, provider-generation and connection-epoch
//! fencing, observation-only ADB/Fastboot/Apple/USB-serial normalization, Device leases,
//! and read-only protocol-operation admission. Backend serials, USB paths, COM/TTY names,
//! UDIDs and other endpoint identifiers remain aliases/evidence and never become canonical
//! Ptah Device identity.
//!
//! C08 deliberately exposes no device-write, erase, repartition, reset, security-state,
//! protected-NV or payload-execution facility.

use ptah_identifiers::{EntityRef, IdentifierError};
use ptah_provider_api::{
    ProviderContext, ProviderError, ProviderGeneration, ProviderInstance, ProviderKind,
    ProviderRevision,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

/// Frozen Device schema identity consumed by C08.
pub const DEVICE_SCHEMA_ID: &str = "urn:ptah:schema:domain:device:0.1.0";
/// Frozen Device Interface schema identity consumed by C08.
pub const DEVICE_INTERFACE_SCHEMA_ID: &str =
    "urn:ptah:schema:domain:device-interface:0.1.0";
/// Frozen Device Connection schema identity consumed by C08.
pub const DEVICE_CONNECTION_SCHEMA_ID: &str =
    "urn:ptah:schema:domain:device-connection:0.1.0";
/// Frozen Device Connection Observation schema identity consumed by C08.
pub const DEVICE_CONNECTION_OBSERVATION_SCHEMA_ID: &str =
    "urn:ptah:schema:domain:device-connection-observation:0.1.0";
/// Frozen Device Protocol Operation schema identity consumed by C08.
pub const DEVICE_PROTOCOL_OPERATION_SCHEMA_ID: &str =
    "urn:ptah:schema:domain:device-protocol-operation:0.1.0";
/// Frozen Lease schema identity consumed by C08.
pub const DEVICE_LEASE_SCHEMA_ID: &str = "urn:ptah:schema:isolation:lease:0.1.0";
/// Frozen Fence Observation schema identity consumed by C08.
pub const FENCE_OBSERVATION_SCHEMA_ID: &str =
    "urn:ptah:schema:isolation:fence-observation:0.1.0";

/// Device substrate failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DeviceError {
    /// Provider identity/revision/generation evidence was invalid.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// Canonical Ptah identity construction failed.
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
    /// A required observation string was empty.
    #[error("required device observation field is empty: {0}")]
    EmptyField(&'static str),
    /// No canonical evidence basis was supplied for stable Device identity.
    #[error("device observation requires at least one canonical identity-basis reference")]
    MissingIdentityBasis,
    /// No canonical continuity evidence was supplied for a connection epoch.
    #[error("device observation requires at least one continuity-basis reference")]
    MissingContinuityBasis,
    /// No canonical evidence reference was supplied for an observation.
    #[error("device observation requires at least one evidence reference")]
    MissingEvidence,
    /// A supposedly unique reference list contained duplicates.
    #[error("device observation contains duplicate canonical references")]
    DuplicateReference,
    /// The provider lane received an incompatible transport.
    #[error("device observation transport is incompatible with this provider lane")]
    UnsupportedTransport,
    /// One observation overlaps more than one existing canonical Device basis.
    #[error("device identity basis is ambiguous across multiple canonical Devices")]
    AmbiguousIdentity,
    /// Stable identity evidence disagrees about Device kind.
    #[error("stable device identity evidence conflicts with existing device kind")]
    DeviceKindMismatch,
    /// A backend alias resolved to more than one canonical Device.
    #[error("backend alias is ambiguous across multiple Devices")]
    AmbiguousAlias,
    /// A backend alias did not resolve to a current Device.
    #[error("backend alias did not resolve to a Device")]
    AliasNotFound,
    /// Connection-epoch arithmetic overflowed.
    #[error("device connection epoch overflow")]
    EpochOverflow,
    /// Incoming Provider generation is older than the current Interface evidence.
    #[error("device observation provider generation is stale")]
    StaleProviderGeneration,
    /// Incoming Provider control connection epoch is older than the current Interface evidence.
    #[error("device observation provider connection epoch is stale")]
    StaleProviderConnectionEpoch,
    /// Same-generation Provider evidence unexpectedly changed Provider Instance identity.
    #[error("device observation provider instance conflicts at the same generation and epoch")]
    ProviderInstanceMismatch,
    /// Lease fence token must be positive.
    #[error("device lease fence token must be positive")]
    InvalidFenceToken,
    /// Lease scope was empty or missing the requested operation scope.
    #[error("device lease does not authorize the requested scope")]
    LeaseScopeDenied,
    /// Lease subject does not match the current Device.
    #[error("device lease subject does not match current Device")]
    LeaseSubjectMismatch,
    /// Lease has been revoked.
    #[error("device lease has been revoked")]
    LeaseRevoked,
    /// Lease or operation Provider generation is stale.
    #[error("device lease/provider generation is stale")]
    StaleLeaseProviderGeneration,
    /// Operation or lease Device Connection epoch is stale.
    #[error("device connection epoch is stale")]
    StaleConnectionEpoch,
    /// Observed fence token is behind the lease token.
    #[error("observed device fence token is stale")]
    StaleFence,
    /// Observed fence token is unexpectedly ahead of the lease token.
    #[error("observed device fence token is ahead of the lease token")]
    AheadFence,
    /// Protocol-operation evidence was incomplete or mismatched.
    #[error("device protocol-operation evidence is incomplete or mismatched")]
    OperationEvidenceMismatch,
    /// C08 does not grant mutation authority.
    #[error("device mutation is outside C08 transport-substrate authority")]
    MutationOutsideC08,
}

/// Frozen Device kind vocabulary used by C08.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    /// Physical Android device.
    PhysicalAndroid,
    /// Android emulator.
    AndroidEmulator,
    /// Physical iOS/iPadOS device.
    PhysicalIos,
    /// iOS simulator.
    IosSimulator,
    /// Linux host represented through the Device domain.
    LinuxHost,
    /// Windows host represented through the Device domain.
    WindowsHost,
    /// macOS host represented through the Device domain.
    MacosHost,
    /// Virtual machine.
    VirtualMachine,
    /// Remote application Provider represented through the Device domain.
    RemoteApplicationProvider,
    /// Registered extension outside the frozen narrower vocabulary.
    OtherRegistered,
}

/// Frozen Device Interface transport vocabulary used by C08.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceTransport {
    /// ADB over USB.
    AdbUsb,
    /// ADB over TCP.
    AdbTcp,
    /// ADB over TLS.
    AdbTls,
    /// Fastboot over USB.
    FastbootUsb,
    /// Fastboot over TCP.
    FastbootTcp,
    /// MTP.
    Mtp,
    /// USB serial/COM/TTY.
    UsbSerial,
    /// Vendor USB protocol, including Apple USB observations.
    UsbVendor,
    /// Vendor network protocol.
    NetworkVendor,
    /// Appium proxy.
    AppiumProxy,
    /// Accessibility service.
    AccessibilityService,
    /// scrcpy server transport.
    ScrcpyServer,
    /// Provider-native transport.
    ProviderNative,
    /// Registered extension transport.
    OtherRegistered,
}

/// C08 Provider lanes are node-local in the first substrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceLocality {
    /// Provider and transport are bound to the exact local Node Generation.
    NodeLocal,
}

/// Reachability value retained from Device Connection Observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    /// Current evidence shows the endpoint is reachable.
    Reachable,
    /// Current evidence shows the endpoint is unreachable.
    Unreachable,
    /// Current evidence shows unstable/intermittent reachability.
    Intermittent,
    /// Access was denied.
    PermissionDenied,
    /// Endpoint is currently claimed by another consumer.
    ClaimedByOther,
    /// Reachability is unknown.
    Unknown,
}

/// Connection transition reason retained by C08.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionReason {
    /// First observed connection.
    InitialObservation,
    /// Previously degraded/unreachable connection became reachable again.
    Reconnect,
    /// Transport topology/address changed while canonical identity remained stable.
    Reenumeration,
    /// Device changed protocol/mode.
    ModeTransition,
    /// Provider generation or Provider control epoch advanced.
    ProviderRestart,
    /// Continuity evidence changed.
    TransportContinuityLost,
}

/// Protocol class used by C08 read-only protocol-operation projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolClass {
    /// Android Debug Bridge.
    Adb,
    /// Android Fastboot/Fastbootd.
    Fastboot,
    /// Media Transfer Protocol.
    Mtp,
    /// USB serial.
    UsbSerial,
    /// Vendor download protocol.
    VendorDownload,
    /// MediaTek META protocol.
    Meta,
    /// Diagnostic protocol.
    Diag,
    /// Appium.
    Appium,
    /// Accessibility service.
    Accessibility,
    /// Display/input channel.
    DisplayInput,
    /// Package management.
    PackageManagement,
    /// Shell.
    Shell,
    /// File transfer.
    FileTransfer,
    /// Registered extension protocol.
    OtherRegistered,
}

/// Frozen mutation classes relevant to protocol admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationClass {
    /// Pure observation/read-only action.
    NoneReadOnly,
    /// Copy-only action not mutating the physical Device.
    CopyOnly,
    /// Workspace Object mutation only.
    WorkspaceObjectMutation,
    /// Filesystem write overlay.
    FilesystemWriteOverlay,
    /// Physical Device read.
    DeviceRead,
    /// Physical Device backup/read-out.
    DeviceBackup,
    /// Physical Device write.
    DeviceWrite,
    /// Physical Device erase.
    DeviceErase,
    /// Physical Device repartition.
    DeviceRepartition,
    /// Physical Device reset/reboot.
    DeviceResetOrReboot,
    /// Device security-state mutation.
    DeviceSecurityState,
    /// Protected-NV mutation.
    DeviceProtectedNv,
    /// Device-side payload execution.
    DevicePayloadExecute,
    /// Registered extension mutation class.
    OtherRegistered,
}

impl MutationClass {
    /// Return whether C08 can admit the class without manufacturing physical write authority.
    #[must_use]
    pub const fn is_c08_read_only(self) -> bool {
        matches!(
            self,
            Self::NoneReadOnly
                | Self::CopyOnly
                | Self::WorkspaceObjectMutation
                | Self::DeviceRead
                | Self::DeviceBackup
        )
    }
}

/// Exact Device Provider binding used by observation lanes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceProviderBinding {
    /// Validated immutable Provider context.
    pub context: ProviderContext,
    /// Capability evidence retained from the exact Provider Revision.
    pub capability_claim_refs: Vec<EntityRef>,
}

impl DeviceProviderBinding {
    /// Bind an exact Device Provider Revision to a local Provider Instance.
    ///
    /// # Errors
    /// Fails when the Provider kind is not `Device`, mandatory revision evidence is
    /// absent, local instance evidence is invalid, or the instance references a
    /// different Provider Revision.
    pub fn bind(
        revision: &ProviderRevision,
        instance: &ProviderInstance,
    ) -> Result<Self, DeviceError> {
        if revision.provider_kind != ProviderKind::Device {
            return Err(ProviderError::ProviderKindMismatch.into());
        }
        require_provider_text(&revision.implementation_name, "implementation_name")?;
        require_provider_text(&revision.implementation_version, "implementation_version")?;
        require_provider_text(&revision.build_or_package_digest, "build_or_package_digest")?;
        require_provider_text(&revision.configuration_digest, "configuration_digest")?;
        if revision.supported_facility_refs.is_empty() {
            return Err(ProviderError::MissingEvidence("supported_facility_refs").into());
        }
        instance.validate_local()?;
        if instance.provider_revision_ref != revision.revision_ref {
            return Err(ProviderError::MissingEvidence(
                "instance/provider revision match",
            )
            .into());
        }
        Ok(Self {
            context: ProviderContext {
                provider_ref: revision.provider_ref.clone(),
                provider_revision_ref: revision.revision_ref.clone(),
                provider_instance_ref: instance.instance_ref.clone(),
                provider_generation: instance.provider_generation,
                node_ref: instance.node_ref.clone(),
                node_generation: instance.node_generation,
                connection_epoch: instance.connection_epoch,
                implementation_version: revision.implementation_version.clone(),
            },
            capability_claim_refs: revision.capability_claim_refs.clone(),
        })
    }
}

/// Common mechanical endpoint evidence supplied to one observation Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationSeed {
    /// Device profile Revision selected by prior/static evidence.
    pub profile_revision_ref: EntityRef,
    /// Canonical evidence forming the stable Device identity basis.
    pub identity_basis_refs: Vec<EntityRef>,
    /// Canonical evidence supporting transport continuity.
    pub continuity_basis_refs: Vec<EntityRef>,
    /// Canonical evidence supporting this observation.
    pub evidence_refs: Vec<EntityRef>,
    /// Backend-local endpoint alias. It is never canonical Device identity.
    pub backend_alias: String,
    /// Optional topology/address evidence.
    pub topology_or_address: Option<String>,
    /// Optional VID/PID/endpoint claims.
    pub endpoint_claims: Vec<String>,
    /// Current reachability.
    pub reachability: Reachability,
    /// Observation timestamp.
    pub observed_at: String,
}

/// Normalized C08 transport observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportObservation {
    /// Device Provider context.
    pub provider: DeviceProviderBinding,
    /// Frozen Device kind.
    pub device_kind: DeviceKind,
    /// Exact profile Revision used for this observation.
    pub profile_revision_ref: EntityRef,
    /// Stable Device identity evidence.
    pub identity_basis_refs: Vec<EntityRef>,
    /// Connection continuity evidence.
    pub continuity_basis_refs: Vec<EntityRef>,
    /// Exact observation evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// Backend aliases retained as evidence only.
    pub backend_aliases: Vec<String>,
    /// Interface transport.
    pub transport: InterfaceTransport,
    /// Protocol/mode projection.
    pub mode_or_protocol: String,
    /// Optional protocol version.
    pub protocol_version: Option<String>,
    /// Optional topology/address evidence.
    pub topology_or_address: Option<String>,
    /// VID/PID/endpoint claims retained as evidence only.
    pub endpoint_claims: Vec<String>,
    /// Current reachability.
    pub reachability: Reachability,
    /// Observation timestamp.
    pub observed_at: String,
    /// Explicit limitations.
    pub limitations: Vec<String>,
}

impl TransportObservation {
    fn validate(&self) -> Result<(), DeviceError> {
        require_entity_kind(&self.profile_revision_ref, "device.profile_revision")?;
        if self.identity_basis_refs.is_empty() {
            return Err(DeviceError::MissingIdentityBasis);
        }
        if self.continuity_basis_refs.is_empty() {
            return Err(DeviceError::MissingContinuityBasis);
        }
        if self.evidence_refs.is_empty() {
            return Err(DeviceError::MissingEvidence);
        }
        require_nonempty(&self.mode_or_protocol, "mode_or_protocol")?;
        require_nonempty(&self.observed_at, "observed_at")?;
        if self.backend_aliases.iter().any(|value| value.trim().is_empty()) {
            return Err(DeviceError::EmptyField("backend_alias"));
        }
        if has_duplicates(&self.identity_basis_refs)
            || has_duplicates(&self.continuity_basis_refs)
            || has_duplicates(&self.evidence_refs)
        {
            return Err(DeviceError::DuplicateReference);
        }
        Ok(())
    }
}

/// Observation-only ADB Provider lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdbObservationProvider {
    binding: DeviceProviderBinding,
}

impl AdbObservationProvider {
    /// Construct an ADB observation Provider from exact Provider evidence.
    #[must_use]
    pub fn new(binding: DeviceProviderBinding) -> Self {
        Self { binding }
    }

    /// Normalize one ADB endpoint observation.
    ///
    /// # Errors
    /// Fails closed for non-ADB transports or incomplete observation evidence.
    pub fn observe(
        &self,
        transport: InterfaceTransport,
        seed: ObservationSeed,
        protocol_version: Option<String>,
    ) -> Result<TransportObservation, DeviceError> {
        if !matches!(
            transport,
            InterfaceTransport::AdbUsb | InterfaceTransport::AdbTcp | InterfaceTransport::AdbTls
        ) {
            return Err(DeviceError::UnsupportedTransport);
        }
        normalized_observation(
            self.binding.clone(),
            DeviceKind::PhysicalAndroid,
            transport,
            "adb",
            protocol_version,
            seed,
        )
    }
}

/// Observation-only Fastboot/Fastbootd Provider lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastbootObservationProvider {
    binding: DeviceProviderBinding,
}

impl FastbootObservationProvider {
    /// Construct a Fastboot observation Provider from exact Provider evidence.
    #[must_use]
    pub fn new(binding: DeviceProviderBinding) -> Self {
        Self { binding }
    }

    /// Normalize one Fastboot or Fastbootd endpoint observation.
    ///
    /// # Errors
    /// Fails closed for non-Fastboot transports or incomplete evidence.
    pub fn observe(
        &self,
        transport: InterfaceTransport,
        fastbootd: bool,
        seed: ObservationSeed,
        protocol_version: Option<String>,
    ) -> Result<TransportObservation, DeviceError> {
        if !matches!(
            transport,
            InterfaceTransport::FastbootUsb | InterfaceTransport::FastbootTcp
        ) {
            return Err(DeviceError::UnsupportedTransport);
        }
        normalized_observation(
            self.binding.clone(),
            DeviceKind::PhysicalAndroid,
            transport,
            if fastbootd { "fastbootd" } else { "fastboot" },
            protocol_version,
            seed,
        )
    }
}

/// Apple USB mode observed by the C08 Apple Provider lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppleMode {
    /// Normal trusted/pairing-capable userspace mode.
    Normal,
    /// Recovery mode.
    Recovery,
    /// DFU mode.
    Dfu,
}

impl AppleMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "apple_normal",
            Self::Recovery => "apple_recovery",
            Self::Dfu => "apple_dfu",
        }
    }
}

/// Observation-only Apple USB Provider lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleObservationProvider {
    binding: DeviceProviderBinding,
}

impl AppleObservationProvider {
    /// Construct an Apple USB observation Provider.
    #[must_use]
    pub fn new(binding: DeviceProviderBinding) -> Self {
        Self { binding }
    }

    /// Normalize one Apple USB observation without granting restore/write authority.
    ///
    /// # Errors
    /// Fails closed for incomplete evidence.
    pub fn observe(
        &self,
        mode: AppleMode,
        seed: ObservationSeed,
        protocol_version: Option<String>,
    ) -> Result<TransportObservation, DeviceError> {
        normalized_observation(
            self.binding.clone(),
            DeviceKind::PhysicalIos,
            InterfaceTransport::UsbVendor,
            mode.as_str(),
            protocol_version,
            seed,
        )
    }
}

/// Observation-only USB serial Provider lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbSerialObservationProvider {
    binding: DeviceProviderBinding,
}

impl UsbSerialObservationProvider {
    /// Construct a USB serial observation Provider.
    #[must_use]
    pub fn new(binding: DeviceProviderBinding) -> Self {
        Self { binding }
    }

    /// Normalize one supported USB serial endpoint observation.
    ///
    /// # Errors
    /// Fails closed for incomplete evidence.
    pub fn observe(
        &self,
        device_kind: DeviceKind,
        mode_or_protocol: &str,
        seed: ObservationSeed,
        protocol_version: Option<String>,
    ) -> Result<TransportObservation, DeviceError> {
        normalized_observation(
            self.binding.clone(),
            device_kind,
            InterfaceTransport::UsbSerial,
            mode_or_protocol,
            protocol_version,
            seed,
        )
    }
}

/// Canonical Device projection owned by C08.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    /// Stable canonical Device reference.
    pub device_ref: EntityRef,
    /// Frozen Device kind.
    pub device_kind: DeviceKind,
    /// Canonical evidence supporting stable identity.
    pub identity_basis_refs: Vec<EntityRef>,
    /// Current profile Revision.
    pub current_profile_revision_ref: EntityRef,
    /// Every retained profile Revision.
    pub profile_revision_refs: Vec<EntityRef>,
    /// Explicit limitations.
    pub limitations: Vec<String>,
}

/// Current Device Interface incarnation projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInterfaceRecord {
    /// Canonical interface reference.
    pub interface_ref: EntityRef,
    /// Stable Device reference.
    pub device_ref: EntityRef,
    /// Interface transport.
    pub transport: InterfaceTransport,
    /// Mode/protocol.
    pub mode_or_protocol: String,
    /// Optional protocol version.
    pub protocol_version: Option<String>,
    /// Backend aliases retained as evidence only.
    pub observed_aliases: Vec<String>,
    /// Optional topology/address evidence.
    pub topology_or_address: Option<String>,
    /// VID/PID/endpoint claims retained as evidence only.
    pub endpoint_claims: Vec<String>,
    /// Exact Provider instance.
    pub provider_instance_ref: EntityRef,
    /// Provider generation.
    pub provider_generation: ProviderGeneration,
    /// First C08 Provider lanes are node-local.
    pub locality: InterfaceLocality,
    /// Exact local Node reference.
    pub node_ref: EntityRef,
    /// Exact local Node generation.
    pub node_generation: u64,
    /// Provider control connection epoch.
    pub provider_connection_epoch: u64,
    /// Current Device connection epoch.
    pub connection_epoch: u64,
    /// Current connection reference.
    pub connection_ref: EntityRef,
    /// Current continuity basis.
    pub continuity_basis_refs: Vec<EntityRef>,
    /// Provider capability evidence retained for the interface.
    pub capability_claim_refs: Vec<EntityRef>,
    /// Current reachability.
    pub reachability: Reachability,
    /// Last observation evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// First observation timestamp for this Interface incarnation.
    pub first_observed_at: String,
    /// Last observation timestamp.
    pub last_observed_at: String,
}

/// Immutable Device Connection epoch projection retained in history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceConnectionRecord {
    /// Canonical connection reference.
    pub connection_ref: EntityRef,
    /// Stable Device reference.
    pub device_ref: EntityRef,
    /// Interface reference.
    pub interface_ref: EntityRef,
    /// Monotonic Device connection epoch.
    pub connection_epoch: u64,
    /// Exact Provider instance.
    pub provider_instance_ref: EntityRef,
    /// Exact Provider generation.
    pub provider_generation: ProviderGeneration,
    /// Continuity basis.
    pub continuity_basis_refs: Vec<EntityRef>,
    /// Previous connection when this epoch superseded one.
    pub predecessor_connection_ref: Option<EntityRef>,
    /// Reason this epoch began.
    pub transition_reason: TransitionReason,
    /// Start observation time.
    pub started_at: String,
    /// Evidence supporting this epoch.
    pub evidence_refs: Vec<EntityRef>,
}

/// Canonical observation projection created after reconciliation binds Device/Interface/Connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceConnectionObservationRecord {
    /// Canonical observation reference.
    pub observation_ref: EntityRef,
    /// Stable Device reference.
    pub device_ref: EntityRef,
    /// Interface reference.
    pub interface_ref: EntityRef,
    /// Exact Connection reference.
    pub connection_ref: EntityRef,
    /// Exact Device connection epoch.
    pub connection_epoch: u64,
    /// Exact Provider instance.
    pub provider_instance_ref: EntityRef,
    /// Exact Provider generation.
    pub provider_generation: ProviderGeneration,
    /// Observed reachability.
    pub reachability: Reachability,
    /// Mode/protocol observed.
    pub mode_or_protocol: String,
    /// Observation timestamp.
    pub observed_at: String,
    /// Evidence supporting the observation.
    pub evidence_refs: Vec<EntityRef>,
}

/// Result of reconciling one transport observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// Canonical Device after reconciliation.
    pub device: DeviceRecord,
    /// Current interface after reconciliation.
    pub interface: DeviceInterfaceRecord,
    /// Current connection after reconciliation.
    pub connection: DeviceConnectionRecord,
    /// Canonical connection observation retained for this reconcile call.
    pub observation: DeviceConnectionObservationRecord,
    /// Whether a new Device identity was allocated.
    pub device_created: bool,
    /// Whether a new interface identity was allocated.
    pub interface_created: bool,
    /// Whether a new connection epoch was allocated.
    pub connection_advanced: bool,
}

/// In-memory C08 reconciliation substrate.
#[derive(Debug, Default, Clone)]
pub struct DeviceRegistry {
    devices: Vec<DeviceRecord>,
    interfaces: Vec<DeviceInterfaceRecord>,
    connections: Vec<DeviceConnectionRecord>,
    observations: Vec<DeviceConnectionObservationRecord>,
}

impl DeviceRegistry {
    /// Return current canonical Devices.
    #[must_use]
    pub fn devices(&self) -> &[DeviceRecord] {
        &self.devices
    }

    /// Return current Device Interfaces.
    #[must_use]
    pub fn interfaces(&self) -> &[DeviceInterfaceRecord] {
        &self.interfaces
    }

    /// Return retained immutable connection-epoch history.
    #[must_use]
    pub fn connections(&self) -> &[DeviceConnectionRecord] {
        &self.connections
    }

    /// Return retained connection observations.
    #[must_use]
    pub fn observations(&self) -> &[DeviceConnectionObservationRecord] {
        &self.observations
    }

    /// Reconcile one bounded transport observation into stable Device identity and
    /// monotonic connection epochs.
    ///
    /// # Errors
    /// Fails closed when identity evidence overlaps more than one canonical Device,
    /// stable identity conflicts with Device kind, Provider/epoch evidence is stale,
    /// required evidence is absent, or epoch arithmetic overflows.
    pub fn reconcile(
        &mut self,
        observation: TransportObservation,
    ) -> Result<ReconcileOutcome, DeviceError> {
        observation.validate()?;
        let matching_devices = self
            .devices
            .iter()
            .enumerate()
            .filter(|(_, device)| {
                basis_overlaps(&device.identity_basis_refs, &observation.identity_basis_refs)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matching_devices.len() > 1 {
            return Err(DeviceError::AmbiguousIdentity);
        }

        let (device_index, device_created) = if let Some(index) = matching_devices.first().copied() {
            if self.devices[index].device_kind != observation.device_kind {
                return Err(DeviceError::DeviceKindMismatch);
            }
            merge_unique_refs(
                &mut self.devices[index].identity_basis_refs,
                &observation.identity_basis_refs,
            );
            if !self.devices[index]
                .profile_revision_refs
                .contains(&observation.profile_revision_ref)
            {
                self.devices[index]
                    .profile_revision_refs
                    .push(observation.profile_revision_ref.clone());
            }
            self.devices[index].current_profile_revision_ref = observation.profile_revision_ref.clone();
            (index, false)
        } else {
            let device = DeviceRecord {
                device_ref: EntityRef::new("device.device")?,
                device_kind: observation.device_kind,
                identity_basis_refs: observation.identity_basis_refs.clone(),
                current_profile_revision_ref: observation.profile_revision_ref.clone(),
                profile_revision_refs: vec![observation.profile_revision_ref.clone()],
                limitations: observation.limitations.clone(),
            };
            self.devices.push(device);
            (self.devices.len() - 1, true)
        };
        let device_ref = self.devices[device_index].device_ref.clone();

        let interface_index = self.interfaces.iter().position(|interface| {
            interface.device_ref == device_ref
                && interface.transport == observation.transport
                && interface.mode_or_protocol == observation.mode_or_protocol
        });

        let (interface_index, interface_created, connection_advanced) =
            if let Some(index) = interface_index {
                validate_observation_freshness(&self.interfaces[index], &observation)?;
                let reason = connection_transition_reason(&self.interfaces[index], &observation);
                if let Some(reason) = reason {
                    let next_epoch = self.interfaces[index]
                        .connection_epoch
                        .checked_add(1)
                        .ok_or(DeviceError::EpochOverflow)?;
                    let predecessor = self.interfaces[index].connection_ref.clone();
                    let connection_ref = EntityRef::new("device.connection")?;
                    self.interfaces[index].connection_epoch = next_epoch;
                    self.interfaces[index].connection_ref = connection_ref.clone();
                    self.interfaces[index].provider_instance_ref =
                        observation.provider.context.provider_instance_ref.clone();
                    self.interfaces[index].provider_generation =
                        observation.provider.context.provider_generation;
                    self.interfaces[index].node_ref = observation.provider.context.node_ref.clone();
                    self.interfaces[index].node_generation = observation.provider.context.node_generation;
                    self.interfaces[index].provider_connection_epoch =
                        observation.provider.context.connection_epoch;
                    self.interfaces[index].continuity_basis_refs =
                        observation.continuity_basis_refs.clone();
                    self.interfaces[index].protocol_version = observation.protocol_version.clone();
                    self.interfaces[index].topology_or_address = observation.topology_or_address.clone();
                    self.interfaces[index].endpoint_claims = observation.endpoint_claims.clone();
                    self.interfaces[index].capability_claim_refs =
                        observation.provider.capability_claim_refs.clone();
                    self.interfaces[index].reachability = observation.reachability;
                    self.interfaces[index].observed_aliases = observation.backend_aliases.clone();
                    self.interfaces[index].evidence_refs = observation.evidence_refs.clone();
                    self.interfaces[index].last_observed_at = observation.observed_at.clone();
                    self.connections.push(DeviceConnectionRecord {
                        connection_ref,
                        device_ref: device_ref.clone(),
                        interface_ref: self.interfaces[index].interface_ref.clone(),
                        connection_epoch: next_epoch,
                        provider_instance_ref: observation
                            .provider
                            .context
                            .provider_instance_ref
                            .clone(),
                        provider_generation: observation.provider.context.provider_generation,
                        continuity_basis_refs: observation.continuity_basis_refs.clone(),
                        predecessor_connection_ref: Some(predecessor),
                        transition_reason: reason,
                        started_at: observation.observed_at.clone(),
                        evidence_refs: observation.evidence_refs.clone(),
                    });
                    (index, false, true)
                } else {
                    self.interfaces[index].protocol_version = observation.protocol_version.clone();
                    self.interfaces[index].endpoint_claims = observation.endpoint_claims.clone();
                    self.interfaces[index].capability_claim_refs =
                        observation.provider.capability_claim_refs.clone();
                    self.interfaces[index].reachability = observation.reachability;
                    self.interfaces[index].observed_aliases = observation.backend_aliases.clone();
                    self.interfaces[index].evidence_refs = observation.evidence_refs.clone();
                    self.interfaces[index].last_observed_at = observation.observed_at.clone();
                    (index, false, false)
                }
            } else {
                let interface_ref = EntityRef::new("device.interface")?;
                let connection_ref = EntityRef::new("device.connection")?;
                let interface = DeviceInterfaceRecord {
                    interface_ref: interface_ref.clone(),
                    device_ref: device_ref.clone(),
                    transport: observation.transport,
                    mode_or_protocol: observation.mode_or_protocol.clone(),
                    protocol_version: observation.protocol_version.clone(),
                    observed_aliases: observation.backend_aliases.clone(),
                    topology_or_address: observation.topology_or_address.clone(),
                    endpoint_claims: observation.endpoint_claims.clone(),
                    provider_instance_ref: observation
                        .provider
                        .context
                        .provider_instance_ref
                        .clone(),
                    provider_generation: observation.provider.context.provider_generation,
                    locality: InterfaceLocality::NodeLocal,
                    node_ref: observation.provider.context.node_ref.clone(),
                    node_generation: observation.provider.context.node_generation,
                    provider_connection_epoch: observation.provider.context.connection_epoch,
                    connection_epoch: 1,
                    connection_ref: connection_ref.clone(),
                    continuity_basis_refs: observation.continuity_basis_refs.clone(),
                    capability_claim_refs: observation.provider.capability_claim_refs.clone(),
                    reachability: observation.reachability,
                    evidence_refs: observation.evidence_refs.clone(),
                    first_observed_at: observation.observed_at.clone(),
                    last_observed_at: observation.observed_at.clone(),
                };
                self.interfaces.push(interface);
                let index = self.interfaces.len() - 1;
                self.connections.push(DeviceConnectionRecord {
                    connection_ref,
                    device_ref: device_ref.clone(),
                    interface_ref,
                    connection_epoch: 1,
                    provider_instance_ref: observation
                        .provider
                        .context
                        .provider_instance_ref
                        .clone(),
                    provider_generation: observation.provider.context.provider_generation,
                    continuity_basis_refs: observation.continuity_basis_refs.clone(),
                    predecessor_connection_ref: None,
                    transition_reason: TransitionReason::InitialObservation,
                    started_at: observation.observed_at.clone(),
                    evidence_refs: observation.evidence_refs.clone(),
                });
                (index, true, true)
            };

        let current_connection_ref = self.interfaces[interface_index].connection_ref.clone();
        let connection = self
            .connections
            .iter()
            .find(|connection| connection.connection_ref == current_connection_ref)
            .cloned()
            .ok_or(DeviceError::OperationEvidenceMismatch)?;
        let connection_observation = DeviceConnectionObservationRecord {
            observation_ref: EntityRef::new("device.connection_observation")?,
            device_ref: device_ref.clone(),
            interface_ref: self.interfaces[interface_index].interface_ref.clone(),
            connection_ref: connection.connection_ref.clone(),
            connection_epoch: connection.connection_epoch,
            provider_instance_ref: observation.provider.context.provider_instance_ref.clone(),
            provider_generation: observation.provider.context.provider_generation,
            reachability: observation.reachability,
            mode_or_protocol: observation.mode_or_protocol,
            observed_at: observation.observed_at,
            evidence_refs: observation.evidence_refs,
        };
        self.observations.push(connection_observation.clone());
        Ok(ReconcileOutcome {
            device: self.devices[device_index].clone(),
            interface: self.interfaces[interface_index].clone(),
            connection,
            observation: connection_observation,
            device_created,
            interface_created,
            connection_advanced,
        })
    }

    /// Resolve a backend alias only as a lookup hint.
    ///
    /// # Errors
    /// Returns [`DeviceError::AmbiguousAlias`] when the alias appears on multiple
    /// canonical Devices and [`DeviceError::AliasNotFound`] when it is absent.
    pub fn resolve_backend_alias(&self, alias: &str) -> Result<&DeviceRecord, DeviceError> {
        require_nonempty(alias, "backend_alias")?;
        let mut device_indexes = BTreeSet::new();
        for interface in &self.interfaces {
            if interface.observed_aliases.iter().any(|value| value == alias) {
                if let Some(index) = self
                    .devices
                    .iter()
                    .position(|device| device.device_ref == interface.device_ref)
                {
                    device_indexes.insert(index);
                }
            }
        }
        match device_indexes.len() {
            0 => Err(DeviceError::AliasNotFound),
            1 => Ok(&self.devices[*device_indexes.first().expect("one index")]),
            _ => Err(DeviceError::AmbiguousAlias),
        }
    }
}

/// Device-control lease bound to exact Provider generation and connection epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLease {
    /// Canonical Lease reference.
    pub lease_ref: EntityRef,
    /// Stable Device subject.
    pub device_ref: EntityRef,
    /// Current holder.
    pub holder_ref: EntityRef,
    /// Authorized operation scopes.
    pub scope: BTreeSet<String>,
    /// Positive fencing token.
    pub fence_token: u64,
    /// Exact Provider generation.
    pub provider_generation: ProviderGeneration,
    /// Exact Device connection epoch.
    pub connection_epoch: u64,
    /// Issue timestamp.
    pub issued_at: String,
    /// Expiry timestamp retained for the canonical Lease lifecycle projection.
    pub expires_at: String,
    /// Revocation projection. Expiry itself remains an A13/lifecycle decision.
    pub revoked: bool,
}

impl DeviceLease {
    /// Issue a Device lease projection.
    ///
    /// # Errors
    /// Rejects zero fence tokens, empty scope, incorrect Device kind, or empty timestamps.
    pub fn issue(
        device_ref: EntityRef,
        holder_ref: EntityRef,
        scope: impl IntoIterator<Item = String>,
        fence_token: u64,
        provider_generation: ProviderGeneration,
        connection_epoch: u64,
        issued_at: impl Into<String>,
        expires_at: impl Into<String>,
    ) -> Result<Self, DeviceError> {
        require_entity_kind(&device_ref, "device.device")?;
        if fence_token == 0 {
            return Err(DeviceError::InvalidFenceToken);
        }
        let scope = scope.into_iter().collect::<BTreeSet<_>>();
        if scope.is_empty() || scope.iter().any(|value| value.trim().is_empty()) {
            return Err(DeviceError::LeaseScopeDenied);
        }
        let issued_at = issued_at.into();
        let expires_at = expires_at.into();
        require_nonempty(&issued_at, "issued_at")?;
        require_nonempty(&expires_at, "expires_at")?;
        Ok(Self {
            lease_ref: EntityRef::new("isolation.lease")?,
            device_ref,
            holder_ref,
            scope,
            fence_token,
            provider_generation,
            connection_epoch,
            issued_at,
            expires_at,
            revoked: false,
        })
    }

    /// Revoke this in-memory lease projection.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Fence an operation against the current interface state.
    ///
    /// # Errors
    /// Rejects revoked, mismatched, stale, ahead-token, or insufficient-scope leases.
    pub fn fence(
        &self,
        interface: &DeviceInterfaceRecord,
        observed_fence_token: u64,
        required_scope: &str,
    ) -> Result<FenceDecision, DeviceError> {
        if self.revoked {
            return Err(DeviceError::LeaseRevoked);
        }
        if self.device_ref != interface.device_ref {
            return Err(DeviceError::LeaseSubjectMismatch);
        }
        if self.provider_generation != interface.provider_generation {
            return Err(DeviceError::StaleLeaseProviderGeneration);
        }
        if self.connection_epoch != interface.connection_epoch {
            return Err(DeviceError::StaleConnectionEpoch);
        }
        if !self.scope.contains(required_scope) {
            return Err(DeviceError::LeaseScopeDenied);
        }
        if observed_fence_token < self.fence_token {
            return Err(DeviceError::StaleFence);
        }
        if observed_fence_token > self.fence_token {
            return Err(DeviceError::AheadFence);
        }
        Ok(FenceDecision::Current)
    }
}

/// Frozen fence-observation decisions needed by C08.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceDecision {
    /// Observed token is exactly current.
    Current,
    /// Observed token is stale.
    Stale,
    /// Observed token is ahead of expected state.
    Ahead,
    /// Token was missing.
    Missing,
    /// Evidence is inconclusive.
    Inconclusive,
}

/// Read-only protocol-operation request.
#[derive(Debug, Clone)]
pub struct ProtocolOperationRequest<'a> {
    /// Stable Device reference.
    pub device_ref: EntityRef,
    /// Device profile Revision.
    pub device_profile_revision_ref: EntityRef,
    /// Device Session reference.
    pub device_session_ref: EntityRef,
    /// Current interface.
    pub interface: &'a DeviceInterfaceRecord,
    /// Exact Provider context.
    pub provider: &'a DeviceProviderBinding,
    /// Current lease.
    pub lease: &'a DeviceLease,
    /// Observed fence token.
    pub observed_fence_token: u64,
    /// Protocol class.
    pub protocol_class: ProtocolClass,
    /// Registered operation key.
    pub protocol_operation_key: String,
    /// Mutation class requested by caller.
    pub mutation_class: MutationClass,
    /// Producing Activity.
    pub activity_ref: EntityRef,
    /// Producing Operation.
    pub operation_ref: EntityRef,
    /// Exact Attempt refs.
    pub attempt_refs: Vec<EntityRef>,
    /// Observation/protocol evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// Start timestamp.
    pub started_at: String,
    /// Optional physical authority evidence supplied by a higher layer. C08 never
    /// upgrades this evidence into mutation authority.
    pub physical_authority_ref: Option<EntityRef>,
}

/// Admitted C08 protocol-operation projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedProtocolOperation {
    /// Canonical Device Protocol Operation reference.
    pub protocol_operation_ref: EntityRef,
    /// Stable Device reference.
    pub device_ref: EntityRef,
    /// Exact Device Profile Revision.
    pub device_profile_revision_ref: EntityRef,
    /// Exact Device Session reference.
    pub device_session_ref: EntityRef,
    /// Current interface reference.
    pub interface_ref: EntityRef,
    /// Current connection reference.
    pub connection_ref: EntityRef,
    /// Exact connection epoch.
    pub connection_epoch: u64,
    /// Exact Provider instance.
    pub provider_instance_ref: EntityRef,
    /// Exact Provider generation.
    pub provider_generation: ProviderGeneration,
    /// Lease reference.
    pub lease_ref: EntityRef,
    /// Protocol class.
    pub protocol_class: ProtocolClass,
    /// Registered operation key.
    pub protocol_operation_key: String,
    /// Mutation class retained exactly.
    pub mutation_class: MutationClass,
    /// Activity reference.
    pub activity_ref: EntityRef,
    /// Operation reference.
    pub operation_ref: EntityRef,
    /// Attempt refs.
    pub attempt_refs: Vec<EntityRef>,
    /// Supporting evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// Start timestamp.
    pub started_at: String,
    /// Physical-authority evidence retained without upgrading C08 authority.
    pub physical_authority_ref: Option<EntityRef>,
    /// Explicit authority result.
    pub authority: OperationAuthority,
}

/// Authority result of C08 admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationAuthority {
    /// Operation is admitted strictly within read/copy/backup observation authority.
    ReadOnly,
}

/// Admit a protocol operation through exact Device/Provider/epoch/lease/fence evidence.
///
/// C08 rejects all physical Device mutation classes even if a higher layer supplies a
/// physical-authority reference. That evidence belongs to later mutation policy and
/// verification packages.
///
/// # Errors
/// Fails closed for stale Provider/connection state, incomplete Activity/Attempt evidence,
/// lease/fence mismatch, malformed canonical refs, or any Device mutation class outside C08.
pub fn admit_protocol_operation(
    request: ProtocolOperationRequest<'_>,
) -> Result<AdmittedProtocolOperation, DeviceError> {
    require_nonempty(&request.protocol_operation_key, "protocol_operation_key")?;
    require_nonempty(&request.started_at, "started_at")?;
    require_entity_kind(&request.device_ref, "device.device")?;
    require_entity_kind(
        &request.device_profile_revision_ref,
        "device.profile_revision",
    )?;
    require_entity_kind(&request.device_session_ref, "device.session")?;
    require_entity_kind(&request.interface.interface_ref, "device.interface")?;
    require_entity_kind(&request.interface.connection_ref, "device.connection")?;
    if request.attempt_refs.is_empty() || request.evidence_refs.is_empty() {
        return Err(DeviceError::OperationEvidenceMismatch);
    }
    if request.device_ref != request.interface.device_ref
        || request.provider.context.provider_instance_ref != request.interface.provider_instance_ref
        || request.provider.context.provider_generation != request.interface.provider_generation
    {
        return Err(DeviceError::OperationEvidenceMismatch);
    }
    if request.provider.context.connection_epoch != request.interface.provider_connection_epoch {
        return Err(DeviceError::StaleProviderConnectionEpoch);
    }
    request.lease.fence(
        request.interface,
        request.observed_fence_token,
        "protocol.observe",
    )?;
    if !request.mutation_class.is_c08_read_only() {
        return Err(DeviceError::MutationOutsideC08);
    }
    Ok(AdmittedProtocolOperation {
        protocol_operation_ref: EntityRef::new("device.protocol_operation")?,
        device_ref: request.device_ref,
        device_profile_revision_ref: request.device_profile_revision_ref,
        device_session_ref: request.device_session_ref,
        interface_ref: request.interface.interface_ref.clone(),
        connection_ref: request.interface.connection_ref.clone(),
        connection_epoch: request.interface.connection_epoch,
        provider_instance_ref: request.provider.context.provider_instance_ref.clone(),
        provider_generation: request.provider.context.provider_generation,
        lease_ref: request.lease.lease_ref.clone(),
        protocol_class: request.protocol_class,
        protocol_operation_key: request.protocol_operation_key,
        mutation_class: request.mutation_class,
        activity_ref: request.activity_ref,
        operation_ref: request.operation_ref,
        attempt_refs: request.attempt_refs,
        evidence_refs: request.evidence_refs,
        started_at: request.started_at,
        physical_authority_ref: request.physical_authority_ref,
        authority: OperationAuthority::ReadOnly,
    })
}

fn normalized_observation(
    binding: DeviceProviderBinding,
    device_kind: DeviceKind,
    transport: InterfaceTransport,
    mode_or_protocol: &str,
    protocol_version: Option<String>,
    seed: ObservationSeed,
) -> Result<TransportObservation, DeviceError> {
    let observation = TransportObservation {
        provider: binding,
        device_kind,
        profile_revision_ref: seed.profile_revision_ref,
        identity_basis_refs: seed.identity_basis_refs,
        continuity_basis_refs: seed.continuity_basis_refs,
        evidence_refs: seed.evidence_refs,
        backend_aliases: vec![seed.backend_alias],
        transport,
        mode_or_protocol: mode_or_protocol.to_owned(),
        protocol_version,
        topology_or_address: seed.topology_or_address,
        endpoint_claims: seed.endpoint_claims,
        reachability: seed.reachability,
        observed_at: seed.observed_at,
        limitations: Vec::new(),
    };
    observation.validate()?;
    Ok(observation)
}

fn validate_observation_freshness(
    current: &DeviceInterfaceRecord,
    observation: &TransportObservation,
) -> Result<(), DeviceError> {
    let incoming_generation = observation.provider.context.provider_generation;
    if incoming_generation < current.provider_generation {
        return Err(DeviceError::StaleProviderGeneration);
    }
    if incoming_generation == current.provider_generation
        && observation.provider.context.connection_epoch < current.provider_connection_epoch
    {
        return Err(DeviceError::StaleProviderConnectionEpoch);
    }
    if incoming_generation == current.provider_generation
        && observation.provider.context.connection_epoch == current.provider_connection_epoch
        && observation.provider.context.provider_instance_ref != current.provider_instance_ref
    {
        return Err(DeviceError::ProviderInstanceMismatch);
    }
    Ok(())
}

fn connection_transition_reason(
    current: &DeviceInterfaceRecord,
    observation: &TransportObservation,
) -> Option<TransitionReason> {
    if observation.provider.context.provider_generation > current.provider_generation
        || observation.provider.context.connection_epoch > current.provider_connection_epoch
    {
        return Some(TransitionReason::ProviderRestart);
    }
    if !same_reference_set(
        &current.continuity_basis_refs,
        &observation.continuity_basis_refs,
    ) {
        return Some(TransitionReason::TransportContinuityLost);
    }
    if current.topology_or_address != observation.topology_or_address {
        return Some(TransitionReason::Reenumeration);
    }
    if current.reachability != Reachability::Reachable
        && observation.reachability == Reachability::Reachable
    {
        return Some(TransitionReason::Reconnect);
    }
    None
}

fn basis_overlaps(left: &[EntityRef], right: &[EntityRef]) -> bool {
    left.iter().any(|reference| right.contains(reference))
}

fn same_reference_set(left: &[EntityRef], right: &[EntityRef]) -> bool {
    left.len() == right.len() && left.iter().all(|reference| right.contains(reference))
}

fn merge_unique_refs(target: &mut Vec<EntityRef>, source: &[EntityRef]) {
    for reference in source {
        if !target.contains(reference) {
            target.push(reference.clone());
        }
    }
}

fn has_duplicates(values: &[EntityRef]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

fn require_provider_text(value: &str, field: &'static str) -> Result<(), DeviceError> {
    if value.trim().is_empty() {
        return Err(ProviderError::EmptyField(field).into());
    }
    Ok(())
}

fn require_nonempty(value: &str, field: &'static str) -> Result<(), DeviceError> {
    if value.trim().is_empty() {
        return Err(DeviceError::EmptyField(field));
    }
    Ok(())
}

fn require_entity_kind(reference: &EntityRef, expected: &str) -> Result<(), DeviceError> {
    if reference.entity_kind.as_str() != expected {
        return Err(DeviceError::OperationEvidenceMismatch);
    }
    Ok(())
}
