from __future__ import annotations

from pathlib import Path
import re

SOURCE = Path("crates/ptah-device-runtime/src/lib.rs")
TESTS = Path("crates/ptah-device-runtime/tests/c08.rs")

source = SOURCE.read_text(encoding="utf-8")
source = source.replace(
    "    /// MediaTek META protocol.\n",
    "    /// `MediaTek` META protocol.\n",
)

reconcile_start = source.index("    /// Reconcile one bounded transport observation")
resolve_start = source.index("    /// Resolve a backend alias only as a lookup hint.", reconcile_start)

reconcile_block = r'''    /// Reconcile one bounded transport observation into stable Device identity and
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
        let (device_index, device_created) = self.reconcile_device(&observation)?;
        let device_ref = self.devices[device_index].device_ref.clone();
        let (interface_index, interface_created, connection_advanced) =
            self.reconcile_interface(&device_ref, &observation)?;
        let connection = self.current_connection(interface_index)?;
        let connection_observation = self.record_connection_observation(
            &device_ref,
            interface_index,
            &connection,
            &observation,
        )?;

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

    fn reconcile_device(
        &mut self,
        observation: &TransportObservation,
    ) -> Result<(usize, bool), DeviceError> {
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

        if let Some(index) = matching_devices.first().copied() {
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
            self.devices[index]
                .current_profile_revision_ref
                .clone_from(&observation.profile_revision_ref);
            return Ok((index, false));
        }

        self.devices.push(DeviceRecord {
            device_ref: EntityRef::new("device.device")?,
            device_kind: observation.device_kind,
            identity_basis_refs: observation.identity_basis_refs.clone(),
            current_profile_revision_ref: observation.profile_revision_ref.clone(),
            profile_revision_refs: vec![observation.profile_revision_ref.clone()],
            limitations: observation.limitations.clone(),
        });
        Ok((self.devices.len() - 1, true))
    }

    fn reconcile_interface(
        &mut self,
        device_ref: &EntityRef,
        observation: &TransportObservation,
    ) -> Result<(usize, bool, bool), DeviceError> {
        let interface_index = self.interfaces.iter().position(|interface| {
            interface.device_ref == *device_ref
                && interface.transport == observation.transport
                && interface.mode_or_protocol == observation.mode_or_protocol
        });

        if let Some(index) = interface_index {
            validate_observation_freshness(&self.interfaces[index], observation)?;
            if let Some(reason) = connection_transition_reason(&self.interfaces[index], observation)
            {
                self.advance_interface_connection(index, device_ref, observation, reason)?;
                return Ok((index, false, true));
            }
            self.refresh_interface(index, observation);
            return Ok((index, false, false));
        }

        let index = self.create_interface(device_ref, observation)?;
        Ok((index, true, true))
    }

    fn advance_interface_connection(
        &mut self,
        index: usize,
        device_ref: &EntityRef,
        observation: &TransportObservation,
        reason: TransitionReason,
    ) -> Result<(), DeviceError> {
        let next_epoch = self.interfaces[index]
            .connection_epoch
            .checked_add(1)
            .ok_or(DeviceError::EpochOverflow)?;
        let predecessor = self.interfaces[index].connection_ref.clone();
        let connection_ref = EntityRef::new("device.connection")?;
        let interface_ref = {
            let interface = &mut self.interfaces[index];
            interface.connection_epoch = next_epoch;
            interface.connection_ref.clone_from(&connection_ref);
            interface
                .provider_instance_ref
                .clone_from(&observation.provider.context.provider_instance_ref);
            interface.provider_generation = observation.provider.context.provider_generation;
            interface.node_ref.clone_from(&observation.provider.context.node_ref);
            interface.node_generation = observation.provider.context.node_generation;
            interface.provider_connection_epoch = observation.provider.context.connection_epoch;
            interface
                .continuity_basis_refs
                .clone_from(&observation.continuity_basis_refs);
            interface.protocol_version.clone_from(&observation.protocol_version);
            interface
                .topology_or_address
                .clone_from(&observation.topology_or_address);
            interface.endpoint_claims.clone_from(&observation.endpoint_claims);
            interface
                .capability_claim_refs
                .clone_from(&observation.provider.capability_claim_refs);
            interface.reachability = observation.reachability;
            interface
                .observed_aliases
                .clone_from(&observation.backend_aliases);
            interface.evidence_refs.clone_from(&observation.evidence_refs);
            interface.last_observed_at.clone_from(&observation.observed_at);
            interface.interface_ref.clone()
        };

        self.connections.push(DeviceConnectionRecord {
            connection_ref,
            device_ref: device_ref.clone(),
            interface_ref,
            connection_epoch: next_epoch,
            provider_instance_ref: observation.provider.context.provider_instance_ref.clone(),
            provider_generation: observation.provider.context.provider_generation,
            continuity_basis_refs: observation.continuity_basis_refs.clone(),
            predecessor_connection_ref: Some(predecessor),
            transition_reason: reason,
            started_at: observation.observed_at.clone(),
            evidence_refs: observation.evidence_refs.clone(),
        });
        Ok(())
    }

    fn refresh_interface(&mut self, index: usize, observation: &TransportObservation) {
        let interface = &mut self.interfaces[index];
        interface.protocol_version.clone_from(&observation.protocol_version);
        interface.endpoint_claims.clone_from(&observation.endpoint_claims);
        interface
            .capability_claim_refs
            .clone_from(&observation.provider.capability_claim_refs);
        interface.reachability = observation.reachability;
        interface
            .observed_aliases
            .clone_from(&observation.backend_aliases);
        interface.evidence_refs.clone_from(&observation.evidence_refs);
        interface.last_observed_at.clone_from(&observation.observed_at);
    }

    fn create_interface(
        &mut self,
        device_ref: &EntityRef,
        observation: &TransportObservation,
    ) -> Result<usize, DeviceError> {
        let interface_ref = EntityRef::new("device.interface")?;
        let connection_ref = EntityRef::new("device.connection")?;
        self.interfaces.push(DeviceInterfaceRecord {
            interface_ref: interface_ref.clone(),
            device_ref: device_ref.clone(),
            transport: observation.transport,
            mode_or_protocol: observation.mode_or_protocol.clone(),
            protocol_version: observation.protocol_version.clone(),
            observed_aliases: observation.backend_aliases.clone(),
            topology_or_address: observation.topology_or_address.clone(),
            endpoint_claims: observation.endpoint_claims.clone(),
            provider_instance_ref: observation.provider.context.provider_instance_ref.clone(),
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
        });
        let index = self.interfaces.len() - 1;
        self.connections.push(DeviceConnectionRecord {
            connection_ref,
            device_ref: device_ref.clone(),
            interface_ref,
            connection_epoch: 1,
            provider_instance_ref: observation.provider.context.provider_instance_ref.clone(),
            provider_generation: observation.provider.context.provider_generation,
            continuity_basis_refs: observation.continuity_basis_refs.clone(),
            predecessor_connection_ref: None,
            transition_reason: TransitionReason::InitialObservation,
            started_at: observation.observed_at.clone(),
            evidence_refs: observation.evidence_refs.clone(),
        });
        Ok(index)
    }

    fn current_connection(
        &self,
        interface_index: usize,
    ) -> Result<DeviceConnectionRecord, DeviceError> {
        let current_connection_ref = &self.interfaces[interface_index].connection_ref;
        self.connections
            .iter()
            .find(|connection| connection.connection_ref == *current_connection_ref)
            .cloned()
            .ok_or(DeviceError::OperationEvidenceMismatch)
    }

    fn record_connection_observation(
        &mut self,
        device_ref: &EntityRef,
        interface_index: usize,
        connection: &DeviceConnectionRecord,
        observation: &TransportObservation,
    ) -> Result<DeviceConnectionObservationRecord, DeviceError> {
        let record = DeviceConnectionObservationRecord {
            observation_ref: EntityRef::new("device.connection_observation")?,
            device_ref: device_ref.clone(),
            interface_ref: self.interfaces[interface_index].interface_ref.clone(),
            connection_ref: connection.connection_ref.clone(),
            connection_epoch: connection.connection_epoch,
            provider_instance_ref: observation.provider.context.provider_instance_ref.clone(),
            provider_generation: observation.provider.context.provider_generation,
            reachability: observation.reachability,
            mode_or_protocol: observation.mode_or_protocol.clone(),
            observed_at: observation.observed_at.clone(),
            evidence_refs: observation.evidence_refs.clone(),
        };
        self.observations.push(record.clone());
        Ok(record)
    }

'''
source = source[:reconcile_start] + reconcile_block + source[resolve_start:]

resolve_start = source.index("    /// Resolve a backend alias only as a lookup hint.")
impl_end_marker = "}\n\n/// Device-control lease bound to exact Provider generation and connection epoch."
resolve_end = source.index(impl_end_marker, resolve_start)
resolve_block = r'''    /// Resolve a backend alias only as a lookup hint.
    ///
    /// # Errors
    /// Returns [`DeviceError::AmbiguousAlias`] when the alias appears on multiple
    /// canonical Devices and [`DeviceError::AliasNotFound`] when it is absent.
    pub fn resolve_backend_alias(&self, alias: &str) -> Result<&DeviceRecord, DeviceError> {
        require_nonempty(alias, "backend_alias")?;
        let mut device_indexes = BTreeSet::new();
        for interface in &self.interfaces {
            if interface.observed_aliases.iter().any(|value| value == alias) {
                device_indexes.extend(
                    self.devices
                        .iter()
                        .position(|device| device.device_ref == interface.device_ref),
                );
            }
        }
        match device_indexes.len() {
            0 => Err(DeviceError::AliasNotFound),
            1 => {
                let index = device_indexes
                    .first()
                    .copied()
                    .ok_or(DeviceError::AliasNotFound)?;
                Ok(&self.devices[index])
            }
            _ => Err(DeviceError::AmbiguousAlias),
        }
    }
'''
source = source[:resolve_start] + resolve_block + source[resolve_end:]

lease_struct_marker = "/// Device-control lease bound to exact Provider generation and connection epoch.\n"
request_block = r'''/// Inputs required to issue a Device-control lease projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLeaseRequest {
    /// Stable Device subject.
    pub device_ref: EntityRef,
    /// Lease holder.
    pub holder_ref: EntityRef,
    /// Authorized operation scopes.
    pub scope: Vec<String>,
    /// Positive fencing token.
    pub fence_token: u64,
    /// Exact Provider generation.
    pub provider_generation: ProviderGeneration,
    /// Exact Device connection epoch.
    pub connection_epoch: u64,
    /// Issue timestamp.
    pub issued_at: String,
    /// Expiry timestamp.
    pub expires_at: String,
}

'''
if "pub struct DeviceLeaseRequest" not in source:
    source = source.replace(lease_struct_marker, request_block + lease_struct_marker, 1)

issue_start = source.index("    /// Issue a Device lease projection.")
revoke_start = source.index("    /// Revoke this in-memory lease projection.", issue_start)
issue_block = r'''    /// Issue a Device lease projection.
    ///
    /// # Errors
    /// Rejects zero fence tokens, empty scope, incorrect Device kind, or empty timestamps.
    pub fn issue(request: DeviceLeaseRequest) -> Result<Self, DeviceError> {
        let DeviceLeaseRequest {
            device_ref,
            holder_ref,
            scope,
            fence_token,
            provider_generation,
            connection_epoch,
            issued_at,
            expires_at,
        } = request;
        require_entity_kind(&device_ref, "device.device")?;
        if fence_token == 0 {
            return Err(DeviceError::InvalidFenceToken);
        }
        let scope = scope.into_iter().collect::<BTreeSet<_>>();
        if scope.is_empty() || scope.iter().any(|value| value.trim().is_empty()) {
            return Err(DeviceError::LeaseScopeDenied);
        }
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

'''
source = source[:issue_start] + issue_block + source[revoke_start:]
SOURCE.write_text(source, encoding="utf-8")

tests = TESTS.read_text(encoding="utf-8")
if not tests.startswith("//!"):
    tests = (
        "//! C08 acceptance corpus for device identity, transport, fencing, and read-only protocol admission.\n\n"
        + tests
    )
tests = tests.replace(
    "    DeviceLease, DeviceProviderBinding, DeviceRegistry, FastbootObservationProvider,\n",
    "    DeviceLease, DeviceLeaseRequest, DeviceProviderBinding, DeviceRegistry,\n    FastbootObservationProvider,\n",
    1,
)

helper_marker = "fn adb_observation(\n"
lease_helper = r'''fn issue_lease(
    device_ref: EntityRef,
    holder_ref: EntityRef,
    fence_token: u64,
    provider_generation: ProviderGeneration,
    connection_epoch: u64,
) -> DeviceLease {
    DeviceLease::issue(DeviceLeaseRequest {
        device_ref,
        holder_ref,
        scope: vec!["protocol.observe".to_owned()],
        fence_token,
        provider_generation,
        connection_epoch,
        issued_at: "2026-08-26T00:00:01Z".to_owned(),
        expires_at: "2026-08-26T01:00:01Z".to_owned(),
    })
    .expect("lease")
}

'''
if "fn issue_lease(" not in tests:
    tests = tests.replace(helper_marker, lease_helper + helper_marker, 1)

lease_pattern = re.compile(
    r'''DeviceLease::issue\(\n\s*current\.device\.device_ref\.clone\(\),\n\s*reference\("core\.session"\),\n\s*vec!\["protocol\.observe"\.to_owned\(\)\],\n\s*(?P<token>\d+),\n\s*provider\.context\.provider_generation,\n\s*current\.interface\.connection_epoch,\n\s*"2026-08-26T00:00:01Z",\n\s*"2026-08-26T01:00:01Z",\n\s*\)\n\s*\.expect\("lease"\)'''
)

def replace_lease(match: re.Match[str]) -> str:
    token = match.group("token")
    return (
        "issue_lease(\n"
        "        current.device.device_ref.clone(),\n"
        "        reference(\"core.session\"),\n"
        f"        {token},\n"
        "        provider.context.provider_generation,\n"
        "        current.interface.connection_epoch,\n"
        "    )"
    )

tests, count = lease_pattern.subn(replace_lease, tests)
if count != 6:
    raise SystemExit(f"expected to rewrite 6 DeviceLease::issue call sites, rewrote {count}")
TESTS.write_text(tests, encoding="utf-8")
