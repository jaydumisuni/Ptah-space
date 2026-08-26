# C08 — Device Identity and Transport Substrate

**Programme:** C — Firmware and Device
**Status:** implementation candidate
**Accepted construction base:** `ae7a9c9c939db03df55f97ebb3edffd68216197b`
**Roadmap dependencies:** A04, A06, A07, A13
**C07 relationship:** reserved vendor-completion work remains parked unless lawful samples, source and proof exist

## Purpose

C08 establishes the runtime substrate required to reason about a physical or virtual Device without confusing backend endpoint names with canonical Device identity.

It delivers:

- stable canonical Device identity and candidate grouping;
- Device Interface incarnations;
- monotonic Device Connection epochs;
- observation-only ADB, Fastboot/Fastbootd, Apple USB and supported USB-serial Provider lanes;
- Provider Generation and provider-control-epoch fencing;
- Device Lease and Fence enforcement;
- Activity/Operation/Attempt-bound protocol-operation projections;
- explicit unstable/re-enumerating USB recovery;
- a hard boundary between read evidence and physical Device mutation authority.

C08 is **not** a vendor firmware pack and is **not** a physical mutation backend.

## Frozen contract authority

C08 consumes the existing frozen Phase-0B contracts rather than inventing replacement entities:

- `urn:ptah:schema:domain:device:0.1.0`;
- `urn:ptah:schema:domain:device-interface:0.1.0`;
- `urn:ptah:schema:domain:device-connection:0.1.0`;
- `urn:ptah:schema:domain:device-connection-observation:0.1.0`;
- `urn:ptah:schema:domain:device-protocol-operation:0.1.0`;
- `urn:ptah:schema:isolation:lease:0.1.0`;
- `urn:ptah:schema:isolation:fence-observation:0.1.0`;
- Device, Interface, Connection, Protocol Operation and Lease lifecycle machines already frozen in the roadmap repository.

The frozen contracts establish that:

- Device identity is canonical Ptah identity backed by `identity_basis_refs`;
- backend serial/port/USB/address facts are aliases/evidence;
- Interface state binds an exact Provider Instance and Provider Generation;
- node-local Interfaces retain a connection epoch;
- Device Connections retain their own monotonic epoch, predecessor and transition reason;
- observations retain exact evidence and reachability;
- protocol operations bind Device/Profile/Session/Interface/Connection, Provider Generation, Activity, Operation and Attempt evidence;
- Lease state carries a positive fence token and Provider Generation;
- Fence Observation distinguishes current, stale, ahead, missing and inconclusive state.

## Canonical identity rule

A backend alias never creates or replaces canonical Device identity.

Examples of alias/evidence only:

- ADB serial;
- Fastboot serial;
- Apple UDID-like backend identifier;
- USB bus/path;
- VID/PID claim;
- COM port or `/dev/tty*` path;
- provider-native endpoint identifier;
- network endpoint.

C08 groups an observation with an existing Device only when canonical identity-basis evidence overlaps exactly one Device. If one observation overlaps more than one Device basis, reconciliation fails closed as ambiguous.

An observation may add new canonical identity-basis evidence to an existing Device without re-keying the Device.

## Interface and connection epochs

A Device Interface represents one protocol/mode incarnation such as:

- ADB USB/TCP/TLS;
- Fastboot;
- Fastbootd;
- Apple normal/recovery/DFU USB observation;
- supported USB serial mode.

The Device remains stable while Interfaces may appear, disappear or coexist.

A Device Connection epoch advances when evidence shows continuity has changed, including:

- Provider Generation change;
- Provider control connection-epoch change;
- transport continuity-basis change;
- topology/address re-enumeration;
- recovery from intermittent/unreachable evidence.

Every new epoch retains its predecessor and transition reason. Old epochs remain evidence and cannot authorize current work.

## Observation Providers

C08 implements observation-only Provider lanes.

### ADB

Accepts `adb_usb`, `adb_tcp` and `adb_tls` observations. Backend ADB serial remains an alias.

### Fastboot / Fastbootd

Accepts `fastboot_usb` and `fastboot_tcp`. Fastboot and Fastbootd are separate Interface modes on the same stable Device when identity evidence matches.

### Apple USB

Normal, Recovery and DFU are normalized as `usb_vendor` observations. C08 does not restore, boot payloads, erase or write Apple devices.

### USB serial

Retains supported COM/TTY/serial endpoint data as aliases/evidence only. It does not infer a vendor, chipset, download authority or write capability from a port name or VID/PID claim.

## Device Lease and Fence

A Device Lease is bound to:

- exact Device subject;
- holder;
- non-empty scope;
- positive fence token;
- exact Provider Generation;
- exact Device Connection epoch;
- issue and expiry projection.

Admission fails closed when:

- the Lease is revoked;
- Device subject differs;
- Provider Generation is stale;
- Device Connection epoch is stale;
- required scope is absent;
- observed fence token is stale;
- observed fence token is unexpectedly ahead.

A stale Lease is evidence, not authority.

## Protocol Operation / Attempt evidence

C08 may admit a protocol operation only when it binds:

- stable Device;
- current Device Interface and Connection;
- exact Provider Instance and Provider Generation;
- current Device Connection epoch;
- current Lease and Fence;
- registered protocol class/key;
- Activity;
- Operation;
- at least one Attempt;
- supporting evidence.

Provider or command acknowledgement alone is never enough to manufacture verified Device state.

## Mutation boundary

C08 may admit only classes that do not grant physical Device mutation authority:

- `none_read_only`;
- `copy_only`;
- `workspace_object_mutation`;
- `device_read`;
- `device_backup`.

C08 rejects:

- filesystem/device write authority;
- physical Device write;
- erase;
- repartition;
- reset/reboot;
- security-state mutation;
- protected-NV mutation;
- Device-side payload execution;
- unregistered mutation classes.

Supplying a `physical_authority_ref` does **not** upgrade C08 into a mutation backend. Higher-level mutation packages must independently establish policy, Grant, exact target/range, precondition, protocol-stage evidence and verified effects.

## C07 boundary

C07 remains a reserved completion lane for Samsung, Huawei/Honor, LG, Sony, OPPO/Realme/OnePlus, embedded and unknown-vendor packs.

C08 does not claim any of those vendor packs. Their implementation remains conditional on lawful samples, source authority and proof.

## Fixed 20-case acceptance corpus

1. Device Provider binding requires `ProviderKind::Device` and exact revision match.
2. Backend alias change cannot replace canonical Device identity.
3. Additional identity evidence extends an existing Device without re-keying it.
4. Identity evidence overlapping two Devices fails closed.
5. One backend alias resolving to multiple Devices fails closed.
6. Fastboot and Fastbootd remain distinct Interfaces on one stable Device.
7. Provider Generation change advances Device Connection epoch.
8. Provider control connection-epoch change advances Device Connection epoch.
9. USB topology re-enumeration advances epoch without replacing Device identity.
10. Changed continuity basis advances epoch and retains predecessor evidence.
11. Intermittent USB recovery advances epoch with explicit reconnect reason.
12. Apple normal/recovery/DFU remain observation-only USB modes.
13. USB serial COM/TTY name remains alias/evidence only.
14. Observation Providers reject incompatible transports and missing identity basis.
15. Current Device Lease and fence are accepted.
16. Lease fails after Provider Generation changes.
17. Lease fails after Device Connection epoch changes.
18. Stale/ahead fences, absent scope and revoked leases fail closed.
19. Read protocol operation requires current Device/Provider/epoch/Lease/Fence/Attempt evidence.
20. Physical-authority evidence cannot upgrade C08 into Device-write authority.

## Permanent proof gate

The exact-head C08 proof must:

- bind to a reviewed C08 candidate based on a descendant of the accepted C06 merge;
- reject overlapping base drift across the C08 protected surface;
- use Rust `1.97.1`;
- pass formatting;
- pass exactly 20 C08 acceptance tests;
- pass strict Clippy with warnings denied;
- mechanically prove no public physical mutation executor is exposed;
- prove backend aliases never form canonical identity;
- prove stale Provider Generation and Device Connection epochs fail closed;
- prove Device Lease/Fence failure behavior;
- prove read evidence cannot become write authority;
- re-prove C06 and inherited C01–C05/B02/B05/B07 surfaces;
- re-prove A13 checkpoint/recovery behavior;
- re-prove the full locked workspace;
- retain an exact-head manifest and proof bundle;
- finish on a clean exact checkout.

Review findings must be corrected before Freeze. Only the unchanged reviewed and proven exact head may be submitted.

## Do-not-break rule

> Never promote an ADB/Fastboot serial, Apple backend identifier, COM/TTY path, USB topology, VID/PID claim, Provider acknowledgement, protocol handshake, current port presence or caller-supplied physical-authority reference into canonical Device identity, current control authority or successful physical mutation. Device identity requires canonical evidence. Control requires current Provider Generation, Connection epoch, Lease and Fence. Physical mutation remains outside C08.
