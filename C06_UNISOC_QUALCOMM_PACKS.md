# C06 — Unisoc and Qualcomm Packs

**Programme:** C — Device and firmware understanding
**Status:** implementation candidate
**Accepted base:** `170b91195fa5e68ae15a8a9c26b9cf677fd78224` (merged C05)
**Dependencies:** C01 immutable disk/partition foundations; C02 read-only filesystem semantics

## Purpose

C06 adds the next static firmware families required by the accepted Ptah implementation roadmap:

- Unisoc/Spreadtrum PAC package inventory and exact embedded component ranges;
- explicit FDL1/FDL2 static identity, digest and base-address evidence;
- Qualcomm MBN/ELF/Firehose programmer bundle inventory;
- rawprogram/patch XML normalized range plans;
- exact sibling component linkage and materialization;
- deterministic source/component comparison;
- A07 registration, Relationship and View plans;
- explicit loader/programmer evidence boundaries that never manufacture device-write authority.

C06 is a **static package-analysis pack**. It does not upload FDL payloads, enter EDL, perform Sahara handshakes, load a Firehose programmer, execute XML, write/erase/repartition storage, reset devices or expose arbitrary protocol commands.

## Recovered authority

The accepted roadmap defines C06 as:

> PAC/FDL and MBN/ELF/Firehose/XML static families with explicit loader/programmer evidence boundaries.

The recovered donor record for Unisoc requires a native Ptah PAC/profile contract with strict bounds, exact component hashes and explicit FDL compatibility boundaries. Existing `spreadtrum_flash`/`unpac` source cannot be copied into Ptah because licence authority is incomplete; `sprdproto` is a transport reference, not the C06 static implementation.

The recovered Qualcomm record identifies `bkerler/edl` as the primary external EDL/Sahara/Firehose backend candidate under GPL-3.0. C06 therefore keeps Qualcomm Core backend-neutral and static. GPL protocol/runtime code remains outside permissive Ptah Core.

## Frozen authority boundary

C06 separates:

1. immutable package/index identity;
2. exact package/bundle component identity;
3. static loader/programmer metadata;
4. static XML operation/range plans;
5. device transport/session evidence;
6. loader/programmer compatibility;
7. destructive mutation authorization and verified effects.

C06 implements only **1–4**.

The following are outside C06 authority:

- Unisoc BootROM/FDL1/FDL2 upload or execution;
- USB/UART download-mode transitions;
- Qualcomm EDL PID `9008` detection as a session claim;
- Sahara identity/session execution;
- Firehose programmer loading/configuration;
- rawprogram/patch execution;
- partition/full-flash write, erase or repartition;
- reset/reboot/unlock/relock/security-state mutation;
- arbitrary XML/protocol/server/attack commands;
- claiming that FDL/programmer filename, chipset string, HWID, PKHash, signature metadata or XML presence proves device compatibility;
- treating command ACK/process exit as verified device state.

`C06TrustAssessment::NotEstablished` is the only device mutation/programmer compatibility trust value exposed by this static pack.

## Unisoc PAC model

C06 consumes a replaceable, untrusted **mechanical PAC Provider**. This is deliberate: recovered donor evidence establishes PAC header/table fields, but does not justify copying unlicensed parser source or guessing unsupported binary-layout variants in Core.

The Provider may report:

- product name/version/alias;
- explicit PAC magic/header validation result;
- explicit header CRC/check validation result;
- explicit file-table CRC/check validation result;
- file ID and canonical path;
- exact source offset and byte size;
- file version, flags and check flag;
- up to five retained address values;
- static role: FDL1, FDL2, XML, partition image or other;
- expected SHA-256;
- completeness claim and explicit limitations.

Core independently:

- hashes the immutable PAC source;
- validates every canonical path;
- rejects duplicate file IDs and paths;
- checks `offset + size` overflow;
- requires every entry range to lie inside the exact PAC source;
- rejects overlapping supported entry ranges;
- re-hashes every exact source slice and rejects Provider digest lies;
- bounds entry/string/source/materialization resources;
- retains missing magic/CRC validation as explicit partial truth;
- derives FDL evidence only from exact retained entries.

PAC entry flags, check flags, addresses and FDL labels are **metadata/evidence only**. They do not grant loader execution or write trust.

### Unisoc relationships

Embedded PAC components use:

```text
contains.unisoc_pac_component
```

Recovered children use A07 `RecoveredEmbeddedSource` provenance and retain the exact source PAC Revision and producing A04 evidence.

Views:

```text
unisoc.pac.inventory
unisoc.loader.evidence
c06.proof_levels
```

## Qualcomm bundle model

C06 consumes a replaceable, untrusted Qualcomm bundle Provider that returns exact recovered sibling bytes and normalized static plan observations.

Supported component kinds:

```text
Mbn
Elf
FirehoseProgrammer
RawprogramXml
PatchXml
Other
```

Core independently:

- validates canonical sibling paths;
- rejects duplicate paths;
- re-hashes every recovered component;
- bounds aggregate recovered bytes;
- requires rawprogram operations to originate from an exact `RawprogramXml` component;
- requires patch operations to originate from an exact `PatchXml` component;
- retains exact physical partition/LUN, sector size and byte ranges;
- rejects zero sector sizes and arithmetic overflow;
- resolves rawprogram filenames only to exact bundle components;
- keeps unresolved references explicit and reduces assessment truth;
- requires programmer metadata to reference an exact MBN/ELF/Firehose-programmer component;
- retains target/HWID/PKHash/signature observations as evidence only.

A programmer digest or metadata claim does **not** establish compatibility. EDL/Sahara/Firehose runtime proof levels belong to a later/live Facility boundary.

### Qualcomm relationships

Sibling bundle components use:

```text
references.qualcomm_firmware_component
```

Because the primary/index source does not prove embedded containment, recovered sibling provenance remains A07 `Unknown`.

Views:

```text
qualcomm.bundle.inventory
qualcomm.firehose.plan
qualcomm.programmer.evidence
c06.proof_levels
```

## Static proof and assessment

Assessment:

```text
Complete
Partial
Inconclusive
```

Static proof:

```text
InventoryOnly
StructureChecked
ComponentsLinked
PlanLinked
ComponentExact
ByteExact
```

Comparison:

```text
Different
Structural
ComponentExact
ByteExact
```

These levels describe **static package truth only**. None imply bootability, device applicability, FDL compatibility, Sahara readiness, Firehose readiness or successful physical mutation.

## Resource limits

One C06 inspection is bounded by:

- immutable primary-source bytes;
- package/bundle entry count;
- aggregate recovered sibling bytes;
- string/path bytes;
- normalized XML plan operation count;
- exact materialized child bytes.

Zero-valued limits fail closed.

## Fixed 20-case acceptance corpus

The permanent C06 test target contains exactly 20 cases.

### Unisoc — 10

1. valid PAC inventory earns exact ranges and static FDL evidence;
2. out-of-range and overlapping PAC entries fail closed;
3. duplicate IDs/paths and unsafe paths fail closed;
4. PAC source-slice digest lies fail closed;
5. missing magic/CRC validation reduces truth;
6. FDL role/base-address evidence never establishes loader/device compatibility;
7. resource bounds and Provider failure remain explicit;
8. report mutation and changed-source reuse fail closed;
9. materialization/A07 registration/Relationship/View plans retain exact source evidence;
10. comparison distinguishes structural, component-exact and byte-exact states.

### Qualcomm — 10

11. exact bundle links rawprogram, patch and programmer evidence;
12. unsafe/duplicate paths and digest lies fail closed;
13. unresolved rawprogram component references reduce truth;
14. zero sector size, arithmetic overflow and invalid patch ranges fail closed;
15. missing/wrong XML source kinds fail closed;
16. programmer target/HWID/PKHash/signature metadata never establishes compatibility;
17. Provider limitations and resource bounds remain explicit;
18. report mutation, changed source and Provider failure remain explicit;
19. materialization/A07 registration/Relationship/View plans retain exact source evidence;
20. comparison distinguishes structural, component-exact and byte-exact states.

## Permanent proof gate

The C06 exact-head proof must:

- bind directly to accepted C05 merge `170b91195fa5e68ae15a8a9c26b9cf677fd78224`;
- reject diff outside the six-file C06 candidate surface;
- use Rust `1.97.1`;
- pass formatting;
- pass exactly 20 C06 tests;
- pass strict Clippy with warnings denied;
- mechanically prove no public mutation/execution API is exposed by `c06.rs`;
- prove static trust remains `NotEstablished`;
- prove both Unisoc and Qualcomm A07 relationship types exist;
- re-prove C05, C04, C03, C02, C01, B02, B05 and B07;
- re-prove the full locked workspace;
- retain an exact-head manifest and hashed evidence bundle;
- finish on a clean exact checkout.

Review findings must be corrected before Freeze. Only the unchanged reviewed/proven exact head may be promoted.

## Do-not-break rule

> Never turn a PAC flag, FDL label/base address, USB VID/PID, EDL PID `9008`, Sahara identity, programmer filename/digest, target/HWID/PKHash claim, signature observation, rawprogram/patch XML, command acknowledgement or process exit into device compatibility, execution authority or successful device state. C06 is static package truth. Live loader/session/mutation authority remains separate.
