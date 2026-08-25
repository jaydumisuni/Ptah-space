# C05 — MediaTek Pack

**Programme:** C — Device and firmware understanding
**Status:** implementation candidate
**Accepted base:** `3b9bcb02c8221d0fc2b0be833c491ac445120b4b` (merged C04)
**Dependencies:** C01 immutable disk/partition foundations; C02 read-only filesystem semantics

## Purpose

C05 adds the MediaTek static firmware pack required by the accepted Ptah implementation roadmap:

- bounded MediaTek scatter parsing;
- exact partition index/name/file/range/region/storage relationships;
- exact sibling bundle inventory through an untrusted replaceable Provider;
- digest-bound linkage from scatter file references to recovered sibling bytes;
- bounded correlation with separately supplied lawful read-only MTK/META evidence;
- deterministic static comparison and rebuild proof levels;
- source-bound A07 registration, relationship and view plans.

C05 is a **static package-analysis pack**. It is not a MediaTek flash engine and it does not activate a physical-device Facility.

## Frozen authority boundary

The accepted Phase 0A firmware architecture separates:

1. immutable firmware package/image identity;
2. package manifest/partition relationships;
3. device/profile observations;
4. compatibility evidence;
5. static read-only analysis;
6. physical read/write/erase/reset/flash operations.

C05 implements only the static package side plus correlation with separately supplied read-only evidence.

The following are explicitly **outside C05 authority**:

- loading a Download Agent, preloader, payload or exploit;
- BROM/Preloader/DA/V6/META mode transitions;
- partition or region writes;
- erase, format, repartition or reset;
- unlock/relock or other security-state mutation;
- RPMB, eFuse, NV or calibration mutation;
- arbitrary protocol commands, memory writes or shell execution;
- physical-write compatibility or authorization;
- treating a command ACK/process exit as device state.

MTKClient remains a separate GPL Facility/backend candidate. Internal native META evidence remains a separate read-only Facility/evidence source. Neither is copied into C05 Core.

## Immutable source and package model

The C05 source is an exact immutable MediaTek scatter Object Revision. Core computes and seals:

- source Object Revision;
- byte size;
- lowercase SHA-256;
- scatter config version when supplied;
- platform claim;
- storage-family claim;
- exact partition records.

A scatter file may reference sibling package files. Those sibling bytes are **referenced**, not embedded in the scatter source. C05 therefore uses a `references.mediatek_firmware_component` relationship rather than a containment relationship.

The current A07 origin vocabulary has no dedicated sibling-package origin. A C05 sibling materialization therefore remains `OriginClass::Unknown` until a wider package Object supplies stronger provenance. It is never mislabeled as an embedded source.

## Scatter grammar accepted by C05

C05 accepts UTF-8 text and recognizes the standard MediaTek partition block beginning with:

```text
- partition_index: <token>
```

For every supported partition, these fields are required exactly once:

```text
partition_index
partition_name
file_name
is_download
type
linear_start_addr
physical_start_addr
partition_size
region
storage
```

Supported numeric values are unsigned decimal or `0x`/`0X` hexadecimal. Signed, malformed or overflowing values fail closed.

`file_name: NONE` means that no sibling component is referenced.

`is_download` is retained as **scatter metadata only**. `is_download: true` does not create a Ptah write capability, compatibility result or device authorization.

Each partition exposes exact half-open linear and physical byte ranges. Range-end arithmetic must not overflow.

Duplicate partition indices or partition names fail closed because they make the supported C05 relationship projection ambiguous.

Unknown scatter keys are tolerated but do not become C05 truth.

## Bundle Provider boundary

Sibling package recovery is mechanical and replaceable. The untrusted Provider returns:

- canonical relative path candidate;
- exact recovered bytes;
- provider-declared lowercase SHA-256;
- bounded completeness claim;
- explicit limitations.

Core independently:

- rejects absolute, drive-qualified, backslash, traversal, empty-component and NUL paths;
- rejects duplicate canonical paths;
- re-hashes every recovered byte sequence;
- enforces entry-count, string and aggregate-byte limits;
- links only exact scatter `file_name` references;
- records unresolved references explicitly;
- prevents an incomplete Provider claim from becoming complete package truth.

A missing bundle Provider is reportable: scatter structure remains useful, but referenced component bytes are not promoted to exact linkage.

Any non-empty validated bundle Provider `limitations` list reduces the package assessment to `Partial` and blocks `BundleLinked`, even when the Provider also sets `complete_claim: true`. The raw completeness claim remains retained evidence; it is not allowed to erase an explicit partial-semantics limitation.

## Lawful MTK/META evidence boundary

C05 may correlate the static scatter projection with separately supplied bounded **read-only evidence**. The evidence Provider can report only:

- mode: BROM, Preloader, DA, V6, META, Stock or Unknown;
- optional USB VID/PID transport identity;
- optional platform claim;
- optional storage-family claim;
- bounded partition-name inventory;
- explicit read-only service-session evidence flag;
- explicit layout-inventory evidence flag;
- completeness claim and limitations.

Proof levels are monotonic:

```text
Unestablished
TransportPresence
ModePresence
ServiceSessionEvidence
LayoutEvidence
```

A service-session claim requires explicit transport identity and a non-Unknown mode. A layout inventory requires a service-session claim and a non-empty bounded partition list.

### META PID 2007 rule

MediaTek USB VID `0x0E8D` / PID `0x2007` may establish transport/mode presence when supplied by the Provider. It **does not establish a valid META service session** by itself.

C05 reaches `ServiceSessionEvidence` only when the Provider separately supplies the explicit service-session evidence flag. `LayoutEvidence` requires the separate layout-inventory evidence flag as well.

No evidence level grants physical mutation authority.

Any non-empty validated evidence Provider `limitations` list reduces the report assessment to `Partial` and blocks `EvidenceCorrelated`, even when the Provider also sets `complete_claim: true`.

## Static evidence correlation

When read-only layout evidence is supplied, Core compares:

- scatter platform claim versus evidence platform claim;
- scatter storage claim versus evidence storage claim;
- exact scatter partition-name set versus evidence partition-name set when a layout was inventoried.

Contradictory supplied evidence reduces the report to `Partial` and remains visible as an explicit limitation.

`EvidenceCorrelated` is earned only when:

- all referenced bundle components are exactly linked (or the scatter references none);
- the evidence Provider claims complete C05-supported evidence;
- `LayoutEvidence` is established;
- platform, storage and partition-name sets all agree.

This is a static correlation result, **not** `compatible_for_write`.

## Assessment and proof levels

### Assessment

```text
Complete
Partial
Inconclusive
```

### Static proof

```text
InventoryOnly
StructureChecked
BundleLinked
EvidenceCorrelated
ComponentExact
ByteExact
```

`BundleLinked` means every scatter-referenced sibling component resolves to exact digest-bound bytes through a complete bundle observation.

`EvidenceCorrelated` adds the strict read-only correlation rules above.

`ComponentExact` and `ByteExact` are comparison/rebuild proof levels only. They do not imply flashability, bootability, loader compatibility or physical-device success.

## Materialization and A07 plans

C05 materializes only exact bundle entries that are referenced by the scatter report.

Every materialization retains:

- exact scatter source Revision;
- exact canonical sibling path;
- exact bytes;
- exact SHA-256.

A07 registration uses:

- revision role `Recovered`;
- origin `Unknown` for sibling-package provenance;
- exact source Revision reference;
- exact producing A04 evidence;
- expected SHA-256.

The relationship type is:

```text
references.mediatek_firmware_component
```

C05 source-bound views are:

```text
mediatek.scatter.inventory
mediatek.partition.relationships
mediatek.lawful_evidence
mediatek.proof_levels
```

A sealed report is revalidated before materialization or view planning. A different source revision, source digest/size, mutated report or mismatched registration fails closed.

## Deterministic comparison

C05 exposes four comparison levels:

```text
Different
Structural
ComponentExact
ByteExact
```

- `Different`: supported scatter/partition structure differs.
- `Structural`: supported structure matches but retained bundle component digests differ.
- `ComponentExact`: supported structure and retained component identities/digests match while scatter bytes differ outside that projection.
- `ByteExact`: scatter bytes **and** retained component identities/digests are exact.

This prevents identical scatter text from masking changed sibling firmware bytes.

## Resource limits

One C05 inspection is bounded by:

- scatter source bytes;
- input lines;
- partition count;
- bundle entry count;
- aggregate recovered bundle bytes;
- string/path bytes;
- evidence partition count;
- materialized child bytes.

Zero-valued limits are invalid.

## Fixed 20-case acceptance corpus

The permanent C05 test target contains exactly 20 cases:

1. valid scatter + complete bundle links exact components;
2. scatter-only inspection remains device-independent and partial when referenced bytes are unavailable;
3. traversal/absolute/backslash/drive bundle paths are rejected;
4. duplicate bundle paths are rejected;
5. recovered-byte digest lies are rejected;
6. entry/byte/string/line resource limits fail closed;
7. malformed UTF-8 scatter is rejected;
8. missing required partition fields are rejected;
9. signed/malformed numeric fields are rejected;
10. partition-range overflow is rejected;
11. duplicate partition index/name is rejected;
12. missing scatter-referenced component reduces truth;
13. incomplete bundle Provider claim remains partial;
14. exact lawful read-only layout evidence earns evidence correlation;
15. VID `0x0E8D` / PID `0x2007` without service evidence stops below service-session proof;
16. contradictory platform/storage/layout evidence reduces truth;
17. `is_download: true` remains metadata and never establishes write trust;
18. report mutation and changed-source reuse fail closed;
19. exact materialization/A07 registration/relationship/view plans retain source evidence;
20. comparison distinguishes `Different`, `Structural`, `ComponentExact` and `ByteExact`.

## Permanent proof gate

The C05 exact-head proof must:

- lock the accepted C04 merge as its base;
- reject any diff outside the six-file C05 candidate surface;
- use Rust `1.97.1`;
- pass formatting;
- pass exactly 20 C05 tests;
- pass strict Clippy with warnings denied;
- mechanically confirm the public C05 source contains no mutation/flash API surface;
- re-prove C04, C03, C02, C01, B02, B05 and B07;
- re-prove the full locked workspace;
- retain an exact-head manifest and hashed evidence bundle;
- finish with a clean exact checkout.

Review findings must be corrected before Freeze. Only the unchanged reviewed/proven exact head may be merged.

## Do-not-break rule

> Never treat a scatter `is_download` flag, partition name, platform/chipset string, USB VID/PID, META PID `0x2007`, mode label, loader/DA presence, service claim, bundle extraction, command acknowledgement or process exit as physical-write compatibility or successful device state. C05 is static package truth plus bounded read-only evidence correlation; destructive device authority remains separate.
