# C11 — Device Manager and MIBU Workload Admissions

Status: frozen implementation/acceptance contract

## Purpose

C11 admits two real THETECHGUY workloads onto the already-proven C09/C10 Device/Application substrate without promoting either specialist product into Ptah Core. The milestone is an admission and proof boundary, not a donor-code import and not a general device-recovery authority.

Dependencies: C09 TTG Device X-Ray admission and C10 Android Application/Device Session v1.

## Frozen donor identities

### THETECHGUY Device Manager

- repository: `https://github.com/jaydumisuni/thetechguy-device-manager`
- visibility: private
- exact commit: `e40189f6a4832124c91172b77967c46c06b5c66a`
- exact tree: `6d1d07b9ca3ddd41dc27c3c159954b578fd16229`
- package: `com.thetechguy.ttgdevicemanager`
- version: `1.0-v1-dev-build`
- `app/build.gradle` blob: `1788d909b968d7f61fdae1faed68e9e35fcf5196`
- manifest blob: `6cb1b744f4cf79f13c84b6757b70124a0b9f4281`
- main activity blob: `3c7a7844b94bc1ee0d4f2131dbf83fbcbc597fe5`
- Device Admin receiver blob: `93a6577dc3a5356d8950f5102efd6a3f71cb9bcf`
- policy preset blob: `f8446ab9ec4fd346ecb49bce60cdac7fda09b93c`
- no reviewed public code-reuse grant is asserted by C11.

The private tree is retained only as exact metadata evidence. No Device Manager Kotlin/Java/batch/private workflow source is copied into the public Ptah implementation.

### MIBU

- repository: `https://github.com/jaydumisuni/MIBU`
- exact commit: `9fb3803dedddc55f07280f660a7c78583f73b138`
- exact tree: `4a300f3825b12be99f8d40b860eb9338dd241d4c`
- Android package: `com.thetechguy.mibu`
- Android version: `0.3.0-dev`
- proof protocol: `3`
- `ProofContract.kt` blob: `7eb86f163521e23d485b0d48a9763a5080f2d115`
- `ProofNonce.kt` blob: `17600f6846259075ddac8fcf019604f8d25a5d5a`
- proof-review tool blob: `3a594bdf1ff57ea9384ebfecc6fc2964406c79c8`
- Windows helper version-info blob: `e83d0dd62f75477af577fb9897f3f9eb12ef21bb`
- no reviewed code-extraction/reuse grant is asserted by C11.

C11 adapts correlation, versioning, proof-level, stale-result, reconnect and release-completeness requirements as native Ptah contracts. It does not copy product workflow implementation.

## Device Manager admission

The first Device Manager slice is intentionally narrow: reversible Device Owner application visibility only.

Admission requires all of the following:

1. exact frozen donor source metadata;
2. current C10 Device Session;
3. current C09 X-Ray disposition `Correlated` with current freshness and exactly matching Device/Interface/Connection/Provider generation/connection epoch;
4. current C10 Device Manager Application Session for the exact package and version;
5. a non-empty C10 `verified_signer`, which is already the result of independent package-signature verification rather than donor/UI assertion;
6. independent current Android Device Owner observation for the Device Manager package/component;
7. explicit current reversible-DPC authorization for `ApplicationVisibility`, bound to the same Device Session, Provider generation and connection epoch;
8. independent pre-operation visibility state;
9. supporting evidence and timestamp.

An admitted operation remains unverified until an independent post-operation Android visibility observation proves the exact requested state under the same Provider generation and connection epoch.

Rollback is separately verified and must restore the independently observed original state. A command return, UI acknowledgement, Device Owner status or policy request alone is never success proof.

### C11 Device Manager exclusions

The C11 Device Manager adapter cannot admit:

- Device Owner enrollment/ownership-changing provisioning;
- factory reset;
- FRP removal;
- MDM removal;
- raw partition writes;
- OTA policy mutation;
- firmware/recovery operations;
- any action inferred merely from DPC ownership.

Those require separately reviewed later adapter families and their own case/consent/backup/authorization/read-back boundaries.

## MIBU admission

MIBU is admitted as a cross-application/device correlation and evidence workload, not as generic Ptah write authority.

Initial admission requires:

1. exact frozen MIBU source metadata;
2. current C10 Device Session;
3. current C10 MIBU Application Session for package `com.thetechguy.mibu`, version `0.3.0-dev`, current Provider generation/connection epoch and verified signer state inherited from C10;
4. current correlated C09 X-Ray evidence for the same Device context;
5. a nonce matching exactly `[A-Za-z0-9_-]{8,64}`;
6. supporting evidence and timestamp.

The admitted record retains only SHA-256 and length of the nonce, not the raw nonce. Automatic replay is always disabled.

### Proof reconciliation

Every presented MIBU proof must match:

- Ptah operation reference;
- current Application Session reference;
- nonce digest and length;
- proof protocol `3`;
- producer application version `0.3.0-dev`;
- current Provider generation;
- current connection epoch;
- independently authenticated producer evidence.

A correct nonce is correlation only; it is not producer authentication.

Proof levels remain distinct:

- `ActivityLaunched` — launch acknowledgement only;
- `RuntimeArmed` — current runtime/service readiness;
- `OperationComplete` — correlated product-workflow completion, not external official authority;
- `ExternalAuthoritativeResult` — separately classified official external result with a retained result reference.

Launch/runtime proof never becomes operation or external success by inference. Once an external authoritative result is recorded, lower or conflicting proof cannot replace it.

### Reconnect

Reconnect may rebind Provider generation/connection epoch while preserving the stable Ptah Device Session, Application Session, operation identity and nonce digest. Rebind increments a generation and never enables automatic replay. Proof from the prior epoch is stale.

## MIBU release completeness

A C11 MIBU release projection must contain one digest-bound Artifact for every required role:

- Android APK;
- Windows helper;
- platform tools;
- expected UI/static evidence;
- checksum manifest.

Every Artifact requires a canonical lowercase SHA-256. Missing/duplicate roles, malformed digests or donor version/protocol/source drift fail closed. Static/release completeness does not claim physical-device facts.

## Acceptance proof

The C11 acceptance corpus contains 22 tests proving:

- exact source-lock and private-source non-extraction behavior;
- exact Device Manager package/version and C10 verified signer requirement;
- explicit current reversible-DPC authorization;
- current C09/C10 Device context and stale-epoch rejection;
- independent Device Owner observation;
- exclusion of ownership-changing/destructive/recovery intents;
- post-condition read-back before policy success;
- verified rollback to original state;
- exact MIBU source/protocol/application version;
- bounded nonce syntax and digest-only retained correlation;
- nonce is not authentication;
- wrong nonce/protocol/version or stale epoch rejection;
- separation of launch/runtime/operation/external-result proof levels;
- preservation of authoritative external results;
- reconnect without automatic replay and rejection of old-epoch proof;
- complete digest-bound release composition.

C09 20-case and C10 26-case acceptance suites are inherited regression gates. The full locked workspace is also re-proven before C11 shipment.

## Frozen non-goals

C11 does not:

- execute either donor product;
- copy private or unlicensed donor implementation;
- make X-Ray evidence execution authority;
- make a nonce authentication;
- infer official external success;
- automatically replay physical operations after disconnect;
- expose generic Device recovery, bootloader, firmware, FRP/MDM removal or raw-write authority.
